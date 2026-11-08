//! Parse `go.work` to discover module directories in a monorepo.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

/// A module entry discovered from `go.work`.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceModule {
    /// Relative directory from the go.work root (e.g. `./oauth-core` → `oauth-core`).
    pub dir: PathBuf,
    /// Absolute path to the module directory.
    pub abs_dir: PathBuf,
}

/// Parse `go.work` in `root` and return the list of `use` directives as
/// module entries. Fails if `go.work` is missing or contains no `use`
/// directives.
pub(crate) fn discover_modules(root: &Path) -> Result<Vec<WorkspaceModule>> {
    let modules = discover_module_entries(root)?;
    for module in &modules {
        if !module.abs_dir.join("main.go").exists() {
            return Err(anyhow!(
                "module {} has no main.go — is it a valid module?",
                module.abs_dir.display()
            ));
        }
    }
    Ok(modules)
}

/// Dev startup historically skips `go.work` entries that are not modules yet.
/// Keep those entries visible long enough for `dev/mod.rs` to distinguish a
/// genuine missing `main.go` from a malformed module, while stricter callers
/// continue using [`discover_modules`].
pub(super) fn discover_dev_modules(root: &Path) -> Result<Vec<WorkspaceModule>> {
    discover_module_entries(root)
}

/// Scan `root` for sibling directories that contain a `go.mod` but are not
/// listed in any `use` directive of `go.work`. `go.work` is gitignored (it
/// carries a machine-absolute SDK replace), so a merged module can go
/// unnoticed on every machine until someone edits their own `go.work` — this
/// is what lets `dev` warn about that drift instead of staying silent.
pub(super) fn scan_unlisted_modules(
    root: &Path,
    modules: &[WorkspaceModule],
) -> Result<Vec<PathBuf>> {
    let mut unlisted = Vec::new();
    let entries =
        fs::read_dir(root).with_context(|| format!("dev: scan {}", root.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("dev: scan {}", root.display()))?;
        let path = entry.path();
        if !path.is_dir() || !path.join("go.mod").is_file() {
            continue;
        }
        let name = entry.file_name();
        let already_listed = modules.iter().any(|m| {
            m.dir
                .components()
                .next()
                .is_some_and(|c| c.as_os_str() == name)
        });
        if !already_listed {
            unlisted.push(PathBuf::from(name));
        }
    }
    unlisted.sort();
    Ok(unlisted)
}

fn discover_module_entries(root: &Path) -> Result<Vec<WorkspaceModule>> {
    let go_work = root.join("go.work");
    let body =
        fs::read_to_string(&go_work).with_context(|| format!("dev: read {}", go_work.display()))?;

    let dirs = parse_use_directives(&body);
    if dirs.is_empty() {
        return Err(anyhow!(
            "go.work has no `use` directives — add at least one module"
        ));
    }

    let mut modules = Vec::with_capacity(dirs.len());
    for rel in dirs {
        let abs = root.join(&rel);
        modules.push(WorkspaceModule {
            dir: PathBuf::from(&rel),
            abs_dir: abs,
        });
    }
    Ok(modules)
}

/// Extract relative paths from `use` directives. Handles both block syntax:
///
/// ```text
/// use (
///     ./oauth-core
///     ./oauth-google
/// )
/// ```
///
/// and single-line syntax: `use ./oauth-core`
fn parse_use_directives(body: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut in_block = false;

    for line in body.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("//") {
            continue;
        }

        if in_block {
            if trimmed == ")" {
                in_block = false;
                continue;
            }
            if let Some(dir) = clean_use_path(trimmed) {
                result.push(dir);
            }
        } else if let Some(rest) = trimmed.strip_prefix("use") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
            } else if let Some(dir) = clean_use_path(rest) {
                result.push(dir);
            }
        }
    }
    result
}

/// Strip `./` prefix and trailing comments from a use-directive path.
fn clean_use_path(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.starts_with("//") {
        return None;
    }
    // Strip inline comment
    let s = match s.find("//") {
        Some(pos) => s[..pos].trim(),
        None => s,
    };
    let s = s.strip_prefix("./").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_block_syntax() {
        let input = r#"
go 1.26

use (
    ./oauth-core
    ./oauth-google
)
"#;
        let dirs = parse_use_directives(input);
        assert_eq!(dirs, vec!["oauth-core", "oauth-google"]);
    }

    #[test]
    fn parse_single_line_syntax() {
        let dirs = parse_use_directives("use ./my-module\n");
        assert_eq!(dirs, vec!["my-module"]);
    }

    #[test]
    fn parse_ignores_comments() {
        let input = r#"
use (
    // ./disabled
    ./active
    ./with-comment // inline note
)
"#;
        let dirs = parse_use_directives(input);
        assert_eq!(dirs, vec!["active", "with-comment"]);
    }

    #[test]
    fn parse_empty_returns_empty() {
        let dirs = parse_use_directives("go 1.26\n");
        assert!(dirs.is_empty());
    }

    #[test]
    fn parse_without_dot_slash_prefix() {
        let dirs = parse_use_directives("use my-module\n");
        assert_eq!(dirs, vec!["my-module"]);
    }

    #[test]
    fn discover_modules_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("go.work"),
            "go 1.26\n\nuse (\n\t./mod-a\n\t./mod-b\n)\n",
        )
        .unwrap();
        std::fs::create_dir(tmp.path().join("mod-a")).unwrap();
        std::fs::write(tmp.path().join("mod-a/main.go"), "package main").unwrap();
        std::fs::create_dir(tmp.path().join("mod-b")).unwrap();
        std::fs::write(tmp.path().join("mod-b/main.go"), "package main").unwrap();

        let mods = discover_modules(tmp.path()).unwrap();
        assert_eq!(mods.len(), 2);
        assert_eq!(mods[0].dir, PathBuf::from("mod-a"));
        assert_eq!(mods[1].dir, PathBuf::from("mod-b"));
    }

    #[test]
    fn discover_modules_rejects_missing_main_go() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("go.work"), "use ./empty-mod\n").unwrap();
        std::fs::create_dir(tmp.path().join("empty-mod")).unwrap();

        let err = discover_modules(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("no main.go"));
    }

    #[test]
    fn scan_unlisted_modules_finds_module_missing_from_go_work() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("go.work"), "use ./oauth-core\n").unwrap();
        std::fs::create_dir(tmp.path().join("oauth-core")).unwrap();
        std::fs::write(tmp.path().join("oauth-core/go.mod"), "module oauth-core").unwrap();
        std::fs::create_dir(tmp.path().join("video-core")).unwrap();
        std::fs::write(tmp.path().join("video-core/go.mod"), "module video-core").unwrap();

        let modules = discover_module_entries(tmp.path()).unwrap();
        let unlisted = scan_unlisted_modules(tmp.path(), &modules).unwrap();
        assert_eq!(unlisted, vec![PathBuf::from("video-core")]);
    }

    #[test]
    fn scan_unlisted_modules_ignores_dirs_without_go_mod() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("go.work"), "use ./oauth-core\n").unwrap();
        std::fs::create_dir(tmp.path().join("oauth-core")).unwrap();
        std::fs::write(tmp.path().join("oauth-core/go.mod"), "module oauth-core").unwrap();
        std::fs::create_dir(tmp.path().join("node_modules")).unwrap();

        let modules = discover_module_entries(tmp.path()).unwrap();
        let unlisted = scan_unlisted_modules(tmp.path(), &modules).unwrap();
        assert!(unlisted.is_empty());
    }

    #[test]
    fn scan_unlisted_modules_empty_when_all_listed() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("go.work"), "use ./oauth-core\n").unwrap();
        std::fs::create_dir(tmp.path().join("oauth-core")).unwrap();
        std::fs::write(tmp.path().join("oauth-core/go.mod"), "module oauth-core").unwrap();

        let modules = discover_module_entries(tmp.path()).unwrap();
        let unlisted = scan_unlisted_modules(tmp.path(), &modules).unwrap();
        assert!(unlisted.is_empty());
    }
}
