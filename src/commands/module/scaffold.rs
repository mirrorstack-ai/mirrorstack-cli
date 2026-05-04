//! Scaffold a new local module source tree from the embedded template.
//!
//! Templates are vendored under `templates/module/` and embedded at build
//! time via `include_str!`. Substitution is straight string replace using
//! `__MS_*__` markers — no template engine, no Go-template syntax conflicts.
//!
//! Source of truth for the template shape is the SDK's
//! `examples/template/`. When the SDK changes shape, the vendored copy here
//! must be re-synced — there is no automatic mirroring yet.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

const MAIN_GO: &str = include_str!("../../../templates/module/main.go.tmpl");
const MCP_GO: &str = include_str!("../../../templates/module/mcp.go.tmpl");
const ROUTES_GO: &str = include_str!("../../../templates/module/routes.go.tmpl");
const GO_MOD: &str = include_str!("../../../templates/module/go.mod.tmpl");
const SQL_INIT: &str =
    include_str!("../../../templates/module/sql/app/0001_init.up.sql.tmpl");

// Placeholder tokens. Kept in one place so the contract between the .tmpl
// files and this renderer is auditable from a single grep.
const SLUG_TOKEN: &str = "__MS_SLUG__";
const NAME_TOKEN: &str = "__MS_NAME__";
const TABLE_PREFIX_TOKEN: &str = "__MS_TABLE_PREFIX__";

/// Inputs collected by the caller before scaffolding.
pub(super) struct Inputs<'a> {
    pub slug: &'a str,
    pub name: &'a str,
}

/// Refuse if `target` already contains files. Empty dir or missing dir = OK.
pub(super) fn ensure_target_writable(target: &Path) -> Result<()> {
    match fs::read_dir(target) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(anyhow!(
                    "{} is not empty — pick a different --dir or remove it",
                    target.display()
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("scaffold: read {}: {e}", target.display())),
    }
}

pub(super) fn write_tree(target: &Path, inputs: &Inputs<'_>) -> Result<()> {
    fs::create_dir_all(target.join("sql/app"))
        .with_context(|| format!("scaffold: mkdir {}/sql/app", target.display()))?;

    write_file(target, "main.go", MAIN_GO, inputs)?;
    write_file(target, "mcp.go", MCP_GO, inputs)?;
    write_file(target, "routes.go", ROUTES_GO, inputs)?;
    write_file(target, "go.mod", GO_MOD, inputs)?;
    write_file(target, "sql/app/0001_init.up.sql", SQL_INIT, inputs)?;
    Ok(())
}

/// Write a rendered template using `create_new` semantics so a file racing
/// in between `ensure_target_writable` and here surfaces as an error rather
/// than a silent overwrite. The caller's own `--dir` is the source of truth
/// for what's safe to write — anything that appeared after we checked is
/// not ours to clobber.
fn write_file(target: &Path, rel: &str, body: &str, inputs: &Inputs<'_>) -> Result<()> {
    let path = target.join(rel);
    let rendered = render(body, inputs);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("scaffold: create {}", path.display()))?;
    f.write_all(rendered.as_bytes())
        .with_context(|| format!("scaffold: write {}", path.display()))?;
    Ok(())
}

fn render(body: &str, inputs: &Inputs<'_>) -> String {
    body.replace(SLUG_TOKEN, inputs.slug)
        .replace(NAME_TOKEN, inputs.name)
        .replace(TABLE_PREFIX_TOKEN, &table_prefix(inputs.slug))
}

/// Convert a module slug (`my-mod`) into a valid Postgres identifier prefix
/// (`my_mod`). The SQL template appends `_items` etc. — caller controls the
/// suffix.
fn table_prefix(slug: &str) -> String {
    slug.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ins<'a>(slug: &'a str, name: &'a str) -> Inputs<'a> {
        Inputs { slug, name }
    }

    #[test]
    fn render_substitutes_slug_and_name() {
        let out = render(MAIN_GO, &ins("my-mod", "My Mod"));
        assert!(out.contains(r#"ID:   "my-mod""#));
        assert!(out.contains(r#"Name: "My Mod""#));
        assert!(!out.contains("__MS_SLUG__"));
        assert!(!out.contains("__MS_NAME__"));
    }

    #[test]
    fn render_substitutes_in_go_mod() {
        let out = render(GO_MOD, &ins("media", "Media"));
        assert!(out.starts_with("module media\n"));
        assert!(!out.contains("__MS_SLUG__"));
    }

    #[test]
    fn table_prefix_replaces_hyphens() {
        assert_eq!(table_prefix("media"), "media");
        assert_eq!(table_prefix("my-mod"), "my_mod");
        assert_eq!(table_prefix("a-b-c"), "a_b_c");
    }

    #[test]
    fn render_sql_uses_table_prefix() {
        let out = render(SQL_INIT, &ins("my-mod", "My Mod"));
        assert!(out.contains("CREATE TABLE IF NOT EXISTS my_mod_items"));
        assert!(!out.contains("__MS_TABLE_PREFIX__"));
    }

    #[test]
    fn render_routes_substitutes_slug_in_response_body() {
        let out = render(ROUTES_GO, &ins("media", "Media"));
        assert!(out.contains(r#""hello from media""#));
    }

    #[test]
    fn ensure_target_writable_accepts_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        ensure_target_writable(&missing).unwrap();
    }

    #[test]
    fn ensure_target_writable_accepts_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_target_writable(tmp.path()).unwrap();
    }

    #[test]
    fn ensure_target_writable_rejects_non_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("anything"), b"x").unwrap();
        let err = ensure_target_writable(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("not empty"));
    }

    #[test]
    fn write_tree_creates_expected_files() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("media");
        write_tree(&target, &ins("media", "Media")).unwrap();
        for rel in [
            "main.go",
            "mcp.go",
            "routes.go",
            "go.mod",
            "sql/app/0001_init.up.sql",
        ] {
            let p = target.join(rel);
            assert!(p.exists(), "missing {}", p.display());
        }
        let main = fs::read_to_string(target.join("main.go")).unwrap();
        assert!(main.contains(r#"ID:   "media""#));
    }

    #[test]
    fn write_tree_refuses_to_clobber_a_racing_file() {
        // Mirrors the TOCTOU window between ensure_target_writable and
        // write_tree: a file slipped in after the empty-dir check should
        // surface as an error, not be silently overwritten.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().to_path_buf();
        fs::create_dir_all(target.join("sql/app")).unwrap();
        fs::write(target.join("main.go"), b"do not clobber").unwrap();
        let err = write_tree(&target, &ins("media", "Media")).unwrap_err();
        assert!(err.to_string().contains("create"));
        // Original file still intact.
        assert_eq!(
            fs::read_to_string(target.join("main.go")).unwrap(),
            "do not clobber"
        );
    }
}
