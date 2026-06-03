//! Read the developer's module identity off the scaffolded source tree.
//!
//! Parses `Config.ID`, `Config.Slug`, and `Config.Name` out of `main.go`.
//! These fields drive tunnel registration, platform registration, and
//! the module display name.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

/// All parseable identity fields from a module's main.go.
#[derive(Debug, Clone)]
pub(crate) struct ModuleMeta {
    pub id: String,
    pub slug: String,
    pub name: String,
}

/// Read ID, Slug, and Name from `main.go` in `module_dir`.
pub(crate) fn read_module_meta(module_dir: &Path) -> Result<ModuleMeta> {
    let path = module_dir.join("main.go");
    let body =
        fs::read_to_string(&path).with_context(|| format!("dev: read {}", path.display()))?;
    let id = extract_field(&body, "ID").unwrap_or_default();
    let slug = extract_field(&body, "Slug").ok_or_else(|| {
        anyhow!(
            "dev: couldn't find `Slug: \"...\"` in {}. Is this a MirrorStack module?",
            path.display()
        )
    })?;
    let name = extract_field(&body, "Name").unwrap_or_else(|| slug.clone());
    Ok(ModuleMeta { id, slug, name })
}

/// Convenience wrapper that returns just the ID (for tunnel registration).
pub(super) fn read_module_id(module_dir: &Path) -> Result<String> {
    let meta = read_module_meta(module_dir)?;
    if meta.id.is_empty() {
        return Err(anyhow!(
            "dev: module {} has no ID set. Run `mirrorstack modules register` first.",
            module_dir.display()
        ));
    }
    Ok(meta.id)
}

/// Extract the value of a `Field: "..."` pattern from Go source.
/// Tolerates variable whitespace between the field name and the value.
fn extract_field(go_source: &str, field: &str) -> Option<String> {
    let needle = format!("{field}:");
    let after_label = find_after(go_source, &needle)?;
    let after_open_quote = find_after(after_label, "\"")?;
    let close = after_open_quote.find('"')?;
    let val = &after_open_quote[..close];
    if val.is_empty() {
        return None;
    }
    Some(val.to_string())
}

/// Write `new_id` into the `ID: "..."` field in `main.go`. If the field
/// has an empty string (`ID: ""`), it's replaced. If the field is missing
/// entirely, it's inserted after the `Slug:` line.
pub(crate) fn write_module_id(module_dir: &Path, new_id: &str) -> Result<()> {
    let path = module_dir.join("main.go");
    let body =
        fs::read_to_string(&path).with_context(|| format!("dev: read {}", path.display()))?;

    let new_body = if let Some(start) = body.find("ID:") {
        let after_id = &body[start..];
        if let Some(q1) = after_id.find('"') {
            let abs_q1 = start + q1 + 1;
            let after_q1 = &body[abs_q1..];
            if let Some(q2) = after_q1.find('"') {
                let abs_q2 = abs_q1 + q2;
                format!("{}{}{}", &body[..abs_q1], new_id, &body[abs_q2..])
            } else {
                return Err(anyhow!("malformed ID field in {}", path.display()));
            }
        } else {
            return Err(anyhow!("malformed ID field in {}", path.display()));
        }
    } else {
        // Insert ID field after Slug line
        if let Some(slug_pos) = body.find("Slug:") {
            let after_slug = &body[slug_pos..];
            if let Some(nl) = after_slug.find('\n') {
                let insert_pos = slug_pos + nl + 1;
                let indent = detect_indent(&body, slug_pos);
                format!(
                    "{}{}ID:   \"{}\",\n{}",
                    &body[..insert_pos],
                    indent,
                    new_id,
                    &body[insert_pos..]
                )
            } else {
                return Err(anyhow!("unexpected EOF after Slug in {}", path.display()));
            }
        } else {
            return Err(anyhow!(
                "no Slug or ID field found in {}",
                path.display()
            ));
        }
    };

    fs::write(&path, new_body)
        .with_context(|| format!("dev: write {}", path.display()))?;
    Ok(())
}

fn detect_indent(source: &str, field_pos: usize) -> String {
    let before = &source[..field_pos];
    if let Some(nl) = before.rfind('\n') {
        let line_start = &before[nl + 1..field_pos];
        // Extract leading whitespace
        let ws: String = line_start.chars().take_while(|c| c.is_whitespace()).collect();
        ws
    } else {
        String::new()
    }
}

fn find_after<'a>(haystack: &'a str, needle: &str) -> Option<&'a str> {
    let pos = haystack.find(needle)?;
    Some(&haystack[pos + needle.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MAIN_GO: &str = r#"
package main

func main() {
    if err := ms.Init(ms.Config{
        ID:   "mbb8a3f8b123456789abcdef012345678",
        Slug: "media",
        Name: "Media",
        Icon: "extension",
    }); err != nil {
        log.Fatalf("init: %v", err)
    }
}
"#;

    #[test]
    fn extract_field_id() {
        assert_eq!(
            extract_field(SAMPLE_MAIN_GO, "ID").unwrap(),
            "mbb8a3f8b123456789abcdef012345678"
        );
    }

    #[test]
    fn extract_field_slug() {
        assert_eq!(extract_field(SAMPLE_MAIN_GO, "Slug").unwrap(), "media");
    }

    #[test]
    fn extract_field_name() {
        assert_eq!(extract_field(SAMPLE_MAIN_GO, "Name").unwrap(), "Media");
    }

    #[test]
    fn extract_field_tolerates_single_space() {
        let src = r#"ms.Config{ ID: "media", Name: "Media" }"#;
        assert_eq!(extract_field(src, "ID").unwrap(), "media");
    }

    #[test]
    fn extract_field_returns_none_when_absent() {
        assert!(extract_field(r#"ms.Config{Name: "X"}"#, "ID").is_none());
    }

    #[test]
    fn extract_field_returns_none_for_empty_string() {
        let src = r#"ms.Config{ ID: "", Slug: "media" }"#;
        assert!(extract_field(src, "ID").is_none());
    }

    #[test]
    fn read_module_meta_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        let meta = read_module_meta(tmp.path()).unwrap();
        assert_eq!(meta.id, "mbb8a3f8b123456789abcdef012345678");
        assert_eq!(meta.slug, "media");
        assert_eq!(meta.name, "Media");
    }

    #[test]
    fn read_module_id_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        assert_eq!(
            read_module_id(tmp.path()).unwrap(),
            "mbb8a3f8b123456789abcdef012345678"
        );
    }

    #[test]
    fn read_module_id_errors_when_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let src = r#"
package main
func main() {
    ms.Init(ms.Config{
        ID:   "",
        Slug: "media",
        Name: "Media",
    })
}
"#;
        std::fs::write(tmp.path().join("main.go"), src).unwrap();
        let err = read_module_id(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("no ID set"));
    }

    #[test]
    fn read_module_id_missing_main_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_module_id(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("read"));
    }

    #[test]
    fn write_module_id_replaces_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let src = "    ID:   \"\",\n    Slug: \"media\",\n";
        std::fs::write(tmp.path().join("main.go"), src).unwrap();
        write_module_id(tmp.path(), "m123abc").unwrap();
        let result = std::fs::read_to_string(tmp.path().join("main.go")).unwrap();
        assert!(result.contains("ID:   \"m123abc\""));
    }

    #[test]
    fn write_module_id_replaces_existing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        write_module_id(tmp.path(), "mnewid").unwrap();
        let result = std::fs::read_to_string(tmp.path().join("main.go")).unwrap();
        assert!(result.contains("\"mnewid\""));
        assert!(!result.contains("mbb8a3f8b123456789abcdef012345678"));
    }
}
