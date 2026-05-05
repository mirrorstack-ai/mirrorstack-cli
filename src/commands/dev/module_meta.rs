//! Read the developer's module identity off the scaffolded source tree.
//!
//! For Phase 1 we parse `Config.ID = "..."` out of `main.go`. That field
//! is what the SDK uses for `mod_<id>` schema names, so it's the right
//! handle to register against the tunnel — and it's already the value
//! the CLI's scaffold substituted from the platform UUID.
//!
//! A future PR may switch to a `.mirrorstack/meta.json` written at
//! scaffold time. Until then, parsing main.go is a one-line regex on a
//! file whose shape we control.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

/// Find the `ID:   "<value>"` line inside the file's `ms.Init(ms.Config{...})`
/// block. The scaffold template's main.go has it on a predictable line,
/// but a developer is free to reformat — so we match the literal token
/// `ID:` followed by `"..."` rather than relying on column positions.
pub(super) fn read_module_id(module_dir: &Path) -> Result<String> {
    let path = module_dir.join("main.go");
    let body =
        fs::read_to_string(&path).with_context(|| format!("dev: read {}", path.display()))?;
    extract_id(&body).ok_or_else(|| {
        anyhow!(
            "dev: couldn't find `ID: \"...\"` in {}. Is this a MirrorStack module?",
            path.display()
        )
    })
}

/// Extract the first occurrence of the literal pattern `ID: "..."`.
///
/// Tolerates any whitespace around `ID:` (the scaffold uses `ID:   `
/// for column alignment with `Name:`, but reformatters may shrink it
/// to a single space). Stops at the first closing quote — `Config.ID`
/// is a single string literal with no escapes possible under the SDK's
/// regex (`^[a-z][a-z0-9_]{0,35}$`).
fn extract_id(go_source: &str) -> Option<String> {
    let after_label = find_after(go_source, "ID:")?;
    let after_open_quote = find_after(after_label, "\"")?;
    let close = after_open_quote.find('"')?;
    Some(after_open_quote[..close].to_string())
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
        Name: "Media",
        Icon: "extension",
    }); err != nil {
        log.Fatalf("init: %v", err)
    }
}
"#;

    #[test]
    fn extract_id_from_scaffold_template() {
        assert_eq!(
            extract_id(SAMPLE_MAIN_GO).unwrap(),
            "mbb8a3f8b123456789abcdef012345678"
        );
    }

    #[test]
    fn extract_id_tolerates_single_space() {
        let src = r#"ms.Config{ ID: "media", Name: "Media" }"#;
        assert_eq!(extract_id(src).unwrap(), "media");
    }

    #[test]
    fn extract_id_returns_none_when_absent() {
        assert!(extract_id(r#"ms.Config{Name: "X"}"#).is_none());
    }

    #[test]
    fn extract_id_first_match_wins() {
        // If the developer adds another `ID:` somewhere later (a struct
        // tag, a comment, a literal in another field), the first one
        // — Config.ID at the top of Init — is the canonical one.
        let src = r#"
ms.Config{
    ID:   "first",
    Name: "X",
}
// later struct: SomethingElse{ID: "ignored"}
"#;
        assert_eq!(extract_id(src).unwrap(), "first");
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
    fn read_module_id_missing_main_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_module_id(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("read"));
    }
}
