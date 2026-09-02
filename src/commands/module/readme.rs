//! README locale-map read for `module deploy`'s record step.
//!
//! README files at the module root are the module's long-form description.
//! Deploy reads them (when present) and records them on the version row so the
//! marketplace catalog can render the reader's locale. `README.md` is the
//! default; `README.<tag>.md` (e.g. `README.zh-TW.md`) contributes a
//! locale-specific translation. Unlike docs/CHANGELOG.md they are optional and
//! free-form — there is no lint. Missing files are not an error (nothing is
//! sent). Each value has its trailing whitespace trimmed and is capped at the
//! platform's byte limit, truncated on a UTF-8 char boundary.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

/// Server-side cap on each `module_versions.readme` value (64KB). Enforced
/// here so an oversized README is truncated client-side instead of
/// round-tripping a `readme_too_large` rejection.
pub(super) const MAX_README_BYTES: usize = 65_536;

/// Result of scanning the module dir for README files.
pub(super) struct Readme {
    /// Locale → trimmed, capped markdown. Key `default` is `README.md`; a
    /// `<tag>` key is `README.<tag>.md`. Empty when the module ships no
    /// README (or every file held only whitespace).
    pub map: BTreeMap<String, String>,
    /// Whether any value was truncated to fit [`MAX_README_BYTES`].
    pub truncated: bool,
}

/// Scan `module_dir` for `README.md` (key `default`) and any
/// `README.<tag>.md` (key `<tag>`), building a locale map. A dir with no
/// README files yields an empty map — READMEs are optional, unlike
/// docs/CHANGELOG.md.
pub(super) fn read(module_dir: &Path) -> Result<Readme> {
    let mut map = BTreeMap::new();
    let mut truncated = false;

    let entries = match std::fs::read_dir(module_dir) {
        Ok(entries) => entries,
        // A missing module dir is treated the same as one with no READMEs —
        // the caller's own preflight already resolved the module.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Readme { map, truncated });
        }
        Err(e) => return Err(e).with_context(|| format!("read dir {}", module_dir.display())),
    };

    for entry in entries {
        let entry = entry.with_context(|| format!("read dir {}", module_dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(key) = readme_key(name) else {
            continue;
        };
        let path = entry.path();
        // `is_file` follows symlinks (matching the old single-file read) and
        // skips a directory that happens to be named like a README.
        if !path.is_file() {
            continue;
        }
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let (body, hit_cap) = cap(raw.trim_end());
        truncated |= hit_cap;
        if !body.is_empty() {
            map.insert(key, body);
        }
    }

    Ok(Readme { map, truncated })
}

/// Locale key for a README file name, or None when it isn't a README:
/// `README.md` → `default`; `README.<tag>.md` → `<tag>` when `<tag>` is a
/// non-empty locale-ish token (`[A-Za-z0-9_-]`, matching the platform's key
/// validation). Anything else (e.g. `README.release.notes`) is ignored.
fn readme_key(file_name: &str) -> Option<String> {
    if file_name == "README.md" {
        return Some("default".to_string());
    }
    let tag = file_name.strip_prefix("README.")?.strip_suffix(".md")?;
    if tag.is_empty()
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(tag.to_string())
}

/// Cap `text` at [`MAX_README_BYTES`], truncating on the nearest UTF-8 char
/// boundary at or below the limit so a multi-byte character is never split.
/// Returns the (possibly truncated) body and whether truncation happened.
fn cap(text: &str) -> (String, bool) {
    if text.len() <= MAX_README_BYTES {
        return (text.to_string(), false);
    }
    let mut end = MAX_README_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_no_readme_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let r = read(tmp.path()).expect("ok");
        assert!(r.map.is_empty());
        assert!(!r.truncated);
    }

    #[test]
    fn read_missing_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let r = read(&tmp.path().join("nope")).expect("ok");
        assert!(r.map.is_empty());
        assert!(!r.truncated);
    }

    #[test]
    fn read_default_trims_trailing_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Media\n\nDocs.\n\n  \n").unwrap();
        let r = read(tmp.path()).expect("ok");
        assert_eq!(
            r.map.get("default").map(String::as_str),
            Some("# Media\n\nDocs.")
        );
        assert_eq!(r.map.len(), 1);
        assert!(!r.truncated);
    }

    #[test]
    fn read_collects_locale_variants() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Media\n").unwrap();
        std::fs::write(tmp.path().join("README.zh-TW.md"), "# 媒體\n").unwrap();
        std::fs::write(tmp.path().join("README.en_US.md"), "# Media US\n").unwrap();
        let r = read(tmp.path()).expect("ok");
        assert_eq!(r.map.get("default").map(String::as_str), Some("# Media"));
        assert_eq!(r.map.get("zh-TW").map(String::as_str), Some("# 媒體"));
        assert_eq!(r.map.get("en_US").map(String::as_str), Some("# Media US"));
        assert_eq!(r.map.len(), 3);
    }

    #[test]
    fn read_omits_empty_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), "\n\n   \n").unwrap();
        std::fs::write(tmp.path().join("README.fr.md"), "# Bonjour\n").unwrap();
        let r = read(tmp.path()).expect("ok");
        assert!(!r.map.contains_key("default"));
        assert_eq!(r.map.get("fr").map(String::as_str), Some("# Bonjour"));
        assert_eq!(r.map.len(), 1);
    }

    #[test]
    fn read_ignores_non_readme_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Media\n").unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.md"), "# Changelog\n").unwrap();
        std::fs::write(tmp.path().join("README.notes.txt"), "not markdown\n").unwrap();
        std::fs::write(tmp.path().join("READMEER.md"), "nope\n").unwrap();
        let r = read(tmp.path()).expect("ok");
        assert_eq!(r.map.len(), 1);
        assert!(r.map.contains_key("default"));
    }

    #[test]
    fn read_flags_truncation() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("README.md"),
            "x".repeat(MAX_README_BYTES + 10),
        )
        .unwrap();
        let r = read(tmp.path()).expect("ok");
        assert!(r.truncated);
        assert_eq!(
            r.map.get("default").map(String::len),
            Some(MAX_README_BYTES)
        );
    }

    #[test]
    fn readme_key_maps_default_and_tags() {
        assert_eq!(readme_key("README.md").as_deref(), Some("default"));
        assert_eq!(readme_key("README.zh-TW.md").as_deref(), Some("zh-TW"));
        assert_eq!(readme_key("README.en_US.md").as_deref(), Some("en_US"));
        assert_eq!(readme_key("README.notes.txt"), None);
        assert_eq!(readme_key("READMEER.md"), None);
        assert_eq!(readme_key("README..md"), None);
        // A multi-dot middle isn't a single locale-ish token.
        assert_eq!(readme_key("README.zh.TW.md"), None);
    }

    #[test]
    fn cap_leaves_small_text_untouched() {
        let (body, truncated) = cap("short");
        assert_eq!(body, "short");
        assert!(!truncated);
    }

    #[test]
    fn cap_truncates_oversized_text() {
        let big = "x".repeat(MAX_README_BYTES + 10);
        let (body, truncated) = cap(&big);
        assert_eq!(body.len(), MAX_README_BYTES);
        assert!(truncated);
    }

    #[test]
    fn cap_truncates_on_char_boundary() {
        // End the buffer with a 2-byte char straddling the cap so a naive byte
        // cut would split it; cap must back off to a char boundary.
        let mut s = "a".repeat(MAX_README_BYTES - 1);
        s.push('é'); // occupies bytes MAX-1 and MAX
        s.push('é'); // pushes total length over the cap
        let (body, truncated) = cap(&s);
        assert!(truncated);
        assert!(body.len() <= MAX_README_BYTES);
        assert!(s.is_char_boundary(body.len()));
    }
}
