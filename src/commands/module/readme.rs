//! README.md read for `module deploy`'s record step.
//!
//! README.md at the module root is the module's long-form description.
//! Deploy reads it (when present) and records it on the version row so the
//! marketplace catalog can render it. Unlike CHANGELOG.md it is optional and
//! free-form — there is no lint. A missing file is not an error (nothing is
//! sent). Trailing whitespace is trimmed and the text is capped at the
//! platform's byte limit, truncated on a UTF-8 char boundary.

use std::path::Path;

use anyhow::{Context, Result};

/// Server-side cap on `module_versions.readme` (64KB). Enforced here so an
/// oversized README is truncated client-side instead of round-tripping a
/// `readme_too_large` rejection.
pub(super) const MAX_README_BYTES: usize = 65_536;

/// Result of reading README.md.
pub(super) struct Readme {
    /// Trimmed, capped README body. Empty when there is no README.md (or it
    /// held only whitespace).
    pub body: String,
    /// Whether `body` was truncated to fit [`MAX_README_BYTES`].
    pub truncated: bool,
}

/// Read `README.md` from `module_dir`. A missing file yields an empty body —
/// READMEs are optional, unlike CHANGELOG.md.
pub(super) fn read(module_dir: &Path) -> Result<Readme> {
    let path = module_dir.join("README.md");
    if !path.exists() {
        return Ok(Readme {
            body: String::new(),
            truncated: false,
        });
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(cap(raw.trim_end()))
}

/// Cap `text` at [`MAX_README_BYTES`], truncating on the nearest UTF-8 char
/// boundary at or below the limit so a multi-byte character is never split.
fn cap(text: &str) -> Readme {
    if text.len() <= MAX_README_BYTES {
        return Readme {
            body: text.to_string(),
            truncated: false,
        };
    }
    let mut end = MAX_README_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Readme {
        body: text[..end].to_string(),
        truncated: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_missing_file_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let r = read(tmp.path()).expect("ok");
        assert!(r.body.is_empty());
        assert!(!r.truncated);
    }

    #[test]
    fn read_trims_trailing_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Media\n\nDocs.\n\n  \n").unwrap();
        let r = read(tmp.path()).expect("ok");
        assert_eq!(r.body, "# Media\n\nDocs.");
        assert!(!r.truncated);
    }

    #[test]
    fn cap_leaves_small_text_untouched() {
        let r = cap("short");
        assert_eq!(r.body, "short");
        assert!(!r.truncated);
    }

    #[test]
    fn cap_truncates_oversized_text() {
        let big = "x".repeat(MAX_README_BYTES + 10);
        let r = cap(&big);
        assert_eq!(r.body.len(), MAX_README_BYTES);
        assert!(r.truncated);
    }

    #[test]
    fn cap_truncates_on_char_boundary() {
        // End the buffer with a 2-byte char straddling the cap so a naive byte
        // cut would split it; cap must back off to a char boundary.
        let mut s = "a".repeat(MAX_README_BYTES - 1);
        s.push('é'); // occupies bytes MAX-1 and MAX
        s.push('é'); // pushes total length over the cap
        let r = cap(&s);
        assert!(r.truncated);
        assert!(r.body.len() <= MAX_README_BYTES);
        assert!(s.is_char_boundary(r.body.len()));
    }
}
