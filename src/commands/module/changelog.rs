//! CHANGELOG.md lint for `module publish`.
//!
//! CHANGELOG.md at the module root is the version log: publish extracts
//! the `## <version>` section and stores it on the version row. Hard
//! errors: file missing, no (or multiple) headings for the version, empty
//! body, section over the platform cap. Ordering/duplicate anomalies are
//! returned as warnings for the caller to print.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::commands::dev::module_meta;

/// Server-side cap on `module_versions.changelog` (16KB). Enforced here so
/// the failure is a lint error, not a `changelog_too_large` round-trip.
const MAX_SECTION_BYTES: usize = 16_384;

#[derive(Debug)]
pub(super) struct ChangelogEntry {
    /// Trimmed section body for the published version.
    pub body: String,
    /// Non-fatal anomalies, one message per line.
    pub warnings: Vec<String>,
}

/// Lint `CHANGELOG.md` in `module_dir` and extract the section for
/// `version` (canonical SemVer, no `v` prefix).
pub(super) fn lint(module_dir: &Path, version: &str) -> Result<ChangelogEntry> {
    let path = module_dir.join("CHANGELOG.md");
    if !path.exists() {
        return Err(anyhow!(
            "no CHANGELOG.md in {} — create one with a `## {version}` section describing this release",
            module_dir.display()
        ));
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    lint_body(&body, version)
}

fn lint_body(changelog: &str, version: &str) -> Result<ChangelogEntry> {
    let lines: Vec<&str> = changelog.lines().collect();
    // Sections end at ANY `## ` heading (e.g. `## Unreleased`), but only
    // version-shaped headings participate in matching and ordering checks.
    let mut heading_lines: Vec<usize> = Vec::new();
    let mut version_headings: Vec<(usize, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(text) = line.strip_prefix("## ") {
            heading_lines.push(i);
            if let Some(v) = heading_version(text) {
                version_headings.push((i, v));
            }
        }
    }

    let matches: Vec<usize> = version_headings
        .iter()
        .filter(|(_, v)| v == version)
        .map(|(i, _)| *i)
        .collect();
    let start = match matches.as_slice() {
        [] => {
            return Err(anyhow!(
                "CHANGELOG.md has no `## {version}` section — add one describing this release"
            ));
        }
        [i] => *i,
        many => {
            return Err(anyhow!(
                "CHANGELOG.md has {} `## {version}` headings — keep exactly one",
                many.len()
            ));
        }
    };

    let end = heading_lines
        .iter()
        .copied()
        .find(|&h| h > start)
        .unwrap_or(lines.len());
    let body = lines[start + 1..end].join("\n").trim().to_string();
    if body.is_empty() {
        return Err(anyhow!(
            "the `## {version}` section in CHANGELOG.md is empty — describe the release before publishing"
        ));
    }
    if body.len() > MAX_SECTION_BYTES {
        return Err(anyhow!(
            "the `## {version}` section in CHANGELOG.md is {} bytes; the platform caps changelogs at {MAX_SECTION_BYTES}",
            body.len()
        ));
    }

    let mut warnings = Vec::new();
    for pair in version_headings.windows(2) {
        let (a, b) = (&pair[0].1, &pair[1].1);
        // Both came from heading_version, so parse_semver always succeeds.
        if module_meta::parse_semver(a) < module_meta::parse_semver(b) {
            warnings.push(format!(
                "CHANGELOG.md versions are not in descending order ({a} appears above {b})"
            ));
            break;
        }
    }
    let mut seen = HashSet::new();
    let mut dup_warned = HashSet::new();
    for (_, v) in &version_headings {
        if v != version && !seen.insert(v.as_str()) && dup_warned.insert(v.as_str()) {
            warnings.push(format!("CHANGELOG.md has duplicate `## {v}` headings"));
        }
    }

    Ok(ChangelogEntry { body, warnings })
}

/// Canonical version from the text after `## `, or None when the heading
/// isn't a version heading (e.g. `## Unreleased`). Tolerates `[x.y.z]`
/// brackets, a `v` prefix, and a trailing ` - <date>` / ` (<date>)` suffix.
fn heading_version(text: &str) -> Option<String> {
    let text = text.trim();
    let (token, rest) = if let Some(inner) = text.strip_prefix('[') {
        let (token, rest) = inner.split_once(']')?;
        (token.trim(), rest.trim())
    } else {
        match text.split_once(char::is_whitespace) {
            Some((t, r)) => (t, r.trim()),
            None => (text, ""),
        }
    };
    if !(rest.is_empty() || rest.starts_with('-') || rest.starts_with('(')) {
        return None;
    }
    let canonical = token.strip_prefix('v').unwrap_or(token);
    module_meta::parse_semver(canonical)?;
    Some(canonical.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Changelog

## Unreleased

- something brewing

## 0.2.0 - 2026-07-01

- added deploy verb
- fixed tunnel reconnect

## [0.1.0] (2026-06-20)

- initial release
";

    #[test]
    fn lint_body_finds_exact_version() {
        let entry = lint_body(SAMPLE, "0.2.0").expect("ok");
        assert_eq!(entry.body, "- added deploy verb\n- fixed tunnel reconnect");
        assert!(entry.warnings.is_empty(), "got {:?}", entry.warnings);
    }

    #[test]
    fn lint_body_tolerates_bracketed_heading_with_date() {
        let entry = lint_body(SAMPLE, "0.1.0").expect("ok");
        assert_eq!(entry.body, "- initial release");
    }

    #[test]
    fn lint_body_tolerates_v_prefix() {
        let entry = lint_body("## v0.1.0\n\n- first\n", "0.1.0").expect("ok");
        assert_eq!(entry.body, "- first");
    }

    #[test]
    fn lint_body_slices_until_next_heading() {
        // The Unreleased body must not bleed into 0.2.0, nor 0.2.0 into 0.1.0.
        let entry = lint_body(SAMPLE, "0.2.0").expect("ok");
        assert!(!entry.body.contains("brewing"));
        assert!(!entry.body.contains("initial release"));
    }

    #[test]
    fn lint_body_ignores_unreleased_section() {
        let err = lint_body("## Unreleased\n\n- wip\n", "0.1.0")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no `## 0.1.0` section"), "got {err}");
    }

    #[test]
    fn lint_body_errors_when_version_absent() {
        let err = lint_body(SAMPLE, "9.9.9").unwrap_err().to_string();
        assert!(err.contains("no `## 9.9.9` section"), "got {err}");
    }

    #[test]
    fn lint_body_errors_for_empty_section() {
        let err = lint_body("## 0.1.0\n\n## 0.0.1\n\n- old\n", "0.1.0")
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "got {err}");
    }

    #[test]
    fn lint_body_errors_on_duplicate_target_headings() {
        let err = lint_body("## 0.1.0\n\n- a\n\n## 0.1.0\n\n- b\n", "0.1.0")
            .unwrap_err()
            .to_string();
        assert!(err.contains("keep exactly one"), "got {err}");
    }

    #[test]
    fn lint_body_errors_on_oversized_section() {
        let big = format!("## 0.1.0\n\n{}\n", "x".repeat(MAX_SECTION_BYTES + 1));
        let err = lint_body(&big, "0.1.0").unwrap_err().to_string();
        assert!(err.contains("caps changelogs"), "got {err}");
    }

    #[test]
    fn lint_body_warns_on_ascending_order() {
        let entry = lint_body("## 0.1.0\n\n- a\n\n## 0.2.0\n\n- b\n", "0.1.0").expect("ok");
        assert_eq!(entry.warnings.len(), 1, "got {:?}", entry.warnings);
        assert!(entry.warnings[0].contains("descending"));
    }

    #[test]
    fn lint_body_warns_on_duplicate_other_versions() {
        let src = "## 0.3.0\n\n- new\n\n## 0.2.0\n\n- a\n\n## 0.2.0\n\n- b\n";
        let entry = lint_body(src, "0.3.0").expect("ok");
        assert_eq!(entry.warnings.len(), 1, "got {:?}", entry.warnings);
        assert!(entry.warnings[0].contains("duplicate `## 0.2.0`"));
    }

    #[test]
    fn lint_missing_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = lint(tmp.path(), "0.1.0").unwrap_err().to_string();
        assert!(err.contains("no CHANGELOG.md"), "got {err}");
    }

    #[test]
    fn lint_reads_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.md"), SAMPLE).unwrap();
        let entry = lint(tmp.path(), "0.2.0").expect("ok");
        assert!(entry.body.contains("deploy verb"));
    }

    #[test]
    fn heading_version_rejects_trailing_prose() {
        assert_eq!(heading_version("0.1.0 fixed stuff"), None);
        assert_eq!(heading_version("0.1.0 - 2026-07-02"), Some("0.1.0".into()));
        assert_eq!(heading_version("[v0.1.0]"), Some("0.1.0".into()));
    }
}
