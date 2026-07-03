//! CHANGELOG locale-map lint for `module deploy`'s record step.
//!
//! CHANGELOG files at the module root are the version log: deploy extracts each
//! one's `## <version>` section and records a locale map on the version row.
//! `CHANGELOG.md` is the `default`; `CHANGELOG.<tag>.md` (e.g.
//! `CHANGELOG.zh-TW.md`) contributes a locale translation. The default is
//! required and hard-linted — file missing, no (or multiple) headings for the
//! version, empty body, or a section over the platform cap are all errors, and
//! ordering/duplicate anomalies are returned as warnings for the caller to
//! print. Locale variants are optional and best-effort: a `CHANGELOG.<tag>.md`
//! that lacks this version's section is simply omitted from the map, no error.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::commands::dev::module_meta;

/// Server-side cap on `module_versions.changelog` (16KB). Enforced here so
/// the failure is a lint error, not a `changelog_too_large` round-trip.
const MAX_SECTION_BYTES: usize = 16_384;

/// A module's changelog for the recorded version: `default` (CHANGELOG.md,
/// always present) plus any `CHANGELOG.<tag>.md` locale sections.
#[derive(Debug)]
pub(super) struct Changelog {
    /// Locale → this version's trimmed section body. Key `default` is
    /// CHANGELOG.md; a `<tag>` key is CHANGELOG.<tag>.md. Always carries
    /// `default` — its section is a hard requirement.
    pub map: BTreeMap<String, String>,
    /// Non-fatal anomalies from the default CHANGELOG.md, one message per line.
    pub warnings: Vec<String>,
}

/// One file's extracted section plus its file-level warnings — the result of
/// linting a single CHANGELOG body.
#[derive(Debug)]
struct ChangelogEntry {
    /// Trimmed section body for the recorded version.
    body: String,
    /// Non-fatal anomalies, one message per line.
    warnings: Vec<String>,
}

/// Lint `CHANGELOG.md` in `module_dir` for `version` (canonical SemVer, no `v`
/// prefix) and collect any `CHANGELOG.<tag>.md` locale sections into a map.
/// The default file is required — a missing or invalid default section is a
/// hard error; locale variants are optional.
pub(super) fn lint(module_dir: &Path, version: &str) -> Result<Changelog> {
    let path = module_dir.join("CHANGELOG.md");
    if !path.exists() {
        return Err(anyhow!(
            "no CHANGELOG.md in {} — create one with a `## {version}` section describing this release",
            module_dir.display()
        ));
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let default = lint_body(&body, version)?;

    let mut map = BTreeMap::new();
    map.insert("default".to_string(), default.body);
    for (tag, section) in locale_sections(module_dir, version)? {
        map.insert(tag, section);
    }

    Ok(Changelog {
        map,
        warnings: default.warnings,
    })
}

/// Scan `module_dir` for `CHANGELOG.<tag>.md` locale files and extract each
/// one's `## <version>` section. Best-effort: a file that lacks (or can't
/// cleanly yield) the section is skipped — only the default is required.
fn locale_sections(module_dir: &Path, version: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(module_dir) {
        Ok(entries) => entries,
        // The default file already resolved above; a dir that vanished in
        // between is treated as "no locale variants".
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("read dir {}", module_dir.display())),
    };
    for entry in entries {
        let entry = entry.with_context(|| format!("read dir {}", module_dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(tag) = locale_tag(name) else { continue };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let body =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        // A locale file that lacks (empty / absent / oversized / duplicated)
        // this version's section is simply omitted, never an error.
        if let Ok(section) = lint_body(&body, version) {
            out.push((tag, section.body));
        }
    }
    Ok(out)
}

/// Locale tag for a `CHANGELOG.<tag>.md` file name, or None when it isn't a
/// locale changelog. `CHANGELOG.md` (the default, linted separately) and any
/// `<tag>` that isn't a single locale-ish token (`[A-Za-z0-9_-]`, matching the
/// platform's key validation) are rejected.
fn locale_tag(file_name: &str) -> Option<String> {
    let tag = file_name.strip_prefix("CHANGELOG.")?.strip_suffix(".md")?;
    if tag.is_empty()
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(tag.to_string())
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
            "the `## {version}` section in CHANGELOG.md is empty — describe the release before deploying"
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
    fn lint_reads_default_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.md"), SAMPLE).unwrap();
        let cl = lint(tmp.path(), "0.2.0").expect("ok");
        assert_eq!(cl.map.len(), 1);
        assert!(cl.map["default"].contains("deploy verb"));
    }

    #[test]
    fn lint_collects_locale_variants() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.md"), SAMPLE).unwrap();
        std::fs::write(
            tmp.path().join("CHANGELOG.zh-TW.md"),
            "## 0.2.0\n\n- 加入部署指令\n",
        )
        .unwrap();
        let cl = lint(tmp.path(), "0.2.0").expect("ok");
        assert!(cl.map["default"].contains("deploy verb"));
        assert_eq!(cl.map.get("zh-TW").map(String::as_str), Some("- 加入部署指令"));
        assert_eq!(cl.map.len(), 2);
    }

    #[test]
    fn lint_omits_locale_missing_the_version_section() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.md"), SAMPLE).unwrap();
        // The French log only documents 0.1.0, not the 0.2.0 being recorded.
        std::fs::write(
            tmp.path().join("CHANGELOG.fr.md"),
            "## 0.1.0\n\n- version initiale\n",
        )
        .unwrap();
        let cl = lint(tmp.path(), "0.2.0").expect("ok");
        assert!(!cl.map.contains_key("fr"));
        assert_eq!(cl.map.len(), 1);
    }

    #[test]
    fn lint_default_missing_section_errors_despite_locale() {
        let tmp = tempfile::tempdir().unwrap();
        // Default lacks 0.2.0; a locale carrying it must not rescue the record.
        std::fs::write(tmp.path().join("CHANGELOG.md"), "## 0.1.0\n\n- old\n").unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.zh-TW.md"), "## 0.2.0\n\n- 新版\n").unwrap();
        let err = lint(tmp.path(), "0.2.0").unwrap_err().to_string();
        assert!(err.contains("no `## 0.2.0` section"), "got {err}");
    }

    #[test]
    fn lint_ignores_non_changelog_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.md"), SAMPLE).unwrap();
        std::fs::write(tmp.path().join("README.md"), "# Media\n").unwrap();
        std::fs::write(tmp.path().join("CHANGELOG.notes.txt"), "## 0.2.0\n\n- x\n").unwrap();
        let cl = lint(tmp.path(), "0.2.0").expect("ok");
        assert_eq!(cl.map.len(), 1);
        assert!(cl.map.contains_key("default"));
    }

    #[test]
    fn locale_tag_maps_tags_and_rejects_default() {
        assert_eq!(locale_tag("CHANGELOG.zh-TW.md").as_deref(), Some("zh-TW"));
        assert_eq!(locale_tag("CHANGELOG.en_US.md").as_deref(), Some("en_US"));
        assert_eq!(locale_tag("CHANGELOG.md"), None);
        assert_eq!(locale_tag("CHANGELOG.notes.txt"), None);
        assert_eq!(locale_tag("CHANGELOG..md"), None);
        // A multi-dot middle isn't a single locale-ish token.
        assert_eq!(locale_tag("CHANGELOG.zh.TW.md"), None);
        assert_eq!(locale_tag("CHANGES.fr.md"), None);
    }

    #[test]
    fn heading_version_rejects_trailing_prose() {
        assert_eq!(heading_version("0.1.0 fixed stuff"), None);
        assert_eq!(heading_version("0.1.0 - 2026-07-02"), Some("0.1.0".into()));
        assert_eq!(heading_version("[v0.1.0]"), Some("0.1.0".into()));
    }
}
