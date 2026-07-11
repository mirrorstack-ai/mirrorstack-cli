//! Read the developer's module identity off the scaffolded source tree.
//!
//! Parses `Config.ID`, `Config.Slug`, `Config.Name`, and the newest
//! `Config.Versions` key out of `main.go`. These fields drive tunnel
//! registration, platform registration, and deploy.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

/// All parseable identity fields from a module's main.go.
#[derive(Debug, Clone)]
pub(crate) struct ModuleMeta {
    pub id: String,
    pub slug: String,
    pub name: String,
    /// Newest `Config.Versions` map key, verbatim (e.g. "v0.1.0-dev").
    /// None when the map is absent or has no SemVer-shaped keys.
    pub version: Option<String>,
}

/// Read ID, Slug, Name, and the newest version from `main.go` in `module_dir`.
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
    let version = latest_version(&extract_versions_keys(&body));
    Ok(ModuleMeta {
        id,
        slug,
        name,
        version,
    })
}

/// Convenience wrapper that returns just the ID (for tunnel registration).
pub(super) fn read_module_id(module_dir: &Path) -> Result<String> {
    let meta = read_module_meta(module_dir)?;
    if meta.id.is_empty() {
        return Err(anyhow!(
            "dev: module {} has no ID set. Run `mirrorstack app module register` first.",
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

/// Collect the keys of the `Versions: map[...]...{...}` literal in Go
/// source. Brace-balanced scan of the map block: a quoted string followed
/// by `:` at depth 1 is a key (nested literals and `//` comments are
/// skipped, so an example version in a comment is never picked up).
fn extract_versions_keys(go_source: &str) -> Vec<String> {
    let Some(label) = go_source.find("Versions:") else {
        return Vec::new();
    };
    let after_label = &go_source[label + "Versions:".len()..];
    let Some(open) = after_label.find('{') else {
        return Vec::new();
    };
    let block = &after_label[open + 1..];
    let bytes = block.as_bytes();

    let mut keys = Vec::new();
    let mut depth = 1usize;
    let mut i = 0;
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
            }
            b'"' => {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    if bytes[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                if j >= bytes.len() {
                    break;
                }
                let mut k = j + 1;
                while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                    k += 1;
                }
                if depth == 1 && bytes.get(k) == Some(&b':') {
                    keys.push(block[start..j].to_string());
                }
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    keys
}

/// Pick the highest SemVer among the Versions map keys, returned verbatim
/// (keys keep the SDK's `v` prefix). Keys that don't parse as SemVer are
/// ignored — multi-entry maps keep historical tags around, and the newest
/// release is the one deploy acts on.
pub(crate) fn latest_version(keys: &[String]) -> Option<String> {
    keys.iter()
        .filter_map(|k| parse_semver(k.strip_prefix('v').unwrap_or(k)).map(|v| (v, k)))
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, k)| k.clone())
}

/// Minimal SemVer 2.0 precedence model — core triple + prerelease ids
/// (build metadata stripped, ignored for precedence). Hand-rolled instead
/// of pulling the `semver` crate for one compare, same call as the inlined
/// slug regex in module/mod.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemVer {
    core: (u64, u64, u64),
    pre: Vec<PreId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PreId {
    // Variant order is load-bearing: derived Ord gives Num < Alpha, which
    // is SemVer's "numeric identifiers have lower precedence" rule.
    Num(u64),
    Alpha(String),
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        self.core.cmp(&other.core).then_with(|| {
            match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release outranks any prerelease of the same core.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            }
        })
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Parse canonical SemVer (no `v` prefix). Mirrors the platform's
/// `module_versions_semver_check` constraint — numeric parts and numeric
/// prerelease ids reject leading zeros — so anything the record-version
/// endpoint would 422 parses as None here.
pub(crate) fn parse_semver(s: &str) -> Option<SemVer> {
    let s = s.split_once('+').map_or(s, |(rest, _)| rest);
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (s, None),
    };
    let mut parts = core.split('.');
    let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let core = (num_part(a)?, num_part(b)?, num_part(c)?);
    let mut ids = Vec::new();
    if let Some(pre) = pre {
        for id in pre.split('.') {
            ids.push(pre_id(id)?);
        }
    }
    Some(SemVer { core, pre: ids })
}

fn num_part(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

fn pre_id(s: &str) -> Option<PreId> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        if s.len() > 1 && s.starts_with('0') {
            return None;
        }
        return Some(PreId::Num(s.parse().ok()?));
    }
    Some(PreId::Alpha(s.to_string()))
}

/// Rename a `Versions` map key in `main.go` — the deploy promote flow
/// ("v0.1.0-dev" → "v0.1.0"). Only the first occurrence after the
/// `Versions:` label is touched, so identical strings elsewhere in the
/// file are safe.
pub(crate) fn promote_version(module_dir: &Path, from: &str, to: &str) -> Result<()> {
    let path = module_dir.join("main.go");
    let body = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let label = body
        .find("Versions:")
        .ok_or_else(|| anyhow!("no Versions field in {}", path.display()))?;
    let needle = format!("\"{from}\"");
    let rel = body[label..]
        .find(&needle)
        .ok_or_else(|| anyhow!("no \"{from}\" key under Versions in {}", path.display()))?;
    let abs = label + rel;
    let new_body = format!("{}\"{to}\"{}", &body[..abs], &body[abs + needle.len()..]);
    fs::write(&path, new_body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
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
            return Err(anyhow!("no Slug or ID field found in {}", path.display()));
        }
    };

    fs::write(&path, new_body).with_context(|| format!("dev: write {}", path.display()))?;
    Ok(())
}

fn detect_indent(source: &str, field_pos: usize) -> String {
    let before = &source[..field_pos];
    if let Some(nl) = before.rfind('\n') {
        let line_start = &before[nl + 1..field_pos];
        // Extract leading whitespace
        let ws: String = line_start
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();
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
        Versions: map[string]system.MigrationVersions{
            // `-dev` marks local iteration; `mirrorstack app module deploy`
            // promotes it before shipping.
            "v0.1.0-dev": {App: "0001"},
        },
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
        assert_eq!(meta.version.as_deref(), Some("v0.1.0-dev"));
    }

    #[test]
    fn version_parsed_from_versions_map_preserves_dev_suffix() {
        let keys = extract_versions_keys(SAMPLE_MAIN_GO);
        assert_eq!(keys, vec!["v0.1.0-dev".to_string()]);
        assert_eq!(latest_version(&keys).as_deref(), Some("v0.1.0-dev"));
    }

    #[test]
    fn version_picks_max_semver_of_multiple_keys() {
        let src = r#"
        Versions: map[string]system.MigrationVersions{
            "v0.9.0":  {App: "0003"},
            "v0.10.0": {App: "0004", Module: "0001"},
            "v0.2.0":  {App: "0001"},
        },
        "#;
        let keys = extract_versions_keys(src);
        assert_eq!(keys.len(), 3, "got {keys:?}");
        // 0.10.0 > 0.9.0 numerically (lexical compare would pick 0.9.0).
        assert_eq!(latest_version(&keys).as_deref(), Some("v0.10.0"));
    }

    #[test]
    fn version_none_when_versions_absent() {
        let src = r#"ms.Config{ Slug: "media", Name: "Media" }"#;
        assert!(extract_versions_keys(src).is_empty());
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), src).unwrap();
        assert_eq!(read_module_meta(tmp.path()).unwrap().version, None);
    }

    #[test]
    fn extract_versions_keys_skips_comments_and_nested_strings() {
        let src = r#"
        Versions: map[string]system.MigrationVersions{
            // example: "v9.9.9": {App: "0001"},
            "v1.0.0": {App: "0001", Module: "0002"},
        },
        "#;
        assert_eq!(extract_versions_keys(src), vec!["v1.0.0".to_string()]);
    }

    #[test]
    fn latest_version_prerelease_loses_to_release() {
        let keys = vec!["v1.0.0-rc.1".to_string(), "v1.0.0".to_string()];
        assert_eq!(latest_version(&keys).as_deref(), Some("v1.0.0"));
    }

    #[test]
    fn parse_semver_orders_prerelease_ids() {
        let cmp = |a: &str, b: &str| parse_semver(a).unwrap().cmp(&parse_semver(b).unwrap());
        assert_eq!(
            cmp("1.0.0-alpha", "1.0.0-alpha.1"),
            std::cmp::Ordering::Less
        );
        assert_eq!(cmp("1.0.0-2", "1.0.0-11"), std::cmp::Ordering::Less);
        assert_eq!(cmp("1.0.0-1", "1.0.0-alpha"), std::cmp::Ordering::Less);
        assert_eq!(cmp("1.0.0+build.1", "1.0.0"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn parse_semver_rejects_non_canonical() {
        for s in [
            "v1.0.0",
            "1.0",
            "01.2.3",
            "1.2.3-",
            "1.2.3-0.03",
            "1.2.3.4",
            "",
        ] {
            assert!(parse_semver(s).is_none(), "expected {s:?} invalid");
        }
    }

    #[test]
    fn promote_version_rewrites_key() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        promote_version(tmp.path(), "v0.1.0-dev", "v0.1.0").unwrap();
        let meta = read_module_meta(tmp.path()).unwrap();
        assert_eq!(meta.version.as_deref(), Some("v0.1.0"));
        // Only the Versions key changed; identity fields are untouched.
        assert_eq!(meta.slug, "media");
    }

    #[test]
    fn promote_version_errors_when_key_absent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        let err = promote_version(tmp.path(), "v2.0.0-dev", "v2.0.0")
            .unwrap_err()
            .to_string();
        assert!(err.contains("v2.0.0-dev"), "got {err}");
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
