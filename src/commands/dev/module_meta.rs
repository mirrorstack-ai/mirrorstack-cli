//! Read the developer's module identity off the scaffolded source tree.
//!
//! Parses `Config.Slug`, `Config.Name`, and the newest `Config.Versions` key
//! out of `main.go`. `Config.ID` is different: it's a per-environment value
//! (local dev and prod each get their own platform-minted ID for the same
//! source tree), so it lives in ONE git-ignored `.env` file at the workspace
//! root (the directory holding `go.work` — or, for a freshly scaffolded
//! standalone module with no `go.work` yet, the scaffold target dir itself)
//! rather than a `main.go` literal or a per-module file. A monorepo's root
//! `.env` holds one `MS_MODULE_ID_<SLUG>` key per module (SCREAMING_SNAKE_CASE
//! of the slug — see [`env_key_for_slug`]) so multiple modules' IDs coexist
//! in that one file without collision.
//!
//! That suffix is a root-`.env`/CLI-tooling-only bookkeeping convention. It
//! never reaches a module's own runtime: each module process only ever sees
//! its OWN environment (a separate `mirrorstack dev` child process, or its
//! own separate Lambda), so the scaffolded `main.go` keeps reading the
//! plain, unsuffixed `os.Getenv("MS_MODULE_ID")`, and `dev/mod.rs` injects a
//! plain `MS_MODULE_ID=<value>` into just that module's child env.

use std::fs;
use std::path::{Path, PathBuf};

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

/// Read ID, Slug, Name, and the newest version for `module_dir`. Slug, Name,
/// and version come from `main.go` in `module_dir`; ID comes from `root`'s
/// `.env`, keyed on the slug just parsed (see module docs). `root` is the
/// workspace directory holding `go.work` (or `module_dir` itself, for a
/// standalone module with no `go.work`).
pub(crate) fn read_module_meta(module_dir: &Path, root: &Path) -> Result<ModuleMeta> {
    let path = module_dir.join("main.go");
    let body =
        fs::read_to_string(&path).with_context(|| format!("dev: read {}", path.display()))?;
    let slug = extract_field(&body, "Slug").ok_or_else(|| {
        anyhow!(
            "dev: couldn't find `Slug: \"...\"` in {}. Is this a MirrorStack module?",
            path.display()
        )
    })?;
    let id = read_env_module_id(root, &slug);
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
#[cfg(test)]
pub(super) fn read_module_id(module_dir: &Path, root: &Path) -> Result<String> {
    let meta = read_module_meta(module_dir, root)?;
    if meta.id.is_empty() {
        return Err(anyhow!(
            "dev: module {} has no ID set. Run `mirrorstack app module register` first.",
            module_dir.display()
        ));
    }
    Ok(meta.id)
}

/// Path to the workspace root's `.env` file — holds one `MS_MODULE_ID_<SLUG>`
/// key per module. Gitignored; not part of the git-committed source tree.
fn env_path(root: &Path) -> PathBuf {
    root.join(".env")
}

/// Root-`.env` key for a module's platform ID: `MS_MODULE_ID_<SLUG>`, where
/// `<SLUG>` is the slug SCREAMING_SNAKE_CASEd (uppercased, `-` → `_`). e.g.
/// `oauth-core` → `MS_MODULE_ID_OAUTH_CORE`, `users-profile` →
/// `MS_MODULE_ID_USERS_PROFILE`. Suffixing every key (even for a
/// single-module workspace) keeps one uniform rule instead of special-casing
/// by module count — and is what lets a monorepo root `.env` hold multiple
/// modules' IDs without collision.
///
/// This is a root-`.env`-file/CLI-lookup-only convention: it never appears
/// in the scaffold template (`main.go` reads plain `os.Getenv("MS_MODULE_ID")`)
/// or in a spawned module's own child-process environment (see
/// `dev::module_process_envs`).
pub(crate) fn env_key_for_slug(slug: &str) -> String {
    format!(
        "MS_MODULE_ID_{}",
        slug.to_ascii_uppercase().replace('-', "_")
    )
}

/// Read `MS_MODULE_ID_<SLUG>` out of `<root>/.env`. Returns an empty string
/// when the file is missing or the key isn't set (or set empty) — all of
/// which mean "not registered in this environment yet," mirroring the old
/// empty-`ID:""`-literal convention this replaces. Parsing (quoting,
/// comments, blank lines) is delegated to `dotenvy` — the same crate the
/// CLI already uses for its own `.env` loading in `main.rs` — instead of a
/// hand-rolled `KEY=value` scanner.
fn read_env_module_id(root: &Path, slug: &str) -> String {
    let key = env_key_for_slug(slug);
    let Ok(iter) = dotenvy::from_path_iter(env_path(root)) else {
        return String::new();
    };
    for item in iter {
        let Ok((k, val)) = item else { continue };
        if k == key && !val.is_empty() {
            return val;
        }
    }
    String::new()
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

/// Build a release SemVer from a core triple — bound construction for
/// version-constraint matching (see commands::module::capabilities::version).
pub(crate) fn semver_from_core(major: u64, minor: u64, patch: u64) -> SemVer {
    SemVer {
        core: (major, minor, patch),
        pre: Vec::new(),
    }
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

/// Write `MS_MODULE_ID_<SLUG>=<new_id>` into `<root>/.env`, creating the
/// file if it doesn't exist yet. Upserts on that module's key so any other
/// module's entry (monorepo: several modules share one root `.env`) or other
/// local-only vars already in the file survive re-running `register`.
pub(crate) fn write_module_id(root: &Path, slug: &str, new_id: &str) -> Result<()> {
    let key = env_key_for_slug(slug);
    let prefix = format!("{key}=");
    let path = env_path(root);
    let existing = fs::read_to_string(&path).unwrap_or_default();

    let mut found = false;
    let mut lines: Vec<String> = existing
        .lines()
        .map(|line| {
            if !found && line.trim_start().starts_with(&prefix) {
                found = true;
                format!("{key}={new_id}")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !found {
        lines.push(format!("{key}={new_id}"));
    }

    let mut new_body = lines.join("\n");
    new_body.push('\n');
    fs::write(&path, new_body).with_context(|| format!("dev: write {}", path.display()))?;
    Ok(())
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
    fn read_module_meta_id_comes_from_env_not_main_go() {
        // SAMPLE_MAIN_GO carries a stale ID literal (the old scaffold
        // shape) but no root .env exists — the clean break means that
        // literal is never read as the ID anymore. Slug/Name/Version still
        // parse from main.go as before.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        let meta = read_module_meta(tmp.path(), tmp.path()).unwrap();
        assert_eq!(meta.id, "");
        assert_eq!(meta.slug, "media");
        assert_eq!(meta.name, "Media");
        assert_eq!(meta.version.as_deref(), Some("v0.1.0-dev"));
    }

    #[test]
    fn read_module_meta_id_reads_suffixed_key_from_root_env_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "MS_MODULE_ID_MEDIA=menvsourced123\n",
        )
        .unwrap();
        let meta = read_module_meta(tmp.path(), tmp.path()).unwrap();
        assert_eq!(meta.id, "menvsourced123");
    }

    #[test]
    fn read_module_meta_id_reads_from_separate_workspace_root() {
        // The realistic monorepo shape: module_dir (main.go) is a
        // subdirectory of root (.env + go.work), not the same directory.
        let tmp = tempfile::tempdir().unwrap();
        let module_dir = tmp.path().join("media");
        std::fs::create_dir(&module_dir).unwrap();
        std::fs::write(module_dir.join("main.go"), SAMPLE_MAIN_GO).unwrap();
        std::fs::write(tmp.path().join(".env"), "MS_MODULE_ID_MEDIA=mrootid\n").unwrap();
        let meta = read_module_meta(&module_dir, tmp.path()).unwrap();
        assert_eq!(meta.id, "mrootid");
    }

    #[test]
    fn env_key_for_slug_screaming_snake_cases() {
        assert_eq!(env_key_for_slug("oauth-core"), "MS_MODULE_ID_OAUTH_CORE");
        assert_eq!(
            env_key_for_slug("users-profile"),
            "MS_MODULE_ID_USERS_PROFILE"
        );
        assert_eq!(
            env_key_for_slug("relay-test-module"),
            "MS_MODULE_ID_RELAY_TEST_MODULE"
        );
        assert_eq!(env_key_for_slug("media"), "MS_MODULE_ID_MEDIA");
    }

    #[test]
    fn root_env_holds_multiple_modules_without_collision() {
        // The actual monorepo scenario being fixed: one root .env, several
        // modules' suffixed keys coexisting — each module's read only ever
        // sees its own value.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "MS_MODULE_ID_OAUTH_CORE=moauthcoreid\nMS_MODULE_ID_OAUTH_GOOGLE=moauthgoogleid\nMS_MODULE_ID_USERS_PROFILE=museridprofileid\n",
        )
        .unwrap();
        assert_eq!(read_env_module_id(tmp.path(), "oauth-core"), "moauthcoreid");
        assert_eq!(
            read_env_module_id(tmp.path(), "oauth-google"),
            "moauthgoogleid"
        );
        assert_eq!(
            read_env_module_id(tmp.path(), "users-profile"),
            "museridprofileid"
        );
    }

    #[test]
    fn read_env_module_id_ignores_comments_and_blank_lines() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "# local dev id\n\nMS_MODULE_ID_MEDIA=mfromfile\n",
        )
        .unwrap();
        assert_eq!(read_env_module_id(tmp.path(), "media"), "mfromfile");
    }

    #[test]
    fn read_env_module_id_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_env_module_id(tmp.path(), "media"), "");
    }

    #[test]
    fn read_env_module_id_empty_when_key_unset() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".env"), "OTHER_VAR=x\n").unwrap();
        assert_eq!(read_env_module_id(tmp.path(), "media"), "");
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
        assert_eq!(
            read_module_meta(tmp.path(), tmp.path()).unwrap().version,
            None
        );
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
        let meta = read_module_meta(tmp.path(), tmp.path()).unwrap();
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
    fn read_module_id_from_root_env_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "MS_MODULE_ID_MEDIA=mbb8a3f8b123456789abcdef012345678\n",
        )
        .unwrap();
        assert_eq!(
            read_module_id(tmp.path(), tmp.path()).unwrap(),
            "mbb8a3f8b123456789abcdef012345678"
        );
    }

    #[test]
    fn read_module_id_errors_when_env_missing() {
        // No .env at all — the "unregistered in this environment" case
        // register is expected to detect and mint a fresh registration for,
        // even for an old-style module with a stale main.go ID literal.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        let err = read_module_id(tmp.path(), tmp.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no ID set"));
    }

    #[test]
    fn read_module_id_errors_when_env_key_empty() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        std::fs::write(tmp.path().join(".env"), "MS_MODULE_ID_MEDIA=\n").unwrap();
        let err = read_module_id(tmp.path(), tmp.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no ID set"));
    }

    #[test]
    fn read_module_id_missing_main_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_module_id(tmp.path(), tmp.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("read"));
    }

    #[test]
    fn write_module_id_creates_root_env_file_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        write_module_id(tmp.path(), "media", "m123abc").unwrap();
        let result = std::fs::read_to_string(tmp.path().join(".env")).unwrap();
        assert_eq!(result, "MS_MODULE_ID_MEDIA=m123abc\n");
    }

    #[test]
    fn write_module_id_upserts_existing_key() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "MS_MODULE_ID_MEDIA=moldid\nOTHER_VAR=keepme\n",
        )
        .unwrap();
        write_module_id(tmp.path(), "media", "mnewid").unwrap();
        let result = std::fs::read_to_string(tmp.path().join(".env")).unwrap();
        assert!(result.contains("MS_MODULE_ID_MEDIA=mnewid"));
        assert!(!result.contains("moldid"));
        // Other local vars in .env survive the upsert.
        assert!(result.contains("OTHER_VAR=keepme"));
    }

    #[test]
    fn write_module_id_appends_when_env_file_lacks_key() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".env"), "OTHER_VAR=keepme\n").unwrap();
        write_module_id(tmp.path(), "media", "mnewid").unwrap();
        let result = std::fs::read_to_string(tmp.path().join(".env")).unwrap();
        assert!(result.contains("OTHER_VAR=keepme"));
        assert!(result.contains("MS_MODULE_ID_MEDIA=mnewid"));
    }

    #[test]
    fn write_module_id_only_touches_its_own_key_when_other_modules_present() {
        // The monorepo scenario: writing oauth-core's ID must not disturb
        // users-profile's already-registered entry in the same root .env.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(".env"),
            "MS_MODULE_ID_USERS_PROFILE=museridprofileid\n",
        )
        .unwrap();
        write_module_id(tmp.path(), "oauth-core", "moauthcoreid").unwrap();
        let result = std::fs::read_to_string(tmp.path().join(".env")).unwrap();
        assert!(result.contains("MS_MODULE_ID_USERS_PROFILE=museridprofileid"));
        assert!(result.contains("MS_MODULE_ID_OAUTH_CORE=moauthcoreid"));
    }

    #[test]
    fn write_module_id_does_not_touch_main_go() {
        // register's write is .env-only now — main.go (with its stale
        // literal, if any) is left completely alone.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("main.go"), SAMPLE_MAIN_GO).unwrap();
        write_module_id(tmp.path(), "media", "mnewid").unwrap();
        let main_go = std::fs::read_to_string(tmp.path().join("main.go")).unwrap();
        assert_eq!(main_go, SAMPLE_MAIN_GO);
    }
}
