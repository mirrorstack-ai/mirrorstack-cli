//! Once-a-day "a newer release exists" notice.
//!
//! Runs after a command finishes (never before, never during `dev` — see
//! `main.rs`), checks the cache at
//! `dirs::cache_dir()/mirrorstack-cli/update-check.json`, and only hits the
//! network when that cache is missing or older than 24 hours. The notice
//! itself only prints on the fetch that discovers a newer release, not on
//! every command for the rest of that day — otherwise a developer who opts
//! in to a noisy terminal would see it on every single invocation.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::http;

const RELEASES_URL: &str =
    "https://api.github.com/repos/mirrorstack-ai/mirrorstack-cli/releases/latest";
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const ENV_NO_UPDATE_CHECK: &str = "MIRRORSTACK_NO_UPDATE_CHECK";
const ENV_CI: &str = "CI";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Cache {
    checked_at: u64,
    latest: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseResponse {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

#[derive(Debug, Default)]
struct Outcome {
    new_cache: Option<Cache>,
    message: Option<String>,
}

/// Entry point: called once after a command finishes.
pub fn maybe_notify() {
    let run = should_run(
        has_json_flag(std::env::args()),
        std::env::var_os(ENV_NO_UPDATE_CHECK).is_some(),
        std::env::var_os(ENV_CI).is_some(),
        std::io::stdout().is_terminal(),
        std::io::stderr().is_terminal(),
    );
    let Some(path) = cache_path() else { return };
    let cached = read_cache(&path);
    let outcome = run_check(
        env!("CARGO_PKG_VERSION"),
        SystemTime::now(),
        cached,
        run,
        fetch_latest_release,
    );
    if let Some(cache) = &outcome.new_cache {
        let _ = write_cache(&path, cache);
    }
    if let Some(message) = outcome.message {
        eprintln!("{message}");
    }
}

fn has_json_flag<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter().any(|a| a == "--json")
}

fn cache_path() -> Option<PathBuf> {
    Some(
        dirs::cache_dir()?
            .join("mirrorstack-cli")
            .join("update-check.json"),
    )
}

/// Whether the notice machinery should run at all this invocation. Kept
/// separate from `run_check` so opt-outs (env vars, `--json`, non-terminal
/// stdio) are decided without ever constructing — let alone calling — the
/// network fetcher.
fn should_run(
    json_flag: bool,
    no_update_check_env: bool,
    ci_env: bool,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    !json_flag && !no_update_check_env && !ci_env && stdout_is_terminal && stderr_is_terminal
}

/// Core decision logic: given the current cache (if any) and whether the
/// gating checks allow a run, decide whether to hit the network and what
/// (if anything) to print. `fetch` is `FnOnce` and only invoked when the
/// cache is missing or stale, so tests can pass a panicking fetcher to
/// prove a fresh cache or a disabled run never reaches the network.
fn run_check(
    current_version: &str,
    now: SystemTime,
    cached: Option<Cache>,
    should_run: bool,
    fetch: impl FnOnce() -> Option<String>,
) -> Outcome {
    if !should_run {
        return Outcome::default();
    }
    if let Some(cache) = &cached
        && is_fresh(cache, now)
    {
        return Outcome::default();
    }
    let Some(latest) = fetch() else {
        return Outcome::default();
    };
    let new_cache = Some(Cache {
        checked_at: unix_secs(now),
        latest: latest.clone(),
    });
    let message = build_message(current_version, &latest);
    Outcome { new_cache, message }
}

fn is_fresh(cache: &Cache, now: SystemTime) -> bool {
    let checked_at = UNIX_EPOCH + Duration::from_secs(cache.checked_at);
    now.duration_since(checked_at)
        .map(|age| age < CHECK_INTERVAL)
        // Clock skew (checked_at is in the future): treat as fresh rather
        // than hammering the network.
        .unwrap_or(true)
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_message(current_version: &str, latest_tag: &str) -> Option<String> {
    let latest_version = parse_release_version(latest_tag)?;
    let current_version_parsed = parse_release_version(current_version)?;
    if latest_version <= current_version_parsed {
        return None;
    }
    Some(format!(
        "mirrorstack {latest_tag} is available, you have {current_version}. Update: \
         cargo install --git https://github.com/mirrorstack-ai/mirrorstack-cli --tag {latest_tag}",
    ))
}

/// A pre-release or an unparseable tag is ignored entirely (returns `None`)
/// rather than treated as "not an update" — we don't want a malformed or
/// pre-release tag silently counted as the current floor.
fn parse_release_version(tag: &str) -> Option<semver::Version> {
    let trimmed = tag.strip_prefix('v').unwrap_or(tag);
    let version = semver::Version::parse(trimmed).ok()?;
    if !version.pre.is_empty() {
        return None;
    }
    Some(version)
}

fn read_cache(path: &Path) -> Option<Cache> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_cache(path: &Path, cache: &Cache) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(cache)?;
    std::fs::write(path, json)
}

/// Real network fetcher: `GET /repos/.../releases/latest` with the CLI's
/// User-Agent and a short timeout. Any failure (offline, rate limit,
/// decode error, non-2xx) is swallowed — the caller treats `None` as
/// "silently skip this check", exactly as required for an advisory notice.
fn fetch_latest_release() -> Option<String> {
    let client = http::client(FETCH_TIMEOUT).ok()?;
    let resp = client.get(RELEASES_URL).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = http::read_capped(resp).ok()?;
    let release: ReleaseResponse = serde_json::from_slice(&body).ok()?;
    if release.draft || release.prerelease {
        return None;
    }
    Some(release.tag_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(n)
    }

    #[test]
    fn should_run_matrix() {
        assert!(should_run(false, false, false, true, true));
        assert!(!should_run(true, false, false, true, true), "--json");
        assert!(
            !should_run(false, true, false, true, true),
            "MIRRORSTACK_NO_UPDATE_CHECK"
        );
        assert!(!should_run(false, false, true, true, true), "CI");
        assert!(
            !should_run(false, false, false, false, true),
            "stdout piped"
        );
        assert!(
            !should_run(false, false, false, true, false),
            "stderr piped"
        );
    }

    #[test]
    fn has_json_flag_detects_the_literal_flag() {
        assert!(has_json_flag([
            "mirrorstack".to_string(),
            "module".to_string(),
            "--json".to_string()
        ]));
        assert!(!has_json_flag([
            "mirrorstack".to_string(),
            "whoami".to_string()
        ]));
    }

    #[test]
    fn prints_once_then_silent_within_24_hours() {
        // No cache yet: fetches, finds a newer release, prints, and writes
        // a cache entry.
        let first = run_check("0.3.0", secs(100_000), None, true, || {
            Some("v0.4.0".to_string())
        });
        assert!(first.message.is_some(), "expected a notice on first run");
        assert!(first.message.unwrap().contains("v0.4.0"));
        let cache = first.new_cache.expect("cache written after a live fetch");
        assert_eq!(cache.latest, "v0.4.0");

        // Same day, fresh cache: no network call (a panicking fetcher would
        // fail the test if called) and no repeat notice.
        let second = run_check(
            "0.3.0",
            secs(100_000 + 3_600),
            Some(cache.clone()),
            true,
            || panic!("must not fetch while cache is fresh"),
        );
        assert!(second.message.is_none());
        assert!(second.new_cache.is_none());

        // 24 hours later: cache is stale, fetch runs again.
        let third = run_check(
            "0.3.0",
            secs(100_000 + CHECK_INTERVAL.as_secs() + 1),
            Some(cache),
            true,
            || Some("v0.4.0".to_string()),
        );
        assert!(third.message.is_some());
    }

    #[test]
    fn silent_when_disabled_and_never_touches_the_network() {
        let outcome = run_check("0.3.0", secs(0), None, false, || {
            panic!("must not fetch when should_run is false")
        });
        assert!(outcome.message.is_none());
        assert!(outcome.new_cache.is_none());
    }

    #[test]
    fn silent_offline() {
        let outcome = run_check("0.3.0", secs(0), None, true, || None);
        assert!(outcome.message.is_none());
        // No cache update either — a transient offline failure should not
        // suppress the check on the very next command.
        assert!(outcome.new_cache.is_none());
    }

    #[test]
    fn silent_when_current_is_newer_or_equal() {
        let equal = run_check("0.4.0", secs(0), None, true, || Some("v0.4.0".to_string()));
        assert!(equal.message.is_none());

        let newer = run_check("0.5.0", secs(0), None, true, || Some("v0.4.0".to_string()));
        assert!(newer.message.is_none());
    }

    #[test]
    fn ignores_prerelease_and_unparseable_tags() {
        let prerelease = run_check("0.3.0", secs(0), None, true, || {
            Some("v0.4.0-rc.1".to_string())
        });
        assert!(prerelease.message.is_none());

        let garbage = run_check("0.3.0", secs(0), None, true, || {
            Some("not-a-version".to_string())
        });
        assert!(garbage.message.is_none());
    }

    #[test]
    fn parse_release_version_strips_leading_v_and_rejects_prerelease() {
        assert_eq!(
            parse_release_version("v1.2.3"),
            Some(semver::Version::new(1, 2, 3))
        );
        assert_eq!(
            parse_release_version("1.2.3"),
            Some(semver::Version::new(1, 2, 3))
        );
        assert_eq!(parse_release_version("v1.2.3-rc.1"), None);
        assert_eq!(parse_release_version("not-a-version"), None);
    }

    #[test]
    fn cache_roundtrips_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("update-check.json");
        let cache = Cache {
            checked_at: 12345,
            latest: "v0.4.0".to_string(),
        };
        write_cache(&path, &cache).expect("write");
        assert_eq!(read_cache(&path), Some(cache));
    }

    #[test]
    fn read_cache_missing_file_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_cache(&dir.path().join("missing.json")), None);
    }
}
