//! `--share`: publish each tunneled module's built web bundle to the CDN so
//! REMOTE viewers of a prod dev-tunnel (`mirrorstack dev --tunnel` against
//! `apps.mirrorstack.ai`) can load it.
//!
//! Why the bundle can't ride the tunnel: the WSS RPC relay is a small-JSON
//! transport (API Gateway caps one frame at ~128 KB), and a ~422 KB web
//! bundle overflows it. So `--share` moves the bundle OUT of the relay and
//! onto the CDN — exactly how deployed modules already serve their bundle —
//! by uploading the built `web/dist/index.js` via a platform-minted,
//! owner-scoped presigned S3 PUT, then confirming so the platform points the
//! live tunnel session's `bundleUrl` at the resulting CDN URL. The relay
//! keeps carrying only API/data. See
//! docs-temp/dev-tunnel-bundle-serving/DESIGN.md.
//!
//! WHERE this runs: the OUTER host process (see `run_outer`). It's the only
//! process that has all three inputs the upload needs at once — the user
//! access token from `credentials.json` (a host file, never mounted into the
//! `docker compose` runner), the built `web/dist/index.js` (written by the
//! in-container esbuild watcher but visible on the host through the `.:/modules`
//! bind mount), and the tunnel session registration whose `bundleUrl` the
//! confirm step updates.
//!
//! WHEN: on tunnel start (after the first clean build produces the bundle)
//! and on each rebuild whose bytes hash differently. There is no clean
//! cross-process rebuild signal on the host (esbuild's `onEnd`/SSE beat lives
//! in the container), so the host polls each bundle's content, gated by a
//! per-module SHA-256 so an unchanged rebuild is a no-op.
//!
//! Best-effort: any failure logs a scoped warning and the watcher keeps
//! serving — a share hiccup must never crash the tunnel or block the module,
//! mirroring the tunnel's don't-teardown ethos (#58).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use console::style;
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};

use super::module_meta::catalog_uuid;
use super::supervisor::ShareInvalidator;
use super::{ok_mark, warn_prefix};
use crate::api::{self, ApiError, DevBundlePresignInput};
use crate::credentials::{self, Credentials};
use crate::http;

/// Built web bundle path, relative to a module's directory. A module has a
/// web bundle iff it ships `web/esbuild.config.mjs` (the same gate the web
/// watcher uses); esbuild writes the bundle here.
const WEB_BUNDLE_REL: &str = "web/dist/index.js";

/// Content-Type the presigned PUT is signed with and the server pins on the
/// object. ESM bundles must serve as JavaScript for the browser `import()`.
const BUNDLE_CONTENT_TYPE: &str = "application/javascript";

/// Client-side mirror of the publisher's `maxModuleBundleBytes` (32 MiB). A
/// bundle this large is almost certainly a build mistake; reject locally so
/// we never spend an upload just to collect a 413 at confirm.
const MAX_BUNDLE_BYTES: u64 = 32 << 20;

/// How often the host re-checks each bundle's content. Matches the Go
/// supervisor's rebuild poll — fast enough that edit→see stays snappy,
/// slow enough to stay off the CPU.
const SCAN_INTERVAL: Duration = Duration::from_millis(2000);
/// Stop-flag / cadence tick — bounds shutdown latency without busy-looping.
const TICK: Duration = Duration::from_millis(200);

/// How long a target may have no bundle before we say so. Long enough that a
/// cold `npm install` plus a first build finishes inside it, short enough that
/// a developer hears about a build that is never going to produce one.
const MISSING_BUNDLE_GRACE: Duration = Duration::from_secs(45);

/// Sentinel in `last_warned`. It shares that field with content hashes, which
/// are 64 hex characters, so a marker containing `-` can never collide with one.
const MISSING_BUNDLE: &str = "__missing-bundle__";

/// Longer timeout for the raw S3 PUT than the 15s JSON API calls use: a
/// bundle body is far larger than an API payload and a slow uplink shouldn't
/// abort it. Matches the deploy path's upload-sized client.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// One tunneled module the watcher shares. `dist` is the absolute path to
/// the built bundle on the host (bind-mount view of the container's output);
/// `module_id` is the catalog id the tunnel registered under (same value
/// `module_meta::read_module_id` resolves), which the presign/confirm
/// endpoints key on.
pub(super) struct ShareTarget {
    pub slug: String,
    pub module_id: String,
    pub dist: PathBuf,
}

impl ShareTarget {
    /// Build a target for a module rooted at `module_dir`. Returns `None`
    /// when the module has no web bundle to share (no `web/esbuild.config.mjs`),
    /// so pure-backend modules are silently skipped.
    pub(super) fn for_module(module_dir: &Path, slug: String, module_id: String) -> Option<Self> {
        if !module_dir.join("web/esbuild.config.mjs").exists() {
            return None;
        }
        Some(Self {
            slug,
            module_id,
            dist: module_dir.join(WEB_BUNDLE_REL),
        })
    }
}

/// Lowercase hex SHA-256 of `bytes`. The content address that both gates
/// re-uploads (unchanged bytes → same hash → skip) and, server-side, becomes
/// the CDN key segment.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Per-module upload flow: presign → PUT → confirm. Returns the confirmed CDN
/// URL on success. `sha256` is precomputed by the caller (it's also the
/// hash-gate key) and declared to presign; the raw bytes go to the presigned
/// S3 URL with the JavaScript content type (no auth header — the URL's
/// signature IS the auth), then confirm hands back the live `bundleUrl`.
fn upload_bundle(
    api_client: &Client,
    upload_client: &Client,
    apps_base: &str,
    creds: &mut Credentials,
    module_id: &str,
    bytes: &[u8],
    sha256: &str,
) -> Result<String, ApiError> {
    // The REST endpoints key on the dashed catalog UUID, not the tunnel's
    // m<hex> form that `module_id` carries here.
    let module_id = &catalog_uuid(module_id);
    let presign = credentials::with_refresh_retry(creds, |tok| {
        api::presign_dev_bundle(
            api_client,
            apps_base,
            tok,
            module_id,
            &DevBundlePresignInput {
                content_type: BUNDLE_CONTENT_TYPE,
                size_bytes: bytes.len() as u64,
                sha256,
            },
        )
    })?;

    put_bundle(upload_client, &presign.upload_url, bytes)?;

    let confirmed = credentials::with_refresh_retry(creds, |tok| {
        api::confirm_dev_bundle(api_client, apps_base, tok, module_id, &presign.key)
    })?;
    Ok(confirmed.url)
}

/// PUT the bundle bytes to the presigned S3 URL with the pinned content type.
/// A non-2xx is surfaced as `ApiError::Unexpected` (with the S3 body) so the
/// watcher logs it and retries on the next tick.
fn put_bundle(upload_client: &Client, url: &str, bytes: &[u8]) -> Result<(), ApiError> {
    let resp = upload_client
        .put(url)
        .header("Content-Type", BUNDLE_CONTENT_TYPE)
        .body(bytes.to_vec())
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = http::read_capped(resp).unwrap_or_default();
    Err(ApiError::Unexpected {
        status: status.as_u16(),
        body: format!(
            "presigned PUT failed: {}",
            String::from_utf8_lossy(&body).trim()
        ),
    })
}

/// Mutable per-target bookkeeping: the hash we last confirmed live, and the
/// hash we last warned about (so a persistently-failing upload doesn't spam
/// an identical warning every tick).
#[derive(Default)]
struct TargetState {
    last_uploaded: Option<String>,
    last_warned: Option<String>,
    /// When this target was first seen with no bundle on disk, cleared the
    /// moment one appears. A bundle that DISAPPEARS therefore starts a fresh
    /// grace period instead of warning instantly off a stale timestamp.
    missing_since: Option<Instant>,
}

/// Spawn the host-side share watcher. Owns its own credentials (loaded fresh
/// so it picks up any refresh the tunnel mint just rotated) and polls each
/// target's bundle, uploading on first appearance and on every changed hash
/// until `stop` is set. Returns the join handle so `run_outer` can join it on
/// teardown. Never returns an error to the caller: a setup failure disables
/// sharing with a warning rather than failing the whole `dev` session.
///
/// `invalidator` carries slugs whose tunnel reconnected. The platform stores
/// the dev-bundle CDN pointer per SESSION and deletes it with the session, so
/// after a reconnect the shared bundle is silently gone — and the hash gate
/// below would never re-upload it, because the bytes on disk are unchanged.
/// Draining the invalidator each scan clears that target's gate so the very
/// next pass re-confirms the pointer.
pub(super) fn spawn_watcher(
    apps_base: String,
    targets: Vec<ShareTarget>,
    stop: Arc<AtomicBool>,
    invalidator: Arc<ShareInvalidator>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || run_watcher(&apps_base, &targets, &stop, &invalidator))
}

fn run_watcher(
    apps_base: &str,
    targets: &[ShareTarget],
    stop: &AtomicBool,
    invalidator: &ShareInvalidator,
) {
    if targets.is_empty() {
        return;
    }

    // The watcher outlives a 15-minute access token, so it owns a mutable
    // credentials copy and refreshes via `with_refresh_retry` per upload. A
    // failure to even load credentials means we can't share at all — warn and
    // bow out, leaving the tunnel (which already registered) untouched.
    let mut creds = match credentials::load_or_login_hint() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} --share disabled: {e:#}. Bundles keep serving over the tunnel relay.",
                warn_prefix()
            );
            return;
        }
    };

    let api_client = match http::client(Duration::from_secs(15)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} --share disabled: build HTTP client: {e}", warn_prefix());
            return;
        }
    };
    let upload_client = match http::client(UPLOAD_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} --share disabled: build upload client: {e}",
                warn_prefix()
            );
            return;
        }
    };

    let mut states: Vec<TargetState> = targets.iter().map(|_| TargetState::default()).collect();

    eprintln!(
        "{} sharing {} web {} to the CDN on change",
        ok_mark(),
        targets.len(),
        if targets.len() == 1 {
            "bundle"
        } else {
            "bundles"
        }
    );

    // Scan immediately so the first clean build is shared the moment it lands,
    // not one full interval later.
    let mut last_scan = Instant::now() - SCAN_INTERVAL;
    while !stop.load(Ordering::SeqCst) {
        if last_scan.elapsed() >= SCAN_INTERVAL {
            last_scan = Instant::now();
            let reconnected = invalidator.drain();
            if !reconnected.is_empty() {
                for (target, state) in targets.iter().zip(states.iter_mut()) {
                    if reconnected.contains(&target.slug) {
                        // Forget both gates: the pointer needs re-confirming,
                        // and a warning about the old session's failure no
                        // longer applies.
                        state.last_uploaded = None;
                        state.last_warned = None;
                    }
                }
            }
            for (target, state) in targets.iter().zip(states.iter_mut()) {
                share_once(
                    &api_client,
                    &upload_client,
                    apps_base,
                    &mut creds,
                    target,
                    state,
                );
            }
        }
        thread::sleep(TICK);
    }
}

/// One scan pass for one target: read the built bundle, hash-gate it, and
/// upload if the content changed since the last confirmed upload. Every
/// failure is a scoped warning + continue — never a panic or early return
/// that would stall the other targets.
fn share_once(
    api_client: &Client,
    upload_client: &Client,
    apps_base: &str,
    creds: &mut Credentials,
    target: &ShareTarget,
    state: &mut TargetState,
) {
    // 🔴 A BUNDLE THAT NEVER ARRIVES IS NOT "NOTHING TO DO THIS TICK".
    //
    // This returned silently on every read error, so a module whose web build
    // never produced `web/dist/index.js` shared nothing for the entire session
    // without printing one line. The developer's next signal was an install
    // failing with no bundle and nothing naming the cause — and the cause was
    // usually that `dev` ran esbuild directly and skipped the module's
    // build:css stage, which is fixed in spawn_web_builder but cannot be the
    // only defence: a build that simply FAILS lands in the same state.
    //
    // Still silent for the grace period, because a cold start legitimately has
    // no bundle until npm install and the first build finish.
    let bytes = match std::fs::read(&target.dist) {
        Ok(b) => {
            if state.missing_since.take().is_some()
                && state.last_warned.as_deref() == Some(MISSING_BUNDLE)
            {
                // Recovered: clear the marker so a LATER disappearance warns
                // again instead of being suppressed by this one.
                state.last_warned = None;
            }
            b
        }
        Err(_) => {
            let waiting = state
                .missing_since
                .get_or_insert_with(Instant::now)
                .elapsed();
            if waiting >= MISSING_BUNDLE_GRACE
                && state.last_warned.as_deref() != Some(MISSING_BUNDLE)
            {
                eprintln!(
                    "{} [{}] no web bundle at {} after {}s — nothing is being shared for this module. \
                     Check the [{}:web] output above for a failed build.",
                    warn_prefix(),
                    target.slug,
                    target.dist.display(),
                    MISSING_BUNDLE_GRACE.as_secs(),
                    target.slug,
                );
                state.last_warned = Some(MISSING_BUNDLE.to_string());
            }
            return;
        }
    };

    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        // Warn once per oversize state, not every tick.
        if state.last_warned.as_deref() != Some("__oversize__") {
            eprintln!(
                "{} [{}] web bundle is {} bytes (over the {} MiB share cap) — not sharing",
                warn_prefix(),
                target.slug,
                bytes.len(),
                MAX_BUNDLE_BYTES >> 20
            );
            state.last_warned = Some("__oversize__".to_string());
        }
        return;
    }

    let hash = sha256_hex(&bytes);
    // Unchanged since the last confirmed upload → no-op (the common
    // no-op-save case stays free).
    if state.last_uploaded.as_deref() == Some(hash.as_str()) {
        return;
    }

    match upload_bundle(
        api_client,
        upload_client,
        apps_base,
        creds,
        &target.module_id,
        &bytes,
        &hash,
    ) {
        Ok(url) => {
            state.last_uploaded = Some(hash);
            state.last_warned = None;
            eprintln!(
                "{} [{}] shared web bundle → {}",
                ok_mark(),
                style(&target.slug).cyan(),
                style(url).dim()
            );
        }
        Err(e) => {
            // "will retry" below is a promise this thread cannot keep once its
            // cached pair has been rotated out from under it: a tunnel
            // supervisor's reconnect, or any authenticated CLI command in
            // another terminal, refreshes through the same credentials.json,
            // and the platform revokes the pair it rotated away from. Every
            // later upload then 401s for the rest of the session, once per
            // distinct content hash. Re-reading the file is what makes the
            // promise true.
            if matches!(e, ApiError::Unauthenticated) {
                credentials::adopt_rotated(creds);
            }
            // Best-effort: keep the tunnel serving. Suppress a repeat warning
            // for the same still-failing bytes; leaving `last_uploaded`
            // unchanged means the next tick retries (recovers from a
            // transient error without needing another edit).
            if state.last_warned.as_deref() != Some(hash.as_str()) {
                eprintln!(
                    "{} [{}] share upload failed ({e}); bundle still serves over the relay, will retry",
                    warn_prefix(),
                    target.slug
                );
                state.last_warned = Some(hash);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of "hello" — pins the hex encoding (lowercase, 64 chars).
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn sha256_hex_is_lowercase_64_hex() {
        let got = sha256_hex(b"hello");
        assert_eq!(got, HELLO_SHA256);
        assert_eq!(got.len(), 64);
        assert!(
            got.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn sha256_hex_changes_with_content() {
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }

    #[test]
    fn catalog_uuid_reverses_m_hex_to_dashed_uuid() {
        assert_eq!(
            catalog_uuid("m5dcba905ba6c4242a9c3696f9efc92e9"),
            "5dcba905-ba6c-4242-a9c3-696f9efc92e9"
        );
        // Already a dashed UUID → passed through unchanged.
        assert_eq!(
            catalog_uuid("5dcba905-ba6c-4242-a9c3-696f9efc92e9"),
            "5dcba905-ba6c-4242-a9c3-696f9efc92e9"
        );
        // Not the m+32-hex shape → unchanged.
        assert_eq!(catalog_uuid("not-an-id"), "not-an-id");
    }

    #[test]
    fn for_module_none_without_esbuild_config() {
        let tmp = tempfile::tempdir().unwrap();
        let t = ShareTarget::for_module(tmp.path(), "media".into(), "m-1".into());
        assert!(t.is_none(), "a backend-only module has no bundle to share");
    }

    #[test]
    fn for_module_some_points_at_dist_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("web")).unwrap();
        std::fs::write(tmp.path().join("web/esbuild.config.mjs"), "// build").unwrap();
        let t = ShareTarget::for_module(tmp.path(), "media".into(), "m-1".into()).unwrap();
        assert_eq!(t.slug, "media");
        assert_eq!(t.module_id, "m-1");
        assert_eq!(t.dist, tmp.path().join("web/dist/index.js"));
    }

    #[test]
    fn share_once_skips_when_bundle_absent() {
        // No dist file on disk → no network, no state change (nothing to
        // gate against). A missing bundle is the pre-first-build state.
        let tmp = tempfile::tempdir().unwrap();
        let api_client = http::client(Duration::from_secs(5)).unwrap();
        let upload_client = http::client(Duration::from_secs(5)).unwrap();
        let mut creds = Credentials {
            access_token: "AT".into(),
            refresh_token: "RT".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };
        let target = ShareTarget {
            slug: "media".into(),
            module_id: "m-1".into(),
            dist: tmp.path().join("web/dist/index.js"),
        };
        let mut state = TargetState {
            last_uploaded: None,
            ..Default::default()
        };
        // apps_base points nowhere reachable; if it tried to upload this would
        // error, but an absent bundle must return before any network call.
        share_once(
            &api_client,
            &upload_client,
            "http://127.0.0.1:1",
            &mut creds,
            &target,
            &mut state,
        );
        assert!(state.last_uploaded.is_none());
        assert!(state.last_warned.is_none());
    }

    /// 🔴 A BUNDLE THAT NEVER ARRIVES MUST EVENTUALLY SAY SO.
    ///
    /// share_once returned silently on every read error, so a module whose web
    /// build produced nothing shared nothing for a whole session without one
    /// line of output. The developer's next signal was an install failing with
    /// no bundle and nothing naming the cause.
    ///
    /// The grace period is driven by back-dating missing_since rather than by
    /// sleeping, so this asserts the real threshold without costing 45 seconds.
    #[test]
    fn a_bundle_that_never_appears_warns_once_after_the_grace_period() {
        let tmp = tempfile::tempdir().unwrap();
        let api_client = http::client(Duration::from_secs(5)).unwrap();
        let upload_client = http::client(Duration::from_secs(5)).unwrap();
        let creds = Credentials {
            access_token: "AT".into(),
            refresh_token: "RT".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };
        let target = ShareTarget {
            slug: "media".into(),
            module_id: "m-1".into(),
            dist: tmp.path().join("web/dist/index.js"),
        };
        let mut state = TargetState::default();
        let call = |state: &mut TargetState| {
            share_once(
                &api_client,
                &upload_client,
                "http://127.0.0.1:1",
                &mut creds.clone(),
                &target,
                state,
            )
        };

        // Inside the grace period a cold start is legitimately bundle-less, so
        // this must stay quiet — a warning on every dev startup is noise that
        // trains people to ignore the one that matters.
        call(&mut state);
        assert!(
            state.missing_since.is_some(),
            "the wait must start on the first miss"
        );
        assert!(
            state.last_warned.is_none(),
            "must not warn during the grace period"
        );

        // Past the threshold: warn, exactly once.
        state.missing_since = Some(Instant::now() - MISSING_BUNDLE_GRACE - Duration::from_secs(1));
        call(&mut state);
        assert_eq!(state.last_warned.as_deref(), Some(MISSING_BUNDLE));
        let after_first = state.last_warned.clone();
        call(&mut state);
        assert_eq!(
            state.last_warned, after_first,
            "must not re-warn every tick"
        );

        // A bundle that finally appears clears the marker, so a LATER
        // disappearance is reported again instead of being suppressed by this
        // one. Without the clear, the second outage is silent forever.
        std::fs::create_dir_all(tmp.path().join("web/dist")).unwrap();
        std::fs::write(tmp.path().join("web/dist/index.js"), b"export default {}").unwrap();
        call(&mut state);
        assert!(
            state.missing_since.is_none(),
            "a present bundle ends the wait"
        );
        assert_ne!(
            state.last_warned.as_deref(),
            Some(MISSING_BUNDLE),
            "the missing marker must be cleared once a bundle exists"
        );
    }

    #[test]
    fn upload_bundle_presign_put_confirm_round_trip() {
        // Full presign → PUT → confirm against mockito, proving the flow
        // wires the presigned URL through and returns the confirmed CDN URL.
        let mut server = mockito::Server::new();
        let bytes = b"export default {}";
        let hash = sha256_hex(bytes);

        let presign = server
            .mock("POST", "/v1/modules/m-1/dev-bundle/presign")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "upload_url": format!("{}/s3-put", server.url()),
                    "key": "modules/m-1/dev/u-1/hash/web/index.js",
                    "expires_at": "2026-07-14T00:15:00Z"
                })
                .to_string(),
            )
            .create();
        let put = server
            .mock("PUT", "/s3-put")
            .match_header("content-type", "application/javascript")
            .with_status(200)
            .create();
        let confirm = server
            .mock("POST", "/v1/modules/m-1/dev-bundle/confirm")
            .match_body(mockito::Matcher::JsonString(
                r#"{"key":"modules/m-1/dev/u-1/hash/web/index.js"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                serde_json::json!({ "url": "https://cdn.mirrorstack.ai/modules/m-1/dev/u-1/hash/web/index.js" })
                    .to_string(),
            )
            .create();

        let api_client = http::client(Duration::from_secs(5)).unwrap();
        let upload_client = http::client(Duration::from_secs(5)).unwrap();
        let mut creds = Credentials {
            access_token: "AT".into(),
            refresh_token: "RT".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };
        let url = upload_bundle(
            &api_client,
            &upload_client,
            &server.url(),
            &mut creds,
            "m-1",
            bytes,
            &hash,
        )
        .expect("upload ok");
        assert_eq!(
            url,
            "https://cdn.mirrorstack.ai/modules/m-1/dev/u-1/hash/web/index.js"
        );
        presign.assert();
        put.assert();
        confirm.assert();
    }

    #[test]
    fn share_once_skips_upload_when_hash_unchanged() {
        // Pre-seed `last_uploaded` with the current bundle's hash: the scan
        // must short-circuit before any network call (apps_base is
        // unroutable, so an attempted upload would error and flip
        // `last_warned`). This is the no-op-save gate.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("web/dist")).unwrap();
        let bytes = b"export default {}";
        std::fs::write(tmp.path().join("web/dist/index.js"), bytes).unwrap();

        let api_client = http::client(Duration::from_secs(5)).unwrap();
        let upload_client = http::client(Duration::from_secs(5)).unwrap();
        let mut creds = Credentials {
            access_token: "AT".into(),
            refresh_token: "RT".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };
        let target = ShareTarget {
            slug: "media".into(),
            module_id: "m-1".into(),
            dist: tmp.path().join("web/dist/index.js"),
        };
        let mut state = TargetState {
            last_uploaded: Some(sha256_hex(bytes)),
            ..Default::default()
        };
        share_once(
            &api_client,
            &upload_client,
            "http://127.0.0.1:1",
            &mut creds,
            &target,
            &mut state,
        );
        // No upload attempted → no warning recorded, hash still marked live.
        assert!(state.last_warned.is_none());
        assert_eq!(
            state.last_uploaded.as_deref(),
            Some(sha256_hex(bytes).as_str())
        );
    }

    #[test]
    fn share_once_oversize_warns_once_and_skips() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("web/dist")).unwrap();
        // One byte over the cap.
        let big = vec![b'a'; (MAX_BUNDLE_BYTES + 1) as usize];
        std::fs::write(tmp.path().join("web/dist/index.js"), &big).unwrap();

        let api_client = http::client(Duration::from_secs(5)).unwrap();
        let upload_client = http::client(Duration::from_secs(5)).unwrap();
        let mut creds = Credentials {
            access_token: "AT".into(),
            refresh_token: "RT".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };
        let target = ShareTarget {
            slug: "media".into(),
            module_id: "m-1".into(),
            dist: tmp.path().join("web/dist/index.js"),
        };
        let mut state = TargetState {
            last_uploaded: None,
            ..Default::default()
        };
        share_once(
            &api_client,
            &upload_client,
            "http://127.0.0.1:1",
            &mut creds,
            &target,
            &mut state,
        );
        assert_eq!(state.last_warned.as_deref(), Some("__oversize__"));
        assert!(state.last_uploaded.is_none());
    }

    #[test]
    fn a_rotation_by_someone_else_is_adopted_from_disk() {
        // The watcher loads credentials once and refreshes its own copy per
        // upload. A tunnel supervisor's reconnect — or `mirrorstack whoami` in
        // another terminal — rotates the same file, and the platform revokes
        // the pair it rotated away from, so this copy 401s for the rest of the
        // session and "will retry" becomes a promise the watcher cannot keep.
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = tempfile::tempdir().expect("config tempdir");
        let _restore = credentials::redirect_config_dir(config.path());

        let mut mine = Credentials {
            access_token: "AT_stale".into(),
            refresh_token: "RT_spent".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };

        // Nothing on disk yet → nothing to adopt, and no panic.
        assert!(!credentials::adopt_rotated(&mut mine));
        assert_eq!(mine.refresh_token, "RT_spent");

        credentials::save(&Credentials {
            access_token: "AT_live".into(),
            refresh_token: "RT_rotated".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        })
        .expect("seed credentials.json");

        assert!(credentials::adopt_rotated(&mut mine));
        assert_eq!(mine.access_token, "AT_live");
        assert_eq!(mine.refresh_token, "RT_rotated");

        // Already current → no adoption, so a genuinely dead session does not
        // re-read the file on every failing tick.
        assert!(!credentials::adopt_rotated(&mut mine));
    }
}
