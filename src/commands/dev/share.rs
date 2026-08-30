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
use super::release_session::ReleaseSessionStore;
use super::supervisor::{SessionTracker, ShareInvalidator};
use super::{ok_mark, warn_prefix, web_pipeline};
use crate::api::{self, ApiError, DevBundlePresignInput};
use crate::credentials::{self, Credentials};
use crate::http;

/// Built web bundle path, relative to a module's directory. The module's
/// discovered web pipeline writes the bundle here.
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
    /// when the module has no runnable web pipeline for this dev mode, so
    /// pure-backend modules are silently skipped. This is the same discovery
    /// rule the inner builder uses to produce the bundle.
    pub(super) fn for_module(
        module_dir: &Path,
        slug: String,
        module_id: String,
        watch: bool,
    ) -> Option<Self> {
        web_pipeline(&module_dir.join("web"), watch)?;
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

#[derive(Clone, Copy)]
struct ShareHttp<'a> {
    api_client: &'a Client,
    upload_client: &'a Client,
    apps_base: &'a str,
}

#[derive(Clone, Copy)]
struct BundleUpload<'a> {
    module_id: &'a str,
    session_id: &'a str,
    bytes: &'a [u8],
    sha256: &'a str,
}

/// Per-module upload flow: presign → PUT → confirm. Returns the confirmed CDN
/// URL on success. `sha256` is precomputed by the caller (it's also the
/// hash-gate key) and declared to presign; the raw bytes go to the presigned
/// S3 URL with the JavaScript content type (no auth header — the URL's
/// signature IS the auth), then confirm hands back the live `bundleUrl`.
fn upload_bundle(
    http: ShareHttp<'_>,
    creds: &mut Credentials,
    upload: BundleUpload<'_>,
) -> Result<api::DevBundleConfirmed, ApiError> {
    // The REST endpoints key on the dashed catalog UUID, not the tunnel's
    // m<hex> form that `module_id` carries here.
    let module_id = &catalog_uuid(upload.module_id);
    let presign = credentials::with_refresh_retry(creds, |tok| {
        api::presign_dev_bundle(
            http.api_client,
            http.apps_base,
            tok,
            module_id,
            &DevBundlePresignInput {
                content_type: BUNDLE_CONTENT_TYPE,
                size_bytes: upload.bytes.len() as u64,
                sha256: upload.sha256,
            },
        )
    })?;
    if presign.upload_url.is_empty() || presign.key.is_empty() || presign.expires_at.is_empty() {
        return Err(invalid_presign("upload URL, key, or expiry was missing"));
    }

    put_bundle(
        http.upload_client,
        &presign.upload_url,
        &presign.headers,
        upload.bytes,
    )?;

    let confirmed = credentials::with_refresh_retry(creds, |tok| {
        api::confirm_dev_bundle(
            http.api_client,
            http.apps_base,
            tok,
            module_id,
            &presign.key,
            upload.session_id,
        )
    })?;
    if confirmed.url.is_empty()
        || confirmed.session_id != upload.session_id
        || confirmed.sha256 != upload.sha256
        || confirmed.size_bytes != upload.bytes.len() as u64
    {
        return Err(ApiError::Unexpected {
            status: 200,
            body: format!(
                "dev-bundle confirmation did not echo the current exact descriptor (expected session {}, sha256 {}, size {}; got session {}, sha256 {}, size {})",
                upload.session_id,
                upload.sha256,
                upload.bytes.len(),
                confirmed.session_id,
                confirmed.sha256,
                confirmed.size_bytes
            ),
        });
    }
    Ok(confirmed)
}

/// PUT the bundle bytes to the presigned S3 URL with the pinned content type.
/// A non-2xx is surfaced without the storage body, which may echo the signed
/// URL; the watcher logs the redacted failure and retries on the next tick.
fn put_bundle(
    upload_client: &Client,
    url: &str,
    signed_headers: &std::collections::BTreeMap<String, String>,
    bytes: &[u8],
) -> Result<(), ApiError> {
    let headers = validated_upload_headers(signed_headers, bytes.len())?;
    let resp = upload_client
        .put(url)
        .headers(headers)
        .body(bytes.to_vec())
        .send()
        .map_err(|error| ApiError::Http(error.without_url()))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    // Storage errors may echo the request URI, whose query string is the
    // bearer-like upload credential. Never surface that response body.
    Err(ApiError::Unexpected {
        status: status.as_u16(),
        body: "presigned dev-bundle upload failed".to_string(),
    })
}

fn validated_upload_headers(
    signed: &std::collections::BTreeMap<String, String>,
    size_bytes: usize,
) -> Result<reqwest::header::HeaderMap, ApiError> {
    if signed.is_empty() {
        return Err(invalid_presign("signed upload headers were missing"));
    }
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in signed {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid_presign("a signed upload header name was invalid"))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| invalid_presign("a signed upload header value was invalid"))?;
        if headers.insert(name, value).is_some() {
            return Err(invalid_presign(
                "signed upload headers contained a duplicate name",
            ));
        }
    }

    let expected_length = size_bytes.to_string();
    if headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        != Some(expected_length.as_str())
    {
        return Err(invalid_presign(
            "signed Content-Length did not match the exact bundle size",
        ));
    }
    if headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(BUNDLE_CONTENT_TYPE)
    {
        return Err(invalid_presign(
            "signed Content-Type did not match application/javascript",
        ));
    }
    Ok(headers)
}

fn invalid_presign(message: &str) -> ApiError {
    ApiError::Unexpected {
        status: 200,
        body: format!("invalid dev-bundle presign response: {message}"),
    }
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

struct ShareContext<'a> {
    http: ShareHttp<'a>,
    sessions: &'a SessionTracker,
    releases: &'a ReleaseSessionStore,
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
    sessions: Arc<SessionTracker>,
    releases: Arc<ReleaseSessionStore>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        run_watcher(
            &apps_base,
            &targets,
            &stop,
            &invalidator,
            &sessions,
            &releases,
        )
    })
}

fn run_watcher(
    apps_base: &str,
    targets: &[ShareTarget],
    stop: &AtomicBool,
    invalidator: &ShareInvalidator,
    sessions: &SessionTracker,
    releases: &ReleaseSessionStore,
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
    let context = ShareContext {
        http: ShareHttp {
            api_client: &api_client,
            upload_client: &upload_client,
            apps_base,
        },
        sessions,
        releases,
    };

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
                share_once(&context, &mut creds, target, state);
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
    context: &ShareContext<'_>,
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

    let Some(session) = context.sessions.current(&target.slug) else {
        if state.last_warned.as_deref() != Some("__missing-session__") {
            eprintln!(
                "{} [{}] no current tunnel session — web bundle cannot be confirmed",
                warn_prefix(),
                target.slug
            );
            state.last_warned = Some("__missing-session__".to_string());
        }
        return;
    };

    match upload_bundle(
        context.http,
        creds,
        BundleUpload {
            module_id: &target.module_id,
            session_id: &session.session_id,
            bytes: &bytes,
            sha256: &hash,
        },
    ) {
        Ok(confirmed) => {
            let current = context.sessions.current(&target.slug);
            if current.as_ref() != Some(&session) {
                // The server-side #663 precondition also rejects this race;
                // this local gate keeps an old response out of the durable
                // receipt even while the API rollout is in progress.
                state.last_warned = Some("__session-changed__".to_string());
                eprintln!(
                    "{} [{}] tunnel reconnected while web confirmation was in flight; discarding the old-session result and retrying",
                    warn_prefix(),
                    target.slug
                );
                return;
            }
            if let Err(error) = context.releases.confirm_web(
                &target.slug,
                &confirmed.session_id,
                &confirmed.sha256,
                confirmed.size_bytes,
            ) {
                state.last_warned = Some("__receipt-failed__".to_string());
                eprintln!(
                    "{} [{}] shared web bundle but could not publish current-session release evidence ({error:#}); will retry",
                    warn_prefix(),
                    target.slug
                );
                return;
            }
            state.last_uploaded = Some(hash);
            state.last_warned = None;
            eprintln!(
                "{} [{}] shared web bundle → {}",
                ok_mark(),
                style(&target.slug).cyan(),
                style(confirmed.url).dim()
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

    fn share_once_test(
        api_client: &Client,
        upload_client: &Client,
        apps_base: &str,
        creds: &mut Credentials,
        target: &ShareTarget,
        state: &mut TargetState,
    ) {
        let workspace = tempfile::tempdir().unwrap();
        let module_dir = workspace.path().join(&target.slug);
        std::fs::create_dir_all(&module_dir).unwrap();
        let sessions = SessionTracker::default();
        sessions.seed(&target.slug, "session-test");
        let releases = ReleaseSessionStore::new(workspace.path()).unwrap();
        releases
            .install(super::super::release_session::SessionOpen {
                slug: &target.slug,
                module_id: &target.module_id,
                session_id: "session-test",
                local_url: "http://127.0.0.1:1",
                module_dir: &module_dir,
                watch: false,
                share: true,
            })
            .unwrap();
        share_once(
            &ShareContext {
                http: ShareHttp {
                    api_client,
                    upload_client,
                    apps_base,
                },
                sessions: &sessions,
                releases: &releases,
            },
            creds,
            target,
            state,
        );
    }

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
    fn for_module_none_for_backend_only_module() {
        let tmp = tempfile::tempdir().unwrap();
        let t = ShareTarget::for_module(tmp.path(), "media".into(), "m-1".into(), true);
        assert!(t.is_none(), "a backend-only module has no bundle to share");
    }

    #[test]
    fn for_module_accepts_shared_compiler_scripts_without_legacy_config() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("web")).unwrap();
        std::fs::write(
            tmp.path().join("web/package.json"),
            r#"{"scripts":{"build":"node ../../scripts/web/build.mjs","watch":"node ../../scripts/web/build.mjs --watch"}}"#,
        )
        .unwrap();

        for watch in [false, true] {
            let t = ShareTarget::for_module(tmp.path(), "media".into(), "m-1".into(), watch)
                .expect("a declared script is a shareable web pipeline");
            assert_eq!(t.dist, tmp.path().join("web/dist/index.js"));
        }
        assert!(!tmp.path().join("web/esbuild.config.mjs").exists());
    }

    #[test]
    fn for_module_preserves_legacy_esbuild_config_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("web")).unwrap();
        std::fs::write(tmp.path().join("web/esbuild.config.mjs"), "// build").unwrap();
        let t = ShareTarget::for_module(tmp.path(), "media".into(), "m-1".into(), true).unwrap();
        assert_eq!(t.slug, "media");
        assert_eq!(t.module_id, "m-1");
        assert_eq!(t.dist, tmp.path().join("web/dist/index.js"));
    }

    #[test]
    fn for_module_rejects_empty_or_malformed_declared_scripts() {
        for package_json in [
            r#"{"scripts":{"build":" ","watch":"\t"}}"#,
            r#"{"scripts":{"build":7,"watch":false}}"#,
            "{not json",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(tmp.path().join("web")).unwrap();
            std::fs::write(tmp.path().join("web/package.json"), package_json).unwrap();

            for watch in [false, true] {
                assert!(
                    ShareTarget::for_module(tmp.path(), "media".into(), "m-1".into(), watch,)
                        .is_none(),
                    "invalid package must not become a web pipeline: {package_json}"
                );
            }
        }
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
        share_once_test(
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
            share_once_test(
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
                    "headers": {
                        "Content-Length": bytes.len().to_string(),
                        "Content-Type": "application/javascript",
                        "X-MirrorStack-Signed": "exact"
                    },
                    "expires_at": "2026-07-14T00:15:00Z"
                })
                .to_string(),
            )
            .create();
        let put = server
            .mock("PUT", "/s3-put")
            .match_header("content-type", "application/javascript")
            .match_header("content-length", bytes.len().to_string().as_str())
            .match_header("x-mirrorstack-signed", "exact")
            .with_status(200)
            .create();
        let confirm = server
            .mock("POST", "/v1/modules/m-1/dev-bundle/confirm")
            .match_body(mockito::Matcher::JsonString(
                r#"{"key":"modules/m-1/dev/u-1/hash/web/index.js","session_id":"session-1"}"#
                    .into(),
            ))
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "url": "https://cdn.mirrorstack.ai/modules/m-1/dev/u-1/hash/web/index.js",
                    "session_id": "session-1",
                    "sha256": hash,
                    "size_bytes": bytes.len()
                })
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
            ShareHttp {
                api_client: &api_client,
                upload_client: &upload_client,
                apps_base: &server.url(),
            },
            &mut creds,
            BundleUpload {
                module_id: "m-1",
                session_id: "session-1",
                bytes,
                sha256: &hash,
            },
        )
        .expect("upload ok");
        assert_eq!(
            url.url,
            "https://cdn.mirrorstack.ai/modules/m-1/dev/u-1/hash/web/index.js"
        );
        presign.assert();
        put.assert();
        confirm.assert();
    }

    #[test]
    fn signed_upload_headers_are_complete_exact_and_case_unique() {
        let valid = std::collections::BTreeMap::from([
            ("Content-Length".to_string(), "5".to_string()),
            ("Content-Type".to_string(), BUNDLE_CONTENT_TYPE.to_string()),
            ("X-MirrorStack-Signed".to_string(), "exact".to_string()),
        ]);
        let parsed = validated_upload_headers(&valid, 5).unwrap();
        assert_eq!(parsed.get("x-mirrorstack-signed").unwrap(), "exact");

        for invalid in [
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::from([
                ("Content-Length".to_string(), "4".to_string()),
                ("Content-Type".to_string(), BUNDLE_CONTENT_TYPE.to_string()),
            ]),
            std::collections::BTreeMap::from([
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/plain".to_string()),
            ]),
            std::collections::BTreeMap::from([
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), BUNDLE_CONTENT_TYPE.to_string()),
                ("content-type".to_string(), BUNDLE_CONTENT_TYPE.to_string()),
            ]),
        ] {
            assert!(validated_upload_headers(&invalid, 5).is_err());
        }
    }

    #[test]
    fn dev_bundle_upload_errors_never_expose_the_presigned_url() {
        let mut server = mockito::Server::new();
        let upload = server
            .mock("PUT", "/upload")
            .match_query(mockito::Matcher::UrlEncoded(
                "X-Amz-Signature".into(),
                "top-secret".into(),
            ))
            .with_status(500)
            .with_body("failed /upload?X-Amz-Signature=top-secret")
            .create();
        let url = format!("{}/upload?X-Amz-Signature=top-secret", server.url());
        let headers = std::collections::BTreeMap::from([
            ("Content-Length".to_string(), "5".to_string()),
            ("Content-Type".to_string(), BUNDLE_CONTENT_TYPE.to_string()),
        ]);
        let client = http::client(Duration::from_secs(2)).unwrap();
        let error = put_bundle(&client, &url, &headers, b"hello")
            .expect_err("storage failure")
            .to_string();
        assert!(error.contains("dev-bundle upload failed"), "{error}");
        assert!(!error.contains("top-secret"), "{error}");
        assert!(!error.contains(&url), "{error}");
        upload.assert();

        let closed_url = {
            let closed = mockito::Server::new();
            format!("{}/gone?X-Amz-Signature=transport-secret", closed.url())
        };
        let error = put_bundle(&client, &closed_url, &headers, b"hello")
            .expect_err("transport failure")
            .to_string();
        assert!(!error.contains("transport-secret"), "{error}");
        assert!(!error.contains(&closed_url), "{error}");
    }

    #[test]
    fn upload_bundle_rejects_mismatched_confirmed_descriptor() {
        let mut server = mockito::Server::new();
        let bytes = b"hello";
        let hash = sha256_hex(bytes);
        let _presign = server
            .mock("POST", "/v1/modules/m-1/dev-bundle/presign")
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "upload_url": format!("{}/s3-put", server.url()),
                    "key": "modules/m-1/dev/u-1/hash/web/index.js",
                    "headers": {
                        "Content-Length": bytes.len().to_string(),
                        "Content-Type": BUNDLE_CONTENT_TYPE
                    },
                    "expires_at": "2026-07-14T00:15:00Z"
                })
                .to_string(),
            )
            .create();
        let _put = server.mock("PUT", "/s3-put").with_status(200).create();
        let _confirm = server
            .mock("POST", "/v1/modules/m-1/dev-bundle/confirm")
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "url": "https://cdn.example/bundle.js",
                    "session_id": "stale-session",
                    "sha256": hash,
                    "size_bytes": bytes.len()
                })
                .to_string(),
            )
            .create();
        let api_client = http::client(Duration::from_secs(2)).unwrap();
        let upload_client = http::client(Duration::from_secs(2)).unwrap();
        let mut creds = Credentials {
            access_token: "AT".into(),
            refresh_token: "RT".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        };
        let error = upload_bundle(
            ShareHttp {
                api_client: &api_client,
                upload_client: &upload_client,
                apps_base: &server.url(),
            },
            &mut creds,
            BundleUpload {
                module_id: "m-1",
                session_id: "current-session",
                bytes,
                sha256: &hash,
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("did not echo the current exact descriptor"),
            "{error}"
        );
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
        share_once_test(
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
        share_once_test(
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
