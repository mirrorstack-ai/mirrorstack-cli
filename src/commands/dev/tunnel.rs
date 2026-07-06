//! WSS tunnel client for `mirrorstack dev`.
//!
//! Two layers:
//!   - `frames`  — typed envelopes (mirrors api-platform's `internal/dispatch/ws/frames.go`)
//!   - `connect` — open the WSS, send `register`, await `register_ack`, hold the
//!     connection and ping every 30s until the host process tells us to stop
//!
//! Phase 1 ships the connect + register half. RPC frames + SQL frames are
//! deferred to Phase 2/3 per the design doc; this module's enum
//! intentionally enumerates them so future PRs only add handler arms.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::time::MissedTickBehavior;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;
use uuid_lite::uuid_v4_string;

use super::super::warn_prefix;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

/// Cap inbound frames at 1 MiB. tokio-tungstenite's default is 64 MiB —
/// way too generous for our wire format (L1.5 says 128 KB per frame; 1 MiB
/// gives an order of magnitude headroom for streaming row batches without
/// exposing a memory-bomb surface to a misbehaving server.
const MAX_INBOUND_FRAME_BYTES: usize = 1 << 20;

/// Local Internal-scope endpoint the SDK serves the module manifest on. The
/// heartbeat GETs this (through the CLI's own dev proxy) purely to read the
/// hash response header — it is NOT the platform's `/v1/tunnel/manifest` route.
const MODULE_MANIFEST_PATH: &str = "/__mirrorstack/platform/manifest";

/// Response header the SDK stamps with its own manifest hash. The CLI forwards
/// this value verbatim on the heartbeat; it never computes a hash itself, so
/// the ping stays byte-consistent with what the platform reads on its fetch.
const MANIFEST_HASH_HEADER: &str = "X-MS-Manifest-Hash";

/// Hard cap on the heartbeat's manifest fetch. A wedged module must never
/// stall ping/pong, so the GET is abandoned well inside the 30s beat.
// Kept deliberately short: the manifest fetch is awaited inside the heartbeat
// select! arm, so this bounds how long inbound-frame handling (server ping/pong)
// can be delayed each beat. The endpoint is loopback-local (~tens of ms healthy;
// a mid-restart module refuses the connection and fails fast), so 500ms is a
// generous ceiling that keeps the beat responsive.
const MANIFEST_FETCH_TIMEOUT: Duration = Duration::from_millis(500);

mod uuid_lite {
    //! Tiny v4 UUID generator. We don't pull `uuid` for one call site — the
    //! envelope just wants a unique ID to correlate frames, not anything
    //! cryptographic. Bytes come from `rand::random` (already a CLI dep).
    pub(super) fn uuid_v4_string() -> String {
        let mut b: [u8; 16] = rand::random();
        // RFC 4122 variant + version-4 bits.
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FrameType {
    Register,
    RegisterAck,
    Ping,
    Pong,
    Close,
    // RPC + SQL planes are reserved here so server frames of those types
    // don't fail to deserialize and force a reconnect.
    #[serde(rename = "rpc.req")]
    RpcReq,
    #[serde(rename = "rpc.resp")]
    RpcResp,
    #[serde(rename = "rpc.err")]
    RpcErr,
    #[serde(rename = "sql.req")]
    SqlReq,
    #[serde(rename = "sql.rows")]
    SqlRows,
    #[serde(rename = "sql.end")]
    SqlEnd,
    #[serde(rename = "sql.err")]
    SqlErr,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Frame {
    #[serde(rename = "type")]
    pub frame_type: FrameType,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corr_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl Frame {
    pub(super) fn new(frame_type: FrameType, payload: Option<serde_json::Value>) -> Self {
        Self {
            frame_type,
            id: format!("frm_{}", uuid_v4_string()),
            corr_id: None,
            stream_id: None,
            payload,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct RegisterPayload<'a> {
    pub module_id: &'a str,
    pub local_url: &'a str,
    pub version: &'a str,
    /// Per-session shared secret the module enforces on its Internal
    /// scope routes (X-MS-Internal-Secret header). The CLI mints this,
    /// sets `MS_INTERNAL_SECRET` on the spawned module process, and
    /// sends the same value here so dispatch can attach the header to
    /// every forwarded request. None until --tunnel is set; serialized
    /// only when present so older dispatch builds keep round-tripping
    /// the register frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_secret: Option<&'a str>,
    /// The module's current manifest hash — the SDK's `X-MS-Manifest-Hash`
    /// value, read verbatim off a local manifest fetch. None at register time
    /// (the module isn't up yet when `open_tunnels` runs); the platform seeds
    /// its stored hash from its own fetch and the first heartbeat. Serialized
    /// only when present so older dispatch builds keep round-tripping register.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RegisterAck {
    pub session_id: String,
    /// The per-tunnel service token. The dev runner writes it to a
    /// per-module `.ms-platform-token-<slug>` file so each spawned module
    /// authenticates platform-initiated calls against ITS own session.
    pub service_token: String,
    /// RFC3339 — informational; the L1.5 reconnect contract makes the
    /// client retry on any failure rather than expiry-driven refresh.
    #[allow(dead_code)]
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
struct ErrorPayload {
    code: String,
    message: String,
    #[serde(default)]
    slug: Option<String>,
}

/// Typed register-time rejection. Distinguishes the cases the CLI knows
/// how to coach the user through (`module_dev_mode_off`,
/// `module_not_yours`) from "every other rpc.err on the register
/// channel" so callers can match without string-sniffing.
#[derive(Debug, thiserror::Error)]
pub(super) enum RegisterError {
    #[error("dev mode is disabled on this module")]
    ModuleDevModeOff {
        /// Module slug from the rpc.err payload — empty when the
        /// platform predates the slug-in-error PR. Callers should
        /// degrade to the /dev list URL when None.
        slug: Option<String>,
    },
    #[error("module is not owned by you")]
    ModuleNotYours,
    #[error("register rejected ({code}): {message}")]
    Rejected { code: String, message: String },
    #[error(transparent)]
    Transport(anyhow::Error),
}

impl From<anyhow::Error> for RegisterError {
    fn from(e: anyhow::Error) -> Self {
        RegisterError::Transport(e)
    }
}

impl From<serde_json::Error> for RegisterError {
    fn from(e: serde_json::Error) -> Self {
        RegisterError::Transport(anyhow::Error::new(e))
    }
}

/// Local Result alias — anyhow::Result is in scope at module level, so
/// every typed handshake return path would otherwise need the
/// fully-qualified std form. Keeps signatures readable.
type RegisterResult<T> = std::result::Result<T, RegisterError>;

/// Spawned-task handle. Drop or call [`shutdown`] to close the WSS.
///
/// `service_token` is the per-tunnel dispatch-minted token from the
/// register ack. The dev runner writes it to a per-module
/// `.ms-platform-token-<slug>` file so each spawned module authenticates
/// platform-initiated calls (lifecycle install, manifest read) against
/// ITS own session.
pub(super) struct TunnelHandle {
    pub session_id: String,
    pub service_token: String,
    shutdown: Arc<Notify>,
}

impl TunnelHandle {
    /// Ask the tunnel to close. The background task will send a `close`
    /// frame and drop the connection. Idempotent.
    pub(super) fn shutdown(&self) {
        self.shutdown.notify_one();
    }
}

/// Connect to `wss_url?token=ttok`, send `register`, await `register_ack`,
/// then hand the connection off to a background task that pings every 30s
/// and replies to inbound pings. Returns when the handshake completes; the
/// connection itself lives until [`TunnelHandle::shutdown`] is called.
pub(super) async fn open(
    wss_url: &str,
    ttok: &str,
    register: RegisterPayload<'_>,
) -> RegisterResult<TunnelHandle> {
    let url = with_token_param(wss_url, ttok)?;
    let config = WebSocketConfig {
        max_message_size: Some(MAX_INBOUND_FRAME_BYTES),
        max_frame_size: Some(MAX_INBOUND_FRAME_BYTES),
        ..Default::default()
    };
    let (ws_stream, _resp) =
        tokio_tungstenite::connect_async_with_config(&url, Some(config), false)
            .await
            .with_context(|| format!("dev: connect WSS {wss_url}"))?;
    let (mut sink, mut stream) = ws_stream.split();

    let register_frame = Frame::new(
        FrameType::Register,
        Some(serde_json::to_value(&register).context("dev: serialize register payload")?),
    );
    let register_id = register_frame.id.clone();
    sink.send(Message::Text(serde_json::to_string(&register_frame)?))
        .await
        .context("dev: send register frame")?;

    let ack = tokio::time::timeout(
        Duration::from_secs(10),
        await_register_ack(&mut sink, &mut stream, &register_id),
    )
    .await
    .context("dev: register_ack timeout")??;

    let shutdown = Arc::new(Notify::new());
    // Async client for the heartbeat's local manifest fetch. Client-level
    // timeout guards every GET so a wedged module can't stall the ping loop.
    let http = reqwest::Client::builder()
        .timeout(MANIFEST_FETCH_TIMEOUT)
        .build()
        .context("dev: build manifest-hash http client")?;
    tokio::spawn(run_tunnel_loop(
        sink,
        stream,
        shutdown.clone(),
        http,
        register.local_url.to_string(),
        ack.service_token.clone(),
        register.internal_secret.map(str::to_string),
    ));

    Ok(TunnelHandle {
        session_id: ack.session_id,
        service_token: ack.service_token,
        shutdown,
    })
}

/// Append `?token=<ttok>` (or `&token=<ttok>` if a query already exists) to
/// `wss_url` using the `url` crate's parser — same pattern as
/// `auth::authorize_url` for the OAuth consent URL. Avoids the fragile
/// `?` vs `&` substring check the previous version did.
fn with_token_param(wss_url: &str, ttok: &str) -> Result<String> {
    let mut u = Url::parse(wss_url).with_context(|| format!("dev: parse wss_url {wss_url}"))?;
    u.query_pairs_mut().append_pair("token", ttok);
    Ok(u.into())
}

/// Read frames off `stream` until a `register_ack` correlated with
/// `register_id` arrives. Server-side ping/binary/text-without-ack are
/// tolerated — the server may send heartbeat or status frames before
/// the ack lands. Wrapped in `tokio::time::timeout` by the caller.
// The server replies on the register's corr_id either with
// register_ack (success) or rpc.err (rejection). Anything else during
// handshake (server-initiated ping, future frame types) gets ignored.
async fn await_register_ack(
    sink: &mut WsSink,
    stream: &mut WsReader,
    register_id: &str,
) -> RegisterResult<RegisterAck> {
    loop {
        let next = stream
            .next()
            .await
            .ok_or_else(|| anyhow!("stream closed before register_ack"))?;
        let msg = next.context("dev: read register_ack")?;
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
            Message::Ping(p) => {
                let _ = sink.send(Message::Pong(p)).await;
                continue;
            }
            Message::Close(_) => return Err(anyhow!("server closed before register_ack").into()),
            _ => continue,
        };
        let frame: Frame = serde_json::from_str(&text)
            .with_context(|| format!("dev: parse server frame: {text}"))?;
        if frame.corr_id.as_deref() != Some(register_id) {
            continue;
        }
        match frame.frame_type {
            FrameType::RegisterAck => {
                let payload = frame
                    .payload
                    .ok_or_else(|| anyhow!("register_ack missing payload"))?;
                return Ok(
                    serde_json::from_value(payload).context("dev: deserialize register_ack")?
                );
            }
            FrameType::RpcErr => {
                let payload = frame
                    .payload
                    .ok_or_else(|| anyhow!("rpc.err missing payload"))?;
                let err: ErrorPayload =
                    serde_json::from_value(payload).context("dev: deserialize rpc.err")?;
                return Err(match err.code.as_str() {
                    "module_dev_mode_off" => RegisterError::ModuleDevModeOff { slug: err.slug },
                    "module_not_yours" => RegisterError::ModuleNotYours,
                    _ => RegisterError::Rejected {
                        code: err.code,
                        message: err.message,
                    },
                });
            }
            _ => continue,
        }
    }
}

/// Long-running tunnel loop: ping every 30s, respond to server pings,
/// shut down on signal. Surfaces transport failures via `warn_prefix()`
/// so a silently-dying tunnel doesn't leave the user wondering why
/// inbound calls stop arriving. (See issue #29 for upgrading this to a
/// liveness signal callers can poll.)
async fn run_tunnel_loop(
    mut sink: WsSink,
    mut stream: WsReader,
    shutdown: Arc<Notify>,
    http: reqwest::Client,
    local_url: String,
    service_token: String,
    internal_secret: Option<String>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    // The first tick fires immediately — consume it so the first ping is at
    // t=30s, not t=0. Delay the missed-tick behavior so a paused runtime
    // (e.g. laptop sleep) doesn't burst-ping on resume.
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                let close = Frame::new(FrameType::Close, None);
                if let Ok(body) = serde_json::to_string(&close) {
                    let _ = sink.send(Message::Text(body)).await;
                }
                let _ = sink.close().await;
                return;
            }
            _ = interval.tick() => {
                // Read the module's current manifest hash off its local
                // endpoint, timeout-guarded so a wedged module can never stall
                // the beat. A successful read sends the SDK's hash verbatim; any
                // error/timeout sends a payload-less ping so the tunnel keeps
                // beating. Re-sending an unchanged hash is a no-op on the
                // platform, so fetching every beat is cheap and safe.
                let hash = fetch_manifest_hash(
                    &http,
                    &local_url,
                    &service_token,
                    internal_secret.as_deref(),
                )
                .await;
                let ping = Frame::new(FrameType::Ping, ping_payload(hash.as_deref()));
                if let Ok(body) = serde_json::to_string(&ping) {
                    if let Err(e) = sink.send(Message::Text(body)).await {
                        eprintln!("{} tunnel: ping send failed ({e}); closing tunnel", warn_prefix());
                        return;
                    }
                }
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(_))) | Some(Ok(Message::Binary(_))) => {
                        // Server frames (pong, future RPC responses) ignored
                        // for now — Phase 1 doesn't act on them client-side.
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = sink.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(reason))) => {
                        eprintln!("{} tunnel closed by server: {reason:?}", warn_prefix());
                        return;
                    }
                    Some(Err(e)) => {
                        eprintln!("{} tunnel: read failed ({e}); closing tunnel", warn_prefix());
                        return;
                    }
                    None => {
                        eprintln!("{} tunnel: stream ended", warn_prefix());
                        return;
                    }
                    Some(Ok(Message::Frame(_))) => {}
                }
            }
        }
    }
}

/// Build a ping frame payload for a (possibly absent) manifest hash.
/// `Some(hash)` → `{"manifest_hash": hash}`; `None` → payload-less ping
/// (the frame's `payload` field stays absent).
fn ping_payload(hash: Option<&str>) -> Option<serde_json::Value> {
    hash.map(|h| serde_json::json!({ "manifest_hash": h }))
}

/// GET the module's local manifest endpoint and return the SDK's
/// `X-MS-Manifest-Hash` RESPONSE header verbatim. The CLI never computes a
/// hash — reading the SDK's own header keeps it single-producer-consistent
/// with the platform, which reads the same header on its fetch.
///
/// The GET carries the platform token + internal secret the module's Internal
/// scope requires, and is capped by [`MANIFEST_FETCH_TIMEOUT`]. Any failure —
/// connect refused, timeout, missing/empty header — yields `None` so the caller
/// sends a payload-less ping instead of stalling or dropping the tunnel.
async fn fetch_manifest_hash(
    client: &reqwest::Client,
    local_url: &str,
    service_token: &str,
    internal_secret: Option<&str>,
) -> Option<String> {
    let mut req = client.get(format!("{local_url}{MODULE_MANIFEST_PATH}"));
    if !service_token.is_empty() {
        req = req.header("X-MS-Platform-Token", service_token);
    }
    if let Some(secret) = internal_secret {
        req = req.header("X-MS-Internal-Secret", secret);
    }
    let resp = req.send().await.ok()?;
    let hash = resp
        .headers()
        .get(MANIFEST_HASH_HEADER)?
        .to_str()
        .ok()?
        .trim();
    (!hash.is_empty()).then(|| hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_serialization_round_trip() {
        let f = Frame::new(FrameType::Register, Some(serde_json::json!({"hi": 1})));
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains("\"type\":\"register\""));
        assert!(s.contains("\"id\":\"frm_"));
        let back: Frame = serde_json::from_str(&s).unwrap();
        assert_eq!(back.frame_type, FrameType::Register);
    }

    #[test]
    fn frame_type_renames_match_server_protocol() {
        let cases = [
            (FrameType::Register, "register"),
            (FrameType::RegisterAck, "register_ack"),
            (FrameType::Ping, "ping"),
            (FrameType::Pong, "pong"),
            (FrameType::RpcReq, "rpc.req"),
            (FrameType::SqlRows, "sql.rows"),
        ];
        for (variant, wire) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, format!("\"{wire}\""));
        }
    }

    #[test]
    fn frame_id_is_unique_across_calls() {
        let a = Frame::new(FrameType::Ping, None);
        let b = Frame::new(FrameType::Ping, None);
        assert_ne!(a.id, b.id);
        assert!(a.id.starts_with("frm_"));
    }

    #[test]
    fn register_payload_serializes_with_snake_case_fields() {
        let p = RegisterPayload {
            module_id: "m_abc",
            local_url: "http://localhost:8080",
            version: "0.1.0",
            internal_secret: None,
            manifest_hash: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"module_id\":\"m_abc\""));
        assert!(s.contains("\"local_url\":\"http://localhost:8080\""));
        // Skip-if-none keeps the field absent for older dispatch builds.
        assert!(!s.contains("internal_secret"));
        // manifest_hash is None at register time — also skipped.
        assert!(!s.contains("manifest_hash"));
    }

    #[test]
    fn register_payload_emits_internal_secret_when_set() {
        let p = RegisterPayload {
            module_id: "m_abc",
            local_url: "http://localhost:8080",
            version: "0.1.0",
            internal_secret: Some("s3cret"),
            manifest_hash: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"internal_secret\":\"s3cret\""));
    }

    #[test]
    fn ping_payload_wraps_hash_when_present() {
        let p = ping_payload(Some("sha256:abc")).unwrap();
        assert_eq!(p, serde_json::json!({ "manifest_hash": "sha256:abc" }));
    }

    #[test]
    fn ping_payload_none_stays_payload_less() {
        assert!(ping_payload(None).is_none());
    }

    #[tokio::test]
    async fn fetch_manifest_hash_reads_response_header() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/__mirrorstack/platform/manifest")
            .match_header("x-ms-platform-token", "ptok")
            .match_header("x-ms-internal-secret", "sec")
            .with_status(200)
            .with_header(MANIFEST_HASH_HEADER, "sha256:abc")
            .with_body("{}")
            .create_async()
            .await;
        let client = reqwest::Client::new();
        let got = fetch_manifest_hash(&client, &server.url(), "ptok", Some("sec")).await;
        assert_eq!(got.as_deref(), Some("sha256:abc"));
        m.assert_async().await;
    }

    #[tokio::test]
    async fn fetch_manifest_hash_absent_header_is_none() {
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/__mirrorstack/platform/manifest")
            .with_status(200)
            .with_body("{}")
            .create_async()
            .await;
        let client = reqwest::Client::new();
        assert_eq!(
            fetch_manifest_hash(&client, &server.url(), "", None).await,
            None
        );
    }

    #[tokio::test]
    async fn fetch_manifest_hash_connect_error_is_none() {
        // Nothing listening on this port → connect refused → None, never a stall.
        let client = reqwest::Client::builder()
            .timeout(MANIFEST_FETCH_TIMEOUT)
            .build()
            .unwrap();
        let got = fetch_manifest_hash(&client, "http://127.0.0.1:1", "", None).await;
        assert_eq!(got, None);
    }

    #[test]
    fn with_token_param_appends_when_no_query() {
        let got = with_token_param("wss://api.example/ws", "ttok_abc").unwrap();
        assert_eq!(got, "wss://api.example/ws?token=ttok_abc");
    }

    #[test]
    fn with_token_param_appends_when_query_present() {
        let got = with_token_param("wss://api.example/ws?stage=prod", "ttok_abc").unwrap();
        // url crate may reorder pairs; just assert both made it.
        assert!(got.contains("stage=prod"));
        assert!(got.contains("token=ttok_abc"));
        assert!(got.starts_with("wss://api.example/ws?"));
    }

    #[test]
    fn with_token_param_rejects_malformed_url() {
        assert!(with_token_param("not a url", "ttok").is_err());
    }
}
