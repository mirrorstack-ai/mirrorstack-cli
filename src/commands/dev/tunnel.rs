//! WSS tunnel client for `mirrorstack dev`.
//!
//! Two layers:
//!   - `frames`  — typed envelopes (mirrors api-platform's `internal/dispatch/ws/frames.go`)
//!   - `connect` — open the WSS, send `register`, await `register_ack`, hold the
//!     connection and ping every 30s until the host process tells us to stop
//!
//! This module OWNS one connection and never reopens it. When the connection
//! ends it reports why on [`TunnelSession::exit`]; re-establishing the session
//! is `dev::supervisor`'s job, because a reconnect needs the credentials, the
//! blocking token mint and the per-module token file that live on the host
//! side and are deliberately not reachable from here.
//!
//! Phase 1 shipped the connect + register half. Phase 2 (this module) adds
//! the `rpc.req` handler: the server relays an HTTP request over the WSS
//! connection when dispatch can't reach the local module directly (real
//! Lambda/prod, no shared network); the CLI performs that request against
//! `local_url` and replies with `rpc.resp`/`rpc.err`. SQL frames are still
//! deferred to Phase 3 per the design doc; this module's enum intentionally
//! enumerates them so that PR only adds a handler arm.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, oneshot};
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

/// Cap on the *raw* local-module response body accepted by
/// [`relay_rpc_req_inner`]. The body is base64-encoded into `RpcRespPayload`
/// and then wrapped in a JSON `Frame` before it hits the WSS transport, so
/// checking `body.len()` against [`MAX_INBOUND_FRAME_BYTES`] directly is
/// wrong: base64 alone inflates by ~4/3, and the JSON envelope (headers,
/// frame/corr ids, field names) adds more on top. Scale the raw-body cap
/// down to 3/4 of the transport ceiling for the base64 expansion, then
/// reserve another chunk for the envelope, so a body that passes this check
/// is guaranteed to still fit once encoded and wrapped.
const RELAY_ENVELOPE_OVERHEAD_BYTES: usize = 8 * 1024;

/// Ceiling on the raw local-module response body.
///
/// 🔴 THIS IS NO LONGER A FRAME CALCULATION. It used to be scaled from
/// MAX_INBOUND_FRAME_BYTES, because one reply had to fit one frame — but replies
/// are split across frames now (see split_rpc_resp), so the frame size stops
/// bounding the body entirely.
///
/// Leaving it derived from the frame size made chunking useless for the payload
/// it exists for: a certificate PDF with an embedded background is comfortably
/// over the old ~778 KB, and the check REJECTS a body before it is ever split.
/// The module answers 200, the CLI turns it into an rpc.err, and the browser
/// reports a failed fetch — with nothing in the log to say a cap did it.
///
/// What remains is a memory-bomb guard, not a transport limit: this many bytes
/// are held in RAM and base64-encoded before being split.
const MAX_RELAY_BODY_BYTES: usize = 32 * 1024 * 1024;

/// 🔴 API Gateway's cap on a frame we SEND, which is a different number in a
/// different direction from [`MAX_INBOUND_FRAME_BYTES`] (our own read limit).
/// Confusing the two is how this went unfound for a day: 1 MiB says "payload
/// size cannot be the problem" while 32 KiB is the wall the reply actually hit.
///
/// Over it, API Gateway does not truncate and does not error — it CLOSES the
/// connection. The module has already answered 200 by then, so the tunnel dies
/// on a successful response and the platform reports the module as "installed
/// but has nothing to serve right now".
const MAX_OUTBOUND_FRAME_BYTES: usize = 32 * 1024;

/// Raw bytes of body per part. Base64 inflates by 4/3 and the JSON envelope
/// (status, headers, ids, field names) rides on top, so the raw slice is scaled
/// down for both. A multiple of 3 keeps each part's base64 padding-free, which
/// is not required for correctness — each part is decoded independently — but
/// keeps the encoded sizes even and the arithmetic honest.
const CHUNK_BODY_BYTES: usize =
    ((MAX_OUTBOUND_FRAME_BYTES - RELAY_ENVELOPE_OVERHEAD_BYTES) / 4) * 3 / 3 * 3;

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

/// Per-relay-request HTTP timeout against the local module. Set a few
/// seconds under dispatch's `MS_MODULE_CALL_TIMEOUT` wait (30s default) so
/// the CLI proactively sends `rpc.err` instead of dispatch always hitting a
/// blind timeout waiting on the relay correlation list.
const RELAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(25);

/// Application-level heartbeat period. This is the ONLY thing that keeps a
/// session addressable: dispatch refreshes the session's Redis TTL (20 min)
/// solely on receiving a `{"type":"ping"}` JSON frame, and API Gateway
/// recycles a WSS connection that has been idle for ~10 minutes. 30s is an
/// order of magnitude inside both windows, so the reconnect work deliberately
/// leaves the cadence alone — the observed outage was never an idle timeout.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// How many consecutive heartbeats may pass with NO inbound frame at all
/// before the socket is declared half-open and the tunnel is handed to the
/// supervisor for a reconnect. A TCP connection that has silently gone away
/// (NAT/idle reaper on the path, sleeping laptop) accepts writes forever, so
/// the send-error paths below never fire and the CLI would otherwise hold a
/// socket that reaches nobody. Deliberately generous — ~90-120s of total
/// silence — and only ARMED once a pong has actually been seen (see
/// `pong_seen` in [`tunnel_loop`]), so a dispatch build that never answers
/// pings can never trip it into a reconnect flap.
const MAX_SILENT_BEATS: u32 = 3;

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
    /// Per-module secret the module enforces on its Internal scope routes
    /// (X-MS-Internal-Secret header). The CLI mints this, delivers it to the
    /// module process through that module's own
    /// `.secret/ms-internal-secret-<slug>` file, and sends the same value here
    /// so dispatch can attach the header to every forwarded request. None
    /// until --tunnel is set; serialized only when present so older dispatch
    /// builds keep round-tripping the register frame.
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
    /// per-module `.secret/ms-platform-token-<slug>` file so each spawned module
    /// authenticates platform-initiated calls against ITS own session.
    pub service_token: String,
    /// RFC3339 — informational; the L1.5 reconnect contract makes the
    /// client retry on any failure rather than expiry-driven refresh.
    #[allow(dead_code)]
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorPayload {
    code: String,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
}

/// `rpc.req` payload — mirrors api-platform's `internal/dispatch/ws/frames.go`
/// `RPCReqPayload`. Dispatch builds this from the inbound HTTP request (with
/// `X-MS-*` headers already stripped) when it can't dial the module's
/// `local_url` directly (real Lambda/prod, no shared network).
#[derive(Debug, Deserialize)]
pub(super) struct RpcReqPayload {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub headers: HashMap<String, Vec<String>>,
    /// Base64-encoded (`STANDARD` engine — matches Go's `encoding/json`
    /// `[]byte` convention, not URL-safe) request body. `None` when the
    /// original request had no body (Go's `omitempty` drops a nil/empty
    /// slice entirely rather than emitting an empty string).
    #[serde(default)]
    pub body: Option<String>,
}

/// `rpc.resp` payload — mirrors api-platform's `internal/dispatch/ws/frames.go`
/// `RPCRespPayload`. Sent back on the mpsc channel once the local module
/// answers the relayed request.
#[derive(Debug, Serialize)]
pub(super) struct RpcRespPayload {
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, Vec<String>>>,
    /// Base64-encoded (`STANDARD` engine) response body; `None` for an
    /// empty body, matching the request side's `omitempty` convention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// 0-based index of this part, and how many parts make up the reply.
    /// BOTH omitted on a whole reply, so every frame the CLI sent before
    /// chunking is byte-identical to what it sends now — and a dispatch that
    /// predates chunking keeps reading them as complete replies.
    #[serde(skip_serializing_if = "is_zero")]
    pub seq: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub total: usize,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
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
/// `.secret/ms-platform-token-<slug>` file so each spawned module authenticates
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

    /// A handle with no socket behind it, plus the `Notify` its
    /// [`shutdown`](Self::shutdown) fires.
    ///
    /// The supervisor's teardown-vs-reconnect race is pure bookkeeping —
    /// which handle ends up installed and which one gets closed — so its
    /// tests need a handle they can watch, not a live WebSocket. The
    /// `shutdown` field is private to this module, hence the constructor
    /// living here.
    #[cfg(test)]
    pub(super) fn detached(session_id: &str, service_token: &str) -> (Self, Arc<Notify>) {
        let shutdown = Arc::new(Notify::new());
        (
            TunnelHandle {
                session_id: session_id.to_string(),
                service_token: service_token.to_string(),
                shutdown: shutdown.clone(),
            },
            shutdown,
        )
    }
}

/// Why the background tunnel loop stopped.
///
/// `Shutdown` is the operator tearing the dev session down — expected, and the
/// supervisor exits silently on it. `Lost` is EVERY other terminal condition
/// (server close frame, read error, stream end, ping-send failure, half-open
/// socket) and carries the reason so the supervisor can log one scoped line
/// and reconnect. Before this existed each of those paths just `return`ed from
/// a detached task nobody observed, which is what left the CLI process alive
/// and healthy-looking while dispatch 503'd every call to the module.
#[derive(Debug)]
pub(super) enum TunnelExit {
    Shutdown,
    Lost(String),
}

/// A live tunnel: the [`TunnelHandle`] callers keep for identity/shutdown,
/// plus the one-shot the background loop signals when it stops.
///
/// The receiver is split OUT of the handle rather than stored in it because
/// awaiting it consumes it: the per-module supervisor owns the receiver while
/// `run_outer` keeps the handle for teardown.
pub(super) struct TunnelSession {
    pub handle: TunnelHandle,
    pub exit: oneshot::Receiver<TunnelExit>,
}

/// Connect to `wss_url?token=ttok`, send `register`, await `register_ack`,
/// then hand the connection off to a background task that pings every
/// [`PING_INTERVAL`] and replies to inbound pings. Returns when the handshake
/// completes; the connection itself lives until [`TunnelHandle::shutdown`] is
/// called or the loop signals [`TunnelSession::exit`].
pub(super) async fn open(
    wss_url: &str,
    ttok: &str,
    register: RegisterPayload<'_>,
) -> RegisterResult<TunnelSession> {
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
    // Async client for the heartbeat's local manifest fetch and every WSS
    // HTTP-relay call. Client-level timeout guards every GET so a wedged
    // module can't stall the ping loop.
    let http = relay_http_client().context("dev: build manifest-hash http client")?;
    // Built once per connection and shared via `Arc`: `local_url`,
    // `service_token`, and `internal_secret` are invariant for the whole
    // tunnel's lifetime, so every spawned relay task should bump a refcount
    // rather than re-allocating its own copy of these strings.
    let ctx = Arc::new(RelayCtx {
        local_url: register.local_url.to_string(),
        service_token: ack.service_token.clone(),
        internal_secret: register.internal_secret.map(str::to_string),
    });
    let (exit_tx, exit_rx) = oneshot::channel();
    tokio::spawn(run_tunnel_loop(
        sink,
        stream,
        shutdown.clone(),
        http,
        ctx,
        exit_tx,
    ));

    Ok(TunnelSession {
        handle: TunnelHandle {
            session_id: ack.session_id,
            service_token: ack.service_token,
            shutdown,
        },
        exit: exit_rx,
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

/// Connection-invariant values every relayed request needs: the local
/// module's base URL and the CLI-minted auth its Internal scope requires.
/// Built once per tunnel connection ([`open`]) and shared via `Arc` so each
/// spawned relay task ([`spawn_rpc_relay_if_req`]) clones a cheap refcount
/// instead of re-allocating these strings on every inbound `rpc.req`.
struct RelayCtx {
    local_url: String,
    service_token: String,
    internal_secret: Option<String>,
}

/// A relay reply queued for the sink, paired with the `corr_id` of the
/// `rpc.req` it answers. Carrying the id alongside the already-serialized
/// frame lets [`run_tunnel_loop`] name *which* request it dropped if the
/// sink send fails, without re-parsing the frame body on the hot path.
struct RelayReply {
    corr_id: String,
    msg: Message,
}

/// Drive the tunnel until it ends, then report WHY on `exit_tx`.
///
/// The reason is a value rather than an `eprintln!` because the loop has no
/// idea which module it belongs to — the per-module supervisor that owns the
/// receiver does, and it prints one scoped line and reconnects. A dropped
/// sender (task panic, runtime teardown) surfaces to the receiver as a
/// `RecvError`, which the supervisor treats identically to `Lost`.
async fn run_tunnel_loop(
    sink: WsSink,
    stream: WsReader,
    shutdown: Arc<Notify>,
    http: reqwest::Client,
    ctx: Arc<RelayCtx>,
    exit_tx: oneshot::Sender<TunnelExit>,
) {
    let exit = tunnel_loop(sink, stream, shutdown, http, ctx).await;
    let _ = exit_tx.send(exit);
}

/// Long-running tunnel loop: ping every [`PING_INTERVAL`], respond to server
/// pings, relay `rpc.req`, and stop on shutdown or any transport failure.
/// Returns the [`TunnelExit`] describing which of those happened; the caller
/// forwards it to the supervisor, which is what turns a dead socket into a
/// reconnect instead of a silently idle process.
async fn tunnel_loop(
    mut sink: WsSink,
    mut stream: WsReader,
    shutdown: Arc<Notify>,
    http: reqwest::Client,
    ctx: Arc<RelayCtx>,
) -> TunnelExit {
    let mut interval = tokio::time::interval(PING_INTERVAL);
    // The first tick fires immediately — consume it so the first ping is at
    // t=30s, not t=0. Delay the missed-tick behavior so a paused runtime
    // (e.g. laptop sleep) doesn't burst-ping on resume.
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval.tick().await;
    // Half-open-socket watchdog. `pong_seen` arms it (a server that never
    // answers a ping must never be able to trip it), `silent_beats` counts
    // consecutive heartbeats that saw no inbound frame of any kind — a busy
    // tunnel proves itself alive through `rpc.req` traffic just as well as
    // through pongs.
    let mut pong_seen = false;
    let mut inbound_since_ping = false;
    let mut silent_beats: u32 = 0;
    // Relay replies (`rpc.resp`/`rpc.err`) funnel back through this channel
    // rather than being sent directly from the spawned relay task: a
    // `SplitSink` can't be shared/sent across concurrent tasks, and `sink`
    // is already owned by this loop for pings/pongs/close.
    let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                let close = Frame::new(FrameType::Close, None);
                if let Ok(body) = serde_json::to_string(&close) {
                    let _ = sink.send(Message::Text(body)).await;
                }
                let _ = sink.close().await;
                return TunnelExit::Shutdown;
            }
            _ = interval.tick() => {
                // Watchdog first: a beat that follows a completely silent
                // interval (no pong, no relayed request) is evidence the
                // socket is half-open. Only counted once the server has
                // proven it answers pings at all.
                if pong_seen {
                    if inbound_since_ping {
                        silent_beats = 0;
                    } else {
                        silent_beats += 1;
                        if silent_beats >= MAX_SILENT_BEATS {
                            return TunnelExit::Lost(format!(
                                "no response to {silent_beats} consecutive heartbeats — socket is half-open"
                            ));
                        }
                    }
                }
                inbound_since_ping = false;
                // Read the module's current manifest hash off its local
                // endpoint, timeout-guarded so a wedged module can never stall
                // the beat. A successful read sends the SDK's hash verbatim; any
                // error/timeout sends a payload-less ping so the tunnel keeps
                // beating. Re-sending an unchanged hash is a no-op on the
                // platform, so fetching every beat is cheap and safe.
                let hash = fetch_manifest_hash(
                    &http,
                    &ctx.local_url,
                    &ctx.service_token,
                    ctx.internal_secret.as_deref(),
                )
                .await;
                let ping = Frame::new(FrameType::Ping, ping_payload(hash.as_deref()));
                if let Ok(body) = serde_json::to_string(&ping) {
                    if let Err(e) = sink.send(Message::Text(body)).await {
                        return TunnelExit::Lost(format!("heartbeat ping send failed: {e}"));
                    }
                }
            }
            Some(reply) = rx.recv() => {
                // A single relay-reply send failure must NOT tear down the
                // tunnel. API Gateway severs the WSS connection when one
                // `PostToConnection` frame overflows its ~128 KB ceiling, so
                // this send can return `Broken pipe` for one oversized reply.
                // Returning here would kill the socket owner, the heartbeat,
                // and the reader — flapping the module to 503 for *every*
                // request over a single bad frame. Instead: log the dropped
                // reply (scoped to its corr_id), drop it, and keep serving.
                // Dispatch already degrades one missing reply gracefully
                // (its BLPOP times out → 502 for that request only).
                //
                // We deliberately do NOT try to tell "socket dead" from "one
                // frame too big" here: tungstenite surfaces both as a plain
                // per-send error, and a fragile consecutive-failure counter
                // would only approximate what two liveness paths already
                // detect authoritatively. A genuinely dead socket is torn
                // down by whichever fires first — the `stream.next()` arm
                // (Close/Err/None below) or the 30s heartbeat ping (whose
                // send failure still returns). Both trip within one ping
                // interval, so a wedged socket cannot spin here forever.
                if let Err(e) = sink.send(reply.msg).await {
                    eprintln!(
                        "{} tunnel: relay reply send failed for {} ({e}); dropping this reply, keeping tunnel open",
                        warn_prefix(),
                        reply.corr_id
                    );
                }
            }
            msg = stream.next() => {
                // ANY inbound frame proves the socket still reaches the
                // server, which is exactly what the watchdog above wants to
                // know — set this before matching on the variant.
                if matches!(msg, Some(Ok(_))) {
                    inbound_since_ping = true;
                }
                match msg {
                    // Text and Binary both just carry a JSON frame — extract
                    // the string once (borrowed where possible; only Binary's
                    // lossy UTF-8 conversion may allocate) and relay through
                    // one call, rather than duplicating the relay call per
                    // variant. `t.to_string()` would force-copy the whole
                    // frame before we even know it's an `rpc.req` worth
                    // acting on, so borrow via `as_str()` instead.
                    Some(Ok(m @ (Message::Text(_) | Message::Binary(_)))) => {
                        let text: Cow<'_, str> = match &m {
                            Message::Text(t) => Cow::Borrowed(t.as_str()),
                            Message::Binary(b) => String::from_utf8_lossy(b),
                            _ => unreachable!(),
                        };
                        // The server answers our JSON heartbeat with a JSON
                        // `pong` frame (dispatch's handlePing), so the pong
                        // arrives here as Text — not as a protocol-level
                        // Message::Pong. Seeing one is what arms the
                        // half-open watchdog.
                        if spawn_rpc_relay_if_req(&text, &tx, &http, &ctx) == Some(FrameType::Pong) {
                            pong_seen = true;
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        let _ = sink.send(Message::Pong(p)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(reason))) => {
                        return TunnelExit::Lost(format!("closed by server: {reason:?}"));
                    }
                    Some(Err(e)) => {
                        return TunnelExit::Lost(format!("read failed: {e}"));
                    }
                    None => {
                        return TunnelExit::Lost("stream ended".to_string());
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

/// Parse one inbound WSS text/binary payload as a [`Frame`] and, if it's an
/// `rpc.req`, spawn a child task to relay it to the local module and reply
/// on `tx`. Spawned per-request rather than awaited inline: `select!` fully
/// drives one ready arm before re-polling, so an inline call here would
/// block the 30s heartbeat and serialize concurrent asset/API requests
/// behind it. Any other frame type (register/register_ack only ever arrive
/// during the handshake; the SQL plane is still deferred) is ignored.
///
/// Returns the parsed frame type (`None` when the frame is malformed) so the
/// caller can observe liveness — specifically the `pong` answering our
/// heartbeat — without paying for a second parse of the same bytes.
fn spawn_rpc_relay_if_req(
    text: &str,
    tx: &mpsc::UnboundedSender<RelayReply>,
    http: &reqwest::Client,
    ctx: &Arc<RelayCtx>,
) -> Option<FrameType> {
    let frame: Frame = match serde_json::from_str(text) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "{} tunnel: malformed inbound frame ({e}); ignoring",
                warn_prefix()
            );
            return None;
        }
    };
    if frame.frame_type != FrameType::RpcReq {
        // register/register_ack only ever arrive pre-handshake; sql.* is
        // still deferred to Phase 3; close isn't sent as Text/Binary. `pong`
        // IS — it's the JSON answer to our JSON heartbeat — and the caller
        // uses it as the liveness signal, so report the type either way.
        return Some(frame.frame_type);
    }
    let Some(payload) = frame.payload else {
        eprintln!(
            "{} tunnel: rpc.req missing payload; ignoring",
            warn_prefix()
        );
        return Some(FrameType::RpcReq);
    };
    let req: RpcReqPayload = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{} tunnel: rpc.req malformed payload ({e}); ignoring",
                warn_prefix()
            );
            return Some(FrameType::RpcReq);
        }
    };
    tokio::spawn(relay_rpc_req(
        tx.clone(),
        http.clone(),
        ctx.clone(),
        frame.id,
        req,
    ));
    Some(FrameType::RpcReq)
}

/// Relay one `rpc.req` to the local module and send `rpc.resp`/`rpc.err`
/// (correlated on `corr_id`, the original frame's `id`) back on `tx`.
async fn relay_rpc_req(
    tx: mpsc::UnboundedSender<RelayReply>,
    http: reqwest::Client,
    ctx: Arc<RelayCtx>,
    corr_id: String,
    req: RpcReqPayload,
) {
    let payloads = match relay_rpc_req_inner(
        &http,
        &ctx.local_url,
        &ctx.service_token,
        ctx.internal_secret.as_deref(),
        &req,
    )
    .await
    {
        Ok(resp) => split_rpc_resp(resp)
            .into_iter()
            .map(|part| Frame::new(FrameType::RpcResp, serde_json::to_value(&part).ok()))
            .collect::<Vec<_>>(),
        Err(err) => vec![Frame::new(
            FrameType::RpcErr,
            serde_json::to_value(&err).ok(),
        )],
    };
    for mut frame in payloads {
        frame.corr_id = Some(corr_id.clone());
        send_relay_frame(&tx, &corr_id, frame);
    }
}

/// Send one already-addressed frame on the reply channel.
fn send_relay_frame(tx: &mpsc::UnboundedSender<RelayReply>, corr_id: &str, frame: Frame) {
    if let Ok(body) = serde_json::to_string(&frame) {
        // The receiving end (`rx.recv()` in `run_tunnel_loop`) only goes
        // away when the loop itself is exiting/exited, so a send failure
        // here just means we lost the reply to a tunnel that's already
        // shutting down — nothing left to report it to. The `corr_id` rides
        // along so the loop can name this request if the sink send fails.
        let _ = tx.send(RelayReply {
            corr_id: corr_id.to_string(),
            msg: Message::Text(body),
        });
    }
}

/// Split one reply into as many frames as the outbound ceiling requires.
///
/// A reply that already fits comes back as a single part with `seq`/`total`
/// left at zero, so the frame is byte-identical to what the CLI sent before
/// chunking existed — that is what keeps this safe against a dispatch that has
/// not deployed reassembly yet.
///
/// Status and headers ride on part 0 ONLY. Repeating them on every part would
/// cost a copy of the header block per frame, and dispatch reads them from the
/// first part regardless.
fn split_rpc_resp(resp: RpcRespPayload) -> Vec<RpcRespPayload> {
    let raw = match resp.body.as_deref().map(|b| STANDARD.decode(b)) {
        Some(Ok(bytes)) => bytes,
        // An un-decodable body is not something to split. Pass it through and
        // let the existing path report it.
        _ => return vec![resp],
    };
    if raw.len() <= CHUNK_BODY_BYTES {
        return vec![resp];
    }
    let slices: Vec<&[u8]> = raw.chunks(CHUNK_BODY_BYTES).collect();
    let total = slices.len();
    slices
        .into_iter()
        .enumerate()
        .map(|(seq, slice)| RpcRespPayload {
            status: if seq == 0 { resp.status } else { 0 },
            headers: if seq == 0 { resp.headers.clone() } else { None },
            body: (!slice.is_empty()).then(|| STANDARD.encode(slice)),
            seq,
            total,
        })
        .collect()
}

/// HTTP client for the tunnel's local calls (heartbeat manifest GET +
/// relayed `rpc.req`). Redirects are NEVER followed: a module's 3xx (e.g.
/// oauth-core's `/public/start` → accounts.google.com) must be relayed
/// verbatim so the BROWSER chases the Location — following it here relays
/// the redirect target's response instead, which breaks the flow outright
/// and (with Google's multi-KB headers) blows API Gateway's response
/// limits into a bare 502. Dispatch's direct-dial client pins the same
/// semantics with Go's `http.ErrUseLastResponse`.
fn relay_http_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(MANIFEST_FETCH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Attach the CLI-minted `X-MS-Platform-Token`/`X-MS-Internal-Secret`
/// headers a module's Internal scope requires. Shared by
/// [`fetch_manifest_hash`] (heartbeat GET) and [`relay_rpc_req_inner`]
/// (relayed request) — both need the identical conditional-header logic:
/// the token header is only sent when non-empty (pre-register-ack calls
/// have none yet), the secret header only when the module was started
/// with one.
fn attach_internal_auth(
    mut builder: reqwest::RequestBuilder,
    service_token: &str,
    internal_secret: Option<&str>,
) -> reqwest::RequestBuilder {
    if !service_token.is_empty() {
        builder = builder.header("X-MS-Platform-Token", service_token);
    }
    if let Some(secret) = internal_secret {
        builder = builder.header("X-MS-Internal-Secret", secret);
    }
    builder
}

/// Perform the actual local HTTP call for [`relay_rpc_req`]. Split out so
/// the happy/error paths can be expressed with `?` and converted to a
/// single `Frame` by the caller.
async fn relay_rpc_req_inner(
    http: &reqwest::Client,
    local_url: &str,
    service_token: &str,
    internal_secret: Option<&str>,
    req: &RpcReqPayload,
) -> std::result::Result<RpcRespPayload, ErrorPayload> {
    let body_bytes: Vec<u8> = match &req.body {
        Some(b64) => STANDARD.decode(b64).map_err(|e| ErrorPayload {
            code: "local_module_unreachable".to_string(),
            message: format!("dev: decode relay request body: {e}"),
            slug: None,
        })?,
        None => Vec::new(),
    };

    let method = req
        .method
        .parse::<reqwest::Method>()
        .map_err(|e| ErrorPayload {
            code: "local_module_unreachable".to_string(),
            message: format!("dev: invalid relay method {:?}: {e}", req.method),
            slug: None,
        })?;

    // Only append `?query` when a query string is actually present — an
    // unconditional trailing `?` changes the request target (some servers,
    // and notably mockito's matcher in tests, don't treat `/big?` as
    // equivalent to `/big`).
    let url = if req.query.is_empty() {
        format!("{local_url}{path}", path = req.path)
    } else {
        format!(
            "{local_url}{path}?{query}",
            path = req.path,
            query = req.query
        )
    };
    let mut builder = http.request(method, url).timeout(RELAY_REQUEST_TIMEOUT);
    for (name, values) in &req.headers {
        // Defense in depth: dispatch is expected to strip these off the
        // original inbound request before building the relay payload (see
        // the precedent in `fetch_manifest_hash`), but `RequestBuilder::header`
        // *appends* rather than replaces, so trusting that unconditionally
        // would let a forwarded value for either header land ahead of the
        // CLI-minted one below — first-value-wins header readers (e.g. Go's
        // `http.Header.Get`) would then pick the spoofed value over the
        // authoritative one. Drop any wire-supplied value for these two
        // names regardless of what dispatch is supposed to have done.
        if name.eq_ignore_ascii_case("x-ms-platform-token")
            || name.eq_ignore_ascii_case("x-ms-internal-secret")
        {
            continue;
        }
        for value in values {
            builder = builder.header(name.as_str(), value.as_str());
        }
    }
    // Same precedent as `fetch_manifest_hash`: the module's Internal scope
    // enforces these on every call, dispatch strips them off the original
    // inbound request before building the relay payload, so the CLI is the
    // one place that (re)attaches them.
    builder = attach_internal_auth(builder, service_token, internal_secret);
    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }

    let resp = builder.send().await.map_err(|e| ErrorPayload {
        code: "local_module_unreachable".to_string(),
        message: format!("dev: local module unreachable: {e}"),
        slug: None,
    })?;

    let status = resp.status().as_u16();
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            headers
                .entry(name.as_str().to_string())
                .or_default()
                .push(v.to_string());
        }
    }

    let body = resp.bytes().await.map_err(|e| ErrorPayload {
        code: "local_module_malformed_response".to_string(),
        message: format!("dev: read local module response body: {e}"),
        slug: None,
    })?;

    // A memory guard, NOT a transport check: the body is split across frames
    // below, so its size no longer has to fit anything. What it does bound is
    // how much this process will hold and base64 in one go. Compare against
    // MAX_RELAY_BODY_BYTES, which is deliberately no longer derived from the
    // frame size.
    if body.len() > MAX_RELAY_BODY_BYTES {
        return Err(ErrorPayload {
            code: "local_body_too_large".to_string(),
            message: format!(
                "dev: local module response body ({} bytes) exceeds the {} byte relay cap",
                body.len(),
                MAX_RELAY_BODY_BYTES
            ),
            slug: None,
        });
    }

    Ok(RpcRespPayload {
        status,
        headers: (!headers.is_empty()).then_some(headers),
        body: (!body.is_empty()).then(|| STANDARD.encode(&body)),
        // Whole reply. split_rpc_resp decides whether it stays one.
        seq: 0,
        total: 0,
    })
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
/// One-shot [`fetch_manifest_hash`] for a RE-register, with its own client.
///
/// The FIRST register carries `manifest_hash: None` because `open_tunnels`
/// runs before `docker compose up` — there is no module to ask yet. A
/// reconnect is the opposite: the module has been serving for however long the
/// dev session has run, so the re-register can carry its real hash instead of
/// leaving the platform to rediscover it.
///
/// `service_token` is the PREVIOUS session's token. That is deliberate and
/// correct: the module authenticates this call against its
/// `MS_PLATFORM_TOKEN_FILE`, which still holds the old value because the
/// supervisor only rewrites that file AFTER a successful re-register. A
/// failure here is a `None` hash, never a failed reconnect.
pub(super) async fn current_manifest_hash(
    local_url: &str,
    service_token: &str,
    internal_secret: Option<&str>,
) -> Option<String> {
    let client = relay_http_client().ok()?;
    fetch_manifest_hash(&client, local_url, service_token, internal_secret).await
}

async fn fetch_manifest_hash(
    client: &reqwest::Client,
    local_url: &str,
    service_token: &str,
    internal_secret: Option<&str>,
) -> Option<String> {
    let req = attach_internal_auth(
        client.get(format!("{local_url}{MODULE_MANIFEST_PATH}")),
        service_token,
        internal_secret,
    );
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

    /// Pull the next message off `rx`, assert it's `Message::Text`, and
    /// parse it as a [`Frame`]. Shared by the `relay_rpc_req_*` tests below
    /// — each previously duplicated this same unwrap-then-parse block.
    async fn recv_frame(rx: &mut mpsc::UnboundedReceiver<RelayReply>) -> Frame {
        let reply = rx.recv().await.expect("expected a relay reply");
        let Message::Text(text) = reply.msg else {
            panic!("expected a text message")
        };
        serde_json::from_str(&text).unwrap()
    }

    /// Build a [`RelayCtx`] for tests — a thin `Arc::new` wrapper so call
    /// sites read the same as the pre-refactor plain-argument calls.
    fn test_ctx(
        local_url: impl Into<String>,
        service_token: impl Into<String>,
        internal_secret: Option<&str>,
    ) -> Arc<RelayCtx> {
        Arc::new(RelayCtx {
            local_url: local_url.into(),
            service_token: service_token.into(),
            internal_secret: internal_secret.map(str::to_string),
        })
    }

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

    #[test]
    fn rpc_req_payload_deserializes_go_json_marshal_fixture() {
        // Shaped like Go's `json.Marshal(RPCReqPayload{...})` output.
        let fixture = r#"{"method":"POST","path":"/api/widgets","query":"limit=10","headers":{"Content-Type":["application/json"]},"body":"aGVsbG8="}"#;
        let payload: RpcReqPayload = serde_json::from_str(fixture).unwrap();
        assert_eq!(payload.method, "POST");
        assert_eq!(payload.path, "/api/widgets");
        assert_eq!(payload.query, "limit=10");
        assert_eq!(
            payload.headers.get("Content-Type").unwrap(),
            &vec!["application/json".to_string()]
        );
        let decoded = STANDARD.decode(payload.body.unwrap()).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn rpc_req_payload_body_uses_standard_base64_not_url_safe() {
        // 0xFF 0xFF 0xFF encodes to "////" under STANDARD but "____" under
        // URL_SAFE — pins the engine so a future drift to url-safe breaks
        // loudly instead of silently mis-decoding relayed request bodies.
        let fixture = r#"{"method":"POST","path":"/x","body":"////"}"#;
        let payload: RpcReqPayload = serde_json::from_str(fixture).unwrap();
        let decoded = STANDARD.decode(payload.body.unwrap()).unwrap();
        assert_eq!(decoded, vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn rpc_req_payload_omitted_fields_default_empty() {
        let payload: RpcReqPayload =
            serde_json::from_str(r#"{"method":"GET","path":"/"}"#).unwrap();
        assert_eq!(payload.query, "");
        assert!(payload.headers.is_empty());
        assert!(payload.body.is_none());
    }

    #[test]
    fn rpc_resp_payload_omits_absent_fields() {
        let payload = RpcRespPayload {
            status: 204,
            headers: None,
            body: None,
            seq: 0,
            total: 0,
        };
        let s = serde_json::to_string(&payload).unwrap();
        assert_eq!(s, r#"{"status":204}"#);
    }

    #[test]
    fn rpc_resp_payload_encodes_body_as_standard_base64() {
        let payload = RpcRespPayload {
            status: 200,
            headers: Some(HashMap::from([(
                "Content-Type".to_string(),
                vec!["text/plain".to_string()],
            )])),
            body: Some(STANDARD.encode(b"hello")),
            seq: 0,
            total: 0,
        };
        let s = serde_json::to_string(&payload).unwrap();
        assert!(s.contains(r#""status":200"#));
        assert!(s.contains(r#""body":"aGVsbG8=""#));
    }

    #[tokio::test]
    async fn relay_rpc_req_success_round_trips_through_channel() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/hello?x=1")
            .match_header("x-ms-platform-token", "ptok")
            .match_header("x-ms-internal-secret", "sec")
            .match_header("x-custom", "abc")
            .with_status(201)
            .with_header("content-type", "text/plain")
            .with_body("hi there")
            .create_async()
            .await;

        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/hello".to_string(),
            query: "x=1".to_string(),
            headers: HashMap::from([("X-Custom".to_string(), vec!["abc".to_string()])]),
            body: None,
        };
        relay_rpc_req(
            tx,
            reqwest::Client::new(),
            test_ctx(server.url(), "ptok", Some("sec")),
            "frm_corr".to_string(),
            req,
        )
        .await;

        let frame = recv_frame(&mut rx).await;
        assert_eq!(frame.frame_type, FrameType::RpcResp);
        assert_eq!(frame.corr_id.as_deref(), Some("frm_corr"));
        let payload = frame.payload.unwrap();
        assert_eq!(payload["status"], 201);
        let body_b64 = payload["body"].as_str().unwrap();
        assert_eq!(STANDARD.decode(body_b64).unwrap(), b"hi there");
        m.assert_async().await;
    }

    #[tokio::test]
    async fn relay_rpc_req_relays_redirect_verbatim() {
        // A module 3xx (oauth-core /public/start → accounts.google.com) must
        // reach dispatch as-is so the BROWSER follows the Location. reqwest's
        // default policy chases it and relays the redirect target's response
        // instead — the bug this pins. Uses the production client
        // (relay_http_client, Policy::none()), not Client::new().
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("GET", "/public/start")
            .with_status(302)
            .with_header(
                "location",
                "https://accounts.google.com/o/oauth2/v2/auth?state=x",
            )
            .with_header("set-cookie", "ms_oauth_state=abc; Path=/; HttpOnly")
            .create_async()
            .await;

        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/public/start".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: None,
        };
        relay_rpc_req(
            tx,
            relay_http_client().unwrap(),
            test_ctx(server.url(), "ptok", Some("sec")),
            "frm_redirect".to_string(),
            req,
        )
        .await;

        let frame = recv_frame(&mut rx).await;
        assert_eq!(frame.frame_type, FrameType::RpcResp);
        assert_eq!(frame.corr_id.as_deref(), Some("frm_redirect"));
        let payload = frame.payload.unwrap();
        assert_eq!(payload["status"], 302);
        assert_eq!(
            payload["headers"]["location"][0],
            "https://accounts.google.com/o/oauth2/v2/auth?state=x"
        );
        assert_eq!(
            payload["headers"]["set-cookie"][0],
            "ms_oauth_state=abc; Path=/; HttpOnly"
        );
        m.assert_async().await;
    }

    #[tokio::test]
    async fn relay_rpc_req_unreachable_module_sends_rpc_err() {
        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/x".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: None,
        };
        // Nothing listening on this port → connect refused.
        relay_rpc_req(
            tx,
            reqwest::Client::new(),
            test_ctx("http://127.0.0.1:1", "", None),
            "frm_corr2".to_string(),
            req,
        )
        .await;

        let frame = recv_frame(&mut rx).await;
        assert_eq!(frame.frame_type, FrameType::RpcErr);
        assert_eq!(frame.corr_id.as_deref(), Some("frm_corr2"));
        assert_eq!(frame.payload.unwrap()["code"], "local_module_unreachable");
    }

    #[tokio::test]
    async fn relay_reply_carries_corr_id_for_scoped_drop_logging() {
        // The queued reply carries the originating `corr_id` alongside the
        // serialized frame so `run_tunnel_loop` can name *which* request it
        // dropped when a sink send fails — without re-parsing the frame on
        // the hot path. Guards against the id being silently dropped from the
        // channel item, which would unscope the "keeping tunnel open" warning
        // that replaces the old whole-tunnel teardown.
        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/x".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: None,
        };
        // Unreachable module → rpc.err, but the reply is still enqueued with
        // its corr_id (the drop path we guard is transport, not the module).
        relay_rpc_req(
            tx,
            reqwest::Client::new(),
            test_ctx("http://127.0.0.1:1", "", None),
            "frm_scope".to_string(),
            req,
        )
        .await;

        let reply = rx.recv().await.expect("expected a relay reply");
        assert_eq!(reply.corr_id, "frm_scope");
        // The wrapper's corr_id mirrors the frame's, so logging either names
        // the same request.
        let Message::Text(text) = reply.msg else {
            panic!("expected a text message")
        };
        let frame: Frame = serde_json::from_str(&text).unwrap();
        assert_eq!(frame.corr_id.as_deref(), Some("frm_scope"));
    }

    #[tokio::test]
    async fn relay_rpc_req_oversized_response_is_rejected() {
        let mut server = mockito::Server::new_async().await;
        // One byte over MAX_RELAY_BODY_BYTES (the raw-body cap), not
        // MAX_INBOUND_FRAME_BYTES (the transport cap) — regression guard
        // for the base64+JSON-envelope inflation the raw-body cap accounts
        // for. A body sized to the *transport* cap would base64-inflate to
        // well past it and should already be rejected here.
        let big_body = vec![b'a'; MAX_RELAY_BODY_BYTES + 1];
        let _m = server
            .mock("GET", "/big")
            .with_status(200)
            .with_body(big_body)
            .create_async()
            .await;

        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/big".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: None,
        };
        relay_rpc_req(
            tx,
            reqwest::Client::new(),
            test_ctx(server.url(), "", None),
            "frm_corr3".to_string(),
            req,
        )
        .await;

        let frame = recv_frame(&mut rx).await;
        assert_eq!(frame.frame_type, FrameType::RpcErr);
        assert_eq!(frame.payload.unwrap()["code"], "local_body_too_large");
    }

    #[tokio::test]
    async fn relay_rpc_req_accepted_body_fits_transport_cap_once_encoded() {
        // Regression guard for the base64/JSON-envelope inflation bug: a
        // body right at the raw-body cap must still produce an encoded
        // `rpc.resp` frame that fits under MAX_INBOUND_FRAME_BYTES, the
        // actual WSS transport ceiling.
        let mut server = mockito::Server::new_async().await;
        let body = vec![b'a'; MAX_RELAY_BODY_BYTES];
        let _m = server
            .mock("GET", "/big-ok")
            .with_status(200)
            .with_body(body)
            .create_async()
            .await;

        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/big-ok".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body: None,
        };
        relay_rpc_req(
            tx,
            reqwest::Client::new(),
            test_ctx(server.url(), "", None),
            "frm_corr3b".to_string(),
            req,
        )
        .await;

        let frame = recv_frame(&mut rx).await;
        // Re-encode the parsed frame to check its size: JSON key order may
        // differ from the bytes actually sent over the channel (serde_json
        // parses objects into a sorted map), but the byte *count* is
        // unaffected by key order, so this still pins the same transport-cap
        // regression guard.
        let encoded_len = serde_json::to_string(&frame).unwrap().len();
        assert!(
            encoded_len <= MAX_INBOUND_FRAME_BYTES,
            "encoded rpc.resp frame ({encoded_len} bytes) exceeds the transport cap ({MAX_INBOUND_FRAME_BYTES} bytes)"
        );
        assert_eq!(frame.frame_type, FrameType::RpcResp);
    }

    #[tokio::test]
    async fn relay_rpc_req_strips_wire_supplied_auth_headers_before_forwarding() {
        // Regression guard for the header-smuggling finding: if `req.headers`
        // (server-relayed) already carries X-MS-Platform-Token/
        // X-MS-Internal-Secret — e.g. a buggy/compromised dispatch that
        // failed to strip them — the CLI must not forward the wire-supplied
        // value. Only the CLI-minted value (passed in as `service_token`/
        // `internal_secret`) should reach the local module.
        let mut server = mockito::Server::new_async().await;
        let _m = server
            .mock("GET", "/secure")
            .match_header("x-ms-platform-token", "cli-minted-token")
            .match_header("x-ms-internal-secret", "cli-minted-secret")
            .with_status(200)
            .create_async()
            .await;

        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let mut headers = HashMap::new();
        headers.insert(
            "X-MS-Platform-Token".to_string(),
            vec!["spoofed-token".to_string()],
        );
        headers.insert(
            "X-MS-Internal-Secret".to_string(),
            vec!["spoofed-secret".to_string()],
        );
        let req = RpcReqPayload {
            method: "GET".to_string(),
            path: "/secure".to_string(),
            query: String::new(),
            headers,
            body: None,
        };
        relay_rpc_req(
            tx,
            reqwest::Client::new(),
            test_ctx(server.url(), "cli-minted-token", Some("cli-minted-secret")),
            "frm_corr_auth".to_string(),
            req,
        )
        .await;

        let frame = recv_frame(&mut rx).await;
        // mockito's match_header on both names, with only one value each,
        // asserts the request had exactly the CLI-minted value — if the
        // spoofed value had also been forwarded (appended), the request
        // would carry two values per header and mockito's exact-match
        // would fail the mock, producing a `local_module_unreachable`
        // rpc.err below instead of a clean rpc.resp.
        assert_eq!(frame.frame_type, FrameType::RpcResp);
    }

    #[test]
    fn spawn_rpc_relay_if_req_ignores_non_rpc_req_frames() {
        // Regression guard: a ping/pong/close text frame (or any frame type
        // other than rpc.req) must not panic or attempt a relay.
        let (tx, mut rx) = mpsc::unbounded_channel::<RelayReply>();
        let http = reqwest::Client::new();
        let ping = Frame::new(FrameType::Ping, None);
        let text = serde_json::to_string(&ping).unwrap();
        let ctx = test_ctx("http://127.0.0.1:1", "", None);
        assert_eq!(
            spawn_rpc_relay_if_req(&text, &tx, &http, &ctx),
            Some(FrameType::Ping)
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn inbound_pong_is_reported_so_the_watchdog_can_arm() {
        // The half-open-socket watchdog is ARMED by seeing a pong, and the
        // server answers our JSON heartbeat with a JSON `pong` Text frame —
        // not a protocol-level Pong. If this ever stops being reported the
        // watchdog silently never arms and a half-open socket goes back to
        // being invisible, which is the whole failure this work removes.
        let (tx, _rx) = mpsc::unbounded_channel::<RelayReply>();
        let http = reqwest::Client::new();
        let ctx = test_ctx("http://127.0.0.1:1", "", None);
        let pong = serde_json::to_string(&Frame::new(FrameType::Pong, None)).unwrap();
        assert_eq!(
            spawn_rpc_relay_if_req(&pong, &tx, &http, &ctx),
            Some(FrameType::Pong)
        );
        // A malformed frame proves nothing about liveness.
        assert_eq!(spawn_rpc_relay_if_req("{not json", &tx, &http, &ctx), None);
    }

    // ── End-to-end loop-exit tests ──────────────────────────────────
    //
    // These stand up a real local WebSocket server and drive `open` against
    // it, because the bug being fixed lives entirely in what the loop does
    // when the connection ends — the thing no unit-level seam could observe
    // while every terminal path was a bare `return` from a detached task.

    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    fn test_register() -> RegisterPayload<'static> {
        RegisterPayload {
            module_id: "m_abc",
            local_url: "http://127.0.0.1:1",
            version: "0.0.0-test",
            internal_secret: Some("sec"),
            manifest_hash: None,
        }
    }

    /// Accept one connection, complete the register handshake, and hand back
    /// the live server-side socket for the test to script.
    async fn accept_and_ack(
        listener: TcpListener,
    ) -> WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>> {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws =
            tokio_tungstenite::accept_async(tokio_tungstenite::MaybeTlsStream::Plain(stream))
                .await
                .unwrap();
        let Some(Ok(Message::Text(text))) = ws.next().await else {
            panic!("expected a register frame")
        };
        let register: Frame = serde_json::from_str(&text).unwrap();
        assert_eq!(register.frame_type, FrameType::Register);
        let mut ack = Frame::new(
            FrameType::RegisterAck,
            Some(serde_json::json!({
                "session_id": "sess_new",
                "service_token": "stk_new",
                "expires_at": "2026-08-06T00:00:00Z",
            })),
        );
        ack.corr_id = Some(register.id);
        ws.send(Message::Text(serde_json::to_string(&ack).unwrap()))
            .await
            .unwrap();
        ws
    }

    async fn wait_exit(session: TunnelSession) -> TunnelExit {
        tokio::time::timeout(Duration::from_secs(5), session.exit)
            .await
            .expect("the tunnel loop must report its exit, not hang")
            .expect("the exit sender must not be dropped without a reason")
    }

    #[tokio::test]
    async fn server_close_frame_surfaces_as_lost() {
        // THE observed outage: after an idle period the server sends WS 1001
        // "Going away". This used to print one warning and end a detached
        // task nobody watched, leaving the process alive while the platform
        // 503'd every routed call. It must now be reported as `Lost` so the
        // supervisor reconnects.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut ws = accept_and_ack(listener).await;
            ws.close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "Going away".into(),
            }))
            .await
            .unwrap();
        });

        let session = open(&format!("ws://{addr}/"), "ttok", test_register())
            .await
            .expect("handshake");
        assert_eq!(session.handle.session_id, "sess_new");
        assert_eq!(session.handle.service_token, "stk_new");

        match wait_exit(session).await {
            TunnelExit::Lost(reason) => {
                assert!(reason.contains("closed by server"), "got {reason:?}");
                // The reason has to name the close code, or the operator
                // still can't tell an idle reap from an auth rejection.
                assert!(reason.contains("Away"), "got {reason:?}");
            }
            other => panic!("expected Lost, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn abrupt_disconnect_surfaces_as_lost() {
        // A socket that simply goes away (no close handshake) is the silent
        // variant of the same failure and must be just as observable.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let ws = accept_and_ack(listener).await;
            drop(ws);
        });

        let session = open(&format!("ws://{addr}/"), "ttok", test_register())
            .await
            .expect("handshake");
        assert!(
            matches!(wait_exit(session).await, TunnelExit::Lost(_)),
            "a dropped connection must not look like a clean shutdown"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn operator_shutdown_surfaces_as_shutdown_not_lost() {
        // The other half of the contract: tearing the dev session down must
        // NOT be mistaken for a lost tunnel, or every Ctrl-C would kick off a
        // pointless reconnect storm on the way out.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut ws = accept_and_ack(listener).await;
            // Stay idle and readable until the client closes.
            while let Some(Ok(msg)) = ws.next().await {
                if msg.is_close() {
                    break;
                }
            }
        });

        let session = open(&format!("ws://{addr}/"), "ttok", test_register())
            .await
            .expect("handshake");
        session.handle.shutdown();
        assert!(
            matches!(wait_exit(session).await, TunnelExit::Shutdown),
            "operator shutdown must be distinguishable from a lost tunnel"
        );
        server.await.unwrap();
    }

    /// A reply that fits stays ONE frame with no chunk fields, so it serializes
    /// byte-identically to what the CLI sent before chunking — that is what
    /// makes this safe to run against a dispatch that has not deployed
    /// reassembly yet.
    #[test]
    fn small_reply_is_not_split_and_declares_no_chunking() {
        let payload = RpcRespPayload {
            status: 200,
            headers: None,
            body: Some(STANDARD.encode(b"hello")),
            seq: 0,
            total: 0,
        };
        let parts = split_rpc_resp(payload);
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].total, 0,
            "a whole reply must not claim a part count"
        );

        let json = serde_json::to_string(&parts[0]).unwrap();
        assert!(
            !json.contains("\"seq\"") && !json.contains("\"total\""),
            "chunk fields must be omitted on a whole reply: {json}"
        );
    }

    /// The bytes the module produced must survive the split exactly — every
    /// part decoded on its own and concatenated in seq order.
    #[test]
    fn large_reply_splits_and_reassembles_byte_for_byte() {
        let raw: Vec<u8> = (0..CHUNK_BODY_BYTES * 2 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        let parts = split_rpc_resp(RpcRespPayload {
            status: 200,
            headers: Some(HashMap::from([(
                "content-type".to_string(),
                vec!["application/pdf".to_string()],
            )])),
            body: Some(STANDARD.encode(&raw)),
            seq: 0,
            total: 0,
        });

        assert_eq!(parts.len(), 3, "two full parts and a remainder");
        for (index, part) in parts.iter().enumerate() {
            assert_eq!(part.seq, index);
            assert_eq!(part.total, 3);
        }

        // Status and headers ride on part 0 only — repeating the header block
        // on every frame would cost a copy of it per part.
        assert_eq!(parts[0].status, 200);
        assert!(parts[0].headers.is_some());
        assert!(parts[1].headers.is_none() && parts[2].headers.is_none());

        let mut rebuilt = Vec::new();
        for part in &parts {
            rebuilt.extend_from_slice(&STANDARD.decode(part.body.as_ref().unwrap()).unwrap());
        }
        assert_eq!(rebuilt, raw, "the body must survive the split unchanged");
    }

    /// Each part must fit the ceiling that closes the socket. This is the whole
    /// point of the change, so it is asserted on the ENCODED frame rather than
    /// on the raw slice.
    #[test]
    fn every_part_fits_the_outbound_frame() {
        let raw = vec![b'x'; CHUNK_BODY_BYTES * 4];
        let parts = split_rpc_resp(RpcRespPayload {
            status: 200,
            headers: Some(HashMap::from([(
                "content-type".to_string(),
                vec!["application/json".to_string()],
            )])),
            body: Some(STANDARD.encode(&raw)),
            seq: 0,
            total: 0,
        });
        for part in &parts {
            let mut frame = Frame::new(FrameType::RpcResp, serde_json::to_value(part).ok());
            frame.corr_id = Some("corr-abcdef0123456789".to_string());
            let encoded = serde_json::to_string(&frame).unwrap();
            assert!(
                encoded.len() <= MAX_OUTBOUND_FRAME_BYTES,
                "part {} encodes to {} bytes, over the {} ceiling that closes the connection",
                part.seq,
                encoded.len(),
                MAX_OUTBOUND_FRAME_BYTES
            );
        }
    }

    /// An empty body is a legal reply (204, HEAD) and must not become a part.
    #[test]
    fn empty_reply_is_left_alone() {
        let parts = split_rpc_resp(RpcRespPayload {
            status: 204,
            headers: None,
            body: None,
            seq: 0,
            total: 0,
        });
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].total, 0);
    }
}
