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
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::Message;
use uuid_lite::uuid_v4_string;

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

    pub(super) fn with_corr(mut self, corr_id: String) -> Self {
        self.corr_id = Some(corr_id);
        self
    }
}

#[derive(Debug, Serialize)]
pub(super) struct RegisterPayload<'a> {
    pub module_id: &'a str,
    pub local_url: &'a str,
    pub version: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct RegisterAck {
    pub session_id: String,
    pub service_token: String,
    pub expires_at: String,
}

/// Spawned-task handle. Drop or call [`shutdown`] to close the WSS.
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
) -> Result<TunnelHandle> {
    let url = if wss_url.contains('?') {
        format!("{wss_url}&token={ttok}")
    } else {
        format!("{wss_url}?token={ttok}")
    };
    let (ws_stream, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("dev: connect WSS {wss_url}"))?;
    let (mut sink, mut stream) = ws_stream.split();

    // Send register.
    let payload = serde_json::to_value(&register).context("dev: serialize register payload")?;
    let register_frame = Frame::new(FrameType::Register, Some(payload));
    let register_id = register_frame.id.clone();
    sink.send(Message::Text(serde_json::to_string(&register_frame)?))
        .await
        .context("dev: send register frame")?;

    // Await register_ack with a generous timeout.
    let ack = tokio::time::timeout(Duration::from_secs(10), async {
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
                    sink.send(Message::Pong(p)).await.ok();
                    continue;
                }
                Message::Close(_) => return Err(anyhow!("server closed before register_ack")),
                _ => continue,
            };
            let frame: Frame = serde_json::from_str(&text)
                .with_context(|| format!("dev: parse server frame: {text}"))?;
            if frame.frame_type == FrameType::RegisterAck
                && frame.corr_id.as_deref() == Some(&register_id)
            {
                let ack_payload = frame
                    .payload
                    .ok_or_else(|| anyhow!("register_ack missing payload"))?;
                let ack: RegisterAck =
                    serde_json::from_value(ack_payload).context("dev: deserialize register_ack")?;
                return Ok(ack);
            }
            // Ignore unrelated frames during handshake — server may send
            // ping or status frames before our ack arrives.
        }
    })
    .await
    .context("dev: register_ack timeout")?
    .context("dev: register_ack")?;

    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();

    // Background task: ping every 30s, respond to server pings, close on shutdown.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        // First tick fires immediately; we don't want a ping at t=0.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_clone.notified() => {
                    let close = Frame::new(FrameType::Close, None);
                    if let Ok(body) = serde_json::to_string(&close) {
                        let _ = sink.send(Message::Text(body)).await;
                    }
                    let _ = sink.close().await;
                    return;
                }
                _ = interval.tick() => {
                    let ping = Frame::new(FrameType::Ping, None);
                    if let Ok(body) = serde_json::to_string(&ping) {
                        if sink.send(Message::Text(body)).await.is_err() {
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
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                        Some(Ok(Message::Frame(_))) => {}
                    }
                }
            }
        }
    });

    Ok(TunnelHandle {
        session_id: ack.session_id,
        service_token: ack.service_token,
        shutdown,
    })
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
        };
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains("\"module_id\":\"m_abc\""));
        assert!(s.contains("\"local_url\":\"http://localhost:8080\""));
    }
}
