//! Dev log shipper: the in-container `dev --all` runner taps each module's
//! stdout/stderr (see `spawn_forwarder`) and POSTs batched lines to dispatch's
//! ingest endpoint, which buffers them into a per-module Redis ring that the
//! developer console's Logcat reads. Best-effort throughout — a failed or
//! unconfigured ship never blocks the module. Deployed modules use CloudWatch,
//! not this path.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use serde::Serialize;

const FLUSH_INTERVAL: Duration = Duration::from_millis(1000);
const MAX_BATCH: usize = 200;

/// One log line in the {ts,level,msg} shape the web Logcat renders, plus the
/// trusted app the line was emitted under (for the app-side console's per-app
/// filtering of a shared dev module's logs).
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct LogEntry {
    pub ts: String,
    pub level: String,
    pub msg: String,
    /// From the SDK's structured log (`app_id`); empty for non-JSON lines.
    /// Omitted from the wire when empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub app_id: String,
    /// Access-line detail from the SDK's `request` log (method/path/status/
    /// duration_ms). Absent on every other line and omitted from the wire; the
    /// names match dispatch's ring `Entry` JSON.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

#[derive(Serialize)]
struct Batch<'a> {
    entries: &'a [LogEntry],
}

/// The channel the forwarder pushes parsed lines into.
pub type LogSink = Sender<LogEntry>;

/// parse_line turns a raw output line into a LogEntry. The SDK emits structured
/// JSON (slog) — extract its level/msg/time/app_id; any other line (a third-party
/// print, a panic, the SDK's own stderr diagnostics) falls back to the stream:
/// stderr → warn, stdout → info, with the raw line as the message, stamped with
/// the time the shipper saw it (the Logcat sorts and renders by `ts`).
pub fn parse_line(raw: &str, is_stderr: bool) -> LogEntry {
    if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(raw)
        && obj.contains_key("level")
    {
        let level = obj
            .get("level")
            .and_then(|v| v.as_str())
            .map(normalize_level)
            .unwrap_or_else(|| default_level(is_stderr));
        let msg = obj
            .get("msg")
            .or_else(|| obj.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or(raw)
            .to_string();
        let ts = obj
            .get("time")
            .and_then(|v| v.as_str())
            .map(short_time)
            .unwrap_or_default();
        let app_id = obj
            .get("app_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let str_field = |k: &str| {
            obj.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        return LogEntry {
            // A JSON line without a parseable time is stamped like a plain one.
            ts: if ts.is_empty() { now_hms() } else { ts },
            level,
            msg,
            app_id,
            method: str_field("method"),
            path: str_field("path"),
            status: obj
                .get("status")
                .and_then(|v| v.as_u64())
                .and_then(|n| u16::try_from(n).ok()),
            duration_ms: obj.get("duration_ms").and_then(|v| v.as_u64()),
        };
    }
    LogEntry {
        ts: now_hms(),
        level: default_level(is_stderr),
        msg: raw.to_string(),
        app_id: String::new(),
        method: String::new(),
        path: String::new(),
        status: None,
        duration_ms: None,
    }
}

/// now_hms is the current UTC time as HH:MM:SS — the same shape `short_time`
/// extracts from the SDK's JSON lines (the dev container logs in UTC), so
/// stamped plain lines sort alongside them.
fn now_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn default_level(is_stderr: bool) -> String {
    if is_stderr { "warn" } else { "info" }.to_string()
}

fn normalize_level(s: &str) -> String {
    match s.to_ascii_lowercase().as_str() {
        "warn" | "warning" => "warn",
        "error" | "fatal" => "error",
        _ => "info",
    }
    .to_string()
}

/// short_time pulls HH:MM:SS out of an RFC3339/slog time string, best-effort.
/// "2026-06-30T12:48:21.123Z" → "12:48:21"; a non-RFC3339 value passes through.
fn short_time(t: &str) -> String {
    match t.split_once('T') {
        Some((_, rest)) => rest.chars().take(8).collect(),
        None => t.to_string(),
    }
}

/// spawn starts a per-module shipper thread that batches entries from the
/// returned sink and POSTs them to dispatch. Returns None (shipping disabled)
/// when no dispatch URL or secret is configured — dev logs then just stay in the
/// terminal, unchanged.
pub fn spawn(
    client: reqwest::blocking::Client,
    base_url: String,
    module_id: String,
    secret: String,
) -> Option<LogSink> {
    if base_url.is_empty() || secret.is_empty() {
        return None;
    }
    let url = format!(
        "{}/internal/modules/{}/logs",
        base_url.trim_end_matches('/'),
        module_id
    );
    let (tx, rx) = mpsc::channel::<LogEntry>();
    thread::spawn(move || run(rx, client, url, secret));
    Some(tx)
}

fn run(rx: Receiver<LogEntry>, client: reqwest::blocking::Client, url: String, secret: String) {
    let mut buf: Vec<LogEntry> = Vec::new();
    loop {
        match rx.recv_timeout(FLUSH_INTERVAL) {
            Ok(entry) => {
                buf.push(entry);
                while buf.len() < MAX_BATCH {
                    match rx.try_recv() {
                        Ok(e) => buf.push(e),
                        Err(_) => break,
                    }
                }
                if buf.len() >= MAX_BATCH {
                    flush(&client, &url, &secret, &mut buf);
                }
            }
            Err(RecvTimeoutError::Timeout) => flush(&client, &url, &secret, &mut buf),
            Err(RecvTimeoutError::Disconnected) => {
                flush(&client, &url, &secret, &mut buf);
                return;
            }
        }
    }
}

fn flush(client: &reqwest::blocking::Client, url: &str, secret: &str, buf: &mut Vec<LogEntry>) {
    if buf.is_empty() {
        return;
    }
    // Best-effort: a transport failure drops the batch rather than blocking the
    // module or growing the buffer unboundedly.
    let _ = client
        .post(url)
        .header("X-MS-Service-Secret", secret)
        .json(&Batch { entries: buf })
        .send();
    buf.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_line() {
        let raw = r#"{"time":"2026-06-30T12:48:21.123Z","level":"WARN","msg":"slow query","app_id":"app-7"}"#;
        let e = parse_line(raw, false);
        assert_eq!(e.level, "warn");
        assert_eq!(e.msg, "slow query");
        assert_eq!(e.ts, "12:48:21");
        assert_eq!(e.app_id, "app-7");
    }

    #[test]
    fn parse_json_message_alias_and_error() {
        let e = parse_line(r#"{"level":"error","message":"boom"}"#, false);
        assert_eq!(e.level, "error");
        assert_eq!(e.msg, "boom");
        assert_eq!(e.ts, "");
        assert_eq!(e.app_id, "");
    }

    #[test]
    fn parse_non_json_falls_back_to_stream() {
        let out = parse_line("plain stdout line", false);
        assert_eq!(out.level, "info");
        assert_eq!(out.msg, "plain stdout line");
        assert_eq!(
            out.ts.len(),
            8,
            "non-JSON lines are stamped HH:MM:SS: {:?}",
            out.ts
        );
        assert_eq!(out.ts.as_bytes()[2], b':');

        let err = parse_line("go: cannot find module", true);
        assert_eq!(err.level, "warn");
        assert_eq!(err.msg, "go: cannot find module");
    }

    #[test]
    fn parse_access_line_carries_request_detail() {
        let e = parse_line(
            r#"{"time":"2026-06-30T12:48:21.123Z","level":"INFO","msg":"request","method":"POST","path":"/x","status":500,"duration_ms":42,"app_id":"a1"}"#,
            true,
        );
        assert_eq!(e.ts, "12:48:21");
        assert_eq!(e.msg, "request");
        assert_eq!(
            (e.method.as_str(), e.path.as_str(), e.status, e.duration_ms),
            ("POST", "/x", Some(500), Some(42))
        );
        let wire = serde_json::to_value(&e).unwrap();
        assert_eq!(wire["status"], 500);
        assert_eq!(wire["duration_ms"], 42);
        // A plain log line keeps the old wire shape: no request keys at all.
        let plain =
            serde_json::to_value(parse_line(r#"{"level":"info","msg":"hi"}"#, false)).unwrap();
        for k in ["method", "path", "status", "duration_ms"] {
            assert!(plain.get(k).is_none(), "{k} must be omitted");
        }
        assert_eq!(
            plain["ts"].as_str().unwrap().len(),
            8,
            "time-less JSON line is stamped"
        );
    }

    #[test]
    fn normalize_levels() {
        assert_eq!(normalize_level("DEBUG"), "info");
        assert_eq!(normalize_level("Warning"), "warn");
        assert_eq!(normalize_level("FATAL"), "error");
    }

    #[test]
    fn spawn_disabled_without_config() {
        let c = reqwest::blocking::Client::new();
        assert!(spawn(c.clone(), String::new(), "m1".into(), "s".into()).is_none());
        assert!(spawn(c, "http://x".into(), "m1".into(), String::new()).is_none());
    }
}
