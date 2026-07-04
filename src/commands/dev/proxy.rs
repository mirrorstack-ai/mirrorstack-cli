//! In-process dev reverse proxy for `dev --all` — replaces the shell
//! runner's `scripts/dev-proxy.go`.
//!
//! Routes `/_m/<slug>/*` → `127.0.0.1:<internal_port>/*` by stripping the
//! `/_m/<slug>` prefix (empty result → `/`, query preserved), reproducing
//! dev-proxy.go's `TrimPrefix` semantics. After the rewritten request head
//! is sent, bytes are relayed raw in both directions, so chunked bodies,
//! SSE streams, and protocol upgrades pass through untouched. A module
//! that is still compiling simply refuses the backend connect → 502, the
//! same startup race the shell runner tolerated.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};

const MAX_HEAD: usize = 64 * 1024;

/// Bind the proxy and serve on a background thread. Returns the bound port
/// (`port` 0 picks an ephemeral one, used by tests).
pub(super) fn spawn(port: u16, routes: HashMap<String, u16>) -> Result<u16> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .with_context(|| format!("dev: bind dev-proxy on :{port}"))?;
    let bound = listener.local_addr().context("dev: dev-proxy local addr")?;
    // The table is immutable after spawn and every request is a fresh
    // connection (`Connection: close` below), so share it via Arc rather
    // than deep-cloning it per connection.
    let routes = Arc::new(routes);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let routes = Arc::clone(&routes);
            thread::spawn(move || {
                let _ = handle(stream, &routes);
            });
        }
    });
    Ok(bound.port())
}

/// Map a request target `/_m/<slug><rest>` to `(backend_port, <rest>)` with
/// the prefix stripped and an empty path normalized to `/` (query kept).
/// `None` → no matching route (404).
fn rewrite_target(target: &str, routes: &HashMap<String, u16>) -> Option<(u16, String)> {
    let rest = target.strip_prefix(super::MODULE_ROUTE_PREFIX)?;
    let slug_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (slug, remainder) = rest.split_at(slug_end);
    let port = *routes.get(slug)?;
    let rewritten = if remainder.is_empty() || remainder.starts_with('?') {
        format!("/{remainder}")
    } else {
        remainder.to_string()
    };
    Some((port, rewritten))
}

fn handle(mut client: TcpStream, routes: &HashMap<String, u16>) -> std::io::Result<()> {
    // Read the request head (plus whatever body bytes arrived with it).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        // Only scan the new tail (the terminator may straddle the chunk
        // boundary by up to 3 bytes) — rescanning from 0 on every read
        // would be O(head × chunks).
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_head_end(&buf[scan_from..]) {
            break scan_from + end;
        }
        if buf.len() > MAX_HEAD {
            return respond(&mut client, "431 Request Header Fields Too Large");
        }
    };
    let (head, body_prefix) = buf.split_at(head_end);
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().splitn(3, ' ');
    let method = request_line.next().unwrap_or_default();
    let target = request_line.next().unwrap_or_default();
    let version = request_line.next().unwrap_or("HTTP/1.1");

    let Some((port, rewritten)) = rewrite_target(target, routes) else {
        return respond(&mut client, "404 Not Found");
    };
    let Ok(mut backend) = TcpStream::connect(("127.0.0.1", port)) else {
        // Module still compiling / crashed — same 502 the Go proxy returned.
        return respond(&mut client, "502 Bad Gateway");
    };

    // Rebuild the head with the stripped path. Force `Connection: close`
    // so each proxied request gets its own connection pair — a reused
    // client connection would carry the next request's /_m/ prefix past
    // this rewrite. Protocol upgrades keep their original Connection
    // header (the connection becomes a dedicated duplex stream anyway).
    let is_upgrade = lines.clone().any(|l| header_starts(l, "upgrade:"));
    let mut out = format!("{method} {rewritten} {version}\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if !is_upgrade && header_starts(line, "connection:") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !is_upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    backend.write_all(out.as_bytes())?;
    backend.write_all(body_prefix)?;

    // Relay raw bytes both ways until either side closes.
    let mut client_rd = client.try_clone()?;
    let mut backend_wr = backend.try_clone()?;
    let upstream = thread::spawn(move || {
        let _ = std::io::copy(&mut client_rd, &mut backend_wr);
        let _ = backend_wr.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut backend, &mut client);
    // Unblock the upstream copy (shutdown on a clone reaches the shared fd).
    let _ = client.shutdown(Shutdown::Both);
    let _ = backend.shutdown(Shutdown::Both);
    let _ = upstream.join();
    Ok(())
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Case-insensitive "header line starts with `prefix`" without allocating
/// a lowercased copy of every line.
fn header_starts(line: &str, prefix: &str) -> bool {
    line.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn respond(client: &mut TcpStream, status: &str) -> std::io::Result<()> {
    client.write_all(
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes() -> HashMap<String, u16> {
        HashMap::from([("oauth-core".to_string(), 18080)])
    }

    #[test]
    fn rewrite_strips_prefix() {
        assert_eq!(
            rewrite_target("/_m/oauth-core/foo", &routes()),
            Some((18080, "/foo".into()))
        );
        assert_eq!(
            rewrite_target("/_m/oauth-core/a/b?q=2", &routes()),
            Some((18080, "/a/b?q=2".into()))
        );
    }

    #[test]
    fn rewrite_empty_path_becomes_root() {
        assert_eq!(
            rewrite_target("/_m/oauth-core", &routes()),
            Some((18080, "/".into()))
        );
        assert_eq!(
            rewrite_target("/_m/oauth-core/", &routes()),
            Some((18080, "/".into()))
        );
        // Bare slug + query: path is empty, query survives.
        assert_eq!(
            rewrite_target("/_m/oauth-core?x=1", &routes()),
            Some((18080, "/?x=1".into()))
        );
    }

    #[test]
    fn rewrite_rejects_unknown_slug_and_non_module_paths() {
        assert_eq!(rewrite_target("/_m/unknown/foo", &routes()), None);
        assert_eq!(rewrite_target("/healthz", &routes()), None);
        // Slug must be delimiter-bounded, not prefix-matched.
        assert_eq!(rewrite_target("/_m/oauth-corefoo", &routes()), None);
    }

    /// End-to-end: proxied request reaches a real backend with the prefix
    /// stripped, and the response relays back.
    #[test]
    fn proxies_to_backend_with_stripped_path() {
        // Dummy backend: echo the request line's target in the body.
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend_port = backend.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in backend.incoming() {
                let mut stream = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = head.split(' ').nth(1).unwrap_or("").to_string();
                let body = format!("saw {target}");
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });

        let proxy_port = spawn(0, HashMap::from([("test-mod".to_string(), backend_port)])).unwrap();

        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client
            .write_all(b"GET /_m/test-mod/hello?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "got {response}");
        assert!(response.ends_with("saw /hello?x=1"), "got {response}");

        // Unknown slug → 404 from the proxy itself.
        let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        client
            .write_all(b"GET /_m/nope/x HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 404"), "got {response}");
    }
}
