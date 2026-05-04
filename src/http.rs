//! Shared reqwest Client builder. Centralizes the User-Agent string so
//! every outbound request labels itself as the CLI — the platform's
//! session list (and any audit log) can then render "MirrorStack CLI"
//! instead of falling through to a generic browser-UA parser.

use std::io::{self, Read};
use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder, Response};

/// Cap on response bodies we'll deserialize. The platform's success
/// payloads are sub-1 KB; 64 KiB is generous slack for error envelopes
/// and protects against a hostile endpoint trying to OOM the CLI.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// User-Agent shape: `mirrorstack-cli/<version> (<os>; <arch>)`.
/// Mirrors the convention of curl, gh CLI, brew, etc.
fn user_agent() -> String {
    format!(
        "mirrorstack-cli/{} ({}; {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

/// Construct a reqwest blocking Client with the CLI's User-Agent and a
/// caller-supplied timeout. Use this everywhere we make HTTP calls so
/// the UA stays consistent.
pub fn client(timeout: Duration) -> reqwest::Result<Client> {
    builder(timeout).build()
}

/// Same as [`client`] but returns the builder so callers can layer on
/// additional config before `.build()`. Currently unused — exposed so
/// the seam is obvious for future commands.
pub fn builder(timeout: Duration) -> ClientBuilder {
    Client::builder().timeout(timeout).user_agent(user_agent())
}

/// Read a response body into memory with a hard size cap. Truncated
/// bodies are returned as-is — the caller's parse step fails loudly
/// rather than silently misinterpreting a partial document. Each
/// caller maps the io::Error into its own error type.
pub fn read_capped(resp: Response) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    resp.take(MAX_RESPONSE_BYTES).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_matches_expected_shape() {
        let ua = user_agent();
        assert!(ua.starts_with("mirrorstack-cli/"), "got {ua}");
        assert!(ua.contains('('), "expected (os; arch) in {ua}");
    }
}
