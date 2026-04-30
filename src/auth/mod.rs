//! OAuth 2.0 authorization-code + PKCE client. Pairs with api-platform's
//! `/v1/oauth/*` endpoints and the web-account `/authorize` consent page.
//!
//! OOB delivery (`urn:ietf:wg:oauth:2.0:oob`): the user pastes the code
//! displayed on the consent page back into the terminal. Custom-scheme
//! and per-OS handler registration is the follow-up tracked at #7.

use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

/// Cap on response bodies we'll deserialize. /token and /me return
/// sub-1KB JSON in practice; 64 KiB is generous slack and protects
/// against a hostile endpoint trying to OOM the CLI.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Identifies the CLI to the platform; matches the seed in
/// api-platform migration `011_oauth.up.sql`.
pub const CLIENT_ID: &str = "mirrorstack-cli";

/// RFC 6749 §1.3.1 OOB sentinel — used while custom-scheme delivery is
/// not yet shipped (mirrorstack-cli#7).
pub const REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";

/// PKCE method the platform accepts. RFC 7636 §4.3.
const CHALLENGE_METHOD: &str = "S256";

#[derive(Debug, Clone)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// 32 random bytes encoded base64url-no-pad → SHA256 → base64url-no-pad.
    pub fn generate() -> Result<Self, AuthError> {
        let verifier = random_b64url(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Ok(Self {
            verifier,
            challenge,
        })
    }
}

/// Build the consent-page URL the user opens in a browser.
pub fn authorize_url(web_base: &str, state: &str, pkce: &Pkce) -> String {
    let base = web_base.trim_end_matches('/');
    let mut u = Url::parse(&format!("{base}/authorize"))
        .unwrap_or_else(|_| Url::parse("https://account.mirrorstack.ai/authorize").unwrap());
    u.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("response_type", "code")
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", CHALLENGE_METHOD)
        .append_pair("state", state);
    u.into()
}

/// 16 random bytes, base64url-no-pad. State is required by the auth
/// server but not validated end-to-end in OOB (paste only carries the
/// code). Generalizes when custom-scheme delivery lands.
pub fn random_state() -> Result<String, AuthError> {
    random_b64url(16)
}

/// RFC 6749 §5.1 token endpoint success body. MirrorStack returns the
/// opaque refresh_token in the body for non-cookie callers like CLIs.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // token_type is read by serde but not branched on
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

/// Exchange the pasted auth code (+ PKCE verifier) for tokens.
pub fn exchange_code(
    http: &Client,
    api_base: &str,
    code: &str,
    pkce: &Pkce,
) -> Result<TokenResponse, AuthError> {
    let endpoint = format!("{}/v1/oauth/token", api_base.trim_end_matches('/'));
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("code_verifier", &pkce.verifier),
        ("redirect_uri", REDIRECT_URI),
    ];

    let resp = http
        .post(&endpoint)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .map_err(AuthError::Http)?;

    let status = resp.status();

    if status.is_success() {
        return resp
            .json::<TokenResponse>()
            .map_err(|e| AuthError::Decode(e.to_string()));
    }

    // RFC 6749 §5.2 error body — map known codes to typed sentinels.
    // Cap body so a hostile endpoint can't OOM us with a giant response.
    let body = read_capped(resp)?;
    let parsed: ErrorBody = serde_json::from_str(&body).unwrap_or_default();
    match parsed.error.as_deref() {
        Some("invalid_grant") => Err(AuthError::InvalidGrant),
        Some("invalid_request") => Err(AuthError::InvalidRequest),
        Some("invalid_client") => Err(AuthError::InvalidClient),
        Some("unsupported_grant_type") => Err(AuthError::UnsupportedGrant),
        _ if status.is_server_error() => Err(AuthError::Server {
            status: status.as_u16(),
            description: parsed.error_description.unwrap_or_default(),
        }),
        Some(code) => Err(AuthError::Other {
            code: code.to_string(),
            description: parsed.error_description.unwrap_or_default(),
        }),
        None => Err(AuthError::Unexpected {
            status: status.as_u16(),
            body,
        }),
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("auth: code is invalid, expired, or already used")]
    InvalidGrant,
    #[error("auth: malformed token request")]
    InvalidRequest,
    #[error("auth: client authentication failed")]
    InvalidClient,
    #[error("auth: grant_type not supported")]
    UnsupportedGrant,
    #[error("auth: server error ({status}): {description}")]
    Server { status: u16, description: String },
    #[error("auth: {code}: {description}")]
    Other { code: String, description: String },
    #[error("auth: unexpected response {status}: {body}")]
    Unexpected { status: u16, body: String },
    #[error("auth: HTTP error: {0}")]
    Http(#[source] reqwest::Error),
    #[error("auth: decode response: {0}")]
    Decode(String),
    #[error("auth: random source: {0}")]
    Random(#[source] rand::rand_core::OsError),
}

#[derive(Debug, Default, Deserialize)]
struct ErrorBody {
    error: Option<String>,
    error_description: Option<String>,
}

fn random_b64url(n: usize) -> Result<String, AuthError> {
    let mut buf = vec![0u8; n];
    OsRng.try_fill_bytes(&mut buf).map_err(AuthError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Read a response body into memory with a hard size cap. Truncated
/// bodies are returned as-is — the JSON parse downstream will fail
/// loudly rather than silently misinterpret a partial document.
fn read_capped(resp: Response) -> Result<String, AuthError> {
    let mut buf = Vec::with_capacity(1024);
    resp.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| AuthError::Decode(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| AuthError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests;
