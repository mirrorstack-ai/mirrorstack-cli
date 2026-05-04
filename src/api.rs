//! Authenticated calls to the api-platform account service. Endpoints
//! that require a session expect `Authorization: Bearer <access_token>`.

use std::io::Read;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http;

const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // profile_url is part of the API surface; whoami doesn't print it yet
pub struct Identity {
    pub id: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub profile_url: Option<String>,
    #[serde(default)]
    pub slug: Option<String>,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("not signed in or session expired — run `mirrorstack login` again")]
    Unauthenticated,
    #[error("api: HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api: decode response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("api: unexpected response {status}: {body}")]
    Unexpected { status: u16, body: String },
    /// Server returned a structured error envelope. The `code` is the
    /// machine-readable identifier (e.g. `slug_taken`); callers branch on it.
    #[error("api: {code}: {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },
}

/// Subset of the platform's structured error body. The platform consistently
/// wraps errors as `{"error": {"code": "...", "message": "..."}}` for any
/// 4xx the application layer produces; we only need those two fields.
#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}
#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // name / owner_id / created_at are part of the API surface
pub struct Module {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateModuleInput<'a> {
    pub name: &'a str,
    pub slug: &'a str,
}

/// GET /v1/auth/me — returns the authenticated user's identity.
pub fn me(api_base: &str, access_token: &str) -> Result<Identity, ApiError> {
    let endpoint = format!("{}/v1/auth/me", api_base.trim_end_matches('/'));
    let http = http::client(Duration::from_secs(15))?;

    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();

    if status.is_success() {
        return Ok(resp.json::<Identity>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    // Bound the error-path body so a hostile endpoint can't OOM us.
    let mut body = Vec::with_capacity(1024);
    resp.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| ApiError::Unexpected {
            status: status.as_u16(),
            body: format!("(read body failed: {e})"),
        })?;
    let body = String::from_utf8_lossy(&body).into_owned();
    Err(ApiError::Unexpected {
        status: status.as_u16(),
        body,
    })
}

/// GET /v1/modules/{slug} — returns the caller's module by slug.
/// `Ok(None)` on 404 (caller has no module with that slug). Note this
/// only checks ownership by the *current* user — module slugs are scoped
/// per-owner, so 404 here does NOT mean the platform-wide name is unique
/// (reserved/format checks still happen on POST).
pub fn get_module(
    apps_base: &str,
    access_token: &str,
    slug: &str,
) -> Result<Option<Module>, ApiError> {
    // Slug is pre-validated against `^[a-z][a-z0-9-]{1,38}[a-z0-9]$` before
    // this call, so it's URL-safe with no encoding needed.
    let endpoint = format!("{}/v1/modules/{}", apps_base.trim_end_matches('/'), slug);
    let http = http::client(Duration::from_secs(15))?;

    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(Some(resp.json::<Module>()?));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    let mut body = Vec::with_capacity(1024);
    resp.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| ApiError::Unexpected {
            status: status.as_u16(),
            body: format!("(read body failed: {e})"),
        })?;
    Err(ApiError::Unexpected {
        status: status.as_u16(),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// POST /v1/modules — create a developer-owned module.
pub fn create_module(
    apps_base: &str,
    access_token: &str,
    input: &CreateModuleInput,
) -> Result<Module, ApiError> {
    let endpoint = format!("{}/v1/modules", apps_base.trim_end_matches('/'));
    let http = http::client(Duration::from_secs(15))?;

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(input)
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<Module>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }

    // 4xx with platform error-envelope: surface code + message so callers
    // can branch on `slug_taken` / `slug_reserved` / `slug_invalid` without
    // re-parsing the body.
    let mut body = Vec::with_capacity(1024);
    resp.take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| ApiError::Unexpected {
            status: status.as_u16(),
            body: format!("(read body failed: {e})"),
        })?;
    if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body) {
        return Err(ApiError::Server {
            status: status.as_u16(),
            code: env.error.code,
            message: env.error.message,
        });
    }
    Err(ApiError::Unexpected {
        status: status.as_u16(),
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use mockito::Server;
    use serde_json::json;

    #[test]
    fn me_success() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/auth/me")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "id": "u-1",
                    "email": "user@example.com",
                    "name": "Test User",
                    "profile_url": null,
                    "slug": "test-user"
                })
                .to_string(),
            )
            .create();

        let id = me(&server.url(), "AT").expect("ok");
        assert_eq!(id.email, "user@example.com");
        assert_eq!(id.slug.as_deref(), Some("test-user"));
    }

    #[test]
    fn me_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/auth/me")
            .with_status(401)
            .with_body(r#"{"error":{"code":"token_invalid"}}"#)
            .create();

        let err = me(&server.url(), "expired").unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn create_module_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"name":"Media","slug":"media"}"#.into(),
            ))
            .with_status(201)
            .with_body(
                json!({
                    "id": "m-1",
                    "name": "Media",
                    "slug": "media",
                    "owner_id": "u-1",
                    "created_at": "2026-05-04T00:00:00Z"
                })
                .to_string(),
            )
            .create();

        let m = create_module(
            &server.url(),
            "AT",
            &CreateModuleInput {
                name: "Media",
                slug: "media",
            },
        )
        .expect("ok");
        assert_eq!(m.slug, "media");
        assert_eq!(m.id, "m-1");
    }

    #[test]
    fn get_module_200_returns_some() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/media")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "id": "m-1",
                    "name": "Media",
                    "slug": "media",
                    "owner_id": "u-1",
                })
                .to_string(),
            )
            .create();

        let m = get_module(&server.url(), "AT", "media").expect("ok");
        assert!(m.is_some());
        assert_eq!(m.unwrap().slug, "media");
    }

    #[test]
    fn get_module_404_returns_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/none")
            .with_status(404)
            .create();

        let m = get_module(&server.url(), "AT", "none").expect("ok");
        assert!(m.is_none());
    }

    #[test]
    fn create_module_409_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules")
            .with_status(409)
            .with_body(
                r#"{"error":{"code":"slug_taken","message":"slug already taken for this owner"}}"#,
            )
            .create();

        let err = create_module(
            &server.url(),
            "AT",
            &CreateModuleInput {
                name: "Media",
                slug: "media",
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 409);
                assert_eq!(code, "slug_taken");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }
}
