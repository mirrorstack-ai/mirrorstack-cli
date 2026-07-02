//! Authenticated calls to the api-platform account and applications
//! services. Endpoints that require a session expect
//! `Authorization: Bearer <access_token>`.
//!
//! Functions accept a `&Client` so a single command builds one client
//! and reuses its connection pool across multiple calls (e.g. `me` +
//! `get_module` + `create_module` from `module init`).

use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http;

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
/// Response shape from `POST /v1/tunnel/token`. The CLI follows up with
/// a WebSocket connect against `wss_url` carrying `?token=<token>`.
#[derive(Deserialize, Debug)]
pub struct TunnelToken {
    pub token: String,
    pub wss_url: String,
    /// RFC3339. Server-side TTL is short (60s); we don't act on this
    /// value (any failure triggers a fresh mint), but it's surfaced for
    /// diagnostic logging if the connect hangs.
    #[allow(dead_code)]
    pub expires_at: String,
}

/// POST /v1/tunnel/token — mint a connect token for the WSS dev tunnel.
pub fn tunnel_token(
    http: &Client,
    dispatch_base: &str,
    access_token: &str,
) -> Result<TunnelToken, ApiError> {
    let endpoint = format!("{}/v1/tunnel/token", dispatch_base.trim_end_matches('/'));
    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<TunnelToken>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
}

pub fn me(http: &Client, api_base: &str, access_token: &str) -> Result<Identity, ApiError> {
    let endpoint = format!("{}/v1/auth/me", api_base.trim_end_matches('/'));

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
    Err(unexpected_body_error(resp))
}

/// GET /v1/modules/{slug} — returns the caller's module by slug.
/// `Ok(None)` on 404 (caller has no module with that slug). Note this
/// only checks ownership by the *current* user — module slugs are scoped
/// per-owner, so 404 here does NOT mean the platform-wide name is unique
/// (reserved/format checks still happen on POST).
pub fn get_module(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    slug: &str,
) -> Result<Option<Module>, ApiError> {
    // Slug is pre-validated against `^[a-z][a-z0-9-]{1,38}[a-z0-9]$` before
    // this call, so it's URL-safe with no encoding needed.
    let endpoint = format!("{}/v1/modules/{}", apps_base.trim_end_matches('/'), slug);

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
    Err(unexpected_body_error(resp))
}

/// POST /v1/modules — create a developer-owned module.
pub fn create_module(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    input: &CreateModuleInput,
) -> Result<Module, ApiError> {
    let endpoint = format!("{}/v1/modules", apps_base.trim_end_matches('/'));

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
    let status_u16 = status.as_u16();
    let body = match http::read_capped(resp) {
        Ok(b) => b,
        Err(e) => {
            return Err(ApiError::Unexpected {
                status: status_u16,
                body: format!("(read body failed: {e})"),
            });
        }
    };
    if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body) {
        return Err(ApiError::Server {
            status: status_u16,
            code: env.error.code,
            message: env.error.message,
        });
    }
    Err(ApiError::Unexpected {
        status: status_u16,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[derive(Debug, Serialize)]
pub struct SetModuleDeployInput<'a> {
    pub invoke_target: &'a str,
    /// Omitted → server default `active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // module_id / timestamps are part of the API surface
pub struct ModuleDeploy {
    pub version_id: String,
    pub module_id: String,
    pub invoke_target: String,
    pub status: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// POST /v1/modules/{moduleId}/versions/{versionId}/deploy — point a module
/// version at a Lambda invoke target (upsert: one deploy row per version).
/// `module_id` is the raw platform UUID, not the sanitized `m<hex>` form
/// written into main.go.
pub fn set_module_deploy(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_id: &str,
    input: &SetModuleDeployInput,
) -> Result<ModuleDeploy, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/versions/{}/deploy",
        apps_base.trim_end_matches('/'),
        module_id,
        version_id
    );

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(input)
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleDeploy>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }

    // 4xx with platform error-envelope: surface code + message so callers
    // can branch on `not_found` / `invoke_target_invalid` / `status_invalid`
    // without re-parsing the body.
    let status_u16 = status.as_u16();
    let body = match http::read_capped(resp) {
        Ok(b) => b,
        Err(e) => {
            return Err(ApiError::Unexpected {
                status: status_u16,
                body: format!("(read body failed: {e})"),
            });
        }
    };
    if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body) {
        return Err(ApiError::Server {
            status: status_u16,
            code: env.error.code,
            message: env.error.message,
        });
    }
    Err(ApiError::Unexpected {
        status: status_u16,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct App {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateAppInput<'a> {
    pub name: &'a str,
    pub slug: &'a str,
}

/// POST /v1/apps — create an application on the platform.
pub fn create_app(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    input: &CreateAppInput,
) -> Result<App, ApiError> {
    let endpoint = format!("{}/v1/apps", apps_base.trim_end_matches('/'));

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(input)
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<App>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }

    let status_u16 = status.as_u16();
    let body = match http::read_capped(resp) {
        Ok(b) => b,
        Err(e) => {
            return Err(ApiError::Unexpected {
                status: status_u16,
                body: format!("(read body failed: {e})"),
            });
        }
    };
    if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body) {
        return Err(ApiError::Server {
            status: status_u16,
            code: env.error.code,
            message: env.error.message,
        });
    }
    Err(ApiError::Unexpected {
        status: status_u16,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// POST /v1/auth/sessions/refresh — exchange a refresh token for new tokens.
pub fn refresh_session(
    http: &Client,
    api_base: &str,
    refresh_token: &str,
) -> Result<TokenPair, ApiError> {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        refresh_token: &'a str,
    }
    let endpoint = format!(
        "{}/v1/auth/sessions/refresh",
        api_base.trim_end_matches('/')
    );
    let resp = http
        .post(&endpoint)
        .header("Accept", "application/json")
        .json(&Body { refresh_token })
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<TokenPair>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
}

#[derive(Debug, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// DELETE /v1/auth/sessions/current — revoke the supplied refresh token
/// (CLI flow: token in body, not cookie). The platform treats a missing
/// or already-revoked session as success, so callers can call this
/// idempotently. A 401 means the access token is gone but does NOT
/// necessarily mean the refresh token is — surface as Unauthenticated
/// and let the caller decide whether to still wipe local creds.
pub fn revoke_session(
    http: &Client,
    api_base: &str,
    access_token: &str,
    refresh_token: &str,
) -> Result<(), ApiError> {
    #[derive(Serialize)]
    struct Body<'a> {
        refresh_token: &'a str,
    }
    let endpoint = format!(
        "{}/v1/auth/sessions/current",
        api_base.trim_end_matches('/')
    );

    let resp = http
        .delete(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(&Body { refresh_token })
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
}

/// Common tail for unexpected (non-success, non-typed) responses: read
/// the body with [`http::read_capped`] and wrap as `ApiError::Unexpected`.
/// If reading fails, the io error is folded into the body for diagnosis.
fn unexpected_body_error(resp: Response) -> ApiError {
    let status = resp.status().as_u16();
    match http::read_capped(resp) {
        Ok(bytes) => ApiError::Unexpected {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        },
        Err(e) => ApiError::Unexpected {
            status,
            body: format!("(read body failed: {e})"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use mockito::Server;
    use serde_json::json;

    fn test_client() -> Client {
        http::client(Duration::from_secs(15)).expect("client")
    }

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

        let id = me(&test_client(), &server.url(), "AT").expect("ok");
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

        let err = me(&test_client(), &server.url(), "expired").unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn me_5xx_is_unexpected_with_body() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/auth/me")
            .with_status(503)
            .with_body("upstream timeout")
            .create();

        let err = me(&test_client(), &server.url(), "AT").unwrap_err();
        match err {
            ApiError::Unexpected { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("upstream timeout"), "got body {body:?}");
            }
            other => panic!("expected Unexpected, got {other:?}"),
        }
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
            &test_client(),
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

        let m = get_module(&test_client(), &server.url(), "AT", "media").expect("ok");
        assert!(m.is_some());
        assert_eq!(m.unwrap().slug, "media");
    }

    #[test]
    fn get_module_404_returns_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/none")
            .match_header("authorization", "Bearer AT")
            .with_status(404)
            .create();

        let m = get_module(&test_client(), &server.url(), "AT", "none").expect("ok");
        assert!(m.is_none());
    }

    #[test]
    fn get_module_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/forbidden-slug")
            .with_status(401)
            .create();

        let err =
            get_module(&test_client(), &server.url(), "expired", "forbidden-slug").unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
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
            &test_client(),
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

    #[test]
    fn revoke_session_204_is_ok() {
        let mut server = Server::new();
        let _m = server
            .mock("DELETE", "/v1/auth/sessions/current")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"refresh_token":"RT"}"#.into(),
            ))
            .with_status(204)
            .create();

        revoke_session(&test_client(), &server.url(), "AT", "RT").expect("ok");
    }

    #[test]
    fn revoke_session_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("DELETE", "/v1/auth/sessions/current")
            .with_status(401)
            .create();

        let err = revoke_session(&test_client(), &server.url(), "expired", "RT").unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn revoke_session_5xx_is_unexpected() {
        let mut server = Server::new();
        let _m = server
            .mock("DELETE", "/v1/auth/sessions/current")
            .with_status(503)
            .with_body("upstream timeout")
            .create();

        let err = revoke_session(&test_client(), &server.url(), "AT", "RT").unwrap_err();
        match err {
            ApiError::Unexpected { status, body } => {
                assert_eq!(status, 503);
                assert!(body.contains("upstream timeout"), "got body {body:?}");
            }
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }

    #[test]
    fn create_app_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps")
            .match_header("authorization", "Bearer AT")
            .with_status(201)
            .with_body(
                json!({
                    "id": "a-1",
                    "name": "My App",
                    "slug": "my-app",
                    "owner_id": "u-1",
                    "created_at": "2026-05-28T00:00:00Z"
                })
                .to_string(),
            )
            .create();

        let a = create_app(
            &test_client(),
            &server.url(),
            "AT",
            &CreateAppInput {
                name: "My App",
                slug: "my-app",
            },
        )
        .expect("ok");
        assert_eq!(a.slug, "my-app");
        assert_eq!(a.id, "a-1");
    }

    #[test]
    fn create_app_409_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps")
            .with_status(409)
            .with_body(
                r#"{"error":{"code":"slug_taken","message":"app slug already taken"}}"#,
            )
            .create();

        let err = create_app(
            &test_client(),
            &server.url(),
            "AT",
            &CreateAppInput {
                name: "My App",
                slug: "my-app",
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { code, .. } => assert_eq!(code, "slug_taken"),
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn set_module_deploy_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions/ver-uuid/deploy")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"invoke_target":"my-fn","status":"active"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "invoke_target": "my-fn",
                    "status": "active",
                    "created_at": "2026-07-01T00:00:00Z",
                    "updated_at": "2026-07-02T00:00:00Z"
                })
                .to_string(),
            )
            .create();

        let d = set_module_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "ver-uuid",
            &SetModuleDeployInput {
                invoke_target: "my-fn",
                status: Some("active"),
            },
        )
        .expect("ok");
        assert_eq!(d.version_id, "ver-uuid");
        assert_eq!(d.invoke_target, "my-fn");
        assert_eq!(d.status, "active");
    }

    #[test]
    fn set_module_deploy_omits_status_when_none() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions/ver-uuid/deploy")
            .match_body(mockito::Matcher::JsonString(
                r#"{"invoke_target":"my-fn"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "invoke_target": "my-fn",
                    "status": "active"
                })
                .to_string(),
            )
            .create();

        let d = set_module_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "ver-uuid",
            &SetModuleDeployInput {
                invoke_target: "my-fn",
                status: None,
            },
        )
        .expect("ok");
        assert_eq!(d.status, "active");
    }

    #[test]
    fn set_module_deploy_404_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions/ver-uuid/deploy")
            .with_status(404)
            .with_body(
                r#"{"error":{"code":"not_found","message":"version not found for this module"}}"#,
            )
            .create();

        let err = set_module_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "ver-uuid",
            &SetModuleDeployInput {
                invoke_target: "my-fn",
                status: None,
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 404);
                assert_eq!(code, "not_found");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn set_module_deploy_422_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions/ver-uuid/deploy")
            .with_status(422)
            .with_body(
                r#"{"error":{"code":"invoke_target_invalid","message":"invoke_target must be a Lambda function name or ARN"}}"#,
            )
            .create();

        let err = set_module_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "ver-uuid",
            &SetModuleDeployInput {
                invoke_target: "not a lambda!",
                status: None,
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 422);
                assert_eq!(code, "invoke_target_invalid");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn set_module_deploy_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions/ver-uuid/deploy")
            .with_status(401)
            .with_body(r#"{"error":{"code":"token_expired","message":"token expired"}}"#)
            .create();

        let err = set_module_deploy(
            &test_client(),
            &server.url(),
            "expired",
            "mod-uuid",
            "ver-uuid",
            &SetModuleDeployInput {
                invoke_target: "my-fn",
                status: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn create_module_4xx_without_envelope_is_unexpected() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules")
            .with_status(400)
            .with_body("not json")
            .create();

        let err = create_module(
            &test_client(),
            &server.url(),
            "AT",
            &CreateModuleInput {
                name: "x",
                slug: "x",
            },
        )
        .unwrap_err();
        match err {
            ApiError::Unexpected { status, body } => {
                assert_eq!(status, 400);
                assert!(body.contains("not json"), "got body {body:?}");
            }
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }
}
