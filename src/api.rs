//! Authenticated calls to the api-platform account and applications
//! services. Endpoints that require a session expect
//! `Authorization: Bearer <access_token>`.
//!
//! Functions accept a `&Client` so a single command builds one client
//! and reuses its connection pool across multiple calls (e.g. `me` +
//! `get_module` + `create_module` from `module init`).

use std::collections::BTreeMap;

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

/// GET /v1/tunnel/manifest/{moduleId} — the module's live manifest, proxied
/// off its `mirrorstack dev` tunnel by the dispatch service. `module_id` is
/// the raw platform UUID. The 200 body is the manifest object itself (no
/// envelope), returned as opaque JSON. Owner-gated: someone else's (or an
/// unknown) module is a 404 `not_found`, and a module without a live tunnel
/// is a 503 `tunnel_offline` — callers branch on those codes to tell "start
/// `mirrorstack dev`" apart from real failures.
pub fn get_tunnel_manifest(
    http: &Client,
    dispatch_base: &str,
    access_token: &str,
    module_id: &str,
) -> Result<serde_json::Value, ApiError> {
    let endpoint = format!(
        "{}/v1/tunnel/manifest/{}",
        dispatch_base.trim_end_matches('/'),
        module_id
    );

    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<serde_json::Value>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }

    // Error envelope: surface code + message so callers can branch on
    // `tunnel_offline` / `not_found` without re-parsing the body.
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
pub struct RecordModuleVersionInput<'a> {
    /// Canonical SemVer, no `v` prefix (the platform 422s anything else).
    pub version: &'a str,
    /// This version's changelog locale map — `{ "default": <CHANGELOG.md
    /// section>, "<tag>": <CHANGELOG.<tag>.md section> }`, each the module's
    /// `## <version>` section extracted off disk. `default` is required;
    /// omitted only when empty. Capped server-side at 16KB per value
    /// (`changelog_too_large`).
    #[serde(skip_serializing_if = "map_is_empty")]
    pub changelog: &'a BTreeMap<String, String>,
    /// The module's README locale map — `{ "default": <README.md>, "<tag>":
    /// <README.<tag>.md> }` read off disk at the module root. Optional and
    /// free-form; omitted when empty. Each value is capped client-side at 64KB
    /// to match the platform (`readme_too_large`).
    #[serde(skip_serializing_if = "map_is_empty")]
    pub readme: &'a BTreeMap<String, String>,
    /// The module's full live manifest as read off the dev tunnel
    /// (`get_tunnel_manifest`), passed through as opaque JSON. The platform
    /// stores it verbatim on the version row and the web console mounts the
    /// installed version's UI from it — a stub here loses the module's pages.
    pub manifest: &'a serde_json::Value,
}

/// `skip_serializing_if` predicate for the borrowed changelog / readme maps.
/// The field is a reference, so serde hands the predicate a double reference.
fn map_is_empty(map: &&BTreeMap<String, String>) -> bool {
    map.is_empty()
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // module_id / channel / published_at are part of the API surface
pub struct ModuleVersion {
    /// Version row UUID.
    pub id: String,
    pub module_id: String,
    pub version: String,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
}

/// POST /v1/modules/{moduleId}/versions — record an immutable module
/// version (snapshot + changelog). Recording carries no visibility
/// semantics; "publish" is reserved for the future marketplace listing
/// act. Re-recording an existing version is a 409 `version_exists`; the
/// changelog is capped server-side at 16KB (`changelog_too_large`).
pub fn record_module_version(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    input: &RecordModuleVersionInput,
) -> Result<ModuleVersion, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/versions",
        apps_base.trim_end_matches('/'),
        module_id
    );

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(input)
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleVersion>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }

    // 4xx with platform error-envelope: surface code + message so callers
    // can branch on `version_exists` / `version_invalid` /
    // `changelog_too_large` without re-parsing the body.
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

/// Envelope for GET /v1/modules/{moduleId}/versions.
#[derive(Debug, Deserialize)]
struct ModuleVersionList {
    versions: Vec<ModuleVersion>,
}

/// GET /v1/modules/{moduleId}/versions — the module's recorded versions,
/// newest first (changelogs included, manifests omitted). Owner-scoped;
/// someone else's module is a 404, surfaced as `Unexpected` since deploy
/// resolves ownership via `get_module` before calling this.
pub fn list_module_versions(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
) -> Result<Vec<ModuleVersion>, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/versions",
        apps_base.trim_end_matches('/'),
        module_id
    );

    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleVersionList>()?.versions);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
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

/// POST /v1/modules/{moduleId}/versions/{versionRef}/deploy — point a module
/// version at a Lambda invoke target (upsert: one deploy row per version).
/// `version_ref` is the version UUID or the version string — the platform
/// tries the UUID shape first, then resolves UNIQUE(module_id, version).
/// SemVer strings are path-safe verbatim ([0-9A-Za-z.+-] only). `module_id`
/// is the raw platform UUID, not the sanitized `m<hex>` form in main.go.
pub fn set_module_deploy(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
    input: &SetModuleDeployInput,
) -> Result<ModuleDeploy, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/versions/{}/deploy",
        apps_base.trim_end_matches('/'),
        module_id,
        version_ref
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

/// GET /v1/apps/{ref} — the caller's app by ID or slug (the platform
/// resolves either shape). Member-scoped: `Ok(None)` on 404, which covers
/// both "does not exist" and "exists but the caller isn't a member".
pub fn get_app(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_ref: &str,
) -> Result<Option<App>, ApiError> {
    let endpoint = format!("{}/v1/apps/{}", apps_base.trim_end_matches('/'), app_ref);

    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(Some(resp.json::<App>()?));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
}

/// One file of an app deploy's manifest, as POSTed to the platform.
#[derive(Debug, Serialize)]
pub struct DeployFile<'a> {
    /// Relative forward-slash path under the deploy root (the S3 key tail).
    pub path: &'a str,
    pub size: u64,
    /// Lowercase hex SHA-256 of the file contents.
    pub sha256: &'a str,
}

#[derive(Debug, Serialize)]
pub struct CreateAppDeployInput<'a> {
    pub env: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'a str>,
    /// `"ssr"` for a packaged Next.js standalone bundle deploy; omitted
    /// (server default: `"static"`) for today's static-export deploys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<&'a str>,
    pub files: &'a [DeployFile<'a>],
}

/// One presigned S3 PUT the CLI must perform to ship a deploy file.
#[derive(Debug, Deserialize)]
pub struct UploadTarget {
    /// The manifest path this URL uploads (maps back to the local file).
    pub path: String,
    pub url: String,
    /// Headers the presigned URL was signed with — sent verbatim on the PUT.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct CreatedDeploy {
    pub deploy_id: String,
    pub uploads: Vec<UploadTarget>,
}

/// POST /v1/apps/{appId}/deploys — register a pending deploy and mint one
/// presigned S3 PUT per manifest file (15-minute expiry). Owner/admin
/// gated; the platform re-validates the manifest (≤500 files, ≤25MB
/// total, safe relative paths) and surfaces violations as error envelopes.
pub fn create_app_deploy(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_id: &str,
    input: &CreateAppDeployInput,
) -> Result<CreatedDeploy, ApiError> {
    let endpoint = format!(
        "{}/v1/apps/{}/deploys",
        apps_base.trim_end_matches('/'),
        app_id
    );

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(input)
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<CreatedDeploy>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// Body of a successful finalize: the deploy's new status (`ready`).
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // status is part of the API surface; deploy treats 2xx as ready
pub struct DeployStatus {
    pub status: String,
}

/// POST /v1/apps/{appId}/deploys/{deployId}/finalize — the platform spot
/// checks the uploaded objects (HeadObject on a sample) and flips the
/// deploy to `ready`. A missing object is a 4xx envelope, not a 200 with
/// a failed status.
pub fn finalize_app_deploy(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_id: &str,
    deploy_id: &str,
) -> Result<DeployStatus, ApiError> {
    let endpoint = format!(
        "{}/v1/apps/{}/deploys/{}/finalize",
        apps_base.trim_end_matches('/'),
        app_id,
        deploy_id
    );

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<DeployStatus>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // active_deploy_id is part of the API surface; deploy echoes its own id
pub struct ActivatedStage {
    pub active_deploy_id: String,
}

/// POST /v1/apps/{appId}/stages/{env}/activate — point the stage at a
/// `ready` deploy. The platform rewrites the edge manifest so the change
/// is live within the worker's cache TTL (~30s).
pub fn activate_app_stage(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_id: &str,
    env: &str,
    deploy_id: &str,
) -> Result<ActivatedStage, ApiError> {
    #[derive(Serialize)]
    struct Body<'a> {
        deploy_id: &'a str,
    }
    let endpoint = format!(
        "{}/v1/apps/{}/stages/{}/activate",
        apps_base.trim_end_matches('/'),
        app_id,
        env
    );

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(&Body { deploy_id })
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ActivatedStage>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// Body of a successful `POST /v1/auth/sessions/refresh`. The platform
/// rotates the refresh token on every refresh (replay defense), so we
/// must persist the new one back to credentials. expires_at is RFC3339
/// from the server but informational only — the CLI re-derives the
/// 15-minute access TTL locally when saving.
#[derive(Debug, Deserialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[allow(dead_code)]
    pub expires_at: String,
}

/// POST /v1/auth/sessions/refresh — exchange a refresh token for a new
/// access + refresh pair. The CLI calls this on a 401 from any
/// access-token-bearing endpoint to recover without a fresh
/// `mirrorstack login`. A 401 from this endpoint means the refresh
/// token itself is gone (revoked, expired, or never existed) — surface
/// as Unauthenticated so callers can fall back to the login hint.
pub fn refresh_session(
    http: &Client,
    api_base: &str,
    refresh_token: &str,
) -> Result<RefreshResponse, ApiError> {
    #[derive(Serialize)]
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
        return Ok(resp.json::<RefreshResponse>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
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

/// Common tail for non-success responses that may carry the platform's
/// structured error envelope: `{"error":{code,message}}` becomes
/// [`ApiError::Server`] so callers can branch on the code, anything else
/// falls through to [`ApiError::Unexpected`] with the raw body.
fn envelope_error(resp: Response) -> ApiError {
    let status = resp.status().as_u16();
    let body = match http::read_capped(resp) {
        Ok(b) => b,
        Err(e) => {
            return ApiError::Unexpected {
                status,
                body: format!("(read body failed: {e})"),
            };
        }
    };
    if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body) {
        return ApiError::Server {
            status,
            code: env.error.code,
            message: env.error.message,
        };
    }
    ApiError::Unexpected {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
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

    use std::collections::BTreeMap;
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
            .with_body(r#"{"error":{"code":"slug_taken","message":"app slug already taken"}}"#)
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
    fn set_module_deploy_accepts_version_string_ref() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions/1.2.0/deploy")
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
            "1.2.0",
            &SetModuleDeployInput {
                invoke_target: "my-fn",
                status: None,
            },
        )
        .expect("ok");
        assert_eq!(d.version_id, "ver-uuid");
    }

    /// Small manifest Value for record tests that don't exercise the body.
    fn stub_manifest() -> serde_json::Value {
        json!({"id": "mabc123", "slug": "media"})
    }

    #[test]
    fn record_module_version_sends_manifest_verbatim() {
        let mut server = Server::new();
        // A full manifest (pages, routes) must survive as-is — the platform
        // stores it on the version row and mounts the module's UI from it.
        // Changelog and README both ship as locale maps: `default` plus any
        // `<tag>` translation, all frozen on the version row.
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r##"{"version":"0.1.0","changelog":{"default":"- initial release","zh-TW":"- 初始版本"},"readme":{"default":"# Media\n\nLong-form module docs.","zh-TW":"# 媒體\n\n模組長篇說明。"},"manifest":{"id":"mabc123","slug":"media","ui":{"defaultPages":[{"path":"/"}]},"routes":{"public":[{"method":"GET","path":"/public/me"}]}}}"##.into(),
            ))
            .with_status(201)
            .with_body(
                json!({
                    "id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "version": "0.1.0",
                    "channel": "stable",
                    "published_at": "2026-07-02T00:00:00Z"
                })
                .to_string(),
            )
            .create();

        let manifest = json!({
            "id": "mabc123",
            "slug": "media",
            "ui": {"defaultPages": [{"path": "/"}]},
            "routes": {"public": [{"method": "GET", "path": "/public/me"}]}
        });
        let changelog = BTreeMap::from([
            ("default".to_string(), "- initial release".to_string()),
            ("zh-TW".to_string(), "- 初始版本".to_string()),
        ]);
        let readme = BTreeMap::from([
            (
                "default".to_string(),
                "# Media\n\nLong-form module docs.".to_string(),
            ),
            ("zh-TW".to_string(), "# 媒體\n\n模組長篇說明。".to_string()),
        ]);
        let v = record_module_version(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &RecordModuleVersionInput {
                version: "0.1.0",
                changelog: &changelog,
                readme: &readme,
                manifest: &manifest,
            },
        )
        .expect("ok");
        assert_eq!(v.id, "ver-uuid");
        assert_eq!(v.version, "0.1.0");
        assert_eq!(v.channel.as_deref(), Some("stable"));
    }

    #[test]
    fn record_module_version_omits_changelog_when_empty() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions")
            .match_body(mockito::Matcher::JsonString(
                r#"{"version":"0.1.0","manifest":{"id":"mabc123","slug":"media"}}"#.into(),
            ))
            .with_status(201)
            .with_body(
                json!({
                    "id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "version": "0.1.0"
                })
                .to_string(),
            )
            .create();

        let v = record_module_version(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &RecordModuleVersionInput {
                version: "0.1.0",
                changelog: &BTreeMap::new(),
                readme: &BTreeMap::new(),
                manifest: &stub_manifest(),
            },
        )
        .expect("ok");
        assert_eq!(v.published_at, None);
    }

    #[test]
    fn record_module_version_409_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions")
            .with_status(409)
            .with_body(
                r#"{"error":{"code":"version_exists","message":"this version is already published"}}"#,
            )
            .create();

        let err = record_module_version(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &RecordModuleVersionInput {
                version: "0.1.0",
                changelog: &BTreeMap::new(),
                readme: &BTreeMap::new(),
                manifest: &stub_manifest(),
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 409);
                assert_eq!(code, "version_exists");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn record_module_version_422_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions")
            .with_status(422)
            .with_body(
                r#"{"error":{"code":"changelog_too_large","message":"changelog must be 16384 characters or fewer"}}"#,
            )
            .create();

        let err = record_module_version(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &RecordModuleVersionInput {
                version: "0.1.0",
                changelog: &BTreeMap::from([("default".to_string(), "huge".to_string())]),
                readme: &BTreeMap::new(),
                manifest: &stub_manifest(),
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 422);
                assert_eq!(code, "changelog_too_large");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn record_module_version_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions")
            .with_status(401)
            .with_body(r#"{"error":{"code":"token_expired","message":"token expired"}}"#)
            .create();

        let err = record_module_version(
            &test_client(),
            &server.url(),
            "expired",
            "mod-uuid",
            &RecordModuleVersionInput {
                version: "0.1.0",
                changelog: &BTreeMap::new(),
                readme: &BTreeMap::new(),
                manifest: &stub_manifest(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn list_module_versions_success() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/versions")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "versions": [
                        {"id": "ver-2", "module_id": "mod-uuid", "version": "0.2.0"},
                        {"id": "ver-1", "module_id": "mod-uuid", "version": "0.1.0"}
                    ]
                })
                .to_string(),
            )
            .create();

        let vs = list_module_versions(&test_client(), &server.url(), "AT", "mod-uuid").expect("ok");
        assert_eq!(vs.len(), 2);
        assert_eq!(vs[0].version, "0.2.0");
        assert_eq!(vs[1].id, "ver-1");
    }

    #[test]
    fn list_module_versions_empty() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/versions")
            .with_status(200)
            .with_body(json!({"versions": []}).to_string())
            .create();

        let vs = list_module_versions(&test_client(), &server.url(), "AT", "mod-uuid").expect("ok");
        assert!(vs.is_empty());
    }

    #[test]
    fn list_module_versions_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/versions")
            .with_status(401)
            .create();

        let err =
            list_module_versions(&test_client(), &server.url(), "expired", "mod-uuid").unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn get_tunnel_manifest_success() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/tunnel/manifest/mod-uuid")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "id": "mabc123",
                    "slug": "media",
                    "ui": {"defaultPages": [{"path": "/"}, {"path": "/settings"}]},
                    "routes": {"public": []}
                })
                .to_string(),
            )
            .create();

        let m = get_tunnel_manifest(&test_client(), &server.url(), "AT", "mod-uuid").expect("ok");
        assert_eq!(m["slug"], "media");
        assert_eq!(m["ui"]["defaultPages"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn get_tunnel_manifest_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/tunnel/manifest/mod-uuid")
            .with_status(401)
            .with_body(r#"{"error":{"code":"token_expired","message":"token expired"}}"#)
            .create();

        let err =
            get_tunnel_manifest(&test_client(), &server.url(), "expired", "mod-uuid").unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn get_tunnel_manifest_404_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/tunnel/manifest/mod-uuid")
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"module not found"}}"#)
            .create();

        let err = get_tunnel_manifest(&test_client(), &server.url(), "AT", "mod-uuid").unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 404);
                assert_eq!(code, "not_found");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn get_tunnel_manifest_503_tunnel_offline_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/tunnel/manifest/mod-uuid")
            .with_status(503)
            .with_body(
                r#"{"error":{"code":"tunnel_offline","message":"no live dev tunnel for this module"}}"#,
            )
            .create();

        let err = get_tunnel_manifest(&test_client(), &server.url(), "AT", "mod-uuid").unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 503);
                assert_eq!(code, "tunnel_offline");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn get_app_200_returns_some() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/apps/my-app")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "id": "a-1",
                    "name": "My App",
                    "slug": "my-app",
                    "owner_id": "u-1"
                })
                .to_string(),
            )
            .create();

        let a = get_app(&test_client(), &server.url(), "AT", "my-app").expect("ok");
        assert!(a.is_some());
        assert_eq!(a.unwrap().id, "a-1");
    }

    #[test]
    fn get_app_404_returns_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/apps/nope")
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"app not found"}}"#)
            .create();

        let a = get_app(&test_client(), &server.url(), "AT", "nope").expect("ok");
        assert!(a.is_none());
    }

    #[test]
    fn create_app_deploy_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/a-1/deploys")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"env":"prod","note":"first ship","files":[{"path":"index.html","size":5,"sha256":"aa"}]}"#.into(),
            ))
            .with_status(201)
            .with_body(
                json!({
                    "deploy_id": "d-1",
                    "uploads": [{
                        "path": "index.html",
                        "url": "https://s3.example/put",
                        "headers": {"Content-Type": "text/html"}
                    }]
                })
                .to_string(),
            )
            .create();

        let d = create_app_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "a-1",
            &CreateAppDeployInput {
                env: "prod",
                note: Some("first ship"),
                runtime: None,
                files: &[DeployFile {
                    path: "index.html",
                    size: 5,
                    sha256: "aa",
                }],
            },
        )
        .expect("ok");
        assert_eq!(d.deploy_id, "d-1");
        assert_eq!(d.uploads.len(), 1);
        assert_eq!(d.uploads[0].path, "index.html");
        assert_eq!(
            d.uploads[0].headers.get("Content-Type").map(String::as_str),
            Some("text/html")
        );
    }

    #[test]
    fn create_app_deploy_sends_runtime_when_ssr() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/a-1/deploys")
            .match_body(mockito::Matcher::JsonString(
                r#"{"env":"prod","runtime":"ssr","files":[{"path":"ssr-bundle.zip","size":9,"sha256":"bb"}]}"#.into(),
            ))
            .with_status(201)
            .with_body(
                json!({
                    "deploy_id": "d-2",
                    "uploads": [{
                        "path": "ssr-bundle.zip",
                        "url": "https://s3.example/put",
                        "headers": {}
                    }]
                })
                .to_string(),
            )
            .create();

        let d = create_app_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "a-1",
            &CreateAppDeployInput {
                env: "prod",
                note: None,
                runtime: Some("ssr"),
                files: &[DeployFile {
                    path: "ssr-bundle.zip",
                    size: 9,
                    sha256: "bb",
                }],
            },
        )
        .expect("ok");
        assert_eq!(d.deploy_id, "d-2");
    }

    #[test]
    fn create_app_deploy_omits_note_when_none_and_surfaces_422() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/a-1/deploys")
            .match_body(mockito::Matcher::JsonString(
                r#"{"env":"prod","files":[{"path":"index.html","size":5,"sha256":"aa"}]}"#.into(),
            ))
            .with_status(422)
            .with_body(
                r#"{"error":{"code":"deploy_too_large","message":"total size exceeds 25MB"}}"#,
            )
            .create();

        let err = create_app_deploy(
            &test_client(),
            &server.url(),
            "AT",
            "a-1",
            &CreateAppDeployInput {
                env: "prod",
                note: None,
                runtime: None,
                files: &[DeployFile {
                    path: "index.html",
                    size: 5,
                    sha256: "aa",
                }],
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 422);
                assert_eq!(code, "deploy_too_large");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn finalize_app_deploy_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/a-1/deploys/d-1/finalize")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(json!({"status": "ready"}).to_string())
            .create();

        let s = finalize_app_deploy(&test_client(), &server.url(), "AT", "a-1", "d-1").expect("ok");
        assert_eq!(s.status, "ready");
    }

    #[test]
    fn activate_app_stage_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/a-1/stages/prod/activate")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"deploy_id":"d-1"}"#.into(),
            ))
            .with_status(200)
            .with_body(json!({"active_deploy_id": "d-1"}).to_string())
            .create();

        let a = activate_app_stage(&test_client(), &server.url(), "AT", "a-1", "prod", "d-1")
            .expect("ok");
        assert_eq!(a.active_deploy_id, "d-1");
    }

    #[test]
    fn activate_app_stage_409_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/a-1/stages/prod/activate")
            .with_status(409)
            .with_body(r#"{"error":{"code":"deploy_not_ready","message":"deploy is not ready"}}"#)
            .create();

        let err = activate_app_stage(&test_client(), &server.url(), "AT", "a-1", "prod", "d-1")
            .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 409);
                assert_eq!(code, "deploy_not_ready");
            }
            other => panic!("expected Server, got {other:?}"),
        }
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
