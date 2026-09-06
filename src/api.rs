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
/// Response shape from `POST /v1/dispatch/tunnel/token`. The CLI follows up with
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

/// POST /v1/dispatch/tunnel/token — mint a connect token for the WSS dev tunnel.
pub fn tunnel_token(
    http: &Client,
    dispatch_base: &str,
    access_token: &str,
) -> Result<TunnelToken, ApiError> {
    let endpoint = format!(
        "{}/v1/dispatch/tunnel/token",
        dispatch_base.trim_end_matches('/')
    );
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

/// PUT /v1/modules/{id}/slug — rename a module without changing its platform
/// identity, installed references, or ID-namespaced tables. `module_id` is the
/// catalog UUID (`get_module(...).id`), never the sanitized `.env` form.
///
/// The endpoint ships in the api-platform slug-rename PR and does not exist on
/// `main` yet; this one `format!` is the whole contract surface, so a change to
/// the agreed path or body is a one-line edit here.
pub fn rename_module_slug(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    new_slug: &str,
) -> Result<Module, ApiError> {
    #[derive(Serialize)]
    struct Body<'a> {
        slug: &'a str,
    }

    let endpoint = format!(
        "{}/v1/modules/{module_id}/slug",
        apps_base.trim_end_matches('/')
    );
    let resp = http
        .put(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(&Body { slug: new_slug })
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<Module>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
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
    /// Exactly one immutable module declaration. Existing callers may still
    /// send a legacy semantic manifest; attested deploys send the complete
    /// release-candidate receipt so the API can decode/hash the SDK's exact
    /// manifest bytes and bind artifact evidence before inserting the row.
    #[serde(flatten)]
    pub declaration: ModuleVersionDeclaration<'a>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(dead_code)] // retained for legacy manifest callers; safe deploy uses ReleaseCandidate
pub enum ModuleVersionDeclaration<'a> {
    Manifest {
        manifest: &'a serde_json::Value,
        /// Exact server-confirmed dev-session web descriptor for legacy
        /// manifest callers. It deliberately lives inside this variant so a
        /// release candidate plus a legacy top-level tuple is unrepresentable.
        #[serde(skip_serializing_if = "Option::is_none")]
        web_bundle: Option<WebBundleExpectation<'a>>,
    },
    ReleaseCandidate {
        release_candidate: &'a serde_json::Value,
    },
}

#[derive(Debug, Serialize)]
pub struct WebBundleExpectation<'a> {
    pub session_id: &'a str,
    pub sha256: &'a str,
    pub size_bytes: u64,
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
    #[serde(default)]
    pub web_bundle_url: String,
    #[serde(default)]
    pub web_bundle_sha256: String,
    #[serde(default)]
    pub web_bundle_size_bytes: u64,
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

/// Owner-only immutable release state for one module version. The attested
/// receipt is exposed even before an artifact row exists, so a CLI that races
/// a concurrent `version_exists` can prove it found the exact candidate it
/// prepared before making any artifact or deploy write.
#[derive(Debug, Deserialize)]
pub struct ModuleReleaseState {
    pub version: ModuleReleaseStateVersion,
    pub release_receipt: ModuleReleaseReceipt,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // the exact owner-state version is shared with safe deploy planning
pub struct ModuleReleaseStateVersion {
    pub id: String,
    pub module_id: String,
    pub version: String,
    pub title: String,
    pub description: Option<String>,
    pub channel: String,
    pub changelog: BTreeMap<String, String>,
    pub readme: BTreeMap<String, String>,
    pub migration_app: i64,
    pub migration_module: i64,
    pub manifest: serde_json::Value,
    pub published_at: String,
    #[serde(default)]
    pub yanked_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // ready/deploy are consumed by the follow-on state planner
pub struct ModuleReleaseReceipt {
    pub state: String,
    pub protocol: Option<String>,
    pub source_sha256: Option<String>,
    pub manifest: Option<ModuleReleaseManifestEvidence>,
    pub web: Option<ModuleReleaseWebEvidence>,
    pub artifact: Option<ModuleReleaseArtifactEvidence>,
    pub deploy: Option<ModuleReleaseDeployEvidence>,
    pub coherent: bool,
    pub ready: bool,
}

#[derive(Debug, Deserialize)]
pub struct ModuleReleaseManifestEvidence {
    pub sha256: String,
    pub base64: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // URL is capture state, not immutable candidate input
pub struct ModuleReleaseWebEvidence {
    pub sha256: String,
    pub size_bytes: u64,
    /// Empty while post-commit bundle promotion still needs recovery.
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // lifecycle timestamps are part of the owner API surface
pub struct ModuleReleaseArtifactEvidence {
    pub status: String,
    pub source_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub sha256: String,
    pub size_bytes: u64,
    pub os: String,
    pub arch: String,
    pub format: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub finalized_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // decoded now so the exact wire is ready for the state planner
pub struct ModuleReleaseDeployEvidence {
    pub mode: String,
    pub status: String,
    pub source_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub artifact_sha256: Option<String>,
    pub lambda_version: Option<String>,
    pub lambda_code_sha256: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// GET /v1/modules/{moduleId}/versions/{versionRef} — owner-only exact state
/// for an immutable version. UUID and canonical SemVer refs are accepted by
/// the platform. Missing, foreign-owner, and cross-module refs all return the
/// same structured `not_found` error.
pub fn get_module_release_state(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
) -> Result<ModuleReleaseState, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/versions/{}",
        apps_base.trim_end_matches('/'),
        module_id,
        version_ref
    );
    let resp = http
        .get(endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleReleaseState>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// Result of idempotently promoting the web bundle descriptor frozen on an
/// immutable module version. Recovery never accepts caller-supplied source
/// coordinates; the platform replays only its stored release receipt.
#[derive(Debug, Deserialize)]
pub struct ModuleBundleCapture {
    pub module_id: String,
    pub version_id: String,
    pub version: String,
    pub web_bundle_url: String,
    pub web_bundle_sha256: String,
    pub web_bundle_size_bytes: u64,
}

/// POST /v1/modules/{moduleId}/versions/{versionRef}/bundle/capture — bodyless
/// owner-only recovery for a bound version whose post-commit initial web
/// promotion failed. Idempotent when the pinned destination already exists;
/// legacy-unbound versions fail closed on the platform.
pub fn capture_module_version_bundle(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
) -> Result<ModuleBundleCapture, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/versions/{}/bundle/capture",
        apps_base.trim_end_matches('/'),
        module_id,
        version_ref
    );
    let resp = http
        .post(endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleBundleCapture>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

#[derive(Debug, Serialize)]
pub struct SetModuleDeployInput<'a> {
    /// Attested deploys are explicit: artifact-backed production, or the
    /// narrowly server-gated local simulator fallback after artifact storage
    /// explicitly reported itself unconfigured.
    pub mode: ModuleDeployMode,
    /// Omitted → server default `active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleDeployMode {
    Artifact,
    LocalSimulation,
}

impl ModuleDeployMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::LocalSimulation => "local_simulation",
        }
    }
}

/// Redacted immutable candidate evidence returned with every operational
/// release mutation. Exact manifest bytes and the web session stay private to
/// version creation/owner state, while this receipt is sufficient to prove
/// that create-upload, finalize, and deploy all acted on the same tuple.
#[derive(Debug, Deserialize)]
pub struct ModuleOperationReleaseReceipt {
    pub protocol: String,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub artifact: ModuleOperationArtifactReceipt,
    pub web: Option<ModuleOperationWebReceipt>,
}

#[derive(Debug, Deserialize)]
pub struct ModuleOperationArtifactReceipt {
    pub sha256: String,
    pub size_bytes: i64,
    pub os: String,
    pub arch: String,
    pub format: String,
}

#[derive(Debug, Deserialize)]
pub struct ModuleOperationWebReceipt {
    pub sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // module_id / timestamps are part of the API surface
pub struct ModuleDeploy {
    pub version_id: String,
    pub module_id: String,
    pub invoke_target: String,
    pub status: String,
    pub mode: String,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub artifact_sha256: Option<String>,
    pub lambda_version: Option<String>,
    pub lambda_code_sha256: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub release_receipt: ModuleOperationReleaseReceipt,
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

/// One-time PUT instruction for a version's Lambda artifact, returned by
/// [`create_module_artifact_upload`]. The platform owns the storage key
/// outright and deliberately never exposes it to the CLI.
#[derive(Deserialize)]
#[allow(dead_code)] // version_id / module_id / expires_at are part of the API surface
pub struct ModuleArtifactUpload {
    pub url: String,
    /// Headers the presigned URL expects — sent verbatim on the PUT, exactly
    /// like an app deploy's `UploadTarget`.
    pub headers: BTreeMap<String, String>,
    pub version_id: String,
    pub module_id: String,
    /// RFC3339 presign expiry — informational only (the PUT follows
    /// immediately, so the CLI never acts on it).
    pub expires_at: String,
    pub release_receipt: ModuleOperationReleaseReceipt,
}

impl std::fmt::Debug for ModuleArtifactUpload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ModuleArtifactUpload")
            .field("url", &"<redacted>")
            .field("headers", &"<redacted>")
            .field("version_id", &self.version_id)
            .field("module_id", &self.module_id)
            .field("expires_at", &self.expires_at)
            .field("release_receipt", &self.release_receipt)
            .finish()
    }
}

/// POST /v1/modules/{moduleId}/versions/{versionRef}/artifact — record a
/// pending artifact for the version and mint its presigned PUT. Takes no
/// body: exact size/digest are derived from the release candidate already
/// frozen on the version, then proved against object storage at finalize.
/// The response contains upload instructions but no storage key.
/// `version_ref` is the version UUID or the
/// canonical SemVer string — path-safe verbatim ([0-9A-Za-z.+-] only), same
/// as [`set_module_deploy`]. Owner-scoped; a module the caller doesn't own
/// collapses to 404.
pub fn create_module_artifact_upload(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
) -> Result<ModuleArtifactUpload, ApiError> {
    let resp = http
        .post(artifact_endpoint(apps_base, module_id, version_ref, ""))
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleArtifactUpload>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// The persisted verification state of one version's immutable Lambda zip.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // the whole row is the API surface; deploy only needs success
pub struct ModuleArtifact {
    pub status: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub version_id: String,
    pub module_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub finalized_at: Option<String>,
    pub release_receipt: ModuleOperationReleaseReceipt,
}

/// POST /v1/modules/{moduleId}/versions/{versionRef}/artifact/finalize —
/// HEAD-verify the uploaded object and mark it deployable. Also takes no
/// body: the version receipt and pending row already hold the expected tuple
/// and private storage identity, so there is nothing for the caller to supply,
/// spoof, or learn from the response.
/// `artifact_missing` / `artifact_invalid` /
/// `artifact_storage_unconfigured` come back as `ApiError::Server`.
pub fn finalize_module_artifact(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
) -> Result<ModuleArtifact, ApiError> {
    let resp = http
        .post(artifact_endpoint(
            apps_base,
            module_id,
            version_ref,
            "/finalize",
        ))
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleArtifact>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

fn artifact_endpoint(apps_base: &str, module_id: &str, version_ref: &str, tail: &str) -> String {
    format!(
        "{}/v1/modules/{}/versions/{}/artifact{}",
        apps_base.trim_end_matches('/'),
        module_id,
        version_ref,
        tail
    )
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

/// One module installed into an app. `manifest` is the manifest FROZEN at the
/// installed version — the same document the runtime authorizes against — so
/// it is what capability resolution must read rather than local source.
/// Absent for a dev-mount install (no pinned version) and for a pinned version
/// the platform recorded without one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInstall {
    pub module_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub installed_version: String,
    #[serde(default)]
    pub manifest: Option<serde_json::Value>,
    #[serde(default)]
    pub serving: String,
}

#[derive(Deserialize)]
struct AppInstallList {
    installs: Vec<AppInstall>,
}

/// GET /v1/apps/{appId}/installs — every module installed into the app, with
/// the manifest frozen at its installed version. `app_id` must be the app
/// UUID: the handler resolves the per-app tenant schema from it, so a slug
/// 404s — resolve one with [`get_app`] first. Member-scoped.
pub fn list_app_installs(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_id: &str,
) -> Result<Vec<AppInstall>, ApiError> {
    let endpoint = format!(
        "{}/v1/apps/{}/installs",
        apps_base.trim_end_matches('/'),
        app_id
    );
    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<AppInstallList>()?.installs);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
}

/// One published version of a module, as returned by
/// `GET /v1/modules/{moduleId}/version-history`. The changelog map the
/// platform also returns is deliberately not modelled — the CLI lists
/// versions to pick from, it doesn't render release notes.
#[derive(Debug, Deserialize)]
pub struct PublishedVersion {
    pub version: String,
    #[serde(default)]
    pub published_at: String,
}

#[derive(Deserialize)]
struct PublishedVersionList {
    versions: Vec<PublishedVersion>,
}

/// GET /v1/modules/{moduleId}/version-history — every published (non-yanked)
/// version of a module, newest first.
///
/// This is the any-authenticated-user sibling of [`list_module_versions`]:
/// that one is OWNER-scoped (404 for an app admin who merely installed the
/// module), this one deliberately is not, so an operator can enumerate the
/// versions of somebody else's module before moving an install onto one.
/// A module with no published versions yields an empty list, not a 404.
pub fn list_module_version_history(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
) -> Result<Vec<PublishedVersion>, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/version-history",
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
        return Ok(resp.json::<PublishedVersionList>()?.versions);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiError::Unauthenticated);
    }
    Err(unexpected_body_error(resp))
}

#[derive(Debug, Serialize)]
pub struct UpdateInstallInput<'a> {
    /// Canonical SemVer of the target published version, no `v` prefix.
    pub version: &'a str,
    /// Explicit opt-in to moving BACKWARDS to an older version. Skipped
    /// entirely when false so a platform that predates the field receives
    /// byte-for-byte the body it has always received. camelCase to match the
    /// install family's request bodies (`moduleId`, `routeLocal`).
    #[serde(rename = "allowDowngrade", skip_serializing_if = "is_false")]
    pub allow_downgrade: bool,
}

/// `skip_serializing_if` predicate for [`UpdateInstallInput::allow_downgrade`].
fn is_false(b: &bool) -> bool {
    !*b
}

/// One peer install whose pinned dependency constraint rejects the target
/// version, carried on the 409 `update_held` envelope.
#[derive(Debug, Deserialize)]
pub struct UpdateBlocker {
    /// The peer module's slug.
    pub module: String,
    /// The peer's published version constraint on the module being moved.
    pub constraint: String,
}

/// The two outcomes of a version move that are both *answers*, not failures.
/// `update_held` is modelled as a value rather than an [`ApiError`] for the
/// same reason [`get_module`] returns `Option`: the platform is telling the
/// caller something specific about their request, and the blocker list has
/// to survive the trip. Keeping the error type as `ApiError` also lets the
/// call sit inside `credentials::with_refresh_retry` unchanged.
#[derive(Debug)]
pub enum UpdateOutcome {
    Updated(Box<AppInstall>),
    Held(Vec<UpdateBlocker>),
}

/// Error envelope for the update endpoint. A superset of [`ErrorEnvelope`]:
/// `update_held` adds the blocker list alongside code/message.
#[derive(Deserialize)]
struct UpdateErrorEnvelope {
    error: UpdateErrorBody,
}
#[derive(Deserialize)]
struct UpdateErrorBody {
    code: String,
    message: String,
    #[serde(default)]
    blockers: Vec<UpdateBlocker>,
}

/// POST /v1/apps/{appRef}/modules/{moduleId}/update — move an installed
/// module's version pin to another published version of that module.
/// `app_ref` is an app id or slug (the platform resolves either);
/// `module_id` is the raw platform UUID, not the sanitized `m<hex>` form.
///
/// Owner/admin gated and membership-scoped: a non-member sees the same 404
/// as a missing app. The platform re-checks every peer install's dependency
/// constraint authoritatively and runs the module's app-scope migrations
/// before repinning, so this call can take a while and a failure leaves the
/// install on its old version.
pub fn update_install_version(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_ref: &str,
    module_id: &str,
    input: &UpdateInstallInput,
) -> Result<UpdateOutcome, ApiError> {
    let endpoint = format!(
        "{}/v1/apps/{}/modules/{}/update",
        apps_base.trim_end_matches('/'),
        app_ref,
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
        return Ok(UpdateOutcome::Updated(Box::new(resp.json::<AppInstall>()?)));
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
    if let Ok(env) = serde_json::from_slice::<UpdateErrorEnvelope>(&body) {
        if env.error.code == "update_held" {
            return Ok(UpdateOutcome::Held(env.error.blockers));
        }
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

#[derive(Serialize)]
pub struct DeployGrantInput<'a> {
    pub token: &'a str,
    pub app: &'a str,
    pub env: &'a str,
    /// What the exchanged grant is for: `None` (omitted from the wire body
    /// entirely, so a deploy exchange stays byte-identical to before this
    /// field existed) means `"deploy"`; `Some("client_install")` scopes the
    /// grant to the module-client endpoints instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<&'a str>,
}

impl std::fmt::Debug for DeployGrantInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployGrantInput")
            .field("token", &"<redacted>")
            .field("app", &self.app)
            .field("env", &self.env)
            .field("purpose", &self.purpose)
            .finish()
    }
}

#[derive(Deserialize)]
pub struct DeployGrant {
    pub grant: String,
    #[allow(dead_code)] // expiry is server-enforced; the CLI diagnoses a rejected grant on 401
    pub expires_at: String,
    pub app_id: String,
    pub env: String,
}

impl std::fmt::Debug for DeployGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeployGrant(<redacted>)")
    }
}

/// Errors from the public OIDC exchange retain the binding payload that
/// makes an otherwise opaque 403 actionable to a CI operator.
#[derive(Error)]
pub enum DeployGrantError {
    #[error("OIDC deploy-grant request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("OIDC deploy-grant response could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("OIDC deploy-grant response was invalid: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("{message}")]
    BindingPending {
        sub: String,
        approval_url: String,
        message: String,
    },
    #[error("{message}")]
    BindingRevoked { message: String },
    #[error("OIDC deploy-grant exchange failed: {code}: {message}")]
    Server {
        status: u16,
        code: String,
        message: String,
    },
    #[error("OIDC deploy-grant exchange returned HTTP {status}")]
    Unexpected { status: u16 },
}

impl std::fmt::Debug for DeployGrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(_) => f.write_str("DeployGrantError::Http(<redacted>)"),
            Self::Io(_) => f.write_str("DeployGrantError::Io(<redacted>)"),
            Self::Decode(_) => f.write_str("DeployGrantError::Decode(<redacted>)"),
            Self::BindingPending { .. } => {
                f.write_str("DeployGrantError::BindingPending(<redacted>)")
            }
            Self::BindingRevoked { .. } => {
                f.write_str("DeployGrantError::BindingRevoked(<redacted>)")
            }
            Self::Server { status, .. } => f
                .debug_struct("DeployGrantError::Server")
                .field("status", status)
                .field("details", &"<redacted>")
                .finish(),
            Self::Unexpected { status } => f
                .debug_struct("DeployGrantError::Unexpected")
                .field("status", status)
                .finish(),
        }
    }
}

#[derive(Default, Deserialize)]
struct DeployGrantErrorFields {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    approval_url: Option<String>,
}

#[derive(Deserialize)]
struct DeployGrantErrorBody {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    approval_url: Option<String>,
    #[serde(default)]
    error: Option<DeployGrantErrorFields>,
}

impl std::fmt::Debug for DeployGrantErrorBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeployGrantErrorBody(<redacted>)")
    }
}

impl DeployGrantErrorBody {
    fn merged(self) -> Option<(String, String, Option<String>, Option<String>)> {
        let inner = self.error.unwrap_or_default();
        let flat_code = self.code.filter(|code| !code.trim().is_empty());
        let inner_code = inner.code.filter(|code| !code.trim().is_empty());
        let (code, message) = match flat_code {
            Some(code) => (code, self.message.or(inner.message)),
            None => (inner_code?, inner.message.or(self.message)),
        };

        Some((
            code,
            message.unwrap_or_default(),
            inner.sub.or(self.sub),
            inner.approval_url.or(self.approval_url),
        ))
    }
}

/// Exchange a GitHub Actions OIDC JWT for an app+environment-bound deploy
/// grant. This endpoint is intentionally public; adding bearer auth here
/// would violate the deploy-grant contract.
pub fn exchange_deploy_grant(
    http: &Client,
    apps_base: &str,
    input: &DeployGrantInput<'_>,
) -> Result<DeployGrant, DeployGrantError> {
    let endpoint = format!("{}/v1/oidc/deploy-grant", apps_base.trim_end_matches('/'));
    let resp = http
        .post(&endpoint)
        .header("Accept", "application/json")
        .json(input)
        .send()?;
    let status = resp.status();
    let status_u16 = status.as_u16();
    let body = http::read_capped(resp)?;

    if status.is_success() {
        return Ok(serde_json::from_slice(&body)?);
    }

    let Ok(error) = serde_json::from_slice::<DeployGrantErrorBody>(&body) else {
        return Err(DeployGrantError::Unexpected { status: status_u16 });
    };
    let Some((code, message, sub, approval_url)) = error.merged() else {
        return Err(DeployGrantError::Unexpected { status: status_u16 });
    };
    match code.as_str() {
        "binding_pending" => match (sub, approval_url) {
            (Some(sub), Some(approval_url)) => Err(DeployGrantError::BindingPending {
                sub,
                approval_url,
                message,
            }),
            _ => Err(DeployGrantError::Server {
                status: status_u16,
                code,
                message,
            }),
        },
        "binding_revoked" => Err(DeployGrantError::BindingRevoked { message }),
        _ => Err(DeployGrantError::Server {
            status: status_u16,
            code,
            message,
        }),
    }
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

/// Body for `POST /v1/modules/{moduleId}/dev-bundle/presign` — declares the
/// bundle the CLI is about to upload. The platform derives the S3 key
/// server-side from `(moduleId, ownerUserID, sha256)`; the CLI never picks
/// the key. `content_type` is always `application/javascript` and
/// `size_bytes` is the raw bundle length (server caps it at 32 MiB).
#[derive(Debug, Serialize)]
pub struct DevBundlePresignInput<'a> {
    pub content_type: &'a str,
    pub size_bytes: u64,
    /// Lowercase hex SHA-256 of the bundle bytes (64 chars).
    pub sha256: &'a str,
}

/// Response from the dev-bundle presign step: a short-lived presigned S3 PUT
/// plus the server-derived key the CLI echoes back on confirm.
// Do not derive Debug: upload_url is a bearer-like presigned credential and
// must never become printable through an otherwise harmless debug log.
#[derive(Deserialize)]
pub struct DevBundlePresign {
    pub upload_url: String,
    pub key: String,
    /// Authoritative signed request headers. Callers must apply the complete
    /// map rather than reconstructing storage-provider signing behavior.
    pub headers: BTreeMap<String, String>,
    /// RFC3339 presign expiry — informational only (the PUT follows
    /// immediately, so the CLI never acts on it).
    #[allow(dead_code)]
    pub expires_at: String,
}

impl std::fmt::Debug for DevBundlePresign {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DevBundlePresign")
            .field("upload_url", &"<redacted>")
            .field("key", &self.key)
            .field("headers", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// POST /v1/modules/{moduleId}/dev-bundle/presign — mint a presigned S3 PUT
/// for a dev-tunnel web bundle (opt-in `--share`). Owner-gated: a module the
/// caller doesn't own (or an unknown/non-UUID id) collapses to 404
/// `not_found`. `415` rejects a non-`application/javascript` content type;
/// `413` rejects an oversize (>32 MiB) declaration; `422` rejects an
/// ill-formed sha256 — all surfaced as `ApiError::Server` so the caller can
/// log the specific reason.
pub fn presign_dev_bundle(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    input: &DevBundlePresignInput,
) -> Result<DevBundlePresign, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/dev-bundle/presign",
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
        return Ok(resp.json::<DevBundlePresign>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// Body for `POST /v1/modules/{moduleId}/dev-bundle/confirm` — the key the
/// presign step returned. The platform HEAD-verifies the uploaded object,
/// records the CDN URL as the live tunnel session's dev-bundle pointer, and
/// returns that URL.
#[derive(Debug, Serialize)]
pub struct DevBundleConfirmInput<'a> {
    pub key: &'a str,
    pub session_id: &'a str,
}

/// Response from the dev-bundle confirm step: the CDN URL now served as the
/// module's `bundleUrl` for the live dev tunnel.
#[derive(Debug, Deserialize)]
pub struct DevBundleConfirmed {
    pub url: String,
    pub session_id: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// POST /v1/modules/{moduleId}/dev-bundle/confirm — finalize a dev-bundle
/// upload. The platform HEAD-verifies the object (content-type,
/// size ≤ 32 MiB, declared sha256) and points the live tunnel session at the
/// resulting CDN URL. `403` (IDOR: key outside the caller's own prefix),
/// `409` (session superseded), `410` (session expired/upload missing), and
/// `422` (`confirm_mismatch`) come back as `ApiError::Server`.
pub fn confirm_dev_bundle(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    key: &str,
    session_id: &str,
) -> Result<DevBundleConfirmed, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/dev-bundle/confirm",
        apps_base.trim_end_matches('/'),
        module_id
    );

    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(&DevBundleConfirmInput { key, session_id })
        .send()?;

    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<DevBundleConfirmed>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// The client artifact currently installable for one module installed on an
/// app. `client` is absent whenever nothing is installable right now, and
/// `reason` then says why in a stable machine-readable code — a dev-mode
/// module whose tunnel is gone is the common case, not an error.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppModuleClient {
    pub module_id: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub owner_username: String,
    #[serde(default)]
    pub installed_version: String,
    #[serde(default)]
    pub client: Option<ModuleClientDescriptor>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// The immutable artifact a live tunnel session has published. `revision` is
/// `sha256:<lowercase-hex>` and is the only value a watcher may compare to
/// decide that the artifact changed.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleClientDescriptor {
    // source/format_version/confirmed_at/session_id are part of the contract
    // and are decoded so a mismatch surfaces here rather than silently, but
    // the installer decides on revision + sha256 + size alone.
    #[allow(dead_code)]
    pub source: String,
    pub revision: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[allow(dead_code)]
    pub format_version: u8,
    #[allow(dead_code)]
    #[serde(default)]
    pub confirmed_at: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub session_id: String,
}

#[derive(Deserialize)]
struct AppModuleClientList {
    clients: Vec<AppModuleClient>,
}

fn app_module_clients_endpoint(apps_base: &str, app_id: &str) -> String {
    format!(
        "{}/v1/apps/{}/module-clients",
        apps_base.trim_end_matches('/'),
        app_id
    )
}

/// GET /v1/apps/{appId}/module-clients — one row per module installed on the
/// app, each carrying the client that is installable right now or the reason
/// there is none. `app_id` must be the app UUID for the same reason
/// [`list_app_installs`] needs one: the handler resolves the per-app tenant
/// schema from it. Member-scoped for a user session.
///
/// Also accepts a deploy grant or deploy token as the bearer (`{appId}` then
/// takes an id or slug). Only 401 collapses to [`ApiError::Unauthenticated`]
/// here — a machine credential's 403 (bound to a different app than the
/// path) is left as [`ApiError::Server`]/[`ApiError::Unexpected`] with its
/// real status so a caller presenting one can tell the two apart, matching
/// [`request_module_client_download`].
pub fn list_app_module_clients(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_id: &str,
) -> Result<Vec<AppModuleClient>, ApiError> {
    let endpoint = app_module_clients_endpoint(apps_base, app_id);
    let resp = http
        .get(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<AppModuleClientList>()?.clients);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

// Do not derive Debug: `url` is a presigned credential and must never become
// printable through an otherwise harmless debug log.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleClientDownload {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub revision: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub expires_at: String,
}

fn module_client_download_endpoint(apps_base: &str, app_id: &str, module_id: &str) -> String {
    format!(
        "{}/v1/apps/{}/module-clients/{}/download",
        apps_base.trim_end_matches('/'),
        app_id,
        module_id
    )
}

/// POST /v1/apps/{appId}/module-clients/{moduleId}/download — mint a
/// short-lived presigned GET for exactly the artifact the caller just listed.
/// The URL is minted per request rather than returned by the list so an
/// object credential is never handed out for a module nobody downloads.
///
/// Also accepts a deploy grant or deploy token as the bearer, same as
/// [`list_app_module_clients`] — only 401 collapses to
/// [`ApiError::Unauthenticated`] here, a 403 (wrong app) stays distinguishable.
pub fn request_module_client_download(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    app_id: &str,
    module_id: &str,
) -> Result<ModuleClientDownload, ApiError> {
    let endpoint = module_client_download_endpoint(apps_base, app_id, module_id);
    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<ModuleClientDownload>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

/// Declaration for one canonical module-client artifact. The exact tunnel
/// session is part of both phases so a predecessor cannot publish after a
/// reconnect installs its successor.
#[derive(Debug, Serialize)]
pub struct DevClientPresignInput<'a> {
    pub session_id: &'a str,
    pub size_bytes: u64,
    pub sha256: &'a str,
    pub format_version: u8,
}

// Do not derive Debug: upload_url is a bearer-like presigned credential and
// must never become printable through an otherwise harmless debug log.
#[derive(Deserialize)]
pub struct DevClientPresign {
    pub upload_url: String,
    pub key: String,
    pub headers: BTreeMap<String, String>,
    #[allow(dead_code)]
    pub expires_at: String,
}

fn dev_client_presign_endpoint(apps_base: &str, module_id: &str) -> String {
    format!(
        "{}/v1/modules/{}/dev-client/presign",
        apps_base.trim_end_matches('/'),
        module_id
    )
}

pub fn presign_dev_client(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    input: &DevClientPresignInput<'_>,
) -> Result<DevClientPresign, ApiError> {
    let endpoint = dev_client_presign_endpoint(apps_base, module_id);
    let resp = http
        .post(&endpoint)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .json(input)
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json::<DevClientPresign>()?);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(ApiError::Unauthenticated);
    }
    Err(envelope_error(resp))
}

#[derive(Debug, Serialize)]
pub struct DevClientConfirmInput<'a> {
    pub key: &'a str,
    pub session_id: &'a str,
    pub size_bytes: u64,
    pub sha256: &'a str,
    pub format_version: u8,
}

#[derive(Debug, Deserialize)]
pub struct DevClientConfirmed {
    pub source: String,
    pub revision: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[allow(dead_code)]
    pub confirmed_at: String,
}

pub fn confirm_dev_client(
    http: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    input: &DevClientConfirmInput<'_>,
) -> Result<DevClientConfirmed, ApiError> {
    let endpoint = format!(
        "{}/v1/modules/{}/dev-client/confirm",
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
        return Ok(resp.json::<DevClientConfirmed>()?);
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

    #[test]
    fn list_app_installs_preserves_manifest() {
        let mut server = Server::new();
        let _m = server.mock("GET", "/v1/apps/app-id/installs")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(r#"{"installs":[{"moduleId":"m1","slug":"core","installedVersion":"1.2.3","serving":"tunnel","manifest":{"provides":[{"key":"x"}]}}]}"#)
            .create();
        let installs = list_app_installs(&test_client(), &server.url(), "AT", "app-id").unwrap();
        assert_eq!(
            installs[0].manifest.as_ref().unwrap()["provides"][0]["key"],
            "x"
        );
        assert_eq!(installs[0].serving, "tunnel");
    }

    #[test]
    fn list_app_installs_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/apps/app-id/installs")
            .with_status(401)
            .create();
        assert!(matches!(
            list_app_installs(&test_client(), &server.url(), "bad", "app-id"),
            Err(ApiError::Unauthenticated)
        ));
    }

    #[test]
    fn list_app_module_clients_decodes_an_artifact_and_a_reason() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/apps/app-id/module-clients")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                r#"{"clients":[
                    {"moduleId":"m1","slug":"user-core","ownerUsername":"mirrorstack","installedVersion":"dev",
                     "client":{"source":"tunnel","revision":"sha256:aa","sha256":"aa","sizeBytes":2048,"formatVersion":1,"confirmedAt":"2026-09-06T12:00:00Z","sessionId":"s-1"}},
                    {"moduleId":"m2","slug":"credit","ownerUsername":"mirrorstack","installedVersion":"dev","client":null,"reason":"tunnel_offline"}
                ]}"#,
            )
            .create();

        let clients =
            list_app_module_clients(&test_client(), &server.url(), "AT", "app-id").unwrap();

        assert_eq!(clients.len(), 2);
        let installable = clients[0].client.as_ref().expect("m1 has a client");
        assert_eq!(installable.revision, "sha256:aa");
        assert_eq!(installable.sha256, "aa");
        assert_eq!(installable.size_bytes, 2048);
        assert_eq!(clients[0].owner_username, "mirrorstack");
        assert!(clients[1].client.is_none());
        assert_eq!(clients[1].reason.as_deref(), Some("tunnel_offline"));
    }

    #[test]
    fn list_app_module_clients_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/apps/app-id/module-clients")
            .with_status(401)
            .create();

        assert!(matches!(
            list_app_module_clients(&test_client(), &server.url(), "bad", "app-id"),
            Err(ApiError::Unauthenticated)
        ));
    }

    #[test]
    fn request_module_client_download_surfaces_the_platform_reason() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-id/module-clients/m1/download")
            .with_status(409)
            .with_body(
                r#"{"error":{"code":"tunnel_session_expired","message":"no installable client"}}"#,
            )
            .create();

        // Not formatted with {:?}: ModuleClientDownload deliberately has no
        // Debug impl because it carries a presigned URL.
        match request_module_client_download(&test_client(), &server.url(), "AT", "app-id", "m1") {
            Err(ApiError::Server { code, .. }) => assert_eq!(code, "tunnel_session_expired"),
            Err(other) => panic!("expected a server error carrying the reason, got {other}"),
            Ok(_) => panic!("expected a server error carrying the reason, got success"),
        }
    }

    #[test]
    fn request_module_client_download_decodes_the_verification_metadata() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-id/module-clients/m1/download")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                r#"{"url":"https://example.invalid/signed","sha256":"aa","sizeBytes":2048,"revision":"sha256:aa","expiresAt":"2026-09-06T12:02:00Z"}"#,
            )
            .create();

        let download =
            request_module_client_download(&test_client(), &server.url(), "AT", "app-id", "m1")
                .unwrap();

        assert_eq!(download.url, "https://example.invalid/signed");
        assert_eq!(download.sha256, "aa");
        assert_eq!(download.size_bytes, 2048);
        assert_eq!(download.revision, "sha256:aa");
    }

    #[test]
    fn default_apps_base_builds_bare_module_client_routes() {
        let list = app_module_clients_endpoint(crate::commands::DEFAULT_APPS_API_BASE, "app-id");
        assert_eq!(
            list,
            "https://api.mirrorstack.ai/v1/apps/app-id/module-clients"
        );
        assert!(!list.contains("/apps/v1/"));

        let download =
            module_client_download_endpoint(crate::commands::DEFAULT_APPS_API_BASE, "app-id", "m1");
        assert_eq!(
            download,
            "https://api.mirrorstack.ai/v1/apps/app-id/module-clients/m1/download"
        );
        assert!(!download.contains("/apps/v1/"));
    }

    fn test_client() -> Client {
        http::client(Duration::from_secs(15)).expect("client")
    }

    fn operation_receipt() -> serde_json::Value {
        json!({
            "protocol": "mirrorstack.release-candidate/v1",
            "source_sha256": "a".repeat(64),
            "manifest_sha256": "b".repeat(64),
            "artifact": {
                "sha256": "c".repeat(64),
                "size_bytes": 2048,
                "os": "linux",
                "arch": "arm64",
                "format": "lambda-bootstrap-zip"
            },
            "web": null
        })
    }

    fn deploy_grant_exchange_error(status: usize, body: serde_json::Value) -> DeployGrantError {
        let mut server = Server::new();
        let response = server
            .mock("POST", "/v1/oidc/deploy-grant")
            .with_status(status)
            .with_body(body.to_string())
            .create();
        let error = exchange_deploy_grant(
            &test_client(),
            &server.url(),
            &DeployGrantInput {
                token: "github-jwt",
                app: "company",
                env: "prod",
                purpose: None,
            },
        )
        .expect_err("exchange error");
        response.assert();
        error
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
    fn deploy_grant_exchange_is_public_and_preserves_binding_payload() {
        let mut server = Server::new();
        let success = server
            .mock("POST", "/v1/oidc/deploy-grant")
            .match_header("authorization", mockito::Matcher::Missing)
            .match_body(mockito::Matcher::Json(json!({
                "token": "github-jwt",
                "app": "company",
                "env": "prod"
            })))
            .with_status(200)
            .with_body(
                json!({
                    "grant": "grant-secret",
                    "expires_at": "2026-07-27T05:30:00Z",
                    "app_id": "app-1",
                    "env": "prod"
                })
                .to_string(),
            )
            .create();

        let grant = exchange_deploy_grant(
            &test_client(),
            &server.url(),
            &DeployGrantInput {
                token: "github-jwt",
                app: "company",
                env: "prod",
                purpose: None,
            },
        )
        .expect("exchange");
        assert_eq!(grant.grant, "grant-secret");
        assert_eq!(grant.app_id, "app-1");
        assert_eq!(grant.env, "prod");
        success.assert();

        let pending = server
            .mock("POST", "/v1/oidc/deploy-grant")
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(403)
            .with_body(
                json!({
                    "code": "binding_pending",
                    "message": "approval required",
                    "sub": "repo:org/repo:ref:refs/heads/main",
                    "approval_url": "https://apps.mirrorstack.ai/apps/app-1/settings/deployment"
                })
                .to_string(),
            )
            .create();
        let error = exchange_deploy_grant(
            &test_client(),
            &server.url(),
            &DeployGrantInput {
                token: "different-jwt",
                app: "company",
                env: "prod",
                purpose: None,
            },
        )
        .expect_err("pending");
        match error {
            DeployGrantError::BindingPending {
                sub,
                approval_url,
                message,
            } => {
                assert_eq!(sub, "repo:org/repo:ref:refs/heads/main");
                assert_eq!(
                    approval_url,
                    "https://apps.mirrorstack.ai/apps/app-1/settings/deployment"
                );
                assert_eq!(message, "approval required");
            }
            other => panic!("expected binding payload, got {other:?}"),
        }
        pending.assert();
    }

    /// `purpose` is the whole point of the field: a deploy exchange omits it
    /// (asserted above, where the matcher is the 3-key body with no
    /// `purpose` at all — `Matcher::Json` is exact, so an extra key there
    /// would already fail it) and `apps client install --oidc` sets it.
    #[test]
    fn deploy_grant_exchange_sends_purpose_when_set() {
        let mut server = Server::new();
        let request = server
            .mock("POST", "/v1/oidc/deploy-grant")
            .match_body(mockito::Matcher::Json(json!({
                "token": "github-jwt",
                "app": "company",
                "env": "prod",
                "purpose": "client_install"
            })))
            .with_status(200)
            .with_body(
                json!({
                    "grant": "msg-secret",
                    "expires_at": "2026-07-27T05:30:00Z",
                    "app_id": "app-1",
                    "env": "prod"
                })
                .to_string(),
            )
            .create();

        let grant = exchange_deploy_grant(
            &test_client(),
            &server.url(),
            &DeployGrantInput {
                token: "github-jwt",
                app: "company",
                env: "prod",
                purpose: Some("client_install"),
            },
        )
        .expect("exchange with purpose");
        assert_eq!(grant.grant, "msg-secret");
        request.assert();
    }

    #[test]
    fn deploy_grant_nested_and_mixed_binding_errors_preserve_payload() {
        let sub = "repo:org/repo:ref:refs/heads/main";
        let approval_url = "https://apps.example/approve";
        for (body, expected_message) in [
            (
                json!({
                    "error": {
                        "code": "binding_pending",
                        "message": "nested approval required",
                        "sub": sub,
                        "approval_url": approval_url
                    }
                }),
                "nested approval required",
            ),
            (
                json!({
                    "sub": sub,
                    "approval_url": approval_url,
                    "error": {
                        "code": "binding_pending",
                        "message": "nested approval required"
                    }
                }),
                "nested approval required",
            ),
            (
                json!({
                    "code": "binding_pending",
                    "message": "flat approval required",
                    "sub": "outer-sub",
                    "approval_url": "https://outer.example/approve",
                    "error": {
                        "sub": sub,
                        "approval_url": approval_url
                    }
                }),
                "flat approval required",
            ),
        ] {
            match deploy_grant_exchange_error(403, body) {
                DeployGrantError::BindingPending {
                    sub: actual_sub,
                    approval_url: actual_approval_url,
                    message,
                } => {
                    assert_eq!(actual_sub, sub);
                    assert_eq!(actual_approval_url, approval_url);
                    assert_eq!(message, expected_message);
                }
                other => panic!("expected binding payload, got {other:?}"),
            }
        }
    }

    #[test]
    fn deploy_grant_flat_and_nested_server_errors_preserve_code_and_message() {
        for (status, code, message) in [
            (401, "invalid_token", "token rejected"),
            (404, "app_not_found", "app missing"),
            (429, "rate_limited", "try later"),
        ] {
            let fields = json!({"code": code, "message": message});
            for body in [fields.clone(), json!({"error": fields})] {
                match deploy_grant_exchange_error(status, body) {
                    DeployGrantError::Server {
                        status: actual_status,
                        code: actual_code,
                        message: actual_message,
                    } => {
                        assert_eq!(actual_status, status as u16);
                        assert_eq!(actual_code, code);
                        assert_eq!(actual_message, message);
                    }
                    other => panic!("expected actionable server error, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn deploy_grant_flat_and_nested_revoked_errors_preserve_message() {
        let fields = json!({
            "code": "binding_revoked",
            "message": "binding was revoked"
        });
        for body in [fields.clone(), json!({"error": fields})] {
            match deploy_grant_exchange_error(403, body) {
                DeployGrantError::BindingRevoked { message } => {
                    assert_eq!(message, "binding was revoked");
                }
                other => panic!("expected binding revoked, got {other:?}"),
            }
        }
    }

    #[test]
    fn deploy_grant_error_without_code_is_unexpected() {
        assert!(matches!(
            deploy_grant_exchange_error(502, json!({"detail": "nope"})),
            DeployGrantError::Unexpected { status: 502 }
        ));
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
    fn rename_module_slug_puts_identity_preserving_request() {
        let mut server = Server::new();
        let request = server
            .mock(
                "PUT",
                "/v1/modules/01234567-89ab-cdef-0123-456789abcdef/slug",
            )
            .match_header("authorization", "Bearer AT")
            .match_header("accept", "application/json")
            .match_body(mockito::Matcher::JsonString(
                r#"{"slug":"identity-core"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "id": "01234567-89ab-cdef-0123-456789abcdef",
                    "name": "OAuth Core",
                    "slug": "identity-core",
                    "owner_id": "u-1"
                })
                .to_string(),
            )
            .create();

        let module = rename_module_slug(
            &test_client(),
            &server.url(),
            "AT",
            "01234567-89ab-cdef-0123-456789abcdef",
            "identity-core",
        )
        .unwrap();
        request.assert();
        assert_eq!(module.slug, "identity-core");
        assert_eq!(module.id, "01234567-89ab-cdef-0123-456789abcdef");
    }

    #[test]
    fn rename_module_slug_surfaces_slug_taken_envelope() {
        let mut server = Server::new();
        let request = server
            .mock("PUT", "/v1/modules/module-id/slug")
            .with_status(409)
            .with_body(
                r#"{"error":{"code":"slug_taken","message":"slug already belongs to a module"}}"#,
            )
            .create();

        let error = rename_module_slug(
            &test_client(),
            &server.url(),
            "AT",
            "module-id",
            "identity-core",
        )
        .unwrap_err();
        request.assert();
        match error {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 409);
                assert_eq!(code, "slug_taken");
            }
            other => panic!("expected Server, got {other:?}"),
        }
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
                r#"{"mode":"artifact","status":"active"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "invoke_target": "my-fn",
                    "status": "active",
                    "mode": "artifact",
                    "source_sha256": "a".repeat(64),
                    "manifest_sha256": "b".repeat(64),
                    "artifact_sha256": "c".repeat(64),
                    "lambda_version": "7",
                    "lambda_code_sha256": "lambda-code",
                    "created_at": "2026-07-01T00:00:00Z",
                    "updated_at": "2026-07-02T00:00:00Z",
                    "release_receipt": operation_receipt()
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
                mode: ModuleDeployMode::Artifact,
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
                r#"{"mode":"local_simulation"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "invoke_target": "my-fn",
                    "status": "active",
                    "mode": "local_simulation",
                    "source_sha256": "a".repeat(64),
                    "manifest_sha256": "b".repeat(64),
                    "artifact_sha256": null,
                    "lambda_version": null,
                    "lambda_code_sha256": null,
                    "created_at": "2026-07-01T00:00:00Z",
                    "updated_at": "2026-07-02T00:00:00Z",
                    "release_receipt": operation_receipt()
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
                mode: ModuleDeployMode::LocalSimulation,
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
                mode: ModuleDeployMode::Artifact,
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
                mode: ModuleDeployMode::Artifact,
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
                mode: ModuleDeployMode::Artifact,
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
                    "status": "active",
                    "mode": "artifact",
                    "source_sha256": "a".repeat(64),
                    "manifest_sha256": "b".repeat(64),
                    "artifact_sha256": "c".repeat(64),
                    "lambda_version": "7",
                    "lambda_code_sha256": "lambda-code",
                    "created_at": "2026-07-01T00:00:00Z",
                    "updated_at": "2026-07-02T00:00:00Z",
                    "release_receipt": operation_receipt()
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
                mode: ModuleDeployMode::Artifact,
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
                declaration: ModuleVersionDeclaration::Manifest {
                    manifest: &manifest,
                    web_bundle: None,
                },
            },
        )
        .expect("ok");
        assert_eq!(v.id, "ver-uuid");
        assert_eq!(v.version, "0.1.0");
        assert_eq!(v.channel.as_deref(), Some("stable"));
    }

    #[test]
    fn record_module_version_binds_exact_confirmed_web_descriptor() {
        let mut server = Server::new();
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/versions")
            .match_body(mockito::Matcher::JsonString(
                format!(
                    r#"{{"version":"0.1.0","manifest":{{"id":"mabc123","slug":"media"}},"web_bundle":{{"session_id":"session-1","sha256":"{sha}","size_bytes":422}}}}"#
                ),
            ))
            .with_status(201)
            .with_body(
                json!({
                    "id": "ver-uuid",
                    "module_id": "mod-uuid",
                    "version": "0.1.0",
                    "web_bundle_url": "",
                    "web_bundle_sha256": sha,
                    "web_bundle_size_bytes": 422
                })
                .to_string(),
            )
            .create();

        let manifest = stub_manifest();
        let version = record_module_version(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &RecordModuleVersionInput {
                version: "0.1.0",
                changelog: &BTreeMap::new(),
                readme: &BTreeMap::new(),
                declaration: ModuleVersionDeclaration::Manifest {
                    manifest: &manifest,
                    web_bundle: Some(WebBundleExpectation {
                        session_id: "session-1",
                        sha256: sha,
                        size_bytes: 422,
                    }),
                },
            },
        )
        .unwrap();
        assert_eq!(version.web_bundle_sha256, sha);
        assert_eq!(version.web_bundle_size_bytes, 422);
    }

    #[test]
    fn attested_version_create_sends_the_receipt_without_legacy_manifest_or_web_tuple() {
        let receipt = json!({
            "protocol": "mirrorstack.release-candidate/v1",
            "module_id": "mod-uuid",
            "slug": "media",
            "version": "0.1.0",
            "source_sha256": "a".repeat(64),
            "manifest": {
                "sha256": "b".repeat(64),
                "base64": "e30K"
            },
            "web": {
                "session_id": "session-1",
                "sha256": "c".repeat(64),
                "size_bytes": 422
            },
            "artifact": {
                "sha256": "d".repeat(64),
                "size_bytes": 2048,
                "os": "linux",
                "arch": "arm64",
                "format": "lambda-bootstrap-zip"
            }
        });
        let empty = BTreeMap::new();
        let input = RecordModuleVersionInput {
            version: "0.1.0",
            changelog: &empty,
            readme: &empty,
            declaration: ModuleVersionDeclaration::ReleaseCandidate {
                release_candidate: &receipt,
            },
        };
        let encoded = serde_json::to_value(input).unwrap();
        assert_eq!(encoded.get("release_candidate"), Some(&receipt));
        assert!(encoded.get("manifest").is_none());
        assert!(encoded.get("web_bundle").is_none());
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
                declaration: ModuleVersionDeclaration::Manifest {
                    manifest: &stub_manifest(),
                    web_bundle: None,
                },
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
                declaration: ModuleVersionDeclaration::Manifest {
                    manifest: &stub_manifest(),
                    web_bundle: None,
                },
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
                declaration: ModuleVersionDeclaration::Manifest {
                    manifest: &stub_manifest(),
                    web_bundle: None,
                },
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
                declaration: ModuleVersionDeclaration::Manifest {
                    manifest: &stub_manifest(),
                    web_bundle: None,
                },
            },
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn get_module_release_state_decodes_bound_missing_artifact_receipt() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/versions/1.2.3")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "version": {
                        "id": "ver-uuid",
                        "module_id": "mod-uuid",
                        "version": "1.2.3",
                        "title": "",
                        "description": null,
                        "channel": "stable",
                        "changelog": {"default": "- ship it"},
                        "readme": {"default": "# Media"},
                        "migration_app": 1,
                        "migration_module": 0,
                        "manifest": {"id": "m11111111111111111111111111111111", "slug": "media"},
                        "published_at": "2026-08-31T00:00:00Z",
                        "yanked_at": null,
                        "created_at": "2026-08-31T00:00:00Z"
                    },
                    "release_receipt": {
                        "state": "bound",
                        "protocol": "mirrorstack.release-candidate/v1",
                        "source_sha256": "a".repeat(64),
                        "manifest": {"sha256": "b".repeat(64), "base64": "e30K"},
                        "web": {"sha256": "c".repeat(64), "size_bytes": 422, "url": ""},
                        "artifact": {
                            "status": "missing",
                            "source_sha256": "a".repeat(64),
                            "manifest_sha256": "b".repeat(64),
                            "sha256": "d".repeat(64),
                            "size_bytes": 2048,
                            "os": "linux",
                            "arch": "arm64",
                            "format": "lambda-bootstrap-zip",
                            "created_at": null,
                            "updated_at": null,
                            "finalized_at": null
                        },
                        "deploy": null,
                        "coherent": true,
                        "ready": false
                    }
                })
                .to_string(),
            )
            .create();

        let state =
            get_module_release_state(&test_client(), &server.url(), "AT", "mod-uuid", "1.2.3")
                .unwrap();
        assert_eq!(state.version.id, "ver-uuid");
        assert_eq!(state.release_receipt.state, "bound");
        assert_eq!(
            state.release_receipt.artifact.as_ref().unwrap().status,
            "missing"
        );
        assert!(!state.release_receipt.ready);
    }

    #[test]
    fn get_module_release_state_preserves_owner_hidden_not_found() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/versions/1.2.3")
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"module version not found"}}"#)
            .create();

        let error =
            get_module_release_state(&test_client(), &server.url(), "AT", "mod-uuid", "1.2.3")
                .unwrap_err();
        assert!(
            matches!(error, ApiError::Server { status: 404, ref code, .. } if code == "not_found"),
            "got {error:?}"
        );
    }

    #[test]
    fn capture_module_version_bundle_is_bodyless_and_decodes_exact_receipt() {
        let mut server = Server::new();
        let sha = "c".repeat(64);
        let capture = server
            .mock("POST", "/v1/modules/mod-uuid/versions/1.2.3/bundle/capture")
            .match_header("authorization", "Bearer AT")
            .match_body("")
            .with_status(200)
            .with_body(
                json!({
                    "module_id": "mod-uuid",
                    "version_id": "ver-uuid",
                    "version": "1.2.3",
                    "web_bundle_url": "https://cdn.example.test/index.js",
                    "web_bundle_sha256": sha,
                    "web_bundle_size_bytes": 422
                })
                .to_string(),
            )
            .create();

        let result =
            capture_module_version_bundle(&test_client(), &server.url(), "AT", "mod-uuid", "1.2.3")
                .unwrap();
        capture.assert();
        assert_eq!(result.version_id, "ver-uuid");
        assert_eq!(result.web_bundle_sha256, sha);
        assert_eq!(result.web_bundle_size_bytes, 422);
        assert!(!result.web_bundle_url.is_empty());
    }

    #[test]
    fn capture_module_version_bundle_preserves_structured_recovery_error() {
        let mut server = Server::new();
        let _capture = server
            .mock(
                "POST",
                "/v1/modules/mod-uuid/versions/1.2.3/bundle/capture",
            )
            .with_status(409)
            .with_body(
                r#"{"error":{"code":"bundle_capture_conflict","message":"pinned destination differs"}}"#,
            )
            .create();

        let error =
            capture_module_version_bundle(&test_client(), &server.url(), "AT", "mod-uuid", "1.2.3")
                .unwrap_err();
        assert!(
            matches!(error, ApiError::Server { status: 409, ref code, .. } if code == "bundle_capture_conflict"),
            "got {error:?}"
        );
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
    fn presign_dev_bundle_success_sends_declaration() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/presign")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"content_type":"application/javascript","size_bytes":422,"sha256":"abc123"}"#
                    .into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "upload_url": "https://s3.example/put?sig=1",
                    "key": "modules/mod-uuid/dev/u-1/abc123/web/index.js",
                    "headers": {
                        "Content-Length": "422",
                        "Content-Type": "application/javascript"
                    },
                    "expires_at": "2026-07-14T00:15:00Z"
                })
                .to_string(),
            )
            .create();

        let p = presign_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevBundlePresignInput {
                content_type: "application/javascript",
                size_bytes: 422,
                sha256: "abc123",
            },
        )
        .expect("ok");
        assert_eq!(p.upload_url, "https://s3.example/put?sig=1");
        assert_eq!(p.key, "modules/mod-uuid/dev/u-1/abc123/web/index.js");
        assert_eq!(
            p.headers.get("Content-Length").map(String::as_str),
            Some("422")
        );
    }

    #[test]
    fn presign_dev_bundle_rejects_legacy_success_without_signed_headers() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/presign")
            .with_status(200)
            .with_body(
                json!({
                    "upload_url": "https://s3.example/put?secret=redacted",
                    "key": "modules/mod-uuid/dev/u-1/abc123/web/index.js",
                    "expires_at": "2026-07-14T00:15:00Z"
                })
                .to_string(),
            )
            .create();

        let error = presign_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevBundlePresignInput {
                content_type: "application/javascript",
                size_bytes: 422,
                sha256: "abc123",
            },
        )
        .unwrap_err();
        assert!(matches!(error, ApiError::Http(_)), "got {error:?}");
    }

    #[test]
    fn presign_dev_bundle_413_oversize_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/presign")
            .with_status(413)
            .with_body(r#"{"error":{"code":"bundle_too_large","message":"bundle exceeds 32 MiB"}}"#)
            .create();

        let err = presign_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevBundlePresignInput {
                content_type: "application/javascript",
                size_bytes: 99,
                sha256: "abc123",
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 413);
                assert_eq!(code, "bundle_too_large");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn presign_dev_bundle_404_not_owner_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/presign")
            .with_status(404)
            .with_body(r#"{"error":{"code":"not_found","message":"module not found"}}"#)
            .create();

        let err = presign_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevBundlePresignInput {
                content_type: "application/javascript",
                size_bytes: 1,
                sha256: "abc123",
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
    fn presign_dev_bundle_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/presign")
            .with_status(401)
            .create();

        let err = presign_dev_bundle(
            &test_client(),
            &server.url(),
            "expired",
            "mod-uuid",
            &DevBundlePresignInput {
                content_type: "application/javascript",
                size_bytes: 1,
                sha256: "abc123",
            },
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::Unauthenticated), "got {err:?}");
    }

    #[test]
    fn confirm_dev_bundle_success_returns_cdn_url() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/confirm")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"key":"modules/mod-uuid/dev/u-1/abc123/web/index.js","session_id":"session-1"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "url": "https://cdn.mirrorstack.ai/modules/mod-uuid/dev/u-1/abc123/web/index.js",
                    "session_id": "session-1",
                    "sha256": "abc123",
                    "size_bytes": 422
                })
                .to_string(),
            )
            .create();

        let c = confirm_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "modules/mod-uuid/dev/u-1/abc123/web/index.js",
            "session-1",
        )
        .expect("ok");
        assert_eq!(
            c.url,
            "https://cdn.mirrorstack.ai/modules/mod-uuid/dev/u-1/abc123/web/index.js"
        );
    }

    #[test]
    fn confirm_dev_bundle_422_mismatch_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/confirm")
            .with_status(422)
            .with_body(
                r#"{"error":{"code":"confirm_mismatch","message":"object hash does not match declared sha256"}}"#,
            )
            .create();

        let err = confirm_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "some/key",
            "session-1",
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 422);
                assert_eq!(code, "confirm_mismatch");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn confirm_dev_bundle_403_idor_surfaces_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/confirm")
            .with_status(403)
            .with_body(r#"{"error":{"code":"forbidden","message":"key outside caller prefix"}}"#)
            .create();

        let err = confirm_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "modules/other/dev/u-2/x/web/index.js",
            "session-1",
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 403);
                assert_eq!(code, "forbidden");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn confirm_dev_bundle_rejects_legacy_url_only_success() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-bundle/confirm")
            .with_status(200)
            .with_body(r#"{"url":"https://cdn.example/legacy.js"}"#)
            .create();

        let error = confirm_dev_bundle(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            "some/key",
            "session-1",
        )
        .unwrap_err();
        assert!(matches!(error, ApiError::Http(_)), "got {error:?}");
    }

    #[test]
    fn default_apps_base_builds_bare_dev_client_presign_route() {
        let endpoint =
            dev_client_presign_endpoint(crate::commands::DEFAULT_APPS_API_BASE, "mod-uuid");

        assert_eq!(
            endpoint,
            "https://api.mirrorstack.ai/v1/modules/mod-uuid/dev-client/presign"
        );
        assert!(!endpoint.contains("/apps/v1/"));
    }

    #[test]
    fn presign_dev_client_binds_exact_session_and_artifact() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-client/presign")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"session_id":"session-1","size_bytes":512,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","format_version":1}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "upload_url": "https://s3.example/put?secret=redacted",
                    "key": "dev-client/uploads/mod-uuid/session/sha.tgz",
                    "headers": {"Content-Type": "application/octet-stream"},
                    "expires_at": "2026-08-22T00:01:00Z"
                })
                .to_string(),
            )
            .create();

        let response = presign_dev_client(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevClientPresignInput {
                session_id: "session-1",
                size_bytes: 512,
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                format_version: 1,
            },
        )
        .unwrap();

        assert_eq!(response.headers["Content-Type"], "application/octet-stream");
        assert!(response.upload_url.contains("secret=redacted"));
    }

    #[test]
    fn confirm_dev_client_repeats_presigned_declaration() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-client/confirm")
            .match_header("authorization", "Bearer AT")
            .match_body(mockito::Matcher::JsonString(
                r#"{"key":"dev-client/uploads/mod-uuid/session/sha.tgz","session_id":"session-1","size_bytes":512,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","format_version":1}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({
                    "source": "tunnel",
                    "revision": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "size_bytes": 512,
                    "confirmed_at": "2026-08-22T00:00:00Z"
                })
                .to_string(),
            )
            .create();

        let response = confirm_dev_client(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevClientConfirmInput {
                key: "dev-client/uploads/mod-uuid/session/sha.tgz",
                session_id: "session-1",
                size_bytes: 512,
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                format_version: 1,
            },
        )
        .unwrap();

        assert_eq!(response.source, "tunnel");
        assert!(response.revision.starts_with("sha256:"));
        assert_eq!(response.size_bytes, 512);
    }

    #[test]
    fn confirm_dev_client_preserves_superseded_session_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/modules/mod-uuid/dev-client/confirm")
            .with_status(409)
            .with_body(r#"{"error":{"code":"tunnel_session_superseded","message":"session was replaced"}}"#)
            .create();

        let error = confirm_dev_client(
            &test_client(),
            &server.url(),
            "AT",
            "mod-uuid",
            &DevClientConfirmInput {
                key: "key",
                session_id: "old",
                size_bytes: 1,
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                format_version: 1,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ApiError::Server { status: 409, ref code, .. }
                if code == "tunnel_session_superseded"
        ));
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

    #[test]
    fn list_module_version_history_returns_versions_newest_first() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/version-history")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({"versions": [
                    {"version": "0.2.0", "changelog": {"default": "notes"}, "published_at": "2026-07-30T00:00:00Z"},
                    {"version": "0.1.0", "changelog": {}, "published_at": "2026-07-01T00:00:00Z"}
                ]})
                .to_string(),
            )
            .create();

        let versions =
            list_module_version_history(&test_client(), &server.url(), "AT", "mod-uuid").unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "0.2.0");
        assert_eq!(versions[0].published_at, "2026-07-30T00:00:00Z");
    }

    #[test]
    fn list_module_version_history_empty_for_versionless_module() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/modules/mod-uuid/version-history")
            .with_status(200)
            .with_body(r#"{"versions":[]}"#)
            .create();

        let versions =
            list_module_version_history(&test_client(), &server.url(), "AT", "mod-uuid").unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn update_install_version_omits_allow_downgrade_when_false() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-1/modules/mod-uuid/update")
            .match_header("authorization", "Bearer AT")
            // A platform that predates opt-in downgrades must see exactly the
            // body it has always seen.
            .match_body(mockito::Matcher::JsonString(
                r#"{"version":"0.2.0"}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({"moduleId": "mod-uuid", "slug": "media", "installedVersion": "0.2.0"})
                    .to_string(),
            )
            .create();

        let outcome = update_install_version(
            &test_client(),
            &server.url(),
            "AT",
            "app-1",
            "mod-uuid",
            &UpdateInstallInput {
                version: "0.2.0",
                allow_downgrade: false,
            },
        )
        .expect("ok");
        match outcome {
            UpdateOutcome::Updated(install) => {
                assert_eq!(install.installed_version, "0.2.0");
                assert_eq!(install.slug, "media");
            }
            other => panic!("expected Updated, got {other:?}"),
        }
    }

    #[test]
    fn update_install_version_sends_allow_downgrade_when_set() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-1/modules/mod-uuid/update")
            .match_body(mockito::Matcher::JsonString(
                r#"{"version":"0.1.0","allowDowngrade":true}"#.into(),
            ))
            .with_status(200)
            .with_body(
                json!({"moduleId": "mod-uuid", "slug": "media", "installedVersion": "0.1.0"})
                    .to_string(),
            )
            .create();

        update_install_version(
            &test_client(),
            &server.url(),
            "AT",
            "app-1",
            "mod-uuid",
            &UpdateInstallInput {
                version: "0.1.0",
                allow_downgrade: true,
            },
        )
        .expect("ok");
    }

    #[test]
    fn update_install_version_409_held_carries_blockers() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-1/modules/mod-uuid/update")
            .with_status(409)
            .with_body(
                json!({"error": {
                    "code": "update_held",
                    "message": "update held by installed peer dependency constraints",
                    "blockers": [{"module": "oauth-google", "constraint": "^0.1"}]
                }})
                .to_string(),
            )
            .create();

        let outcome = update_install_version(
            &test_client(),
            &server.url(),
            "AT",
            "app-1",
            "mod-uuid",
            &UpdateInstallInput {
                version: "0.2.0",
                allow_downgrade: false,
            },
        )
        .expect("held is an outcome, not an error");
        match outcome {
            UpdateOutcome::Held(blockers) => {
                assert_eq!(blockers.len(), 1);
                assert_eq!(blockers[0].module, "oauth-google");
                assert_eq!(blockers[0].constraint, "^0.1");
            }
            other => panic!("expected Held, got {other:?}"),
        }
    }

    #[test]
    fn update_install_version_422_surfaces_downgrade_code() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-1/modules/mod-uuid/update")
            .with_status(422)
            .with_body(
                // Verbatim from api-platform#442's handler for the
                // semver-backward refusal, which is what a request that did
                // NOT opt in gets back. The retired "target version must be
                // newer than the installed version" no longer exists there:
                // #442 made backward moves opt-in rather than impossible.
                r#"{"error":{"code":"downgrade_not_supported","message":"target version is older than the installed version; re-send with \"allowDowngrade\": true to accept the app-scope migration rollback and the data it destroys"}}"#,
            )
            .create();

        let err = update_install_version(
            &test_client(),
            &server.url(),
            "AT",
            "app-1",
            "mod-uuid",
            &UpdateInstallInput {
                version: "0.1.0",
                allow_downgrade: false,
            },
        )
        .unwrap_err();
        match err {
            ApiError::Server { status, code, .. } => {
                assert_eq!(status, 422);
                assert_eq!(code, "downgrade_not_supported");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn update_install_version_401_is_unauthenticated() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/apps/app-1/modules/mod-uuid/update")
            .with_status(401)
            .with_body(r#"{"error":{"code":"token_expired","message":"expired"}}"#)
            .create();

        assert!(matches!(
            update_install_version(
                &test_client(),
                &server.url(),
                "bad",
                "app-1",
                "mod-uuid",
                &UpdateInstallInput {
                    version: "0.2.0",
                    allow_downgrade: false,
                },
            ),
            Err(ApiError::Unauthenticated)
        ));
    }
}
