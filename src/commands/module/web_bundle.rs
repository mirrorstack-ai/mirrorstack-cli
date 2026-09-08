//! Version-scoped web-bundle upload for `mirrorstack module deploy`.
//!
//! 🔴 THIS EXISTS BECAUSE `--share` IS NOT A DEPLOY PATH. Before it, a
//! version's `web_bundle_url` could be filled exactly one way: the platform
//! promoting an object a `mirrorstack dev --share` session had uploaded and
//! the platform had confirmed. That made a developer's tunnel a required
//! input to a production deploy — and api-platform already logs the resulting
//! state at Error level, describing a version that "serves its UI from a
//! laptop and stops working the moment that laptop closes." `--share` lets
//! someone else's device reach a LOCAL module while the tunnel is up; its
//! objects are dev-scoped and reaped. A deploy ships its own bytes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;

use crate::api::{self, ApiError};
use crate::http;

/// Conventional build output every module's web project writes, and the same
/// relative path `mirrorstack dev` watches and `--share` uploads.
pub(crate) const WEB_BUNDLE_REL: &str = "web/dist/index.js";

/// Matches `maxModuleBundleBytes` in api-platform's module_bundle.go. Checked
/// here so an oversize bundle fails before a credential is minted rather than
/// after the bytes are on the wire; the platform re-checks regardless, since
/// a client-side bound is a courtesy and never an enforcement.
const MAX_WEB_BUNDLE_BYTES: u64 = 32 * 1024 * 1024;

const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

const CODE_WEB_BUNDLE_UNCONFIGURED: &str = "web_bundle_storage_unconfigured";

/// What happened to the web bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WebBundleOutcome {
    /// Uploaded and promoted; the version serves its own UI.
    Shipped {
        url: String,
        sha256: String,
        size_bytes: i64,
    },
    /// The platform has no bundle storage wired (local prod-sim). Not an
    /// error, for the same reason the artifact leg tolerates it.
    StorageUnconfigured,
    /// This platform build predates the web-bundle routes. The deploy
    /// continues; the version simply is not bundle-backed yet.
    EndpointsMissing,
    /// The version already carries a bundle. Versions are immutable, so this
    /// is the expected answer on a re-deploy of an unchanged version.
    AlreadyRecorded,
}

/// Where the module's built bundle lives.
///
/// 🔴 THE TWO ABSENCES ARE NOT THE SAME. A module with no `web/` directory
/// ships no UI and must deploy cleanly — returning an error there would break
/// every headless module. A module that HAS a web project but no built bundle
/// is a different thing entirely: its UI silently would not ship, which is the
/// failure this whole path exists to prevent, so that one is fatal and names
/// the file.
pub(crate) fn locate(dir: &Path) -> Result<Option<PathBuf>> {
    let path = dir.join(WEB_BUNDLE_REL);
    if path.is_file() {
        return Ok(Some(path));
    }
    if !dir.join("web").is_dir() {
        return Ok(None);
    }
    Err(anyhow!(
        "no web bundle at {} — the module has a web project but nothing built it. Its UI ships from this file, and a version records the bundle it was cut with, so deploying now would publish a module that cannot render.",
        path.display()
    ))
}

/// Upload the built bundle for `version_ref` and promote it.
pub(crate) fn ship(
    api_client: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
    bundle_path: &Path,
) -> Result<WebBundleOutcome> {
    let bytes =
        std::fs::read(bundle_path).with_context(|| format!("read {}", bundle_path.display()))?;
    if bytes.is_empty() {
        return Err(anyhow!(
            "web bundle at {} is empty — the platform refuses a zero-byte bundle",
            bundle_path.display()
        ));
    }
    if bytes.len() as u64 > MAX_WEB_BUNDLE_BYTES {
        return Err(anyhow!(
            "web bundle too large: {} bytes (capped at {} bytes, matching the platform's own ceiling)",
            bytes.len(),
            MAX_WEB_BUNDLE_BYTES
        ));
    }

    let upload = match api::create_module_web_bundle_upload(
        api_client,
        apps_base,
        access_token,
        module_id,
        version_ref,
    ) {
        Ok(upload) => upload,
        Err(error) if storage_unconfigured(&error) => {
            return Ok(WebBundleOutcome::StorageUnconfigured);
        }
        Err(error) if endpoints_missing(&error) => return Ok(WebBundleOutcome::EndpointsMissing),
        Err(error) if already_recorded(&error) => return Ok(WebBundleOutcome::AlreadyRecorded),
        Err(ApiError::Unauthenticated) => return Err(anyhow!("session expired")),
        Err(error) => return Err(api_error(error)),
    };

    // The presigned URL carries its own auth, so this PUT goes out on a
    // client with no bearer token and an upload-sized timeout.
    let upload_client = http::client(UPLOAD_TIMEOUT)?;
    put(&upload_client, &upload.url, &bytes)?;

    match api::finalize_module_web_bundle(
        api_client,
        apps_base,
        access_token,
        module_id,
        version_ref,
    ) {
        Ok(bundle) => Ok(WebBundleOutcome::Shipped {
            url: bundle.url,
            sha256: bundle.sha256,
            size_bytes: bundle.size_bytes,
        }),
        Err(error) if storage_unconfigured(&error) => Ok(WebBundleOutcome::StorageUnconfigured),
        Err(error) if endpoints_missing(&error) => Ok(WebBundleOutcome::EndpointsMissing),
        Err(error) if already_recorded(&error) => Ok(WebBundleOutcome::AlreadyRecorded),
        Err(ApiError::Unauthenticated) => Err(anyhow!("session expired")),
        Err(error) => Err(api_error(error)),
    }
}

fn put(client: &Client, url: &str, bytes: &[u8]) -> Result<()> {
    // `reqwest::Error` renders the URL it failed on, and this one carries a
    // live signature. In a CI log that is a usable write credential until it
    // expires, so strip the URL before the error can reach stderr.
    let resp = client
        .put(url)
        .body(bytes.to_vec())
        .send()
        .map_err(|error| {
            let _ = error.without_url();
            anyhow!("web bundle upload failed before the platform answered")
        })?;
    let status = resp.status();
    if !status.is_success() {
        // Storage bodies may echo the full signed request URI. Never expose
        // bearer-like presign query parameters through a CLI error.
        return Err(anyhow!("presigned PUT failed: HTTP {}", status.as_u16()));
    }
    Ok(())
}

fn storage_unconfigured(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Server { status: 503, code, .. } if code == CODE_WEB_BUNDLE_UNCONFIGURED
    )
}

fn already_recorded(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Server { status: 409, code, .. } if code == "web_bundle_conflict"
    )
}

fn endpoints_missing(error: &ApiError) -> bool {
    matches!(error, ApiError::Unexpected { status: 404, .. })
}

fn api_error(error: ApiError) -> anyhow::Error {
    match error {
        ApiError::Server { code, message, .. } => anyhow!("{code}: {message}"),
        other => anyhow!(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn server(status: u16, code: &str) -> ApiError {
        ApiError::Server {
            status,
            code: code.to_string(),
            message: "x".to_string(),
        }
    }

    // 🔴 THE THREE STATES MUST NOT COLLAPSE INTO TWO. A headless module and a
    // module whose bundle was never built both "have no bundle", but treating
    // them alike either breaks every headless deploy or silently publishes a
    // UI module that cannot render.
    #[test]
    fn locate_separates_headless_from_unbuilt_from_built() {
        // Headless: no web/ at all — deploys cleanly, ships nothing.
        let headless = tempfile::tempdir().unwrap();
        assert_eq!(locate(headless.path()).unwrap(), None);

        // Has a web project, nothing built: fatal, and the error names the
        // file, because "build your web project" is not actionable on its own
        // in a 14-module workspace.
        let unbuilt = tempfile::tempdir().unwrap();
        fs::create_dir_all(unbuilt.path().join("web/src")).unwrap();
        let err = locate(unbuilt.path()).unwrap_err().to_string();
        assert!(
            err.contains(WEB_BUNDLE_REL),
            "error did not name the path: {err}"
        );

        // Built: the control. Without it, a `locate` that always failed would
        // satisfy the assertion above.
        let built = tempfile::tempdir().unwrap();
        fs::create_dir_all(built.path().join("web/dist")).unwrap();
        fs::write(
            built.path().join(WEB_BUNDLE_REL),
            b"export function mount(){}",
        )
        .unwrap();
        assert_eq!(
            locate(built.path()).unwrap(),
            Some(built.path().join(WEB_BUNDLE_REL))
        );
    }

    #[test]
    fn a_directory_is_not_a_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        // is_file() is the check, not exists(): a directory at the bundle path
        // would otherwise read as a built bundle and fail later, on the PUT.
        fs::create_dir_all(tmp.path().join(WEB_BUNDLE_REL)).unwrap();
        assert!(locate(tmp.path()).is_err());
    }

    #[test]
    fn error_classification_is_narrow() {
        assert!(storage_unconfigured(&server(
            503,
            CODE_WEB_BUNDLE_UNCONFIGURED
        )));
        assert!(already_recorded(&server(409, "web_bundle_conflict")));
        assert!(endpoints_missing(&ApiError::Unexpected {
            status: 404,
            body: String::new()
        }));

        // Each classifier must reject the others' shapes, or a real failure
        // gets swallowed as a benign one and the deploy reports success with
        // no UI shipped.
        assert!(!storage_unconfigured(&server(503, "something_else")));
        assert!(!storage_unconfigured(&server(
            500,
            CODE_WEB_BUNDLE_UNCONFIGURED
        )));
        assert!(!already_recorded(&server(409, "artifact_already_ready")));
        assert!(!already_recorded(&server(422, "web_bundle_conflict")));
        assert!(!endpoints_missing(&ApiError::Unexpected {
            status: 500,
            body: String::new()
        }));
        assert!(!endpoints_missing(&server(404, "module_not_found")));
    }
}
