//! Persisted OAuth tokens. File location is
//! `<config_dir>/mirrorstack/cli/credentials.json` — `~/.config` on
//! Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on
//! Windows. The `cli` segment reserves room for future MirrorStack
//! tools (SDK, daemons, GUIs) under the same parent. Mode 0600 on Unix.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::api::{self, ApiError};
use crate::commands::{DEFAULT_API_BASE, ENV_API_URL, resolve_base, warn_prefix};
use crate::http;

/// Local access-token lifetime re-derived on every refresh. The platform's
/// `TokenConfig` mints 15-minute access tokens; the refresh response's
/// `expires_at` is informational only, so we recompute the TTL locally to
/// keep `expires_at` honest on disk. Mirrors `login`'s use of the
/// exchange's `expires_in`.
const ACCESS_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(with = "humantime_serde_compat")]
    pub expires_at: SystemTime,
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("credentials: not found (run `mirrorstack login`)")]
    NotFound,
    #[error("credentials: I/O: {0}")]
    Io(#[from] io::Error),
    #[error("credentials: decode: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("credentials: locate config dir")]
    NoConfigDir,
}

pub fn path() -> Result<PathBuf, LoadError> {
    let dir = dirs::config_dir().ok_or(LoadError::NoConfigDir)?;
    Ok(dir.join("mirrorstack").join("cli").join("credentials.json"))
}

/// Atomically write `creds` to disk with mode 0600 on Unix. Atomic =
/// write to a temp file in the same directory, then rename — protects
/// against truncated files if the process is killed mid-write.
pub fn save(creds: &Credentials) -> Result<()> {
    let p = path().context("credentials: path")?;
    let parent = p.parent().expect("credentials path has parent");
    fs::create_dir_all(parent).context("credentials: mkdir")?;

    let mut tmp = NamedTempFile::new_in(parent).context("credentials: tempfile")?;
    let json = serde_json::to_vec_pretty(creds).context("credentials: encode")?;
    tmp.as_file_mut()
        .write_all(&json)
        .context("credentials: write")?;
    tmp.as_file_mut().flush().context("credentials: flush")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))
            .context("credentials: chmod")?;
    }

    tmp.persist(&p)
        .map_err(|e| anyhow::anyhow!("credentials: rename: {e}"))?;
    Ok(())
}

#[allow(dead_code)] // API surface for future commands (whoami, etc.)
pub fn load() -> Result<Credentials, LoadError> {
    let p = path()?;
    match fs::read(&p) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(LoadError::NotFound),
        Err(e) => Err(LoadError::Io(e)),
    }
}

/// Exchange the stored refresh token for a fresh access + refresh pair,
/// persist the rotated pair, and return the new credentials.
///
/// `expires_at` is re-derived locally from [`ACCESS_TTL`] (the refresh
/// response's `expires_at` is informational only). The platform rotates
/// the refresh token on every refresh, so the rotated value MUST be saved
/// back — callers that drop the return value still get the new tokens on
/// disk.
///
/// Saving is best-effort: a save failure is surfaced as a non-fatal
/// warning (the in-memory credentials are still valid for the rest of the
/// command) rather than failing the whole operation. A refresh that 401s
/// returns `ApiError::Unauthenticated` via the `?` — the refresh token
/// itself is gone, so the caller should fall back to the login hint.
pub fn refresh_and_save(refresh_token: &str) -> Result<Credentials> {
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let client = http::client(std::time::Duration::from_secs(15))
        .context("credentials: build HTTP client for refresh")?;
    let refreshed = api::refresh_session(&client, &api_base, refresh_token)?;
    let creds = Credentials {
        access_token: refreshed.access_token,
        refresh_token: refreshed.refresh_token,
        expires_at: SystemTime::now() + ACCESS_TTL,
    };
    if let Err(e) = save(&creds) {
        eprintln!(
            "{} refreshed session but failed to save credentials: {e:#}",
            warn_prefix()
        );
    }
    Ok(creds)
}

/// Run an authenticated call, transparently refreshing the access token
/// and retrying ONCE on a 401.
///
/// `call` is handed the current access token and runs against it. If it
/// returns `Ok` or any error other than [`ApiError::Unauthenticated`],
/// that result is returned unchanged. On `Unauthenticated`, this attempts
/// [`refresh_and_save`]: on success the rotated credentials are written
/// back through `creds` and `call` runs exactly one more time (its result
/// — even a second `Unauthenticated` — is returned as-is). If the refresh
/// itself fails (revoked / expired session), the original `Unauthenticated`
/// is returned so the caller's terminal arm surfaces the login hint.
///
/// At most one refresh + one retry — never a loop.
pub fn with_refresh_retry<T>(
    creds: &mut Credentials,
    mut call: impl FnMut(&str) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    match call(&creds.access_token) {
        Err(ApiError::Unauthenticated) => {}
        other => return other,
    }
    match refresh_and_save(&creds.refresh_token) {
        Ok(new) => {
            *creds = new;
            call(&creds.access_token)
        }
        Err(_) => Err(ApiError::Unauthenticated),
    }
}

/// Wrap [`load`] with the auth-required command idiom: a missing file
/// becomes a "run `mirrorstack login`" hint instead of the raw error.
/// Used by every command that needs an authenticated session.
///
/// When the stored access token is already past its `expires_at`, this
/// proactively refreshes from the stored refresh token before returning,
/// so callers start with a live token. A refresh failure here is
/// swallowed: the (stale) credentials are returned and the command's own
/// on-401 retry (see [`with_refresh_retry`]) gets the next attempt at
/// recovery before surfacing the login hint.
pub fn load_or_login_hint() -> Result<Credentials> {
    match load() {
        Ok(c) => {
            if c.expires_at <= SystemTime::now() {
                if let Ok(refreshed) = refresh_and_save(&c.refresh_token) {
                    return Ok(refreshed);
                }
            }
            Ok(c)
        }
        Err(LoadError::NotFound) => Err(anyhow::anyhow!(
            "not signed in. Run `mirrorstack login` to sign in."
        )),
        Err(e) => Err(e.into()),
    }
}

/// Wipe the credentials file. Idempotent — a missing file is treated as
/// success so callers don't need to special-case "already logged out".
/// On other errors (typically permissions) the path is included in the
/// message so the user can act manually.
pub fn delete() -> Result<()> {
    let p = path().context("credentials: path")?;
    match fs::remove_file(&p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("credentials: remove {}: {e}", p.display())),
    }
}

/// Encode `SystemTime` as RFC 3339 in JSON. Avoids pulling chrono just
/// for this; serde_json's default for SystemTime is a tagged struct
/// which is ugly on disk.
mod humantime_serde_compat {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
        let secs = t
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        s.serialize_f64(secs)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
        let secs = f64::deserialize(d)?;
        Ok(UNIX_EPOCH + Duration::from_secs_f64(secs))
    }
}

#[cfg(test)]
mod tests;
