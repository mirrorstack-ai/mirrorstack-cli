//! Persisted OAuth tokens. File location is
//! `<config_dir>/mirrorstack/cli/credentials.json` — `~/.config` on
//! Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on
//! Windows. The `cli` segment reserves room for future MirrorStack
//! tools (SDK, daemons, GUIs) under the same parent. Mode 0600 on Unix.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;

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

/// Load credentials, auto-refreshing if the access token is expired.
/// Falls back to "run `mirrorstack login`" if refresh also fails.
pub fn load_or_login_hint() -> Result<Credentials> {
    let creds = match load() {
        Ok(c) => c,
        Err(LoadError::NotFound) => {
            return Err(anyhow::anyhow!(
                "not signed in. Run `mirrorstack login` to sign in."
            ))
        }
        Err(e) => return Err(e.into()),
    };

    if creds.expires_at > SystemTime::now() {
        return Ok(creds);
    }

    // Token expired — try refresh
    let api_base = std::env::var("MIRRORSTACK_API_URL")
        .unwrap_or_else(|_| "https://api.mirrorstack.ai".into());
    let client = match crate::http::client(std::time::Duration::from_secs(15)) {
        Ok(c) => c,
        Err(_) => return Err(anyhow::anyhow!("session expired. Run `mirrorstack login` to sign in again.")),
    };

    match crate::api::refresh_session(&client, &api_base, &creds.refresh_token) {
        Ok(tokens) => {
            let new_creds = Credentials {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token,
                expires_at: SystemTime::now()
                    + std::time::Duration::from_secs(tokens.expires_in),
            };
            if let Err(e) = save(&new_creds) {
                eprintln!("warning: couldn't save refreshed credentials: {e}");
            }
            Ok(new_creds)
        }
        Err(_) => Err(anyhow::anyhow!(
            "session expired. Run `mirrorstack login` to sign in again."
        )),
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
