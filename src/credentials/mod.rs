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
#[allow(dead_code)] // NotFound is matched in load(); load() is API for future commands
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
