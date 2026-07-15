//! Per-attempt, state-keyed unix domain socket. Listener side (`UnixRelay`) is
//! the waiting `login`; client side (`deliver`) is the OS-launched handler
//! process.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};

use super::{Callback, RelayHandle, WaitError};

fn oauth_dir() -> io::Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config directory not found"))?
        .join("mirrorstack")
        .join("cli")
        .join("oauth");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Length of the `state` prefix used as the per-attempt socket filename.
/// AF_UNIX paths are capped by `sun_path` (104 bytes on macOS, 108 on
/// Linux) and on macOS `config_dir()` already spends ~50 bytes on
/// `Library/Application Support/…`, so the full 22-char nonce would push
/// long-home users over the limit. A 16-char prefix (96 bits of the same
/// CSPRNG output) is unique per attempt; `login` still validates the full
/// `state` byte-for-byte against the callback (defense in depth).
const SOCKET_KEY_LEN: usize = 16;

/// Fixed-length rendezvous key derived from the login `state`.
/// `state` is base64url (ASCII), so a byte slice is always a valid char
/// boundary; anything shorter than the prefix is used whole.
pub(super) fn socket_key(state: &str) -> &str {
    state.get(..SOCKET_KEY_LEN).unwrap_or(state)
}

fn socket_path(state: &str) -> io::Result<PathBuf> {
    Ok(oauth_dir()?.join(format!("{}.sock", socket_key(state))))
}

struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub struct UnixRelay {
    listener: UnixListener,
    _guard: SocketGuard,
    interrupted: Arc<AtomicBool>,
}

impl UnixRelay {
    pub fn bind(state: &str) -> io::Result<Self> {
        Self::bind_path(socket_path(state)?)
    }

    /// Bind the relay at an explicit socket path. The parent directory must
    /// already exist (`bind` provisions the 0700 oauth dir; tests pass a
    /// temp dir). Shared inner impl so tests stay off the mutable global
    /// config dir.
    pub(super) fn bind_path(path: PathBuf) -> io::Result<Self> {
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        let guard = SocketGuard { path: path.clone() };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        let interrupted = Arc::new(AtomicBool::new(false));
        let flag = interrupted.clone();
        let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));

        Ok(Self {
            listener,
            _guard: guard,
            interrupted,
        })
    }
}

impl RelayHandle for UnixRelay {
    fn wait(&self, timeout: Duration) -> Result<Callback, WaitError> {
        const POLL: Duration = Duration::from_millis(50);

        self.listener
            .set_nonblocking(true)
            .map_err(|e| WaitError::Io(e.to_string()))?;
        let deadline = Instant::now() + timeout;

        loop {
            if self.interrupted.load(Ordering::SeqCst) {
                return Err(WaitError::Interrupted);
            }

            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|e| WaitError::Io(e.to_string()))?;
                    let mut buf = String::new();
                    stream
                        .take(8 * 1024)
                        .read_to_string(&mut buf)
                        .map_err(|e| WaitError::Io(e.to_string()))?;
                    return Callback::parse(buf.trim()).map_err(WaitError::from);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(WaitError::Timeout);
                    }
                    thread::sleep(POLL);
                }
                Err(e) => return Err(WaitError::Io(e.to_string())),
            }
        }
    }
}

pub fn deliver(url: &str) -> anyhow::Result<()> {
    let state = super::state_in(url).ok_or_else(|| anyhow!("callback url is missing state"))?;
    deliver_to(&socket_path(&state)?, url)
}

/// Connect the state-keyed socket and write the full callback URL. Shared
/// inner impl so tests can target a temp path.
pub(super) fn deliver_to(path: &Path, url: &str) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connect relay socket {}", path.display()))?;
    stream.write_all(url.as_bytes())?;
    stream.flush()?;
    Ok(())
}
