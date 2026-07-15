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

/// Upper bound on an accepted `state`. The login nonce is 22 chars; this only
/// exists to reject absurd attacker-supplied values before path construction.
const MAX_STATE_LEN: usize = 128;

/// Poll cadence for the non-blocking accept/read loops.
const POLL: Duration = Duration::from_millis(50);

/// Cap on bytes read from one peer; a real callback URL is well under this.
const MAX_CALLBACK_BYTES: u64 = 8 * 1024;

/// The login `state` is base64url-no-pad, so a well-formed callback `state`
/// contains only these bytes. Rejecting anything else is what keeps an
/// attacker-supplied `state` (any web page can invoke the registered scheme
/// handler with an arbitrary URL) from escaping the per-user oauth dir when it
/// is turned into a socket filename — e.g. `state=/run/docker` would otherwise
/// `Path::join` to the absolute `/run/docker.sock`.
pub(super) fn is_nonce(state: &str) -> bool {
    !state.is_empty()
        && state.len() <= MAX_STATE_LEN
        && state
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fixed-length rendezvous key derived from the login `state`.
/// `state` is base64url (ASCII), so a byte slice is always a valid char
/// boundary; anything shorter than the prefix is used whole.
pub(super) fn socket_key(state: &str) -> &str {
    state.get(..SOCKET_KEY_LEN).unwrap_or(state)
}

fn socket_path(state: &str) -> io::Result<PathBuf> {
    if !is_nonce(state) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "callback state is not a valid nonce",
        ));
    }
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
    state: String,
    _guard: SocketGuard,
    interrupted: Arc<AtomicBool>,
}

impl UnixRelay {
    pub fn bind(state: &str) -> io::Result<Self> {
        Self::bind_path(socket_path(state)?, state)
    }

    /// Bind the relay at an explicit socket path. The parent directory must
    /// already exist (`bind` provisions the 0700 oauth dir; tests pass a
    /// temp dir). Shared inner impl so tests stay off the mutable global
    /// config dir. `state` is the full login nonce the delivered callback
    /// must carry.
    pub(super) fn bind_path(path: PathBuf, state: &str) -> io::Result<Self> {
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        let guard = SocketGuard { path: path.clone() };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        let interrupted = Arc::new(AtomicBool::new(false));
        let flag = interrupted.clone();
        let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));

        Ok(Self {
            listener,
            state: state.to_owned(),
            _guard: guard,
            interrupted,
        })
    }

    /// Read one accepted connection. Returns `Some` only for an authenticated
    /// terminal outcome — a callback whose `state` byte-equals this attempt's
    /// nonce (a real completion, or a real denial the server signed with the
    /// same `state`), or a `Ctrl-C`. A peer with a wrong/absent `state`, a
    /// stalled peer (bounded by `deadline`), or a non-UTF-8 peer yields `None`
    /// so the caller keeps waiting: an unauthenticated same-UID process must
    /// not be able to end the attempt, and a peer that connects but never
    /// sends must not hang `login` past its deadline or swallow `Ctrl-C`.
    ///
    /// The read stays non-blocking + polled rather than using
    /// `set_read_timeout`, which macOS rejects with `EINVAL` on `AF_UNIX`.
    fn read_callback(
        &self,
        stream: UnixStream,
        deadline: Instant,
    ) -> Option<Result<Callback, WaitError>> {
        stream.set_nonblocking(true).ok()?;
        let mut data = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if self.interrupted.load(Ordering::SeqCst) {
                return Some(Err(WaitError::Interrupted));
            }
            if data.len() as u64 >= MAX_CALLBACK_BYTES {
                break;
            }
            match (&stream).read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(POLL);
                }
                Err(_) => return None,
            }
        }
        let payload = String::from_utf8_lossy(&data);
        let payload = payload.trim();
        match super::state_in(payload) {
            Some(state) if state == self.state => {
                Some(Callback::parse(payload).map_err(WaitError::from))
            }
            _ => None,
        }
    }
}

impl RelayHandle for UnixRelay {
    fn wait(&self, timeout: Duration) -> Result<Callback, WaitError> {
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
                    if let Some(outcome) = self.read_callback(stream, deadline) {
                        return outcome;
                    }
                    // Unauthenticated / stalled peer: keep waiting for the real
                    // callback until the overall deadline.
                    if Instant::now() >= deadline {
                        return Err(WaitError::Timeout);
                    }
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
