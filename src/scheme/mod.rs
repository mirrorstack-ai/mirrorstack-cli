//! Custom `mirrorstack://` URL-scheme login transport. Registers a per-OS
//! handler that re-invokes this same binary as `mirrorstack __oauth-deliver
//! <url>`, which relays the OAuth callback over a per-attempt unix socket back
//! to the waiting `login` command. Unsupported platforms (Windows, headless)
//! fall back to OOB paste.

use std::time::Duration;

use url::Url;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod register;
#[cfg(unix)]
mod relay;
#[cfg(test)]
mod tests;

pub use register::{RegistrationOutcome, register};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub code: String,
    pub state: String,
}

impl Callback {
    pub fn parse(url: &str) -> Result<Callback, CallbackError> {
        let url = Url::parse(url).map_err(|e| CallbackError::Parse(e.to_string()))?;
        let mut code = None;
        let mut state = None;
        let mut error = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                _ => {}
            }
        }

        if let Some(error) = error {
            return Err(CallbackError::Denied(error));
        }

        Ok(Callback {
            code: code.ok_or(CallbackError::MissingCode)?,
            state: state.ok_or(CallbackError::MissingState)?,
        })
    }
}

pub(crate) fn state_in(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()?
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackError {
    #[error("authorization was denied ({0})")]
    Denied(String),
    #[error("callback is missing the authorization code")]
    MissingCode,
    #[error("callback is missing the state parameter")]
    MissingState,
    #[error("callback url parse: {0}")]
    Parse(String),
}

#[derive(Debug, thiserror::Error)]
pub enum WaitError {
    #[error("timed out waiting for the browser callback")]
    Timeout,
    #[error("login canceled")]
    Interrupted,
    #[error("relay i/o: {0}")]
    Io(String),
    #[error(transparent)]
    Callback(#[from] CallbackError),
}

pub trait Registrar {
    fn register(&self) -> RegistrationOutcome;
}

pub trait RelayFactory {
    fn bind(&self, state: &str) -> std::io::Result<Box<dyn RelayHandle>>;
}

pub trait RelayHandle {
    fn wait(&self, timeout: Duration) -> Result<Callback, WaitError>;
}

pub struct OsRegistrar;

impl Registrar for OsRegistrar {
    fn register(&self) -> RegistrationOutcome {
        register()
    }
}

pub struct SocketRelayFactory;

impl RelayFactory for SocketRelayFactory {
    fn bind(&self, state: &str) -> std::io::Result<Box<dyn RelayHandle>> {
        #[cfg(unix)]
        {
            Ok(Box::new(relay::UnixRelay::bind(state)?))
        }
        #[cfg(not(unix))]
        {
            let _ = state;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "custom-scheme relay requires a unix socket",
            ))
        }
    }
}

pub fn deliver(url: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        relay::deliver(url)
    }
    #[cfg(not(unix))]
    {
        let _ = url;
        anyhow::bail!("custom-scheme delivery is not supported on this platform")
    }
}
