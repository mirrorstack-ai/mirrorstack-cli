//! `mirrorstack logout` — revoke the current session and wipe local
//! credentials. Best-effort: a failed server revoke (network down,
//! 5xx) still wipes the local credentials and exits 0 with a warning.
//! The user's intent is "log me out"; refusing to clear local state
//! because the platform is unreachable would leave them stuck.

use std::time::Duration;

use anyhow::Result;
use clap::Args;
use console::style;

use crate::api::{self, ApiError};
use crate::credentials::{self, LoadError};
use crate::http;

use super::{DEFAULT_API_BASE, ENV_API_URL, ok_mark, resolve_base, warn_prefix};

#[derive(Args)]
pub struct LogoutArgs {}

pub fn run(_args: LogoutArgs) -> Result<()> {
    let creds = match credentials::load() {
        Ok(c) => c,
        Err(LoadError::NotFound) => {
            eprintln!("{} already signed out.", ok_mark());
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let client = http::client(Duration::from_secs(15))?;

    // Server revoke is best-effort: we always wipe local creds afterwards.
    // A 401 means the access token was already gone; the platform's
    // Revoke handler is idempotent on the refresh token, so any non-401
    // failure (network, 5xx) just means we couldn't tell the server.
    let server_warn = match api::revoke_session(
        &client,
        &api_base,
        &creds.access_token,
        &creds.refresh_token,
    ) {
        Ok(()) => None,
        Err(ApiError::Unauthenticated) => None,
        Err(e) => Some(format!("{e}")),
    };

    credentials::delete()?;

    if let Some(reason) = server_warn {
        eprintln!(
            "{} server revoke failed ({reason}); local credentials wiped.",
            warn_prefix(),
        );
        eprintln!(
            "  {}",
            style("the refresh token may still be valid until it expires.").dim(),
        );
    } else {
        eprintln!("{} signed out.", ok_mark());
    }
    Ok(())
}
