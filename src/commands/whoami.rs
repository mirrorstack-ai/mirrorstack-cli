//! `mirrorstack whoami` — print the authenticated user.
//!
//! Reads the access token from the credentials file and calls
//! GET /v1/auth/me. `load_or_login_hint` auto-refreshes a known-expired
//! access token from the stored refresh token before the call, and the
//! call itself is wrapped in `with_refresh_retry` so a server-side 401
//! (clock skew, server-side revocation) triggers one refresh + retry. The
//! `session expired` message is only shown when that refresh also fails —
//! i.e. the refresh token is gone — at which point the user re-runs login.

use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Args;

use crate::api::{self, ApiError};
use crate::credentials;
use crate::http;

use super::{DEFAULT_API_BASE, ENV_API_URL, resolve_base};

#[derive(Args)]
pub struct WhoamiArgs {}

pub fn run(_args: WhoamiArgs) -> Result<()> {
    let mut creds = credentials::load_or_login_hint()?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let client = http::client(Duration::from_secs(15))?;

    match credentials::with_refresh_retry(&mut creds, |tok| api::me(&client, &api_base, tok)) {
        Ok(id) => {
            println!("{}", id.email);
            if !id.name.is_empty() {
                println!("  name:  {}", id.name);
            }
            if let Some(slug) = id.slug.as_deref() {
                println!("  slug:  @{slug}");
            }
            println!("  id:    {}", id.id);
            Ok(())
        }
        Err(ApiError::Unauthenticated) => Err(anyhow!(
            "session expired. Run `mirrorstack login` to sign in again."
        )),
        Err(e) => Err(e.into()),
    }
}
