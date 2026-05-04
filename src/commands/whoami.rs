//! `mirrorstack whoami` — print the authenticated user.
//!
//! Reads the access token from the credentials file and calls
//! GET /v1/auth/me. If the file is missing or the server returns 401,
//! tells the user to run `mirrorstack login`. Auto-refresh on token
//! expiry is a follow-up — for v1 the user re-runs login.

use anyhow::{Result, anyhow};
use clap::Args;

use crate::api::{self, ApiError};
use crate::credentials::{self, LoadError};

use super::{DEFAULT_API_BASE, ENV_API_URL, resolve_base};

#[derive(Args)]
pub struct WhoamiArgs {}

pub fn run(_args: WhoamiArgs) -> Result<()> {
    let creds = match credentials::load() {
        Ok(c) => c,
        Err(LoadError::NotFound) => {
            return Err(anyhow!(
                "not signed in. Run `mirrorstack login` to sign in."
            ));
        }
        Err(e) => return Err(e.into()),
    };

    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);

    match api::me(&api_base, &creds.access_token) {
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
