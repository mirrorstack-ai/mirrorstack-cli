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
use serde::Serialize;

use crate::api::{self, ApiError, Identity};
use crate::credentials;
use crate::http;

use super::{DEFAULT_API_BASE, ENV_API_URL, resolve_base};

#[derive(Args)]
#[command(after_help = "Examples:\n  mirrorstack whoami\n  mirrorstack whoami --json")]
pub struct WhoamiArgs {
    /// Machine-readable output on stdout.
    #[arg(long)]
    json: bool,
}

/// Output shape for `--json`. A dedicated struct (rather than deriving
/// `Serialize` on `Identity`) so the wire fields are scoped to what whoami
/// prints — the access token never comes near this struct.
#[derive(Serialize)]
struct WhoamiJson<'a> {
    id: &'a str,
    email: &'a str,
    name: &'a str,
    slug: Option<&'a str>,
}

impl<'a> From<&'a Identity> for WhoamiJson<'a> {
    fn from(id: &'a Identity) -> Self {
        WhoamiJson {
            id: &id.id,
            email: &id.email,
            name: &id.name,
            slug: id.slug.as_deref(),
        }
    }
}

pub fn run(args: WhoamiArgs) -> Result<()> {
    let mut creds = credentials::load_or_login_hint()?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let client = http::client(Duration::from_secs(15))?;

    match credentials::with_refresh_retry(&mut creds, |tok| api::me(&client, &api_base, tok)) {
        Ok(id) => {
            if args.json {
                println!("{}", serde_json::to_string(&WhoamiJson::from(&id))?);
                return Ok(());
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whoami_json_omits_slug_when_none() {
        let id = Identity {
            id: "u-1".to_string(),
            email: "user@example.com".to_string(),
            name: "Test User".to_string(),
            profile_url: None,
            slug: None,
        };
        let json = serde_json::to_value(WhoamiJson::from(&id)).unwrap();
        assert_eq!(json["id"], "u-1");
        assert_eq!(json["email"], "user@example.com");
        assert_eq!(json["name"], "Test User");
        assert!(json["slug"].is_null());
    }

    #[test]
    fn whoami_json_includes_slug_when_set() {
        let id = Identity {
            id: "u-1".to_string(),
            email: "user@example.com".to_string(),
            name: "Test User".to_string(),
            profile_url: None,
            slug: Some("test-user".to_string()),
        };
        let json = serde_json::to_value(WhoamiJson::from(&id)).unwrap();
        assert_eq!(json["slug"], "test-user");
    }

    #[test]
    fn whoami_accepts_json_flag() {
        use clap::CommandFactory;
        crate::commands::Cli::command()
            .try_get_matches_from(["mirrorstack", "whoami", "--json"])
            .expect("--json should parse");
    }
}
