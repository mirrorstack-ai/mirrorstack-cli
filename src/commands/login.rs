//! `mirrorstack login` — drives the OAuth 2.0 authorization-code+PKCE
//! flow against api-platform's `/v1/oauth/*` endpoints.
//!
//! Today this is OOB-only: the consent page displays the auth code, the
//! user pastes it into the terminal, and the CLI exchanges code+verifier
//! for tokens. Custom-scheme delivery is the follow-up tracked at
//! mirrorstack-cli#7.

use std::io::{self, BufRead, Write};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use clap::Args;

use crate::auth::{self, AuthError};
use crate::browser;
use crate::credentials::{self, Credentials};
use crate::http;

use super::{DEFAULT_API_BASE, DEFAULT_WEB_BASE, ENV_API_URL, ENV_WEB_URL, resolve_base};

#[derive(Args)]
pub struct LoginArgs {}

pub fn run(_args: LoginArgs) -> Result<()> {
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let web_base = resolve_base(ENV_WEB_URL, DEFAULT_WEB_BASE);

    let pkce = auth::Pkce::generate()?;
    let state = auth::random_state()?;
    let authorize_url = auth::authorize_url(&web_base, &state, &pkce);

    println!("Opening your browser to sign in:\n");
    println!("  {authorize_url}\n");
    if browser::open(&authorize_url).is_err() {
        eprintln!("(could not auto-open browser; copy the URL above and paste it manually)");
    }

    print!("After approving in the browser, paste the code here: ");
    io::stdout().flush().ok();
    let code = read_line(io::stdin().lock())?;
    let code = code.trim();
    if code.is_empty() {
        return Err(anyhow!("login: no code entered"));
    }

    let http = http::client(Duration::from_secs(30)).context("login: build HTTP client")?;

    let tokens = match auth::exchange_code(&http, &api_base, code, &pkce) {
        Ok(t) => t,
        Err(AuthError::InvalidGrant) => {
            return Err(anyhow!(
                "login: code didn't work — it may have expired or already been used. \
                 Run `mirrorstack login` again to get a fresh one."
            ));
        }
        Err(e) => return Err(e.into()),
    };

    let creds = Credentials {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_at: SystemTime::now() + Duration::from_secs(tokens.expires_in.max(0) as u64),
    };
    credentials::save(&creds)?;

    let path = credentials::path()?;
    println!("\nSigned in. Tokens saved to {}", path.display());
    Ok(())
}

fn read_line<R: BufRead>(mut r: R) -> Result<String> {
    let mut buf = String::new();
    let n = r.read_line(&mut buf).context("read input")?;
    if n == 0 {
        return Err(anyhow!("read input: end of input (no code provided)"));
    }
    Ok(buf)
}
