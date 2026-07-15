//! `mirrorstack login` — drives the OAuth 2.0 authorization-code+PKCE flow,
//! preferring automatic custom-scheme delivery and falling back to OOB paste.

use std::io::{self, BufRead, Write};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use clap::Args;

use crate::auth::{self, AuthError};
use crate::browser;
use crate::credentials::{self, Credentials};
use crate::http;
use crate::scheme::{
    CallbackError, OsRegistrar, Registrar, RegistrationOutcome, RelayFactory, SocketRelayFactory,
    WaitError,
};

use super::{
    DEFAULT_API_BASE, DEFAULT_WEB_BASE, ENV_API_URL, ENV_WEB_URL, resolve_base, warn_prefix,
};

#[derive(Args)]
pub struct LoginArgs {
    /// Skip the browser handoff and paste the code shown on the page (SSH/headless).
    #[arg(long)]
    pub no_browser: bool,
}

trait LoginIo {
    fn open_browser(&mut self, authorize_url: &str);
    fn note(&mut self, msg: &str);
    fn warn(&mut self, msg: &str);
    fn read_code(&mut self) -> Result<String>;
}

struct StdIo;

impl LoginIo for StdIo {
    fn open_browser(&mut self, authorize_url: &str) {
        println!("Opening your browser to sign in:\n");
        println!("  {authorize_url}\n");
        if browser::open(authorize_url).is_err() {
            self.warn("could not auto-open browser; copy the URL above and paste it manually");
        }
    }

    fn note(&mut self, msg: &str) {
        println!("{msg}");
    }

    fn warn(&mut self, msg: &str) {
        eprintln!("{} {msg}", warn_prefix());
    }

    fn read_code(&mut self) -> Result<String> {
        print!("After approving in the browser, paste the code here: ");
        io::stdout().flush().ok();
        Ok(read_line(io::stdin().lock())?.trim().to_string())
    }
}

struct LoginCfg {
    web_base: String,
    api_base: String,
    no_browser: bool,
    http: reqwest::blocking::Client,
    wait_timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
#[error("login canceled")]
struct Canceled;

enum SchemeAttempt {
    Done(auth::TokenResponse),
    FallBack,
}

fn run_with(
    reg: &dyn Registrar,
    factory: &dyn RelayFactory,
    io: &mut dyn LoginIo,
    cfg: &LoginCfg,
) -> Result<auth::TokenResponse> {
    let pkce = auth::Pkce::generate()?;
    let state = auth::random_state()?;

    if cfg.no_browser {
        return oob(io, cfg, &state, &pkce);
    }

    match reg.register() {
        RegistrationOutcome::Registered => match scheme_attempt(factory, io, cfg, &state, &pkce)? {
            SchemeAttempt::Done(tokens) => return Ok(tokens),
            SchemeAttempt::FallBack => {}
        },
        RegistrationOutcome::Unsupported => {}
        RegistrationOutcome::Failed(error) => {
            io.warn(&format!(
                "couldn't register the mirrorstack:// handler ({error}); falling back to paste-in code."
            ));
        }
    }

    oob(io, cfg, &state, &pkce)
}

fn scheme_attempt(
    factory: &dyn RelayFactory,
    io: &mut dyn LoginIo,
    cfg: &LoginCfg,
    state: &str,
    pkce: &auth::Pkce,
) -> Result<SchemeAttempt> {
    let relay = match factory.bind(state) {
        Ok(relay) => relay,
        Err(error) => {
            io.warn(&format!(
                "couldn't set up the browser callback ({error}); falling back to paste-in code."
            ));
            return Ok(SchemeAttempt::FallBack);
        }
    };

    let url = auth::authorize_url(&cfg.web_base, auth::REDIRECT_URI_SCHEME, state, pkce);
    io.open_browser(&url);
    io.note(
        "Waiting for the browser to complete sign-in… (Ctrl-C to cancel; falls back to paste after 3 min)",
    );

    match relay.wait(cfg.wait_timeout) {
        Ok(callback) if callback.state == state => {
            drop(relay);
            let tokens = exchange(cfg, auth::REDIRECT_URI_SCHEME, &callback.code, pkce)?;
            Ok(SchemeAttempt::Done(tokens))
        }
        Ok(_) => {
            io.warn(
                "callback state didn't match this login attempt; falling back to paste-in code.",
            );
            Ok(SchemeAttempt::FallBack)
        }
        Err(WaitError::Interrupted) => Err(Canceled.into()),
        Err(WaitError::Callback(CallbackError::Denied(error))) => {
            Err(anyhow!("login: authorization was denied ({error})"))
        }
        Err(WaitError::Timeout) => {
            io.note("Didn't hear back from the browser. Paste the code shown on the page instead:");
            Ok(SchemeAttempt::FallBack)
        }
        Err(WaitError::Callback(_)) | Err(WaitError::Io(_)) => {
            io.warn("couldn't read the browser callback; falling back to paste-in code.");
            Ok(SchemeAttempt::FallBack)
        }
    }
}

fn oob(
    io: &mut dyn LoginIo,
    cfg: &LoginCfg,
    state: &str,
    pkce: &auth::Pkce,
) -> Result<auth::TokenResponse> {
    let url = auth::authorize_url(&cfg.web_base, auth::REDIRECT_URI_OOB, state, pkce);
    io.open_browser(&url);
    let code = io.read_code()?;
    let code = code.trim();
    if code.is_empty() {
        return Err(anyhow!("login: no code entered"));
    }
    exchange(cfg, auth::REDIRECT_URI_OOB, code, pkce)
}

fn exchange(
    cfg: &LoginCfg,
    redirect_uri: &str,
    code: &str,
    pkce: &auth::Pkce,
) -> Result<auth::TokenResponse> {
    match auth::exchange_code(&cfg.http, &cfg.api_base, redirect_uri, code, pkce) {
        Ok(tokens) => Ok(tokens),
        Err(AuthError::InvalidGrant) => Err(anyhow!(
            "login: code didn't work — it may have expired or already been used. \
             Run `mirrorstack login` again to get a fresh one."
        )),
        Err(error) => Err(error.into()),
    }
}

pub fn run(args: LoginArgs) -> Result<()> {
    let cfg = LoginCfg {
        web_base: resolve_base(ENV_WEB_URL, DEFAULT_WEB_BASE),
        api_base: resolve_base(ENV_API_URL, DEFAULT_API_BASE),
        no_browser: args.no_browser,
        http: http::client(Duration::from_secs(30)).context("login: build HTTP client")?,
        wait_timeout: Duration::from_secs(180),
    };
    let mut io = StdIo;
    let tokens = match run_with(&OsRegistrar, &SocketRelayFactory, &mut io, &cfg) {
        Ok(tokens) => tokens,
        Err(error) if error.downcast_ref::<Canceled>().is_some() => std::process::exit(130),
        Err(error) => return Err(error),
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

#[cfg(test)]
mod tests;
