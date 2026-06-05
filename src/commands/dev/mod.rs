//! `mirrorstack dev` — run a module locally with the supporting services
//! it needs.
//!
//! The lifecycle is:
//!   1. Bootstrap a `docker-compose.yml` in the cwd if missing
//!   2. `docker compose up -d --wait` (server-side healthcheck blocks until pg is ready)
//!   3. (optional, --tunnel) Mint a connect token and open the WSS so
//!      remote callers can reach this module via the platform's Leaf 1
//!      302 path
//!   4. Spawn `go run .` with `MS_LOCAL_DB_URL` injected
//!   5. Stream the module's stdout/stderr through a labeled prefix
//!   6. On Ctrl-C: kill the module (SIGKILL on unix; SIGTERM-then-SIGKILL
//!      is queued as a follow-up — see issue #25), close the tunnel if
//!      open, then `docker compose down`

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use console::style;
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::blocking::Client;

use super::{
    DEFAULT_DISPATCH_BASE, ENV_DISPATCH_URL, ok_mark, resolve_base, session_expired, warn_prefix,
};
use crate::{api, credentials, http};

mod compose;
mod module_meta;
mod process;
mod tunnel;

#[derive(Args)]
pub struct DevArgs {
    /// Working directory containing the module's main.go. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Skip bringing up `docker-compose` services. Use when you already have
    /// Postgres running yourself.
    #[arg(long)]
    no_compose: bool,
    /// `MS_LOCAL_DB_URL` override. Defaults to the bundled compose Postgres
    /// when --no-compose is unset, otherwise must be supplied via env.
    #[arg(long)]
    db_url: Option<String>,
    /// Open a WSS tunnel to the platform so deployed callers can reach this
    /// module via Leaf 1 (302 → localhost). Requires the developer to be
    /// signed in (via `mirrorstack login`) and the platform's dispatch
    /// service + WS API GW to be reachable. Module identity is parsed from
    /// `Config.ID` in main.go; --local-url defaults to http://localhost:8080.
    #[arg(long)]
    tunnel: bool,
    /// URL the platform should 302 to when routing inbound calls for this
    /// module. Only used when --tunnel is set. Default: http://localhost:8080.
    #[arg(long)]
    local_url: Option<String>,
}

// Matches templates/dev/docker-compose.yml.tmpl: host port 5433 (chosen so
// the bundled compose can coexist with api-platform's own postgres on 5432).
const DEFAULT_DB_URL: &str =
    "postgres://mirrorstack:mirrorstack@localhost:5433/mirrorstack?sslmode=disable";

/// Default local URL the platform should 302 to for Leaf 1 routing. Matches
/// the SDK's default HTTP listener port. Override with `--local-url`.
const DEFAULT_LOCAL_URL: &str = "http://localhost:8080";

pub fn run(args: DevArgs) -> Result<()> {
    let cwd = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    if !cwd.join("main.go").exists() {
        return Err(anyhow!(
            "{} doesn't look like a module — no main.go found. Run `mirrorstack module init` first, or pass --dir <module-path>.",
            cwd.display()
        ));
    }

    let db_url = resolve_db_url(&args)?;

    // Bring the tunnel up BEFORE compose so that a tunnel registration
    // failure (auth expired, dispatch unreachable) doesn't waste the user's
    // time bringing containers up first.
    //
    // Tunnel mode exposes the module to remote callers (via dispatch's
    // Leaf-1 307), so the module MUST enforce Internal-scope auth. Mint a
    // per-session secret, set MS_INTERNAL_SECRET on the spawned module
    // process (which flips the bypass-vs-enforce matrix in
    // auth/middleware.go to enforce), and ship the same value to dispatch
    // in the register frame so dispatch can attach X-MS-Internal-Secret on
    // forwarded requests.
    let tunnel = if args.tunnel {
        let secret = mint_internal_secret()?;
        let (handle, runtime) = open_tunnel(&cwd, args.local_url.as_deref(), &secret)?;
        Some(Tunnel {
            handle,
            runtime,
            internal_secret: secret,
        })
    } else {
        None
    };

    if !args.no_compose {
        compose::ensure_compose_file(&cwd)?;
        compose::up(&cwd)?;
    }

    eprintln!("{} module running — Ctrl-C to stop", ok_mark());
    let internal_secret = tunnel.as_ref().map(|t| t.internal_secret.as_str());
    let module_status = process::run_module(&cwd, &db_url, internal_secret);

    if let Some(t) = tunnel {
        t.handle.shutdown();
        // Block on the runtime briefly to let the close frame land.
        t.runtime.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    }

    if !args.no_compose {
        if let Err(e) = compose::down(&cwd) {
            eprintln!(
                "{} compose down failed: {e:#}. Run `docker compose down` to clean up.",
                warn_prefix()
            );
        }
    }

    module_status
}

/// Build a single-threaded tokio runtime, mint a connect token via
/// dispatch, open the WSS, send `register`, and return the handle so the
/// caller can shut it down on Ctrl-C. Runs blocking under the hood —
/// the tunnel itself stays alive on the runtime's worker thread.
fn open_tunnel(
    module_dir: &Path,
    local_url: Option<&str>,
    internal_secret: &str,
) -> Result<(tunnel::TunnelHandle, tokio::runtime::Runtime)> {
    let mut creds = credentials::load_or_login_hint()?;
    let dispatch_base = resolve_base(ENV_DISPATCH_URL, DEFAULT_DISPATCH_BASE);
    let client = http::client(Duration::from_secs(15))?;
    let module_id = module_meta::read_module_id(module_dir)?;
    let local_url = local_url.unwrap_or(DEFAULT_LOCAL_URL);

    eprintln!(
        "{} fetching tunnel token from {}",
        ok_mark(),
        style(&dispatch_base).cyan().dim()
    );
    let token = match mint_tunnel_token(&client, &dispatch_base, &mut creds) {
        Ok(t) => t,
        Err(api::ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => {
            // Dispatch unreachable is a routine "platform isn't running yet"
            // error — point the user at the right env var.
            return Err(anyhow!(
                "dev: tunnel-token mint failed: {e}. Check {} (or {} env var) and that the dispatch service is running.",
                dispatch_base,
                ENV_DISPATCH_URL
            ));
        }
    };
    // Multi-thread (one worker) so the WSS background task — pinger,
    // server-frame reader — keeps ticking while the rest of the CLI runs
    // its blocking module-process loop. A current-thread runtime would
    // freeze every spawned future the moment block_on returns.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .context("dev: build tokio runtime")?;

    let handle = match runtime.block_on(async {
        tunnel::open(
            &token.wss_url,
            &token.token,
            tunnel::RegisterPayload {
                module_id: &module_id,
                local_url,
                version: env!("CARGO_PKG_VERSION"),
                internal_secret: Some(internal_secret),
            },
        )
        .await
    }) {
        Ok(h) => h,
        Err(tunnel::RegisterError::ModuleDevModeOff { slug }) => {
            return Err(dev_mode_off_hint(&dispatch_base, slug.as_deref()));
        }
        Err(tunnel::RegisterError::ModuleNotYours) => {
            return Err(anyhow!(
                "dev: this module isn't owned by you — only the module owner can open a dev tunnel.\nIf you scaffolded with `mirrorstack module init`, your `Config.ID` should match the platform's record; re-check it under `mirrorstack module list`."
            ));
        }
        Err(tunnel::RegisterError::Rejected { code, message }) => {
            return Err(anyhow!("dev: register rejected ({code}): {message}"));
        }
        Err(tunnel::RegisterError::Transport(e)) => return Err(e),
    };

    eprintln!(
        "{} tunnel registered (session {})",
        ok_mark(),
        style(&handle.session_id).cyan().dim()
    );
    Ok((handle, runtime))
}

/// Access tokens are short (15 min per the platform's TokenConfig).
/// `mirrorstack dev` is a long-running command, so we silently refresh
/// the access token via the stored refresh token (30-day TTL) on a 401
/// and retry the mint once via [`credentials::with_refresh_retry`]. The
/// refresh endpoint rotates the refresh token too, so the rotated pair is
/// persisted back to credentials. If the refresh ALSO 401s (revoked /
/// expired session), Unauthenticated bubbles up and the caller surfaces
/// session_expired.
fn mint_tunnel_token(
    client: &Client,
    dispatch_base: &str,
    creds: &mut credentials::Credentials,
) -> Result<api::TunnelToken, api::ApiError> {
    credentials::with_refresh_retry(creds, |tok| api::tunnel_token(client, dispatch_base, tok))
}

/// Build a user-facing error for the `module_dev_mode_off` rpc.err. The
/// platform refused the tunnel because the module's `dev_mode_enabled`
/// flag is false; coach the user toward the right toggle and offer to
/// open it. When the platform carries the module slug in the error
/// payload, deep-link straight to the Dev tab; otherwise degrade to
/// the modules list (older platforms predate the slug field).
fn dev_mode_off_hint(dispatch_base: &str, slug: Option<&str>) -> anyhow::Error {
    let console = dev_console_url(dispatch_base, slug);
    eprintln!();
    eprintln!(
        "{} dev mode is disabled for this module on the platform.",
        warn_prefix()
    );
    eprintln!("  Open the dev console and toggle Dev mode on:");
    eprintln!("  {}", style(&console).cyan().underlined());
    eprintln!();
    eprint!("  Press Enter to open in your browser, or Ctrl-C to cancel...");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_ok() {
        let _ = open::that(&console);
    }
    anyhow!("dev: module dev_mode disabled — re-run after enabling it")
}

/// Derive the dev-console web URL from the dispatch HTTP URL.
/// localhost/127.0.0.1 → http://localhost:3001; production
/// (`api.<host>`) → `https://apps.<host>`; anything else falls back to
/// the canonical prod console so the message stays useful. When `slug`
/// is provided, deep-link to /dev/module/<slug>/dev; otherwise the
/// modules-list landing page.
fn dev_console_url(dispatch_base: &str, slug: Option<&str>) -> String {
    let parsed = url::Url::parse(dispatch_base).ok();
    let host = parsed.as_ref().and_then(|u| u.host_str());
    let base = match host {
        Some("localhost") | Some("127.0.0.1") | Some("::1") => "http://localhost:3001".to_string(),
        Some(h) if h.starts_with("api.") => {
            format!("https://apps.{}", &h["api.".len()..])
        }
        _ => "https://apps.mirrorstack.ai".to_string(),
    };
    match slug {
        Some(s) if !s.is_empty() => format!("{base}/dev/module/{s}/dev"),
        _ => format!("{base}/dev"),
    }
}

/// Held for the lifetime of `mirrorstack dev --tunnel`. The runtime
/// keeps the WSS background task alive; the secret is the
/// `MS_INTERNAL_SECRET` value the spawned module enforces against.
struct Tunnel {
    handle: tunnel::TunnelHandle,
    runtime: tokio::runtime::Runtime,
    internal_secret: String,
}

/// Mint a 32-byte URL-safe base64 random token used as the module's
/// MS_INTERNAL_SECRET. Same shape as auth::random_state (OsRng → b64url),
/// inlined here to avoid a cross-module dependency for a one-off helper.
fn mint_internal_secret() -> Result<String> {
    let mut buf = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut buf)
        .context("dev: mint tunnel secret")?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

fn resolve_db_url(args: &DevArgs) -> Result<String> {
    if let Some(url) = &args.db_url {
        return Ok(url.clone());
    }
    if let Ok(url) = std::env::var("MS_LOCAL_DB_URL") {
        return Ok(url);
    }
    if args.no_compose {
        return Err(anyhow!(
            "--no-compose requires MS_LOCAL_DB_URL (env or --db-url) — without compose there's no fallback"
        ));
    }
    Ok(DEFAULT_DB_URL.into())
}

/// Color-aware prefix used by both stdout and stderr forwarders. Skipped on
/// non-TTY targets so CI logs stay clean.
pub(super) fn line_prefix(label: &str) -> String {
    if std::io::stderr().is_terminal() {
        format!("{} {}", style(label).cyan().dim(), style("│").dim())
    } else {
        format!("[{label}]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with(no_compose: bool, db_url: Option<String>) -> DevArgs {
        DevArgs {
            dir: None,
            no_compose,
            db_url,
            tunnel: false,
            local_url: None,
        }
    }

    #[test]
    fn resolve_db_url_prefers_explicit_arg() {
        let args = args_with(false, Some("postgres://x".into()));
        assert_eq!(resolve_db_url(&args).unwrap(), "postgres://x");
    }

    #[test]
    fn resolve_db_url_no_compose_requires_env() {
        // Skip when the runner happens to have MS_LOCAL_DB_URL set — the
        // no-env error path is what we're after, and toggling process-global
        // env from a test is a recipe for cross-test interference.
        if std::env::var("MS_LOCAL_DB_URL").is_ok() {
            return;
        }
        let args = args_with(true, None);
        let err = resolve_db_url(&args).unwrap_err().to_string();
        assert!(err.contains("MS_LOCAL_DB_URL"));
    }

    #[test]
    fn resolve_db_url_compose_default_when_unset() {
        if std::env::var("MS_LOCAL_DB_URL").is_ok() {
            return;
        }
        let args = args_with(false, None);
        let url = resolve_db_url(&args).unwrap();
        assert!(url.starts_with("postgres://mirrorstack"));
        assert!(url.contains(":5433/"));
    }
}
