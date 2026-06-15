//! `mirrorstack dev` — run modules locally.
//!
//! Two modes:
//!   - **Outer** (host, default): `docker compose up` — all services
//!     including Go modules run inside Docker.
//!   - **Inner** (`--all`, inside runner container): spawn `go run`
//!     per module directly. This is what the compose runner calls.
//!
//! Tunnel registration always happens on the host side (outer mode).
//!
//! Tunnel mode exposes modules to remote callers (via dispatch's Leaf-1
//! 307), so each module MUST enforce Internal-scope auth rather than
//! bypass it. Two cooperating mechanisms make that happen:
//!   - Per-module `.ms-platform-token-<slug>` files carry the
//!     dispatch-minted `stk_*` service token from each tunnel's register
//!     ack. The runner points each module's MS_PLATFORM_TOKEN_FILE at its
//!     own file (see docs/platform-module-auth.md). This is the primary
//!     platform→module auth path.
//!   - A per-session MS_INTERNAL_SECRET, minted here and both sent on the
//!     register frame and injected into the compose env, keeps the SDK's
//!     legacy InternalAuth fallback enforcing (not bypassing) while
//!     dispatch round-trips the value. Backward-compat with older SDKs.

use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
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

pub(crate) mod module_meta;
mod tunnel;
mod workspace;

#[derive(Args)]
pub struct DevArgs {
    /// Working directory containing go.work.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Open WSS tunnels so deployed callers can reach local modules.
    #[arg(long)]
    tunnel: bool,
    /// Base URL for tunnel routing. Default: http://localhost.
    #[arg(long)]
    local_url: Option<String>,
    /// Run all registered modules directly (used inside Docker runner).
    #[arg(long)]
    all: bool,
    /// Enable file watching with hot reload (used with --all).
    #[arg(long)]
    watch: bool,
}

const DEFAULT_LOCAL_URL: &str = "http://localhost";
const DEFAULT_MODULE_PORT: u16 = 9080;

pub fn run(args: DevArgs) -> Result<()> {
    let cwd = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    if !cwd.join("go.work").exists() {
        return Err(anyhow!(
            "{} has no go.work. Run from a module workspace or pass --dir.",
            cwd.display()
        ));
    }

    if args.all {
        run_inner(&cwd, &args)
    } else {
        run_outer(&cwd, &args)
    }
}

// ── Outer mode: host runs `docker compose up` ───────────────────────

fn run_outer(root: &Path, args: &DevArgs) -> Result<()> {
    let all_modules = workspace::discover_modules(root)?;

    let mut ready = Vec::new();
    let mut skipped = Vec::new();
    for m in &all_modules {
        match module_meta::read_module_meta(&m.abs_dir) {
            Ok(meta) if !meta.id.is_empty() => ready.push(m.clone()),
            Ok(meta) => skipped.push((m.dir.display().to_string(), meta.slug)),
            Err(_) => skipped.push((m.dir.display().to_string(), String::new())),
        }
    }

    eprintln!(
        "{} found {} modules in go.work ({} ready, {} skipped)",
        ok_mark(),
        style(all_modules.len()).cyan().bold(),
        ready.len(),
        skipped.len()
    );
    for m in &ready {
        eprintln!("  {} {}", style("✓").green(), m.dir.display());
    }
    for (dir, slug) in &skipped {
        let reason = if slug.is_empty() {
            "no main.go"
        } else {
            "no ID — run `mirrorstack module register`"
        };
        eprintln!(
            "  {} {} ({})",
            style("–").yellow(),
            dir,
            style(reason).dim()
        );
    }

    if ready.is_empty() {
        return Err(anyhow!(
            "no registered modules to run. Run `mirrorstack module register` first."
        ));
    }

    // Per-module platform-token files. Each tunnel session gets its OWN
    // dispatch-minted service token, so each module process must read the
    // token for ITS session. The old behavior wrote a single shared file
    // (only the first module's token), which authenticated whichever module
    // registered first and 401'd every other module on every
    // platform-initiated call (lifecycle install, manifest read, dev-tunnel
    // API). The files land in `root` and reach the runner through the
    // `.:/modules` bind mount; dev-runner.sh points each module's
    // MS_PLATFORM_TOKEN_FILE at `.ms-platform-token-<slug>`.
    let mut token_files: Vec<PathBuf> = Vec::new();

    // Per-session MS_INTERNAL_SECRET. Sent on each register frame (so
    // dispatch can attach X-MS-Internal-Secret on forwarded requests) and
    // injected into the compose env (so the runner forwards it to each
    // module and the SDK's legacy InternalAuth fallback enforces rather
    // than bypasses). Only minted in tunnel mode — without a tunnel the
    // module isn't reachable by remote callers.
    let internal_secret = if args.tunnel {
        Some(mint_internal_secret()?)
    } else {
        None
    };

    // Register tunnels before compose so auth failures surface early.
    let tunnel_state = if args.tunnel {
        let secret = internal_secret
            .as_deref()
            .expect("tunnel mode mints a secret");
        let state = open_tunnels(&ready, args.local_url.as_deref(), secret)?;
        // `open_tunnels` pushes handles in `ready` order, so zip is aligned.
        for (m, handle) in ready.iter().zip(state.0.iter()) {
            let slug = m.dir.file_name().unwrap().to_string_lossy();
            let f = root.join(format!(".ms-platform-token-{slug}"));
            std::fs::write(&f, &handle.service_token)
                .with_context(|| format!("dev: write platform token file for {slug}"))?;
            eprintln!(
                "{} wrote platform token for {} → {}",
                ok_mark(),
                style(&*slug).cyan(),
                style(f.display()).dim()
            );
            token_files.push(f);
        }
        Some(state)
    } else {
        None
    };

    eprintln!("{} starting docker compose…", ok_mark());
    let mut compose = Command::new("docker");
    compose
        .args(["compose", "up", "--build"])
        .current_dir(root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // MS_PLATFORM_TOKEN_FILE is set per-module by dev-runner.sh (each module
    // reads its own `.ms-platform-token-<slug>`). MS_INTERNAL_SECRET is
    // injected once on the compose env; the runner forwards it to every
    // module process as the SDK's legacy InternalAuth fallback.
    if let Some(secret) = &internal_secret {
        compose.env("MS_INTERNAL_SECRET", secret);
    }

    let compose_status = compose.status().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            anyhow!("`docker` not found on PATH. Install Docker Desktop before running dev.")
        }
        _ => anyhow!("dev: docker compose up: {e}"),
    })?;

    // Cleanup per-module token files.
    for f in &token_files {
        let _ = std::fs::remove_file(f);
    }

    if let Some((handles, runtime)) = tunnel_state {
        for h in &handles {
            h.shutdown();
        }
        runtime.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    }

    if !compose_status.success() {
        return Err(anyhow!(
            "docker compose exited with status {}",
            compose_status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        ));
    }

    Ok(())
}

// ── Inner mode: inside Docker, run modules directly ─────────────────

fn run_inner(root: &Path, _args: &DevArgs) -> Result<()> {
    let all_modules = workspace::discover_modules(root)?;

    let mut ready = Vec::new();
    for m in &all_modules {
        match module_meta::read_module_meta(&m.abs_dir) {
            Ok(meta) if !meta.id.is_empty() => ready.push(m.clone()),
            _ => {
                eprintln!("{} skipping {} (no ID)", warn_prefix(), m.dir.display());
            }
        }
    }

    if ready.is_empty() {
        return Err(anyhow!("no registered modules to run"));
    }

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://mirrorstack:mirrorstack@postgres:5432/ms_app_modules?sslmode=disable".into()
    });

    eprintln!(
        "{} starting {} {}",
        ok_mark(),
        ready.len(),
        if ready.len() == 1 {
            "module"
        } else {
            "modules"
        }
    );

    let mut children: Vec<(String, Child)> = Vec::new();

    for m in &ready {
        let slug = m.dir.file_name().unwrap().to_string_lossy().to_string();

        let mut cmd = Command::new("go");
        cmd.args(["run", &format!("./{}", m.dir.display())])
            .current_dir(root)
            .env("MS_LOCAL_DB_URL", &db_url)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Pass through env vars from compose (MS_INTERNAL_SECRET is the
        // per-session secret minted by the outer run; the rest are infra).
        for var in [
            "MS_INTERNAL_SECRET",
            "REDIS_URL",
            "AWS_ENDPOINT_URL",
            "AWS_REGION",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("dev: spawn module {slug}"))?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let label: &'static str = Box::leak(slug.clone().into_boxed_str());
        spawn_forwarder(stdout, label, false);
        spawn_forwarder(stderr, label, true);

        eprintln!("  {} {}", style("✓").green(), slug);
        children.push((slug, child));
    }

    // Wait for Ctrl-C
    let (tx, rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("dev: install ctrl-c handler")?;

    let mut exited = vec![false; children.len()];
    loop {
        for (i, (label, child)) in children.iter_mut().enumerate() {
            if exited[i] {
                continue;
            }
            if let Ok(Some(status)) = child.try_wait() {
                exited[i] = true;
                eprintln!(
                    "{} module {} exited ({})",
                    warn_prefix(),
                    label,
                    status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".into())
                );
            }
        }

        if exited.iter().all(|e| *e) {
            break;
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(()) => {
                for (_, child) in &mut children {
                    let _ = child.kill();
                }
                for (_, child) in &mut children {
                    let _ = child.wait();
                }
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                for (_, child) in &mut children {
                    let _ = child.wait();
                }
                break;
            }
        }
    }

    Ok(())
}

fn spawn_forwarder<R: Read + Send + 'static>(reader: R, label: &'static str, is_stderr: bool) {
    thread::spawn(move || {
        let prefix = line_prefix(label);
        let mut buf = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match buf.read_line(&mut line) {
                Ok(0) => return,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(['\n', '\r']);
                    if is_stderr {
                        eprintln!("{prefix} {trimmed}");
                    } else {
                        println!("{prefix} {trimmed}");
                    }
                }
                Err(_) => return,
            }
        }
    });
}

fn line_prefix(label: &str) -> String {
    if std::io::stderr().is_terminal() {
        format!("{} {}", style(label).cyan().dim(), style("│").dim())
    } else {
        format!("[{label}]")
    }
}

// ── Tunnel registration ─────────────────────────────────────────────

/// Open one WSS tunnel per ready module. Returns the handles (in `modules`
/// order) plus the tokio runtime keeping their background tasks alive.
///
/// Each module's tunnel-token mint is wrapped in
/// [`credentials::with_refresh_retry`] so a 401 on a long-running
/// `mirrorstack dev` silently refreshes the 15-minute access token from the
/// stored refresh token and retries once, rather than forcing a re-login.
/// The rotated refresh pair is persisted back to credentials between
/// modules. `internal_secret` is the per-session value sent on every
/// register frame so dispatch can attach X-MS-Internal-Secret on forwarded
/// requests.
fn open_tunnels(
    modules: &[workspace::WorkspaceModule],
    local_url_base: Option<&str>,
    internal_secret: &str,
) -> Result<(Vec<tunnel::TunnelHandle>, tokio::runtime::Runtime)> {
    let mut creds = credentials::load_or_login_hint()?;
    let dispatch_base = resolve_base(ENV_DISPATCH_URL, DEFAULT_DISPATCH_BASE);
    let client = http::client(Duration::from_secs(15))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .context("dev: build tokio runtime")?;

    let mut handles = Vec::with_capacity(modules.len());

    let local_url = match local_url_base {
        Some(url) => url.to_string(),
        None => format!("{DEFAULT_LOCAL_URL}:{DEFAULT_MODULE_PORT}"),
    };

    for m in modules {
        let module_id = module_meta::read_module_id(&m.abs_dir)?;
        let slug = m.dir.file_name().unwrap().to_string_lossy();
        let module_local_url = format!("{local_url}/_m/{slug}");

        eprintln!(
            "{} fetching tunnel token for {} from {}",
            ok_mark(),
            style(m.dir.display()).cyan(),
            style(&dispatch_base).dim()
        );

        let token = match mint_tunnel_token(&client, &dispatch_base, &mut creds) {
            Ok(t) => t,
            Err(api::ApiError::Unauthenticated) => return Err(session_expired()),
            Err(e) => {
                return Err(anyhow!(
                    "dev: tunnel-token mint for {} failed: {e}. Check {} (or {} env var) and that the dispatch service is running.",
                    m.dir.display(),
                    dispatch_base,
                    ENV_DISPATCH_URL
                ));
            }
        };

        let handle = match runtime.block_on(async {
            tunnel::open(
                &token.wss_url,
                &token.token,
                tunnel::RegisterPayload {
                    module_id: &module_id,
                    local_url: &module_local_url,
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
                    "dev: module {} isn't owned by you — only the module owner can open a dev tunnel.\nIf you scaffolded with `mirrorstack module init`, your `Config.ID` should match the platform's record; re-check it under `mirrorstack module list`.",
                    m.dir.display()
                ));
            }
            Err(tunnel::RegisterError::Rejected { code, message }) => {
                return Err(anyhow!(
                    "dev: register rejected for {} ({code}): {message}",
                    m.dir.display()
                ));
            }
            Err(tunnel::RegisterError::Transport(e)) => return Err(e),
        };

        eprintln!(
            "{} tunnel {} → {} (session {})",
            ok_mark(),
            style(m.dir.display()).cyan(),
            style(&module_local_url).dim(),
            style(&handle.session_id).dim()
        );

        handles.push(handle);
    }

    Ok((handles, runtime))
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

/// Mint a 32-byte URL-safe base64 random token used as the per-session
/// MS_INTERNAL_SECRET. Same shape as auth::random_state (OsRng → b64url),
/// inlined here to avoid a cross-module dependency for a one-off helper.
fn mint_internal_secret() -> Result<String> {
    let mut buf = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut buf)
        .context("dev: mint tunnel secret")?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

#[cfg(test)]
mod tests {}
