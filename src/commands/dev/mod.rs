//! `mirrorstack dev` — run modules locally.
//!
//! Two modes:
//!   - **Outer** (host, default): `docker compose up` — all services
//!     including Go modules run inside Docker.
//!   - **Inner** (`--all`, inside runner container): spawn `go run`
//!     per module directly. This is what the compose runner calls.
//!
//! Tunnel registration always happens on the host side (outer mode).

use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use console::style;

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

    // Register tunnels before compose so auth failures surface early.
    let tunnel_state = if args.tunnel {
        let state = open_tunnels(&ready, args.local_url.as_deref())?;
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
    // reads its own `.ms-platform-token-<slug>`), so nothing is injected here.

    let compose_status = compose.status()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow!(
                "`docker` not found on PATH. Install Docker Desktop before running dev."
            ),
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
                eprintln!(
                    "{} skipping {} (no ID)",
                    warn_prefix(),
                    m.dir.display()
                );
            }
        }
    }

    if ready.is_empty() {
        return Err(anyhow!("no registered modules to run"));
    }

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://mirrorstack:mirrorstack@postgres:5432/ms_app_modules?sslmode=disable".into());

    eprintln!(
        "{} starting {} {}",
        ok_mark(),
        ready.len(),
        if ready.len() == 1 { "module" } else { "modules" }
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

        // Pass through env vars from compose
        for var in ["MS_INTERNAL_SECRET", "REDIS_URL", "AWS_ENDPOINT_URL", "AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"] {
            if let Ok(val) = std::env::var(var) {
                cmd.env(var, val);
            }
        }

        let mut child = cmd.spawn()
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
    ctrlc::set_handler(move || { let _ = tx.send(()); })
        .context("dev: install ctrl-c handler")?;

    let mut exited = vec![false; children.len()];
    loop {
        for (i, (label, child)) in children.iter_mut().enumerate() {
            if exited[i] { continue; }
            if let Ok(Some(status)) = child.try_wait() {
                exited[i] = true;
                eprintln!(
                    "{} module {} exited ({})",
                    warn_prefix(),
                    label,
                    status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into())
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

fn open_tunnels(
    modules: &[workspace::WorkspaceModule],
    local_url_base: Option<&str>,
) -> Result<(Vec<tunnel::TunnelHandle>, tokio::runtime::Runtime)> {
    let creds = credentials::load_or_login_hint()?;
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

    // The shared internal secret dispatch must attach (X-MS-Internal-Secret) to
    // every platform-initiated forward so the module accepts manifest reads, cron
    // fires, and event deliveries on its Internal scope. It is the SAME value the
    // module process gets as MS_INTERNAL_SECRET (compose / env passthrough); we
    // send it at register so the session can carry it. Empty → serde-skipped.
    let internal_secret = std::env::var("MS_INTERNAL_SECRET").unwrap_or_default();

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

        let token = match api::tunnel_token(&client, &dispatch_base, &creds.access_token) {
            Ok(t) => t,
            Err(api::ApiError::Unauthenticated) => return Err(session_expired()),
            Err(e) => {
                return Err(anyhow!(
                    "dev: tunnel-token mint for {} failed: {e}",
                    m.dir.display()
                ));
            }
        };

        let handle = runtime.block_on(async {
            tunnel::open(
                &token.wss_url,
                &token.token,
                tunnel::RegisterPayload {
                    module_id: &module_id,
                    local_url: &module_local_url,
                    version: env!("CARGO_PKG_VERSION"),
                    internal_secret: &internal_secret,
                },
            )
            .await
        })?;

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

#[cfg(test)]
mod tests {}
