//! `mirrorstack dev` — run modules locally.
//!
//! Two modes:
//!   - **Outer** (host, default): `docker compose up` — all services
//!     including Go modules run inside Docker.
//!   - **Inner** (`--all`, inside runner container): the full dev runner.
//!     Per module: build + run with polling hot-reload (see `reload`),
//!     deterministic internal ports from 18080 (go.work order), a
//!     per-module platform-token file, esbuild web watchers with
//!     livereload ports from 8089, and the #36 log shipper tapping
//!     stdout/stderr. A `/_m/<slug>/*` reverse proxy (see `proxy`)
//!     multiplexes them on one port. This is what the compose runner
//!     calls; it replaces ms-app-modules' scripts/dev-runner.sh +
//!     dev-proxy.go.
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

use std::collections::HashMap;
use std::io::{BufRead, BufReader, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

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

mod log_shipper;
pub(crate) mod module_meta;
mod proxy;
mod reload;
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
    /// Watch module sources and rebuild/restart on change (used with
    /// --all). On by default so the compose runner hot-reloads; pass
    /// --watch=false for a one-shot run.
    #[arg(
        long,
        num_args = 0..=1,
        default_value_t = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    watch: bool,
}

const DEFAULT_LOCAL_URL: &str = "http://localhost";
const DEFAULT_MODULE_PORT: u16 = 9080;

// Inner-runner port layout, matching the retired dev-runner.sh: modules
// bind sequentially from 18080 in go.work order, esbuild livereload
// servers from 8089 (per web-enabled module), and the dev-proxy
// multiplexes them on 8080 (host-published as 9080/9089).
const INTERNAL_PORT_BASE: u16 = 18080;
const LR_PORT_BASE: u16 = 8089;
const PROXY_PORT_DEFAULT: u16 = 8080;

/// Route prefix multiplexing modules on one port. The proxy parses it off
/// incoming targets and tunnel registration embeds it in each module's
/// local_url — dispatch forwards to exactly what was registered, so the
/// two must agree.
const MODULE_ROUTE_PREFIX: &str = "/_m/";

/// Per-module platform-token file. The name is a host↔container contract:
/// the outer run writes it next to go.work, and the inner runner points
/// each module's MS_PLATFORM_TOKEN_FILE at it through the `.:/modules`
/// bind mount.
fn platform_token_file(root: &Path, slug: &str) -> PathBuf {
    root.join(format!(".ms-platform-token-{slug}"))
}

/// How often the supervisor polls module sources for changes — matches the
/// shell runner's air `poll_interval = 2000`.
const REBUILD_POLL: Duration = Duration::from_millis(2000);
/// How often the supervisor checks the stop flag and child liveness.
const SUPERVISE_TICK: Duration = Duration::from_millis(200);

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
            "no ID — run `mirrorstack app module register`"
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
            "no registered modules to run. Run `mirrorstack app module register` first."
        ));
    }

    // Per-module platform-token files. Each tunnel session gets its OWN
    // dispatch-minted service token, so each module process must read the
    // token for ITS session. The old behavior wrote a single shared file
    // (only the first module's token), which authenticated whichever module
    // registered first and 401'd every other module on every
    // platform-initiated call (lifecycle install, manifest read, dev-tunnel
    // API). The files land in `root` and reach the runner through the
    // `.:/modules` bind mount; the inner runner (`run_inner`) points each
    // module's MS_PLATFORM_TOKEN_FILE at `.ms-platform-token-<slug>`.
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
            let f = platform_token_file(root, &slug);
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

    // MS_PLATFORM_TOKEN_FILE is set per-module by the inner runner (each
    // module reads its own `.ms-platform-token-<slug>`). MS_INTERNAL_SECRET
    // is injected once on the compose env; the runner forwards it to every
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

/// Everything one module's supervisor thread needs to build, run, watch,
/// and restart its process.
struct ModuleSpec {
    slug: String,
    /// Absolute module directory (build cwd and process cwd).
    dir: PathBuf,
    /// Where `go build -o` drops the binary (temp dir, per slug).
    bin: PathBuf,
    /// Env set on the module process (PORT, MS_PLATFORM_TOKEN_FILE, infra).
    envs: Vec<(String, String)>,
    /// #36 log shipper sink; None → terminal only.
    sink: Option<log_shipper::LogSink>,
    watch: bool,
    stop: Arc<AtomicBool>,
}

fn run_inner(root: &Path, args: &DevArgs) -> Result<()> {
    let all_modules = workspace::discover_modules(root)?;

    // Ready modules carry their platform id so the shipper sink below
    // doesn't have to re-parse main.go per module.
    let mut ready = Vec::new();
    for m in &all_modules {
        match module_meta::read_module_meta(&m.abs_dir) {
            Ok(meta) if !meta.id.is_empty() => ready.push((m.clone(), meta.id)),
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

    // Dev log shipping: tap each module's stdout/stderr and POST batches to
    // dispatch's ingest, which the developer console reads. Reuses the runner's
    // MS_DISPATCH_URL (container → dispatch) and MS_INTERNAL_SECRET (== the live
    // tunnel session's secret, the ingest's auth). Either unset → shipping is
    // disabled and logs just stay in the terminal.
    let log_dispatch_url = std::env::var("MS_DISPATCH_URL").unwrap_or_default();
    let log_secret = std::env::var("MS_INTERNAL_SECRET").unwrap_or_default();
    if log_dispatch_url.is_empty() || log_secret.is_empty() {
        eprintln!(
            "{} log shipping disabled (MS_DISPATCH_URL / MS_INTERNAL_SECRET unset) — the dev console Logcat will stay empty",
            warn_prefix()
        );
    }
    let log_client = http::client(Duration::from_secs(5)).ok();

    eprintln!(
        "{} starting {} {}{}",
        ok_mark(),
        ready.len(),
        if ready.len() == 1 {
            "module"
        } else {
            "modules"
        },
        if args.watch { " (hot-reload)" } else { "" }
    );

    let stop = Arc::new(AtomicBool::new(false));
    let web_children: Arc<Mutex<Vec<Child>>> = Arc::new(Mutex::new(Vec::new()));
    let mut supervisors = Vec::new();
    let mut routes: HashMap<String, u16> = HashMap::new();
    let mut lr_port = LR_PORT_BASE;

    for (i, (m, module_id)) in ready.iter().enumerate() {
        let slug = m.dir.file_name().unwrap().to_string_lossy().to_string();
        // Deterministic internal port: go.work order, from 18080.
        let port = INTERNAL_PORT_BASE + u16::try_from(i).expect("module count fits u16");
        routes.insert(slug.clone(), port);

        let sink = log_client.as_ref().and_then(|client| {
            log_shipper::spawn(
                client.clone(),
                log_dispatch_url.clone(),
                module_id.clone(),
                log_secret.clone(),
            )
        });

        // Each module reads its OWN per-session platform token — dispatch
        // mints a distinct service token per tunnel, so a shared file would
        // authenticate only the first module and 401 the rest. The files
        // are written by the outer run (host) and arrive via the bind mount.
        let token_file = platform_token_file(root, &slug);

        // `module_id` is what read_module_meta sourced from this module's
        // .env (MS_MODULE_ID) — pass the same value through to the spawned
        // process so the module's own os.Getenv("MS_MODULE_ID") at runtime
        // resolves without re-reading the file a second time.
        let mut envs: Vec<(String, String)> =
            module_process_envs(&db_url, port, module_id, &token_file);
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
                envs.push((var.into(), val));
            }
        }

        eprintln!("  {} {} on internal :{}", style("✓").green(), slug, port);

        let spec = ModuleSpec {
            slug: slug.clone(),
            dir: m.abs_dir.clone(),
            bin: std::env::temp_dir().join(format!("ms-dev-{slug}")),
            envs,
            sink,
            watch: args.watch,
            stop: stop.clone(),
        };
        supervisors.push(thread::spawn(move || supervise_module(spec)));

        if m.abs_dir.join("web/esbuild.config.mjs").exists() {
            eprintln!(
                "  {} {} web watcher (esbuild + livereload :{})",
                style("✓").green(),
                slug,
                lr_port
            );
            spawn_web_watcher(
                slug,
                m.abs_dir.join("web"),
                lr_port,
                web_children.clone(),
                stop.clone(),
            );
            lr_port += 1;
        }
    }

    // The /_m/<slug> multiplexer on the runner's single exposed port.
    let proxy_port = std::env::var("PROXY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(PROXY_PORT_DEFAULT);
    let route_count = routes.len();
    let proxy_port = proxy::spawn(proxy_port, routes)?;
    eprintln!(
        "{} dev-proxy listening on :{} ({} routes)",
        ok_mark(),
        proxy_port,
        route_count
    );

    // Wait for Ctrl-C, or for every supervisor to finish (a supervisor
    // only returns on its own in one-shot mode, after its module exits).
    let (tx, rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("dev: install ctrl-c handler")?;

    loop {
        if supervisors.iter().all(|h| h.is_finished()) {
            break;
        }
        match rx.recv_timeout(SUPERVISE_TICK) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
        }
    }

    // Tear down the whole tree: supervisors kill their module children,
    // then the esbuild watchers go.
    stop.store(true, Ordering::SeqCst);
    for h in supervisors {
        let _ = h.join();
    }
    for child in web_children.lock().unwrap().iter_mut() {
        kill_wait(child);
    }
    // All shipper senders die with the supervisors and the forwarder
    // threads (EOF on the killed children's pipes); give the shipper
    // threads a beat to hit their Disconnected branch and flush the
    // final batch before the process exits.
    thread::sleep(Duration::from_millis(300));

    Ok(())
}

/// Own one module's build → run → watch → restart loop.
///
/// Mirrors the air config the shell runner generated: build with
/// `go build -buildvcs=false -o <bin> .`, run the binary from the module
/// dir, poll sources every 2s (see `reload` for why polling), rebuild and
/// restart on change, and keep the old process running when a rebuild
/// fails. Every (re)start re-taps stdout/stderr into the forwarder +
/// shipper so logs keep flowing across restarts.
fn supervise_module(spec: ModuleSpec) {
    let label: &'static str = Box::leak(spec.slug.clone().into_boxed_str());
    let mut sig = spec.watch.then(|| reload::scan(&spec.dir));
    let mut child = if build_module(&spec, label) {
        start_module(&spec, label)
    } else {
        None
    };
    let mut last_scan = Instant::now();

    loop {
        if spec.stop.load(Ordering::SeqCst) {
            break;
        }

        if let Some(c) = child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                eprintln!(
                    "{} module {} exited ({})",
                    warn_prefix(),
                    label,
                    status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".into())
                );
                child = None;
            }
        }

        // One-shot mode ends with the module; watch mode keeps polling so
        // the next edit revives a crashed (or never-built) module.
        if !spec.watch && child.is_none() {
            return;
        }

        if let Some(prev) = sig.as_mut() {
            if last_scan.elapsed() >= REBUILD_POLL {
                last_scan = Instant::now();
                let next = reload::scan(&spec.dir);
                if *prev != next {
                    *prev = next;
                    eprintln!("{} {} changed — rebuilding…", ok_mark(), label);
                    if build_module(&spec, label) {
                        if let Some(mut old) = child.take() {
                            kill_wait(&mut old);
                        }
                        child = start_module(&spec, label);
                    }
                }
            }
        }

        thread::sleep(SUPERVISE_TICK);
    }

    if let Some(mut c) = child {
        kill_wait(&mut c);
    }
}

/// Kill a child process and reap it (kill alone would leave a zombie).
fn kill_wait(c: &mut Child) {
    let _ = c.kill();
    let _ = c.wait();
}

/// Base env vars every spawned module process gets: local DB, its
/// deterministic internal port, its per-session platform-token file path,
/// and MS_MODULE_ID (the same per-environment value tunnel registration
/// used) so the module's own `os.Getenv("MS_MODULE_ID")` resolves. Isolated
/// as a pure function so the value list is unit-testable without spinning
/// up workspace discovery / docker / a real child process.
fn module_process_envs(
    db_url: &str,
    port: u16,
    module_id: &str,
    token_file: &Path,
) -> Vec<(String, String)> {
    vec![
        ("MS_LOCAL_DB_URL".into(), db_url.to_string()),
        ("PORT".into(), port.to_string()),
        ("MS_MODULE_ID".into(), module_id.to_string()),
        (
            "MS_PLATFORM_TOKEN_FILE".into(),
            token_file.display().to_string(),
        ),
    ]
}

/// `go build -buildvcs=false -o <bin> .` in the module dir. Compile errors
/// are mirrored to the terminal and shipped like module stderr so build
/// failures show up in the dev console Logcat too.
fn build_module(spec: &ModuleSpec, label: &str) -> bool {
    let out = Command::new("go")
        .args(["build", "-buildvcs=false", "-o"])
        .arg(&spec.bin)
        .arg(".")
        .current_dir(&spec.dir)
        .output();
    match out {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let prefix = line_prefix(label);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&out.stdout)
            );
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                forward_line(&prefix, line, true, &spec.sink);
            }
            false
        }
        Err(e) => {
            eprintln!("{} {label}: go build: {e}", warn_prefix());
            false
        }
    }
}

/// Spawn the built module binary and tap its stdout/stderr into the
/// forwarder (terminal prefix + shipper sink).
fn start_module(spec: &ModuleSpec, label: &'static str) -> Option<Child> {
    let mut cmd = Command::new(&spec.bin);
    cmd.current_dir(&spec.dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &spec.envs {
        cmd.env(k, v);
    }
    match cmd.spawn() {
        Ok(mut child) => {
            spawn_forwarder(
                child.stdout.take().unwrap(),
                label,
                false,
                spec.sink.clone(),
            );
            spawn_forwarder(child.stderr.take().unwrap(), label, true, spec.sink.clone());
            Some(child)
        }
        Err(e) => {
            eprintln!("{} spawn {label}: {e}", warn_prefix());
            None
        }
    }
}

/// `npm install --silent` then `node esbuild.config.mjs --watch` with
/// LR_PORT, mirroring the shell runner. The module's own esbuild config
/// hosts the SSE livereload server — the runner only sets LR_PORT. Output
/// is prefixed `[<slug>:web]` and stays terminal-only (the shell runner
/// never shipped web-watcher lines either).
fn spawn_web_watcher(
    slug: String,
    web_dir: PathBuf,
    lr_port: u16,
    children: Arc<Mutex<Vec<Child>>>,
    stop: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let install = Command::new("npm")
            .args(["install", "--silent"])
            .current_dir(&web_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !matches!(install, Ok(s) if s.success()) {
            eprintln!(
                "{} {slug}: npm install failed — starting esbuild anyway",
                warn_prefix()
            );
        }
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let label: &'static str = Box::leak(format!("{slug}:web").into_boxed_str());
        let spawned = Command::new("node")
            .args(["esbuild.config.mjs", "--watch"])
            .current_dir(&web_dir)
            .env("LR_PORT", lr_port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match spawned {
            Ok(mut child) => {
                spawn_forwarder(child.stdout.take().unwrap(), label, false, None);
                spawn_forwarder(child.stderr.take().unwrap(), label, true, None);
                let mut kids = children.lock().unwrap();
                kids.push(child);
                // Shutdown may have raced npm install; don't leave an orphan.
                if stop.load(Ordering::SeqCst) {
                    for c in kids.iter_mut() {
                        let _ = c.kill();
                    }
                }
            }
            Err(e) => eprintln!("{} {slug}: node esbuild: {e}", warn_prefix()),
        }
    });
}

fn spawn_forwarder<R: Read + Send + 'static>(
    reader: R,
    label: &'static str,
    is_stderr: bool,
    sink: Option<log_shipper::LogSink>,
) {
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
                    forward_line(&prefix, trimmed, is_stderr, &sink);
                }
                Err(_) => return,
            }
        }
    });
}

/// Ship one line to the developer console (best-effort), then mirror it to
/// the terminal as before. Shared by the live-process forwarders and
/// `build_module`'s compile-error path so both feed the same pipeline.
fn forward_line(prefix: &str, line: &str, is_stderr: bool, sink: &Option<log_shipper::LogSink>) {
    if let Some(s) = sink {
        let _ = s.send(log_shipper::parse_line(line, is_stderr));
    }
    if is_stderr {
        eprintln!("{prefix} {line}");
    } else {
        println!("{prefix} {line}");
    }
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
        let module_local_url = format!("{local_url}{MODULE_ROUTE_PREFIX}{slug}");

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
                    // The module isn't up yet at register (open_tunnels precedes
                    // `docker compose up`); the platform seeds the hash from its
                    // own fetch and the first heartbeat carries it.
                    manifest_hash: None,
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
                    "dev: module {} isn't owned by you — only the module owner can open a dev tunnel.\nIf you scaffolded with `mirrorstack app module init`, your `Config.ID` should match the platform's record; re-check it under `mirrorstack app module list`.",
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
mod tests {
    use super::*;

    #[test]
    fn module_process_envs_includes_ms_module_id() {
        let envs = module_process_envs(
            "postgres://x/y",
            18080,
            "mbb8a3f8b123456789abcdef012345678",
            Path::new("/tmp/.ms-platform-token-media"),
        );
        assert!(envs.contains(&(
            "MS_MODULE_ID".to_string(),
            "mbb8a3f8b123456789abcdef012345678".to_string()
        )));
        assert!(envs.contains(&("PORT".to_string(), "18080".to_string())));
        assert!(envs.contains(&("MS_LOCAL_DB_URL".to_string(), "postgres://x/y".to_string())));
        assert!(envs.contains(&(
            "MS_PLATFORM_TOKEN_FILE".to_string(),
            "/tmp/.ms-platform-token-media".to_string()
        )));
    }
}
