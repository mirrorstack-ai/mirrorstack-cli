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
//!   - Per-module `.secret/ms-platform-token-<slug>` files carry the
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
    DEFAULT_APPS_API_BASE, DEFAULT_DISPATCH_BASE, ENV_APPS_API_URL, ENV_DISPATCH_URL, ok_mark,
    resolve_base, session_expired, warn_prefix,
};
use crate::{api, credentials, http};

mod log_shipper;
pub(crate) mod module_meta;
mod proxy;
mod reload;
mod share;
mod tunnel;
pub(crate) mod workspace;

const PASSTHROUGH_ENV: [&str; 10] = [
    "MS_INTERNAL_SECRET",
    "REDIS_URL",
    "AWS_ENDPOINT_URL",
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    // Platform plane. `env_clear()` in `start_module` means anything not
    // named here never reaches the module, and the SDK's dispatch fallback
    // is a local port that a tunnel session does not run. Dropping
    // MS_DISPATCH_URL breaks every ms.Call/Emit/Notify request.
    "MS_DISPATCH_URL",
    "MS_PUBLIC_BASE_URL",
    "MS_PLATFORM_BROKER_BASE",
    "MS_PLATFORM_ASSERTION_PUBLIC_KEY",
];

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
    /// Publish each module's built web bundle to the CDN so REMOTE viewers of
    /// a prod dev-tunnel can load it. Only meaningful with --tunnel; in
    /// local-only mode the bundle already serves from localhost and this has
    /// no effect (a warning says so). Off by default — today's behavior.
    #[arg(long)]
    share: bool,
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
    /// Skip the co-located contribution/slot cross-check at boot. Also honored via MS_SKIP_CAPABILITY_CHECK=1.
    #[arg(long)]
    skip_capability_check: bool,
}

const DEFAULT_LOCAL_URL: &str = "http://localhost";
pub(crate) const DEFAULT_MODULE_PORT: u16 = 9080;

// Inner-runner port layout, matching the retired dev-runner.sh: modules
// bind sequentially from 18080 in go.work order, esbuild livereload
// servers from 8089 (per web-enabled module), and the dev-proxy
// multiplexes them on 8080 (host-published as 9080/9089).
pub(crate) const INTERNAL_PORT_BASE: u16 = 18080;
const LR_PORT_BASE: u16 = 8089;
pub(crate) const PROXY_PORT_DEFAULT: u16 = 8080;

/// Route prefix multiplexing modules on one port. The proxy parses it off
/// incoming targets and tunnel registration embeds it in each module's
/// local_url — dispatch forwards to exactly what was registered, so the
/// two must agree.
pub(crate) const MODULE_ROUTE_PREFIX: &str = "/_m/";

/// Per-module platform-token file. The name is a host↔container contract:
/// the outer run writes it into `.secret/` next to go.work, and the inner
/// runner points each module's MS_PLATFORM_TOKEN_FILE at it through the
/// `.:/modules` bind mount.
pub(crate) fn platform_token_file(root: &Path, slug: &str) -> PathBuf {
    root.join(".secret")
        .join(format!("ms-platform-token-{slug}"))
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
        match module_meta::read_module_meta(&m.abs_dir, root) {
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

    // --share only means something for a prod dev-tunnel: a remote viewer
    // can't reach the dev's localhost, so the bundle must go to the CDN. In
    // local-only mode the browser IS on the dev's machine and the localhost
    // bundle serves fine — sharing would be dead work. Warn, don't error.
    if args.share && !args.tunnel {
        eprintln!(
            "{} --share has no effect without --tunnel: local-only dev serves the bundle from localhost.",
            warn_prefix()
        );
    }

    // Per-module platform-token files. Each tunnel session gets its OWN
    // dispatch-minted service token, so each module process must read the
    // token for ITS session. The old behavior wrote a single shared file
    // (only the first module's token), which authenticated whichever module
    // registered first and 401'd every other module on every
    // platform-initiated call (lifecycle install, manifest read, dev-tunnel
    // API). The files land in `root/.secret/` and reach the runner through
    // the `.:/modules` bind mount; the inner runner (`run_inner`) points
    // each module's MS_PLATFORM_TOKEN_FILE at `.secret/ms-platform-token-<slug>`.
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
        let state = open_tunnels(root, &ready, args.local_url.as_deref(), secret)?;
        std::fs::create_dir_all(root.join(".secret"))
            .context("dev: create .secret directory for platform token files")?;
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

    // With --share on a live tunnel, spin up the host-side bundle watcher.
    // It's the only process holding the user access token (credentials.json,
    // never mounted into the runner) AND able to read each module's built
    // web/dist/index.js (via the compose bind mount) AND aware of the tunnel
    // session registration whose bundleUrl the confirm step updates — so the
    // upload belongs here, not in the container (see share.rs). Best-effort:
    // a share failure never blocks the tunnel.
    let share_state = if args.tunnel && args.share {
        let targets = build_share_targets(root, &ready);
        if targets.is_empty() {
            eprintln!(
                "{} --share: no module ships a web bundle — nothing to share",
                warn_prefix()
            );
            None
        } else {
            let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
            let stop = Arc::new(AtomicBool::new(false));
            let handle = share::spawn_watcher(apps_base, targets, stop.clone());
            Some((stop, handle))
        }
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
    // module reads its own `.secret/ms-platform-token-<slug>`). MS_INTERNAL_SECRET
    // is injected once on the compose env; the runner forwards it to every
    // module process as the SDK's legacy InternalAuth fallback.
    if let Some(secret) = &internal_secret {
        compose.env("MS_INTERNAL_SECRET", secret);
    }
    // Outer mode delegates the actual runner to compose, so the escape hatch
    // has to cross that process boundary as an env var. Compose only forwards
    // what its own `environment:` block names (the same reason
    // MS_INTERNAL_SECRET is declared there), so say so rather than leave the
    // flag silently inert on a compose file that doesn't list it.
    if args.skip_capability_check {
        compose.env("MS_SKIP_CAPABILITY_CHECK", "1");
        eprintln!(
            "{} --skip-capability-check reaches the runner via MS_SKIP_CAPABILITY_CHECK; the compose file must forward it",
            warn_prefix()
        );
    }

    let compose_status = compose.status().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            anyhow!("`docker` not found on PATH. Install Docker Desktop before running dev.")
        }
        _ => anyhow!("dev: docker compose up: {e}"),
    })?;

    // Stop the share watcher and let its current scan drain before we return.
    if let Some((stop, handle)) = share_state {
        stop.store(true, Ordering::SeqCst);
        let _ = handle.join();
    }

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

/// Build the `--share` watcher's target list from the ready modules: one
/// entry per web-bundle-shipping module, carrying its slug, catalog id, and
/// the host path to its built bundle. Modules that ship no web bundle
/// (`ShareTarget::for_module` returns None) or whose id can't be resolved
/// (shouldn't happen — `open_tunnels` already resolved every id) are skipped.
fn build_share_targets(
    root: &Path,
    ready: &[workspace::WorkspaceModule],
) -> Vec<share::ShareTarget> {
    let mut targets = Vec::new();
    for m in ready {
        let slug = m.dir.file_name().unwrap().to_string_lossy().to_string();
        let Ok(module_id) = module_meta::read_module_id(&m.abs_dir, root) else {
            continue;
        };
        if let Some(t) = share::ShareTarget::for_module(&m.abs_dir, slug, module_id) {
            targets.push(t);
        }
    }
    targets
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
        match module_meta::read_module_meta(&m.abs_dir, root) {
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

        // `module_id` is what read_module_meta sourced from the workspace
        // root's .env (its MS_MODULE_ID_<SLUG> keyed entry) — pass the plain
        // value through to the spawned process (see module_process_envs) so
        // the module's own os.Getenv("MS_MODULE_ID") at runtime resolves.
        // The <SLUG> suffix is a root-.env bookkeeping detail; it never
        // reaches the child process.
        let mut envs: Vec<(String, String)> =
            module_process_envs(&db_url, port, module_id, &token_file);
        // Pass through env vars from compose (MS_INTERNAL_SECRET is the
        // per-session secret minted by the outer run; the rest configure
        // infrastructure and the platform plane).
        append_passthrough_env(&mut envs);

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
    let check_routes = routes.clone();
    let proxy_port = proxy::spawn(proxy_port, routes)?;
    eprintln!(
        "{} dev-proxy listening on :{} ({} routes)",
        ok_mark(),
        proxy_port,
        route_count
    );

    // Installed BEFORE the contribution check so a Ctrl-C during its readiness
    // wait is buffered on the channel and breaks the loop immediately below,
    // instead of killing the process with the module children still running.
    let (tx, rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("dev: install ctrl-c handler")?;

    // A failed check falls straight through to the shared teardown below and
    // its error becomes this function's — dev must not keep serving a
    // workspace whose contributions cannot land.
    let contribution_result = check_contributions(root, &check_routes, args);
    if contribution_result.is_ok() {
        // Wait for Ctrl-C, or for every supervisor to finish (a supervisor
        // only returns on its own in one-shot mode, after its module exits).
        loop {
            if supervisors.iter().all(|h| h.is_finished()) {
                break;
            }
            match rx.recv_timeout(SUPERVISE_TICK) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
            }
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

    contribution_result
}

fn capability_check_skipped(flag: bool, env: Option<&str>) -> bool {
    flag || env.is_some_and(|value| {
        let value = value.trim();
        !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
    })
}

/// How long boot waits for every module to serve its manifest. Generous enough
/// to cover the first cold `go build` of a workspace, short enough that a
/// module that will never answer (auth failing closed, a crash loop) does not
/// stall dev indefinitely.
const CONTRIBUTION_CHECK_BUDGET: Duration = Duration::from_secs(20);

/// Cross-check every co-located module's declared `ContributesTo` against the
/// hosts' declared `Provide` slots, and fail boot when a contribution targets a
/// slot its resolvable host does not declare. Until this existed the failure
/// mode was silence: the host's reader returns an empty list for "typo'd slot"
/// exactly as it does for "not installed".
fn check_contributions(root: &Path, routes: &HashMap<String, u16>, args: &DevArgs) -> Result<()> {
    use crate::commands::module::capabilities::index::{self, Resolved, Tier};
    use crate::commands::module::capabilities::{resolve, wire::Manifest};

    let skip_env = std::env::var("MS_SKIP_CAPABILITY_CHECK").ok();
    if capability_check_skipped(args.skip_capability_check, skip_env.as_deref()) {
        return Ok(());
    }
    let client = http::client(Duration::from_secs(2))?;
    let deadline = Instant::now() + CONTRIBUTION_CHECK_BUDGET;
    let mut pending = routes.clone();
    let mut resolved = Vec::new();
    let mut last_reason: HashMap<String, String> = HashMap::new();
    while !pending.is_empty() && Instant::now() < deadline {
        let probes: Vec<_> = pending
            .iter()
            .map(|(slug, port)| (slug.clone(), *port))
            .collect();
        for (slug, port) in probes {
            let url = format!("http://127.0.0.1:{port}{}", resolve::MANIFEST_PATH);
            let Ok(response) = resolve::request_headers(client.get(url), root, &slug).send() else {
                continue;
            };
            if !response.status().is_success() {
                // 503 here is the SDK failing closed on an unreadable
                // MS_PLATFORM_TOKEN_FILE — a plain (non-tunnel) `dev` leaves
                // modules in exactly that state, so record it for the warning.
                last_reason.insert(
                    slug,
                    format!("HTTP {} on :{port}", response.status().as_u16()),
                );
                continue;
            }
            match response.json::<Manifest>() {
                Ok(manifest) => {
                    let keys: Vec<_> = manifest.versions.keys().cloned().collect();
                    let version =
                        module_meta::latest_version(&keys).unwrap_or_else(|| "unknown".into());
                    resolved.push(Resolved {
                        slug: if manifest.slug.is_empty() {
                            slug.clone()
                        } else {
                            manifest.slug.clone()
                        },
                        id: manifest.id.clone(),
                        version: version.trim_start_matches('v').into(),
                        tier: Tier::L,
                        manifest,
                    });
                    pending.remove(&slug);
                }
                Err(error) => {
                    last_reason.insert(slug, format!("manifest did not parse: {error}"));
                }
            }
        }
        if !pending.is_empty() {
            thread::sleep(Duration::from_millis(500));
        }
    }

    // An unreachable module is never fatal: it may still be compiling, and a
    // capability check must not be the thing that stops a dev session.
    for slug in pending.keys() {
        let reason = last_reason
            .get(slug)
            .cloned()
            .unwrap_or_else(|| "no response".into());
        eprintln!(
            "{} contribution check skipped {slug} ({reason})",
            warn_prefix()
        );
    }
    if resolved.is_empty() {
        return Ok(());
    }

    let report = index::classify(&resolved);
    // A contribution into a host outside this workspace is legal in dev — the
    // install-time gate is what checks those.
    for diagnostic in report
        .diagnostics
        .iter()
        .filter(|d| d.code == "host_unresolvable")
    {
        eprintln!("{} {}", warn_prefix(), diagnostic.detail);
    }

    let failures: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| matches!(d.code, "slot_unknown" | "payload_mismatch"))
        .collect();
    if !failures.is_empty() {
        eprintln!();
        for diagnostic in &failures {
            eprintln!(
                "{} {} {}",
                style("error:").red().bold(),
                style(&diagnostic.module).cyan().bold(),
                diagnostic.detail
            );
        }
        eprintln!(
            "  {}",
            style(
                "fix the slot name (or declare it on the host with ms.Provide); \
                 pass --skip-capability-check to boot anyway"
            )
            .dim()
        );
        eprintln!();
        return Err(anyhow!(
            "contribution check failed: {} contribution(s) target a slot their host does not declare",
            failures.len()
        ));
    }

    let unfilled: Vec<_> = report
        .slots
        .iter()
        .filter(|slot| slot.filled_by.is_empty())
        .collect();
    eprintln!(
        "{} contributions checked — {} of {} host slots filled",
        ok_mark(),
        report.slots.len() - unfilled.len(),
        report.slots.len()
    );
    // The coverage report: unfilled slots are legal, but they had been
    // invisible, so name them.
    for slot in unfilled {
        eprintln!(
            "  {} {}/{} {}",
            style("○").yellow(),
            slot.host,
            slot.key,
            style("unfilled").dim()
        );
    }
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
/// and a PLAIN `MS_MODULE_ID` (the same per-environment value tunnel
/// registration used, resolved from the workspace root's `.env` under this
/// module's `MS_MODULE_ID_<SLUG>` key) so the module's own
/// `os.Getenv("MS_MODULE_ID")` resolves. The `<SLUG>` suffix is a root-.env
/// lookup convention only — this function deliberately injects the
/// unsuffixed name, since each child process only ever sees its own single
/// module's environment. Isolated as a pure function so the value list is
/// unit-testable without spinning up workspace discovery / docker / a real
/// child process.
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

fn append_passthrough_env(envs: &mut Vec<(String, String)>) {
    for var in PASSTHROUGH_ENV {
        if let Ok(val) = std::env::var(var) {
            envs.push((var.into(), val));
        }
    }
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
///
/// `env_clear()` is load-bearing, not cosmetic: this CLI process's own env
/// carries the *entire* root `.env` (main.rs's `load_dotenv` loads it
/// wholesale via dotenvy, which sets every key — including every sibling
/// module's suffixed `MS_MODULE_ID_<SLUG>` — as a real process env var, not
/// just something the CLI parses locally). `Command` inherits the parent
/// env by default, so without the clear here, every spawned module would
/// see every *other* module's platform ID on top of the curated
/// `spec.envs` list — exactly the cross-module leak this whole `.env`
/// scheme exists to prevent. PATH is re-added explicitly since the module
/// binary may need it (e.g. to exec a subprocess); the curated `spec.envs`
/// includes the explicit infra and platform-plane allowlist above, but
/// nothing else from the CLI's own env passes through implicitly.
fn start_module(spec: &ModuleSpec, label: &'static str) -> Option<Child> {
    let mut cmd = Command::new(&spec.bin);
    cmd.env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
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
/// requests. `root` is the workspace directory holding `go.work` — each
/// module's ID is resolved from `root`'s `.env`, keyed by that module's slug
/// (see `module_meta::env_key_for_slug`).
fn open_tunnels(
    root: &Path,
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
        let module_id = module_meta::read_module_id(&m.abs_dir, root)?;
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
    fn capability_skip_flag_parsing() {
        assert!(capability_check_skipped(true, None));
        assert!(capability_check_skipped(false, Some("1")));
        assert!(capability_check_skipped(false, Some("yes")));
        assert!(!capability_check_skipped(false, None));
        assert!(!capability_check_skipped(false, Some("")));
        assert!(!capability_check_skipped(false, Some("0")));
        assert!(!capability_check_skipped(false, Some("false")));
        assert!(!capability_check_skipped(false, Some("FALSE")));
    }

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

    #[test]
    fn module_process_envs_never_leaks_the_suffixed_env_key() {
        // The MS_MODULE_ID_<SLUG> suffix is a root-.env lookup convention
        // only — the spawned child process must see the plain name, never
        // a slug-suffixed variant (module_meta::env_key_for_slug output).
        let envs = module_process_envs(
            "postgres://x/y",
            18080,
            "moauthcoreid",
            Path::new("/tmp/.ms-platform-token-oauth-core"),
        );
        assert!(
            envs.iter().any(|(k, _)| k == "MS_MODULE_ID"),
            "expected a plain MS_MODULE_ID key"
        );
        assert!(
            !envs.iter().any(|(k, _)| k.starts_with("MS_MODULE_ID_")),
            "child env must not carry a suffixed MS_MODULE_ID_* key: {envs:?}"
        );
    }

    #[test]
    fn passthrough_env_includes_infra_and_platform_plane() {
        for expected in [
            "MS_INTERNAL_SECRET",
            "REDIS_URL",
            "AWS_ENDPOINT_URL",
            "AWS_REGION",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "MS_DISPATCH_URL",
            "MS_PUBLIC_BASE_URL",
            "MS_PLATFORM_BROKER_BASE",
            "MS_PLATFORM_ASSERTION_PUBLIC_KEY",
        ] {
            assert!(
                PASSTHROUGH_ENV.contains(&expected),
                "passthrough allowlist is missing {expected}"
            );
        }
    }

    /// Real spawn, not just the `Vec` `module_process_envs` returns. Regression
    /// for the actual leak: `main.rs`'s `load_dotenv` loads the *whole* root
    /// `.env` into this CLI process's own env (dotenvy sets every key it
    /// finds, not just the ones this module cares about), so every sibling
    /// module's suffixed `MS_MODULE_ID_<SLUG>` becomes a real var on this
    /// process. `Command` inherits the parent env by default, so without an
    /// explicit `env_clear()` in `start_module`, that suffixed key would
    /// leak into every spawned module regardless of what `spec.envs` says.
    /// Simulates the loaded root `.env` and compose platform configuration by
    /// setting the vars directly, spawns `/usr/bin/env` (which just dumps its
    /// own env to stdout) through `start_module`, and asserts the allowlisted
    /// platform vars are forwarded while the poisoned sibling var is not.
    #[cfg(unix)]
    #[test]
    fn start_module_does_not_leak_parent_process_env_into_child() {
        let old_module_id = std::env::var_os("MS_MODULE_ID_OAUTH_CORE");
        let old_dispatch_url = std::env::var_os("MS_DISPATCH_URL");
        let old_assertion_key = std::env::var_os("MS_PLATFORM_ASSERTION_PUBLIC_KEY");

        // SAFETY: test-only process-global env mutation; no other test reads
        // or depends on these keys, and their prior values are restored below.
        unsafe {
            std::env::set_var("MS_MODULE_ID_OAUTH_CORE", "leaked-sibling-id");
            std::env::set_var("MS_DISPATCH_URL", "https://api.mirrorstack.ai/dispatch");
            std::env::set_var(
                "MS_PLATFORM_ASSERTION_PUBLIC_KEY",
                "test-assertion-public-key",
            );
        }

        let (tx, rx) = mpsc::channel();
        let mut envs = vec![("MS_MODULE_ID".into(), "own-id".into())];
        append_passthrough_env(&mut envs);
        let spec = ModuleSpec {
            slug: "media".into(),
            dir: std::env::temp_dir(),
            bin: PathBuf::from("/usr/bin/env"),
            envs,
            sink: Some(tx),
            watch: false,
            stop: Arc::new(AtomicBool::new(false)),
        };

        let mut child = start_module(&spec, "test").expect("spawn /usr/bin/env");
        child.wait().expect("child exits");

        let mut lines = Vec::new();
        while let Ok(entry) = rx.recv_timeout(Duration::from_secs(2)) {
            lines.push(entry.msg);
        }

        unsafe {
            for (key, old_value) in [
                ("MS_MODULE_ID_OAUTH_CORE", old_module_id),
                ("MS_DISPATCH_URL", old_dispatch_url),
                ("MS_PLATFORM_ASSERTION_PUBLIC_KEY", old_assertion_key),
            ] {
                match old_value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }

        assert!(
            lines.iter().any(|l| l == "MS_MODULE_ID=own-id"),
            "expected the child's own plain MS_MODULE_ID in its env: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == "MS_DISPATCH_URL=https://api.mirrorstack.ai/dispatch"),
            "expected MS_DISPATCH_URL to pass through to the child: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == "MS_PLATFORM_ASSERTION_PUBLIC_KEY=test-assertion-public-key"),
            "expected MS_PLATFORM_ASSERTION_PUBLIC_KEY to pass through to the child: {lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.starts_with("MS_MODULE_ID_")),
            "child process env must not inherit a sibling's suffixed MS_MODULE_ID_* key: {lines:?}"
        );
    }
}
