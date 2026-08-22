//! Per-module tunnel supervision for `mirrorstack dev --tunnel`.
//!
//! `tunnel::open` used to be fire-and-forget: the background loop `return`ed
//! on the first terminal condition (server close frame, read error, stream
//! end, ping-send failure) and the dropped `JoinHandle` meant nothing observed
//! it. The CLI process stayed alive and healthy-looking — `pgrep`, the log
//! tail and a direct `curl` against the local module all still succeeded —
//! while dispatch 503'd `tunnel_offline` on every routed call and 403'd
//! `unknown_sender` on every event ingress, because both resolve the sender
//! through the same live-session lookup that the close deleted.
//!
//! This module closes that hole. One OS thread per module waits on the
//! tunnel's exit signal and re-establishes the session with jittered
//! exponential backoff, redoing exactly the state a new session invalidates:
//!
//!   - a FRESH tunnel token (the connect token's server-side TTL is ~60s, so
//!     the original is long dead by the time a session drops),
//!   - a fresh WSS connect + `register` — this time carrying the module's real
//!     manifest hash, since unlike the first register the module is up,
//!   - a REWRITE of `.secret/ms-platform-token-<slug>` with the new session's
//!     service token. This is the step whose absence would turn the loud
//!     `503 tunnel_offline` into a quiet `403 not_proxied`: dispatch injects
//!     the NEW token on every forwarded call while the still-running module
//!     compares it against the file, which the SDK re-reads per request. No
//!     module restart is needed precisely because of that per-call read.
//!   - an invalidation of the `--share` bundle-hash gate, because the platform
//!     stores the dev-bundle CDN pointer per SESSION and deletes it with the
//!     session, while the watcher's content-hash cache would otherwise never
//!     re-confirm it.
//!
//! `MS_INTERNAL_SECRET` is deliberately NOT re-minted: the stability guarantee
//! holds per module. A module keeps the secret it was started with for its
//! whole lifetime, and every re-register replays that same value so the
//! module's process env and its registered session never diverge.
//!
//! Why an OS thread and not a tokio task: the token mint goes through
//! `reqwest::blocking` (`http::client`), which panics when called from inside
//! a runtime. The thread owns the blocking mint and hops into the shared
//! runtime with `block_on` for the async connect.
//!
//! Credentials are SHARED (see [`SharedCredentials`]) rather than copied per
//! thread. The platform rotates the refresh token on every refresh, so five
//! supervisors each refreshing their own copy means one wins and four present
//! a value the platform has already invalidated — `Unauthenticated`, which
//! this module classifies TERMINAL. A single server close would then kill four
//! modules that were never actually signed out. They are also loaded ONCE, by
//! `open_tunnels`, and handed in: a supervisor that had to load its own could
//! fail to, and a supervisor that cannot supervise is the original zombie.
//!
//! Per-module isolation: a supervisor only ever touches its own module. Five
//! sessions dying together produce five independent reconnects, and one module
//! giving up permanently leaves the other four serving. The shared credentials
//! are the one thing they contend on, and only on the refresh itself.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use console::style;
use reqwest::blocking::Client;

use super::tunnel;
use super::{ok_mark, warn_prefix};
use crate::{api, credentials, http};

/// Consecutive failed reconnect attempts before a module is declared
/// permanently offline. With [`RECONNECT_BACKOFF_CAP`] this is roughly three
/// minutes of trying — long enough to ride out a laptop lid, a Wi-Fi hop or a
/// dispatch redeploy, short enough that a genuinely broken session goes loud
/// while the developer is still at the keyboard.
const MAX_RECONNECT_ATTEMPTS: u32 = 10;

/// First backoff step. Doubles per attempt up to [`RECONNECT_BACKOFF_CAP`].
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Ceiling on the backoff step, before jitter.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(30);

/// How often a permanently-offline module re-announces itself. The operator's
/// actual complaint was that the ONE close warning scrolled away among
/// `docker compose`'s inherited container logs, so a dead tunnel keeps saying
/// so for as long as the dev session runs.
const DEAD_NAG_INTERVAL: Duration = Duration::from_secs(60);

/// Stop-flag poll granularity. Bounds teardown latency without busy-looping —
/// same cadence the `--share` watcher uses.
const TICK: Duration = Duration::from_millis(200);

/// Ceiling on one reconnect attempt's connect + register. `tunnel::open` only
/// time-boxes the register-ack wait, so a TCP connect to a black-holed host
/// would otherwise sit at the OS default (~75s on macOS) — long enough to
/// stall the backoff schedule and to make a Ctrl-C feel hung.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long teardown waits for supervisor threads to notice the stop flag
/// before giving up on them. A thread parked in a socket call is bounded by
/// [`CONNECT_TIMEOUT`] and the mint client's own timeout, but the operator
/// pressing Ctrl-C should never wait that out: stragglers are left to be
/// reaped by process exit, and [`Supervisor::publish`] guarantees they can
/// neither install a session nor touch disk once the flag is set.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Everything a reconnect needs that is identical for every module.
pub(super) struct ReconnectCtx {
    pub dispatch_base: String,
    /// The single credential copy every supervisor mints against. Loaded once
    /// by `open_tunnels` and moved in here, so no supervisor thread has a
    /// credential-load step that could fail and silently leave its module
    /// unsupervised.
    pub creds: SharedCredentials,
    /// Notified on each successful reconnect so the `--share` watcher
    /// re-confirms the session-scoped bundle pointer.
    pub share: Arc<ShareInvalidator>,
    /// Exact current tunnel identity for session-bound client publication.
    /// Updated only after a reconnect is fully installed and its service
    /// token is durable on disk.
    pub clients: Arc<SessionTracker>,
}

/// The per-module facts a reconnect replays: who to register as, where the
/// module answers, and which token file to rewrite.
pub(super) struct TunnelTarget {
    pub slug: String,
    pub module_id: String,
    pub local_url: String,
    pub token_file: PathBuf,
    /// Reused verbatim for this module on every re-register.
    pub internal_secret: String,
}

/// Live supervision state for one module, shared between its supervisor thread
/// and `run_outer`'s teardown.
struct Supervisor {
    slug: String,
    /// The CURRENTLY open session's handle, replaced on every successful
    /// reconnect so teardown always closes the session that is actually open
    /// rather than the original (long-dead) one.
    handle: Mutex<Option<tunnel::TunnelHandle>>,
    /// Set by teardown: stops reconnecting and silences the nag.
    stop: AtomicBool,
    /// Set when this module's tunnel is permanently offline.
    dead: AtomicBool,
}

/// What [`Supervisor::publish`] did with a freshly opened session.
#[derive(Debug)]
enum Publish {
    /// Installed as the live session and its token file rewritten.
    Installed,
    /// Teardown got there first. The session has been closed and nothing was
    /// written to disk.
    Refused,
    /// The token file could not be rewritten, so the session was closed. NOT
    /// a reconnect: see [`Supervisor::publish`].
    TokenWriteFailed(anyhow::Error),
}

impl Supervisor {
    /// Cheap, advisory read of the stop flag. The AUTHORITATIVE stop check is
    /// the one [`publish`](Self::publish) does while holding the handle lock;
    /// this one only spares the backoff and nag loops a lock per tick.
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Poisoning means a supervisor panicked while holding this lock. The
    /// guarded value is one handle with no torn invariant, and swallowing the
    /// error (the previous `if let Ok`) would silently skip teardown's close
    /// for that module — exactly the quiet failure this file exists to remove.
    fn lock_handle(&self) -> MutexGuard<'_, Option<tunnel::TunnelHandle>> {
        self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn service_token(&self) -> String {
        self.lock_handle()
            .as_ref()
            .map(|h| h.service_token.clone())
            .unwrap_or_default()
    }

    /// Make `handle` the live session: rewrite the module's platform-token
    /// file and install it, or refuse and close it.
    ///
    /// Both halves happen in ONE critical section, against the same lock
    /// [`begin_stop`](Self::begin_stop) takes, because both race teardown:
    ///
    ///   - Checking the stop flag and then publishing separately lets a Ctrl-C
    ///     land in between. Teardown closes the OLD handle, the new one is
    ///     installed afterwards, and nothing ever closes it — a live session
    ///     surviving the process's own shutdown, which is the zombie this file
    ///     exists to kill, re-created on the way out.
    ///   - `run_outer` deletes the token files as soon as `shutdown` returns,
    ///     so a write outside the section could re-create one after cleanup
    ///     and leave a stale service token on disk.
    ///
    /// A token file that cannot be rewritten is NOT a successful reconnect.
    /// Dispatch starts injecting the new service token the moment the register
    /// ack lands, while the still-running module compares every inbound call
    /// against this file — a stale file trades the loud `503 tunnel_offline`
    /// for a quiet `403 not_proxied` on the same pages. Closing the session is
    /// the only honest outcome: it keeps the failure loud.
    fn publish(&self, handle: tunnel::TunnelHandle, token_file: &Path) -> Publish {
        let mut slot = self.lock_handle();
        if self.stop.load(Ordering::SeqCst) {
            drop(slot);
            handle.shutdown();
            return Publish::Refused;
        }
        if let Err(e) = write_platform_token(token_file, &handle.service_token, &self.slug) {
            drop(slot);
            handle.shutdown();
            return Publish::TokenWriteFailed(e);
        }
        *slot = Some(handle);
        Publish::Installed
    }

    /// Stop supervising and close the session that is currently installed.
    ///
    /// Setting the flag while holding the handle lock is what makes
    /// [`publish`](Self::publish) safe: a reconnect either installed its
    /// session before this ran — in which case this closes that session, not
    /// the one it replaced — or finds the flag already set and closes its own.
    /// Idempotent, and safe when the session has already ended: the notify
    /// simply has no receiver.
    fn begin_stop(&self) {
        let slot = self.lock_handle();
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = slot.as_ref() {
            h.shutdown();
        }
    }
}

/// All supervisors for one `dev --tunnel` run, plus the runtime keeping their
/// tunnels alive.
pub(super) struct SupervisorSet {
    supervisors: Vec<Arc<Supervisor>>,
    /// Count of supervisor threads that have exited. Teardown waits on this
    /// instead of `JoinHandle::join`, which cannot be bounded.
    finished: Arc<AtomicUsize>,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl SupervisorSet {
    /// Slugs whose tunnel is permanently offline. Empty in the healthy case.
    pub(super) fn dead_slugs(&self) -> Vec<String> {
        self.supervisors
            .iter()
            .filter(|s| s.dead.load(Ordering::SeqCst))
            .map(|s| s.slug.clone())
            .collect()
    }

    pub(super) fn len(&self) -> usize {
        self.supervisors.len()
    }

    /// Stop supervising and close every open session.
    ///
    /// Waits only [`SHUTDOWN_GRACE`] for the threads: one parked in a socket
    /// call must never make Ctrl-C feel hung. A straggler can do no damage
    /// because every session it could still open goes through
    /// [`Supervisor::publish`], which sees the flag this just set under the
    /// same lock and closes that session instead of installing it.
    pub(super) fn shutdown(self) {
        let total = self.supervisors.len();
        for s in &self.supervisors {
            s.begin_stop();
        }
        // Let the close frames flush before the runtime goes away — same
        // 200ms grace the pre-supervisor teardown used.
        self.runtime.block_on(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while self.finished.load(Ordering::SeqCst) < total && Instant::now() < deadline {
            thread::sleep(TICK);
        }
    }
}

/// Write a module's platform-token file. Shared by the first registration
/// (`run_outer`) and every reconnect so the two can never drift.
pub(super) fn write_platform_token(file: &Path, token: &str, slug: &str) -> Result<()> {
    std::fs::write(file, token)
        .with_context(|| format!("dev: write platform token file for {slug}"))
}

/// Start one supervisor thread per module. `sessions` and `targets` must be
/// index-aligned (both come from `open_tunnels`, which builds them together).
pub(super) fn spawn(
    runtime: Arc<tokio::runtime::Runtime>,
    sessions: Vec<tunnel::TunnelSession>,
    targets: Vec<TunnelTarget>,
    ctx: ReconnectCtx,
) -> SupervisorSet {
    let ctx = Arc::new(ctx);
    let finished = Arc::new(AtomicUsize::new(0));
    let mut supervisors = Vec::with_capacity(sessions.len());

    for (session, target) in sessions.into_iter().zip(targets) {
        let sup = Arc::new(Supervisor {
            slug: target.slug.clone(),
            handle: Mutex::new(Some(session.handle)),
            stop: AtomicBool::new(false),
            dead: AtomicBool::new(false),
        });
        let thread_sup = sup.clone();
        let thread_ctx = ctx.clone();
        let thread_runtime = runtime.clone();
        let thread_finished = finished.clone();
        thread::spawn(move || {
            supervise(thread_sup, target, thread_ctx, thread_runtime, session.exit);
            thread_finished.fetch_add(1, Ordering::SeqCst);
        });
        supervisors.push(sup);
    }

    SupervisorSet {
        supervisors,
        finished,
        runtime,
    }
}

/// One module's supervision loop: wait for the session to end, reconnect,
/// repeat. Returns only on teardown or permanent failure.
fn supervise(
    sup: Arc<Supervisor>,
    target: TunnelTarget,
    ctx: Arc<ReconnectCtx>,
    runtime: Arc<tokio::runtime::Runtime>,
    first_exit: tokio::sync::oneshot::Receiver<tunnel::TunnelExit>,
) {
    // No credential load here, deliberately. A load that failed used to print
    // one startup warning and return, leaving the original session running
    // with nobody watching it: when that session later died there was no
    // reconnect, no recurring warning, no dead-ledger entry and a zero exit —
    // the original zombie, through another door. `open_tunnels` has already
    // proved the credentials work (it minted with them), so they are handed in
    // and this function has no failure mode before the loop.
    let mut exit = first_exit;
    loop {
        let why = match runtime.block_on(exit) {
            // Teardown is the only thing that closes an INSTALLED session
            // (`begin_stop` sets the flag before it fires the notify, under
            // one lock), so this is the operator leaving.
            Ok(tunnel::TunnelExit::Shutdown) if sup.stopping() => return,
            // A shutdown nobody asked for still leaves the module unroutable.
            // Treat it as a loss rather than a reason to stop watching: this
            // function returning while the dev session runs on is the exact
            // failure the file exists to remove.
            Ok(tunnel::TunnelExit::Shutdown) => "tunnel closed without a teardown".to_string(),
            Ok(tunnel::TunnelExit::Lost(reason)) => reason,
            // The loop task went away without signalling (panic, or the
            // runtime shutting down under us). Indistinguishable from a lost
            // connection as far as the platform is concerned.
            Err(_) => "tunnel task ended without a reason".to_string(),
        };
        if sup.stopping() {
            return;
        }

        eprintln!(
            "{} [{}] tunnel lost ({why}) — the module is unreachable from the platform until it reconnects",
            warn_prefix(),
            style(&target.slug).cyan()
        );

        match reconnect(&sup, &target, &ctx, &runtime) {
            // `reconnect` installed the new handle itself (publishing and the
            // teardown check have to be one operation), so all that comes back
            // is the exit signal to wait on next.
            Some(next_exit) => exit = next_exit,
            None => {
                // Teardown raced us — nothing to complain about on the way out.
                if sup.stopping() {
                    return;
                }
                // Anything else means this module is no longer supervised while
                // the dev session runs on. `reconnect` marks it dead before
                // giving up, so this is a backstop rather than a second path;
                // it exists because the ONE outcome this file must never have
                // is a supervisor that stops quietly.
                let _ = ensure_recorded_dead(&sup, &target, "supervision stopped without a reason");
                nag_until_stopped(&sup, &target);
                return;
            }
        }
    }
}

/// Record a non-teardown end of supervision in the dead ledger, unless
/// something already did. Returns whether it had to announce.
///
/// The ledger is what makes the failure loud beyond the moment it happens:
/// `dead_slugs` reports it at teardown and `run_outer` exits non-zero when
/// every tunnel is on it. A supervisor that returns without landing here is
/// invisible — which is precisely how a tunnel ran 14 hours dead while every
/// local signal said healthy. Re-announcing an already-dead module is the
/// opposite mistake: a second copy of the same banner reads as a second
/// failure, so the caller that already printed one stays silent here.
fn ensure_recorded_dead(sup: &Supervisor, target: &TunnelTarget, reason: &str) -> bool {
    if sup.dead.load(Ordering::SeqCst) {
        return false;
    }
    mark_dead(sup, target, reason);
    true
}

/// Re-establish one module's tunnel, retrying with jittered exponential
/// backoff. `Some` carries the new session's exit signal — the handle itself
/// is installed on `sup` by [`Supervisor::publish`], which has to own that
/// step to keep it atomic against teardown. `None` means the caller should
/// stop supervising: either teardown set the stop flag, or the failure is
/// permanent (in which case `sup.dead` is set and the reason has been
/// printed).
fn reconnect(
    sup: &Supervisor,
    target: &TunnelTarget,
    ctx: &ReconnectCtx,
    runtime: &tokio::runtime::Runtime,
) -> Option<tokio::sync::oneshot::Receiver<tunnel::TunnelExit>> {
    for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
        let delay = reconnect_delay(attempt, rand::random::<f64>());
        eprintln!(
            "{} [{}] tunnel reconnect attempt {attempt}/{MAX_RECONNECT_ATTEMPTS} in {:.1}s…",
            warn_prefix(),
            style(&target.slug).cyan(),
            delay.as_secs_f64()
        );
        if !sleep_unless_stopped(sup, delay) {
            return None;
        }

        match attempt_reconnect(sup, target, ctx, runtime) {
            Ok(tunnel::TunnelSession { handle, exit }) => {
                let session_id = handle.session_id.clone();
                // Install and rewrite the token file in one operation — see
                // `Supervisor::publish` for why neither half can stand alone.
                // Nothing may be announced as reconnected before it returns.
                match sup.publish(handle, &target.token_file) {
                    // Teardown won the race. It closed what we opened and
                    // touched nothing on disk, so leave quietly.
                    Publish::Refused => return None,
                    Publish::TokenWriteFailed(e) => {
                        mark_dead(sup, target, &unusable_session_reason(target, &e));
                        return None;
                    }
                    Publish::Installed => {}
                }
                // The dev-bundle CDN pointer is stored per session and died
                // with the old one; the share watcher's content-hash gate
                // would never notice, since the bytes did not change.
                ctx.share.invalidate(&target.slug);
                ctx.clients.replace(&target.slug, &session_id);
                eprintln!(
                    "{} [{}] tunnel reconnected (session {})",
                    ok_mark(),
                    style(&target.slug).cyan(),
                    style(&session_id).dim()
                );
                return Some(exit);
            }
            Err(outcome) => {
                let terminal = outcome.is_terminal();
                eprintln!(
                    "{} [{}] tunnel reconnect attempt {attempt} failed: {}",
                    warn_prefix(),
                    style(&target.slug).cyan(),
                    outcome.message()
                );
                if terminal {
                    mark_dead(sup, target, outcome.message());
                    return None;
                }
            }
        }
        if sup.stopping() {
            return None;
        }
    }
    mark_dead(
        sup,
        target,
        &format!("no successful reconnect in {MAX_RECONNECT_ATTEMPTS} attempts"),
    );
    None
}

/// One reconnect attempt: mint → read manifest hash → connect + register.
fn attempt_reconnect(
    sup: &Supervisor,
    target: &TunnelTarget,
    ctx: &ReconnectCtx,
    runtime: &tokio::runtime::Runtime,
) -> std::result::Result<tunnel::TunnelSession, AttemptOutcome> {
    let client = http::client(Duration::from_secs(15))
        .map_err(|e| AttemptOutcome::Retry(format!("build HTTP client: {e}")))?;

    // The connect token's server-side TTL is ~60s, so the one that opened the
    // dead session is never reusable — always mint a new one.
    let token = ctx.creds.mint(&client, &ctx.dispatch_base)?;

    // Unlike the first register (which precedes `docker compose up`), the
    // module is running now, so carry its real manifest hash. Authenticated
    // with the OLD service token — still what the module's token file holds.
    let previous_token = sup.service_token();
    let manifest_hash = runtime.block_on(tunnel::current_manifest_hash(
        &target.local_url,
        &previous_token,
        Some(&target.internal_secret),
    ));

    runtime
        .block_on(async {
            tokio::time::timeout(
                CONNECT_TIMEOUT,
                tunnel::open(
                    &token.wss_url,
                    &token.token,
                    tunnel::RegisterPayload {
                        module_id: &target.module_id,
                        local_url: &target.local_url,
                        version: env!("CARGO_PKG_VERSION"),
                        internal_secret: Some(&target.internal_secret),
                        manifest_hash,
                    },
                ),
            )
            .await
        })
        .map_err(|_| {
            AttemptOutcome::Retry(format!(
                "connect + register did not complete within {}s",
                CONNECT_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| classify_register_error(&e))
}

/// The reason a reconnect that CONNECTED still counts as a permanent failure.
///
/// Kept whole here rather than inlined because the wording is the fix: the
/// operator has to understand that the session was closed on purpose, or the
/// obvious reading of "reconnected, but…" is that things are working.
fn unusable_session_reason(target: &TunnelTarget, e: &anyhow::Error) -> String {
    format!(
        "reconnected, but {} could not be rewritten ({e:#}). The new session was CLOSED rather than kept: \
         dispatch would have injected a service token the still-running module cannot match, so every \
         platform→module call would have failed with a quiet 403 not_proxied instead of a visible 503",
        target.token_file.display()
    )
}

/// Mark a module permanently offline and say so in terms the operator can act
/// on — naming both symptoms they would otherwise have to trace back by hand.
fn mark_dead(sup: &Supervisor, target: &TunnelTarget, reason: &str) {
    sup.dead.store(true, Ordering::SeqCst);
    eprintln!();
    eprintln!(
        "{} [{}] TUNNEL PERMANENTLY OFFLINE — {reason}",
        warn_prefix(),
        style(&target.slug).cyan().bold()
    );
    eprintln!("  Calls routed to this module now fail with 503 tunnel_offline, and ms.Emit fails");
    eprintln!("  with 403 unknown_sender, so its events reach no subscriber.");
    eprintln!(
        "  {} restart `mirrorstack dev --tunnel` to recover.",
        style("Fix:").bold()
    );
    eprintln!();
}

/// Keep re-announcing a dead tunnel until teardown. The single close warning
/// this replaces was interleaved into `docker compose`'s inherited output and
/// scrolled away within seconds — which is exactly how a dev session ends up
/// looking healthy while the app is down.
fn nag_until_stopped(sup: &Supervisor, target: &TunnelTarget) {
    let mut last = Instant::now();
    while !sup.stopping() {
        if last.elapsed() >= DEAD_NAG_INTERVAL {
            last = Instant::now();
            eprintln!(
                "{} [{}] tunnel is still offline — this module is not reachable from the platform",
                warn_prefix(),
                style(&target.slug).cyan()
            );
        }
        thread::sleep(TICK);
    }
}

/// Sleep in [`TICK`] slices so teardown never waits out a full backoff.
/// Returns false when the stop flag was set (caller should bail).
fn sleep_unless_stopped(sup: &Supervisor, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if sup.stopping() {
            return false;
        }
        thread::sleep(TICK.min(deadline.saturating_duration_since(Instant::now())));
    }
    !sup.stopping()
}

/// Why one reconnect attempt failed, reduced to the only distinction the
/// supervisor acts on.
#[derive(Debug)]
enum AttemptOutcome {
    /// Transient — the next attempt may well succeed.
    Retry(String),
    /// Needs a human. Retrying cannot fix it, so burning nine more attempts
    /// only buries the message the operator has to read.
    Terminal(String),
}

impl AttemptOutcome {
    fn is_terminal(&self) -> bool {
        matches!(self, AttemptOutcome::Terminal(_))
    }

    fn message(&self) -> &str {
        match self {
            AttemptOutcome::Retry(m) | AttemptOutcome::Terminal(m) => m,
        }
    }
}

/// A failed tunnel-token mint. Only an expired/revoked session is terminal:
/// everything else (dispatch restarting, DNS blip, offline laptop) is exactly
/// what the backoff exists for.
fn classify_mint_error(e: &api::ApiError) -> AttemptOutcome {
    match e {
        api::ApiError::Unauthenticated => AttemptOutcome::Terminal(
            "session expired — run `mirrorstack login`, then restart `mirrorstack dev --tunnel`"
                .to_string(),
        ),
        other => AttemptOutcome::Retry(format!("tunnel-token mint failed: {other}")),
    }
}

/// A failed token refresh. Only the platform answering `Unauthenticated` means
/// the session itself is gone; that is the one case worth giving up on.
/// Everything else (DNS, TLS, a dispatch 503 landing between the 401 and the
/// refresh) is a blip, and mapping it onto "session expired" — which is what
/// `with_refresh_retry` does, since it collapses every refresh failure into
/// `Unauthenticated` — would let one badly-timed second permanently kill a
/// module the backoff would have recovered.
fn classify_refresh_error(e: &anyhow::Error) -> AttemptOutcome {
    match e.downcast_ref::<api::ApiError>() {
        Some(api::ApiError::Unauthenticated) => {
            classify_mint_error(&api::ApiError::Unauthenticated)
        }
        _ => AttemptOutcome::Retry(format!("token refresh failed: {e:#}")),
    }
}

/// A rejected register. The three typed rejections are platform-side policy
/// decisions that will answer identically on every retry; only transport
/// failures are worth backing off on.
fn classify_register_error(e: &tunnel::RegisterError) -> AttemptOutcome {
    match e {
        tunnel::RegisterError::ModuleDevModeOff { .. } => AttemptOutcome::Terminal(
            "dev mode is disabled for this module on the platform — re-enable it in the dev console"
                .to_string(),
        ),
        tunnel::RegisterError::ModuleNotYours => AttemptOutcome::Terminal(
            "module is not owned by you — only the owner can open a dev tunnel".to_string(),
        ),
        tunnel::RegisterError::Rejected { code, message } => {
            AttemptOutcome::Terminal(format!("register rejected ({code}): {message}"))
        }
        tunnel::RegisterError::Transport(err) => AttemptOutcome::Retry(format!("{err:#}")),
    }
}

/// Backoff for reconnect attempt `attempt` (1-based). Doubles from
/// [`RECONNECT_BACKOFF_BASE`] up to [`RECONNECT_BACKOFF_CAP`], then applies
/// ±25% jitter so five sessions that died together (the observed failure mode
/// — one API Gateway event closes all of them at once) don't march back in
/// lockstep and re-thunder the same endpoint.
///
/// `jitter` is supplied by the caller (`rand::random::<f64>()` in production)
/// so the schedule is deterministic under test.
fn reconnect_delay(attempt: u32, jitter: f64) -> Duration {
    let steps = attempt.saturating_sub(1).min(16);
    let base = RECONNECT_BACKOFF_BASE
        .saturating_mul(1u32 << steps)
        .min(RECONNECT_BACKOFF_CAP);
    let factor = 0.75 + 0.5 * jitter.clamp(0.0, 1.0);
    base.mul_f64(factor)
}

/// The one credential copy every supervisor mints against.
///
/// Each thread used to own its own. That is harmless until the access token
/// expires — at which point several supervisors call `with_refresh_retry` at
/// once, the first rotates the refresh token, and every other one then
/// presents a value the platform has already invalidated. That comes back as
/// `Unauthenticated`, which [`classify_mint_error`] calls TERMINAL, so one
/// server close could permanently kill modules whose session was perfectly
/// fine. Refreshing at most once and letting the losers retry with the rotated
/// token is what makes a simultaneous close recoverable.
///
/// Sharing between supervisors is only half of it, because supervisors are not
/// the only rotator. The same `credentials.json` is rotated by the `--share`
/// watcher and by EVERY authenticated CLI command run in a second terminal —
/// `mirrorstack whoami`, `app list`, `module …` all go through
/// `credentials::with_refresh_retry`. The platform hard-revokes the pair it
/// rotates away from (the rotation and the revoke share one `FOR UPDATE`
/// transaction), so one `whoami` is enough to leave this cached pair
/// permanently 401. That is why a failed refresh re-reads the file before it is
/// allowed to end the run — see [`mint_with`](Self::mint_with).
pub(super) struct SharedCredentials {
    inner: Mutex<credentials::Credentials>,
}

/// The pair currently on disk, or `None` when there is none worth trying.
///
/// Every failure collapses to `None` deliberately: a missing file, an
/// unreadable one and a `credentials.json` some hand-edit corrupted all mean
/// the same thing here — "nothing newer to try" — and the caller then reports
/// the refresh failure it already had. This runs on a supervisor thread of a
/// live dev session, so it must never be the thing that panics.
fn reload_from_disk() -> Option<credentials::Credentials> {
    credentials::load().ok()
}

impl SharedCredentials {
    pub(super) fn new(creds: credentials::Credentials) -> Self {
        Self {
            inner: Mutex::new(creds),
        }
    }

    /// See [`Supervisor::lock_handle`] — same reasoning, and a token pair has
    /// no invariant a panic could tear.
    fn lock(&self) -> MutexGuard<'_, credentials::Credentials> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Mint a fresh tunnel-connect token, refreshing the session at most once
    /// across every supervisor.
    fn mint(
        &self,
        client: &Client,
        dispatch_base: &str,
    ) -> std::result::Result<api::TunnelToken, AttemptOutcome> {
        self.mint_with(
            |tok| api::tunnel_token(client, dispatch_base, tok),
            credentials::refresh_and_save,
            reload_from_disk,
        )
    }

    /// [`mint`](Self::mint) with the network and disk steps injected, so the
    /// coordination this exists for is testable without a network.
    ///
    /// `call` runs against the shared access token with NO lock held: five
    /// modules dropped by one server event still mint in parallel, which is
    /// the common case and the one that must stay fast. Only the refresh is
    /// serialized, and only the first arrival performs it — a supervisor that
    /// finds the token already rotated retries with the new one instead of
    /// spending the invalidated refresh token on a second rotation.
    ///
    /// A refresh that fails is NOT yet proof the session is gone, which is why
    /// `reload` gets the last word. In-process coordination cannot see a
    /// rotation performed by another PROCESS, and the platform revokes the pair
    /// it rotates away from, so after one `mirrorstack whoami` in a second
    /// terminal this cached refresh token answers 401 for good. Without the
    /// re-read the next server close ends the whole run on attempt 1 of
    /// [`MAX_RECONNECT_ATTEMPTS`] with "session expired — run `mirrorstack
    /// login`" while `credentials.json` holds a perfectly good pair.
    ///
    /// Exactly ONE re-read per call, and only when disk carries a refresh token
    /// we have not already spent — anything else is the same doomed request a
    /// second time. The disk pair is installed BEFORE that retry and left
    /// installed however the retry ends: it is the newest pair anyone knows of,
    /// and a sibling waking up on this lock must never re-spend the token this
    /// call just proved dead.
    fn mint_with<T>(
        &self,
        mut call: impl FnMut(&str) -> std::result::Result<T, api::ApiError>,
        mut refresh: impl FnMut(&str) -> Result<credentials::Credentials>,
        reload: impl FnOnce() -> Option<credentials::Credentials>,
    ) -> std::result::Result<T, AttemptOutcome> {
        let attempted = self.lock().access_token.clone();
        match call(&attempted) {
            Err(api::ApiError::Unauthenticated) => {}
            other => return other.map_err(|e| classify_mint_error(&e)),
        }
        let retry_with = {
            let mut guard = self.lock();
            if guard.access_token == attempted {
                // Nobody beat us here, so the rotation is ours to do.
                let spent = guard.refresh_token.clone();
                match refresh(&spent) {
                    Ok(new) => *guard = new,
                    Err(ours) => {
                        // Reading a small file while holding the lock is fine —
                        // it takes no lock of ours, so the siblings queued
                        // behind us wait on a file read, not on a deadlock.
                        match reload().filter(|disk| disk.refresh_token != spent) {
                            Some(disk) => {
                                *guard = disk;
                                // Refreshing rather than reusing the disk access
                                // token costs one rotation but recovers on THIS
                                // attempt. Trying the disk access token instead
                                // would go terminal the moment it happened to be
                                // older than its 15 minutes, and
                                // `classify_mint_error` leaves no second attempt
                                // to recover in.
                                let rotated = guard.refresh_token.clone();
                                match refresh(&rotated) {
                                    Ok(new) => *guard = new,
                                    // The newest pair in existence is dead too,
                                    // so the session really is gone.
                                    Err(e) => return Err(classify_refresh_error(&e)),
                                }
                            }
                            // Disk holds the pair we just spent, so it is
                            // already the newest one and there is nothing
                            // better to leave behind.
                            None => return Err(classify_refresh_error(&ours)),
                        }
                    }
                }
            }
            guard.access_token.clone()
        };
        // Released before the retry so the losers of one rotation still mint
        // concurrently.
        call(&retry_with).map_err(|e| classify_mint_error(&e))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionSnapshot {
    pub session_id: String,
    pub generation: u64,
}

/// Current tunnel session per module. Client artifacts are content-addressed,
/// but their live pointer is session-owned, so a reconnect must force a new
/// confirmation even when the bytes did not change.
#[derive(Default)]
pub(super) struct SessionTracker {
    sessions: Mutex<HashMap<String, SessionSnapshot>>,
}

impl SessionTracker {
    pub(super) fn seed(&self, slug: &str, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.insert(
            slug.to_string(),
            SessionSnapshot {
                session_id: session_id.to_string(),
                generation: 0,
            },
        );
    }

    fn replace(&self, slug: &str, session_id: &str) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(current) = sessions.get_mut(slug) else {
            return;
        };
        current.session_id = session_id.to_string();
        current.generation = current.generation.saturating_add(1);
    }

    pub(super) fn current(&self, slug: &str) -> Option<SessionSnapshot> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(slug)
            .cloned()
    }
}

/// Slugs whose `--share` bundle pointer must be re-confirmed after a
/// reconnect. Lives here rather than in `share` so the supervisor can hand one
/// out even when `--share` is off (nothing drains it; it just stays a handful
/// of strings).
#[derive(Default)]
pub(super) struct ShareInvalidator {
    slugs: Mutex<HashSet<String>>,
}

impl ShareInvalidator {
    pub(super) fn invalidate(&self, slug: &str) {
        if let Ok(mut g) = self.slugs.lock() {
            g.insert(slug.to_string());
        }
    }

    /// Take everything queued so far. Called by the share watcher once per
    /// scan.
    pub(super) fn drain(&self) -> HashSet<String> {
        self.slugs
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    /// A supervisor with `session` installed and nothing else going on.
    fn supervisor(slug: &str, session: Option<tunnel::TunnelHandle>) -> Supervisor {
        Supervisor {
            slug: slug.into(),
            handle: Mutex::new(session),
            stop: AtomicBool::new(false),
            dead: AtomicBool::new(false),
        }
    }

    /// A target whose token file lives under `dir`, named the way
    /// `platform_token_file` names it.
    fn target(slug: &str, dir: &Path) -> TunnelTarget {
        TunnelTarget {
            slug: slug.into(),
            module_id: "mod_abc".into(),
            local_url: "http://127.0.0.1:1".into(),
            token_file: dir.join(format!("ms-platform-token-{slug}")),
            internal_secret: format!("secret-{slug}"),
        }
    }

    fn creds(access: &str, refresh: &str) -> credentials::Credentials {
        credentials::Credentials {
            access_token: access.into(),
            refresh_token: refresh.into(),
            expires_at: SystemTime::now() + Duration::from_secs(900),
        }
    }

    /// Was this session asked to close? `Notify::notify_one` leaves a permit,
    /// so a `notified()` that resolves at once means `shutdown` fired.
    fn was_closed(notify: &tokio::sync::Notify) -> bool {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime")
            .block_on(async {
                tokio::time::timeout(Duration::from_millis(50), notify.notified())
                    .await
                    .is_ok()
            })
    }

    #[test]
    fn expired_session_is_terminal_but_transport_is_retryable() {
        // A revoked/expired session answers identically on every retry, so
        // burning the full attempt budget only buries the login hint.
        assert!(classify_mint_error(&api::ApiError::Unauthenticated).is_terminal());
        assert!(
            !classify_mint_error(&api::ApiError::Unexpected {
                status: 503,
                body: "dispatch restarting".into(),
            })
            .is_terminal()
        );
    }

    #[test]
    fn policy_rejections_are_terminal_transport_is_not() {
        assert!(
            classify_register_error(&tunnel::RegisterError::ModuleDevModeOff { slug: None })
                .is_terminal()
        );
        assert!(classify_register_error(&tunnel::RegisterError::ModuleNotYours).is_terminal());
        assert!(
            classify_register_error(&tunnel::RegisterError::Rejected {
                code: "module_not_found".into(),
                message: "gone".into(),
            })
            .is_terminal()
        );
        // The observed outage (WS 1001 from API Gateway) surfaces as a
        // transport failure on the next connect — this MUST keep retrying or
        // the fix does nothing for the actual bug.
        assert!(
            !classify_register_error(&tunnel::RegisterError::Transport(anyhow::anyhow!(
                "connection reset"
            )))
            .is_terminal()
        );
    }

    #[test]
    fn terminal_message_reaches_the_operator() {
        let out = classify_mint_error(&api::ApiError::Unauthenticated);
        assert!(out.message().contains("mirrorstack login"), "{out:?}");
    }

    #[test]
    fn backoff_doubles_then_caps() {
        // Mid-jitter (0.5) is the identity factor, so these are the raw steps.
        let at = |n| reconnect_delay(n, 0.5);
        assert_eq!(at(1), Duration::from_secs(1));
        assert_eq!(at(2), Duration::from_secs(2));
        assert_eq!(at(3), Duration::from_secs(4));
        assert_eq!(at(4), Duration::from_secs(8));
        assert_eq!(at(5), Duration::from_secs(16));
        // 32s would exceed the cap.
        assert_eq!(at(6), RECONNECT_BACKOFF_CAP);
        assert_eq!(at(MAX_RECONNECT_ATTEMPTS), RECONNECT_BACKOFF_CAP);
    }

    #[test]
    fn backoff_never_shrinks_and_never_runs_away() {
        let mut prev = Duration::ZERO;
        for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
            let d = reconnect_delay(attempt, 0.5);
            assert!(d >= prev, "attempt {attempt} went backwards");
            assert!(d <= RECONNECT_BACKOFF_CAP);
            prev = d;
        }
        // A huge attempt number must not overflow the shift or the multiply.
        assert_eq!(
            reconnect_delay(u32::MAX, 1.0),
            RECONNECT_BACKOFF_CAP.mul_f64(1.25)
        );
    }

    #[test]
    fn jitter_spreads_within_25_percent_both_ways() {
        // Five sessions closed by one API Gateway event must not retry in
        // lockstep; the spread is what breaks the thundering herd.
        let low = reconnect_delay(6, 0.0);
        let mid = reconnect_delay(6, 0.5);
        let high = reconnect_delay(6, 1.0);
        assert_eq!(low, RECONNECT_BACKOFF_CAP.mul_f64(0.75));
        assert_eq!(mid, RECONNECT_BACKOFF_CAP);
        assert_eq!(high, RECONNECT_BACKOFF_CAP.mul_f64(1.25));
        assert!(low < mid && mid < high);
        // Out-of-range input is clamped, never inverted.
        assert_eq!(reconnect_delay(6, -1.0), low);
        assert_eq!(reconnect_delay(6, 9.0), high);
    }

    #[test]
    fn total_retry_window_is_minutes_not_seconds() {
        // The budget has to survive a laptop lid or a dispatch redeploy.
        let total: Duration = (1..=MAX_RECONNECT_ATTEMPTS)
            .map(|a| reconnect_delay(a, 0.5))
            .sum();
        assert!(
            total >= Duration::from_secs(150) && total <= Duration::from_secs(600),
            "unexpected retry window {total:?}"
        );
    }

    #[test]
    fn share_invalidator_drains_once() {
        let inv = ShareInvalidator::default();
        inv.invalidate("oauth-core");
        inv.invalidate("users-roles");
        inv.invalidate("oauth-core");
        let first = inv.drain();
        assert_eq!(first.len(), 2);
        assert!(first.contains("oauth-core"));
        // Draining twice must not re-trigger an upload for bytes that never
        // changed.
        assert!(inv.drain().is_empty());
    }

    #[test]
    fn session_tracker_seeds_and_advances_generation() {
        let tracker = SessionTracker::default();
        tracker.seed("oauth-core", "session-1");

        assert_eq!(
            tracker.current("oauth-core"),
            Some(SessionSnapshot {
                session_id: "session-1".into(),
                generation: 0,
            })
        );

        tracker.replace("oauth-core", "session-2");
        assert_eq!(
            tracker.current("oauth-core"),
            Some(SessionSnapshot {
                session_id: "session-2".into(),
                generation: 1,
            })
        );
    }

    #[test]
    fn session_tracker_does_not_create_reconnect_state_without_seed() {
        let tracker = SessionTracker::default();

        tracker.replace("unknown", "session-2");

        assert_eq!(tracker.current("unknown"), None);
    }

    #[test]
    fn sleep_unless_stopped_bails_immediately_when_stopped() {
        let sup = supervisor("oauth-core", None);
        sup.stop.store(true, Ordering::SeqCst);
        let started = Instant::now();
        assert!(!sleep_unless_stopped(&sup, RECONNECT_BACKOFF_CAP));
        // Teardown must not wait out a 30s backoff.
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn sleep_unless_stopped_completes_a_short_wait() {
        let sup = supervisor("oauth-core", None);
        assert!(sleep_unless_stopped(&sup, Duration::from_millis(50)));
    }

    // ── Finding 1: publishing a session races teardown ──────────────

    #[test]
    fn publish_after_teardown_closes_the_session_and_writes_nothing() {
        // Ctrl-C lands while a reconnect is mid-connect. The session that
        // comes back must be closed by the thread that opened it — nobody
        // else holds it — and the token file must be left exactly as
        // `run_outer`'s cleanup expects to find it.
        let dir = tempfile::tempdir().expect("tempdir");
        let token_file = dir.path().join("ms-platform-token-oauth-core");
        std::fs::write(&token_file, "stk_old").expect("seed token file");

        let (old, old_notify) = tunnel::TunnelHandle::detached("sess_old", "stk_old");
        let sup = supervisor("oauth-core", Some(old));
        sup.begin_stop();
        assert!(
            was_closed(&old_notify),
            "teardown must close the session that was installed"
        );

        let (fresh, fresh_notify) = tunnel::TunnelHandle::detached("sess_new", "stk_new");
        assert!(matches!(sup.publish(fresh, &token_file), Publish::Refused));
        assert!(
            was_closed(&fresh_notify),
            "a session opened after teardown began must not be left running"
        );
        assert_eq!(
            std::fs::read_to_string(&token_file).expect("read token file"),
            "stk_old",
            "a refused session must not touch a file cleanup is about to delete"
        );
    }

    #[test]
    fn teardown_racing_a_reconnect_never_leaves_a_session_open() {
        // The reviewed version checked the stop flag in `reconnect` and
        // installed the handle later, in `supervise`. A Ctrl-C between the two
        // closed the OLD handle while the NEW one was installed afterwards and
        // never closed — a live session outliving the process's own shutdown,
        // which is the zombie this file exists to kill, re-created on the way
        // out. Whichever side wins the lock, the new session must end up
        // closed.
        let dir = tempfile::tempdir().expect("tempdir");
        for i in 0..100 {
            let token_file = dir.path().join(format!("ms-platform-token-{i}"));
            let (old, _old_notify) = tunnel::TunnelHandle::detached("sess_old", "stk_old");
            let sup = Arc::new(supervisor("oauth-core", Some(old)));
            let (fresh, fresh_notify) = tunnel::TunnelHandle::detached("sess_new", "stk_new");

            let stopper = {
                let sup = sup.clone();
                thread::spawn(move || sup.begin_stop())
            };
            let outcome = sup.publish(fresh, &token_file);
            stopper.join().expect("teardown thread");

            // Either order is legal — teardown first (Refused, we closed our
            // own) or publish first (Installed, teardown closed it for us,
            // because the flag and the handle move under the same lock).
            if let Publish::TokenWriteFailed(e) = &outcome {
                panic!("iteration {i}: unexpected write failure: {e:#}");
            }
            assert!(
                was_closed(&fresh_notify),
                "iteration {i}: the new session survived teardown ({outcome:?})"
            );
        }
    }

    // ── Finding 2: a token file that cannot be rewritten ────────────

    #[test]
    fn a_token_file_that_cannot_be_rewritten_is_not_a_reconnect() {
        // A directory where the file belongs makes `write` fail on every
        // platform without faking permissions.
        let dir = tempfile::tempdir().expect("tempdir");
        let token_file = dir.path().join("ms-platform-token-oauth-core");
        std::fs::create_dir(&token_file).expect("occupy the token path");

        let (old, _old_notify) = tunnel::TunnelHandle::detached("sess_old", "stk_old");
        let sup = supervisor("oauth-core", Some(old));
        let (fresh, fresh_notify) = tunnel::TunnelHandle::detached("sess_new", "stk_new");

        let outcome = sup.publish(fresh, &token_file);
        assert!(
            matches!(outcome, Publish::TokenWriteFailed(_)),
            "got {outcome:?}"
        );
        // Keeping it would hand dispatch stk_new while the module still
        // compares against stk_old: a quiet 403 on every platform→module call,
        // indefinitely, which is worse than the bug being fixed.
        assert!(
            was_closed(&fresh_notify),
            "an unusable session must be closed, not left live"
        );
        assert_eq!(
            sup.service_token(),
            "stk_old",
            "an unusable session must not become the live one"
        );
    }

    #[test]
    fn an_unusable_session_is_recorded_dead_and_explains_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tgt = target("oauth-core", dir.path());
        let sup = supervisor("oauth-core", None);

        let reason = unusable_session_reason(&tgt, &anyhow::anyhow!("read-only file system"));
        mark_dead(&sup, &tgt, &reason);

        assert!(
            sup.dead.load(Ordering::SeqCst),
            "this path used to warn once and return a live session"
        );
        assert!(reason.contains("CLOSED"), "{reason}");
        assert!(reason.contains("read-only file system"), "{reason}");
        assert!(
            reason.contains("403"),
            "the operator has to be told which symptom to expect: {reason}"
        );
    }

    // ── Finding 3: one rotation must serve every supervisor ─────────

    #[test]
    fn one_rotation_serves_every_supervisor_that_hit_the_same_401() {
        // Five modules dropped by one server close reconnect together. With a
        // credentials copy per thread they each ran their own refresh: the
        // first rotated the refresh token and the other four presented a value
        // the platform had already invalidated, came back Unauthenticated, and
        // were classified TERMINAL. One close permanently killed four modules
        // that were never signed out.
        const MODULES: usize = 5;
        let shared = Arc::new(SharedCredentials::new(creds("access_old", "refresh_old")));
        let refreshes = Arc::new(AtomicUsize::new(0));
        // Every module must have read the pre-rotation access token before any
        // of them refreshes — that simultaneity IS the bug. Without it the
        // threads just run one after another and never collide.
        let collide = Arc::new(std::sync::Barrier::new(MODULES));

        let threads: Vec<_> = (0..MODULES)
            .map(|_| {
                let shared = shared.clone();
                let refreshes = refreshes.clone();
                let collide = collide.clone();
                thread::spawn(move || {
                    let mut first_call = true;
                    shared.mint_with(
                        |tok| {
                            if std::mem::take(&mut first_call) {
                                collide.wait();
                            }
                            match tok {
                                "access_new" => Ok("ttok_fresh".to_string()),
                                _ => Err(api::ApiError::Unauthenticated),
                            }
                        },
                        |refresh_token| {
                            assert_eq!(
                                refresh_token, "refresh_old",
                                "a supervisor refreshed with an already-rotated token"
                            );
                            refreshes.fetch_add(1, Ordering::SeqCst);
                            Ok(creds("access_new", "refresh_new"))
                        },
                        || panic!("a refresh that worked must not re-read the file"),
                    )
                })
            })
            .collect();

        for t in threads {
            assert!(
                t.join().expect("supervisor thread").is_ok(),
                "every supervisor must mint, not just the one that rotated"
            );
        }
        assert_eq!(
            refreshes.load(Ordering::SeqCst),
            1,
            "the refresh token must rotate once per expiry, not once per module"
        );
        assert_eq!(shared.lock().access_token, "access_new");
    }

    #[test]
    fn a_valid_access_token_never_reaches_the_refresh_path() {
        let shared = SharedCredentials::new(creds("access_live", "refresh_live"));
        let out = shared.mint_with(
            |tok| Ok(tok.to_string()),
            |_| panic!("a successful mint must not refresh"),
            || panic!("a successful mint must not touch the credentials file"),
        );
        assert_eq!(out.expect("mint"), "access_live");
    }

    #[test]
    fn a_blip_during_refresh_retries_but_a_dead_session_does_not() {
        // Only the platform saying the session is gone may be terminal. A
        // transport failure between the 401 and the refresh must stay
        // retryable, or one badly-timed second permanently kills a module the
        // backoff would have recovered.
        let shared = SharedCredentials::new(creds("access_old", "refresh_old"));
        let blip = shared
            .mint_with(
                |_| Err::<String, _>(api::ApiError::Unauthenticated),
                |_| Err(anyhow::anyhow!("dns lookup failed")),
                || None,
            )
            .expect_err("the mint cannot succeed here");
        assert!(!blip.is_terminal(), "{blip:?}");
        assert!(blip.message().contains("dns lookup failed"), "{blip:?}");

        let shared = SharedCredentials::new(creds("access_old", "refresh_old"));
        let expired = shared
            .mint_with(
                |_| Err::<String, _>(api::ApiError::Unauthenticated),
                |_| Err(anyhow::Error::new(api::ApiError::Unauthenticated)),
                || None,
            )
            .expect_err("the mint cannot succeed here");
        assert!(expired.is_terminal(), "{expired:?}");
        assert!(
            expired.message().contains("mirrorstack login"),
            "{expired:?}"
        );
    }

    // ── Finding 3, other half: rotation by another PROCESS ──────────

    #[test]
    fn a_rotation_by_another_process_is_recovered_from_disk() {
        // The half the shared handle cannot cover. `mirrorstack whoami` in a
        // second terminal refreshes through the same credentials.json, and the
        // platform revokes the pair it rotated away from — so the pair these
        // supervisors cached at startup is now permanently 401. The next server
        // close used to end the entire run on attempt 1 of 10 with "session
        // expired — run `mirrorstack login`" while the file on disk held a
        // perfectly good pair.
        let shared = SharedCredentials::new(creds("access_stale", "refresh_spent"));
        let refreshed_with: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let reloads = AtomicUsize::new(0);

        let out = shared.mint_with(
            |tok| match tok {
                "access_live" => Ok("ttok_fresh".to_string()),
                _ => Err(api::ApiError::Unauthenticated),
            },
            |rt| {
                refreshed_with.lock().unwrap().push(rt.to_string());
                match rt {
                    // Revoked the moment `whoami` rotated past it.
                    "refresh_spent" => Err(anyhow::Error::new(api::ApiError::Unauthenticated)),
                    "refresh_disk" => Ok(creds("access_live", "refresh_live")),
                    other => panic!("unexpected refresh token {other}"),
                }
            },
            || {
                reloads.fetch_add(1, Ordering::SeqCst);
                Some(creds("access_disk", "refresh_disk"))
            },
        );

        assert_eq!(
            out.expect("the mint must recover, not report the session expired"),
            "ttok_fresh"
        );
        assert_eq!(reloads.load(Ordering::SeqCst), 1, "exactly one re-read");
        assert_eq!(
            *refreshed_with.lock().unwrap(),
            vec!["refresh_spent".to_string(), "refresh_disk".to_string()],
            "the disk pair must be what the second refresh spends"
        );
        // Every sibling now reads the rotated pair off the shared handle
        // instead of repeating the doomed refresh.
        let after = shared.lock();
        assert_eq!(after.access_token, "access_live");
        assert_eq!(after.refresh_token, "refresh_live");
    }

    #[test]
    fn a_disk_pair_we_already_spent_is_still_terminal() {
        // Nobody rotated: the file holds the same refresh token the platform
        // just rejected. Re-spending it would be the identical doomed request,
        // so this must stay a single refresh and a terminal verdict — the
        // reload must not turn a genuinely expired session into an endless
        // reconnect loop.
        let shared = SharedCredentials::new(creds("access_stale", "refresh_spent"));
        let refreshes = AtomicUsize::new(0);

        let out = shared
            .mint_with(
                |_| Err::<String, _>(api::ApiError::Unauthenticated),
                |rt| {
                    refreshes.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(rt, "refresh_spent");
                    Err(anyhow::Error::new(api::ApiError::Unauthenticated))
                },
                // A second CLI command wrote the file, but only re-saved the
                // pair we already have.
                || Some(creds("access_stale", "refresh_spent")),
            )
            .expect_err("an expired session must not mint");

        assert!(out.is_terminal(), "{out:?}");
        assert!(out.message().contains("mirrorstack login"), "{out:?}");
        assert_eq!(
            refreshes.load(Ordering::SeqCst),
            1,
            "the token we just spent must not be spent again"
        );
    }

    #[test]
    fn a_disk_pair_that_is_dead_too_is_terminal_but_stays_installed() {
        // Signed out in another terminal and then signed back in as someone
        // whose session is also gone: disk is newer, so it is worth one retry,
        // and it must be LEFT in the shared handle. Dropping back to the pair
        // that just failed is what made every sibling repeat the same doomed
        // refresh and go terminal one after another.
        let shared = SharedCredentials::new(creds("access_stale", "refresh_spent"));

        let out = shared
            .mint_with(
                |_| Err::<String, _>(api::ApiError::Unauthenticated),
                |_| Err(anyhow::Error::new(api::ApiError::Unauthenticated)),
                || Some(creds("access_disk", "refresh_disk")),
            )
            .expect_err("both pairs are dead");

        assert!(out.is_terminal(), "{out:?}");
        let after = shared.lock();
        assert_eq!(after.refresh_token, "refresh_disk");
        assert_eq!(after.access_token, "access_disk");
    }

    #[test]
    fn an_unreadable_credentials_file_is_not_a_panic() {
        // Deleted or hand-corrupted mid-session. `reload_from_disk` has to
        // answer "nothing newer" rather than take the supervisor thread down
        // with it, and the original refresh failure is what gets reported.
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = tempfile::tempdir().expect("config tempdir");
        let _restore = credentials::redirect_config_dir(config.path());

        // No file at all.
        assert!(reload_from_disk().is_none());

        // Present but not JSON.
        let p = credentials::path().expect("credentials path");
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(&p, b"{ this is not credentials").expect("write garbage");
        assert!(reload_from_disk().is_none());

        let shared = SharedCredentials::new(creds("access_stale", "refresh_spent"));
        let out = shared
            .mint_with(
                |_| Err::<String, _>(api::ApiError::Unauthenticated),
                |_| Err(anyhow::anyhow!("dns lookup failed")),
                reload_from_disk,
            )
            .expect_err("the mint cannot succeed here");
        assert!(!out.is_terminal(), "a blip stays retryable: {out:?}");
        assert!(out.message().contains("dns lookup failed"), "{out:?}");
    }

    #[test]
    fn mint_reads_the_real_credentials_file_when_its_refresh_fails() {
        // The closures above prove the logic; this proves the WIRING — that
        // `mint` hands `mint_with` a reload that reaches the actual file. With
        // it stubbed out to `None` the logic tests still pass and the bug is
        // fully intact in production.
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = tempfile::tempdir().expect("config tempdir");
        let _restore = credentials::redirect_config_dir(config.path());

        // What the second terminal's `whoami` left behind.
        credentials::save(&creds("access_live", "refresh_disk")).expect("seed credentials.json");

        let shared = SharedCredentials::new(creds("access_stale", "refresh_spent"));
        let out = shared.mint_with(
            |tok| match tok {
                "access_live" => Ok("ttok_fresh".to_string()),
                _ => Err(api::ApiError::Unauthenticated),
            },
            |rt| match rt {
                "refresh_spent" => Err(anyhow::Error::new(api::ApiError::Unauthenticated)),
                "refresh_disk" => Ok(creds("access_live", "refresh_live")),
                other => panic!("unexpected refresh token {other}"),
            },
            reload_from_disk,
        );

        assert_eq!(out.expect("recovered from the real file"), "ttok_fresh");
        assert_eq!(shared.lock().refresh_token, "refresh_live");
    }

    // ── Finding 4: supervision must never stop quietly ──────────────

    #[test]
    fn supervision_that_stops_without_teardown_is_recorded_dead() {
        // The shape of the original zombie: the thread returned early (its
        // credential load failed), the session it was watching kept running,
        // and when that session later died there was no reconnect, no
        // recurring warning, no ledger entry and a zero exit. Every
        // non-teardown exit has to land in the ledger, which is what feeds the
        // nag, the end-of-session report and the non-zero exit.
        let dir = tempfile::tempdir().expect("tempdir");
        let tgt = target("oauth-core", dir.path());
        let sup = supervisor("oauth-core", None);

        assert!(
            ensure_recorded_dead(&sup, &tgt, "supervision stopped without a reason"),
            "a supervisor that stopped for any other reason must announce it"
        );
        assert!(sup.dead.load(Ordering::SeqCst));
    }

    #[test]
    fn a_module_already_marked_dead_is_not_announced_twice() {
        // The backstop must not repeat the block `reconnect` already printed;
        // a second copy of the same banner reads like a second failure.
        let dir = tempfile::tempdir().expect("tempdir");
        let tgt = target("oauth-core", dir.path());
        let sup = supervisor("oauth-core", None);
        sup.dead.store(true, Ordering::SeqCst);

        assert!(!ensure_recorded_dead(
            &sup,
            &tgt,
            "supervision stopped without a reason"
        ));
        assert!(sup.dead.load(Ordering::SeqCst));
    }
}
