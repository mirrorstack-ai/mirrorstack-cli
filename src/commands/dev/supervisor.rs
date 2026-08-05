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
//! `MS_INTERNAL_SECRET` is deliberately NOT re-minted: it is minted once per
//! `dev` invocation and injected into the compose environment, so every
//! already-running module process holds that exact value. Minting a new one
//! would break module→dispatch ingress for the rest of the session.
//!
//! Why an OS thread and not a tokio task: the token mint goes through
//! `reqwest::blocking` (`http::client`), which panics when called from inside
//! a runtime. The thread owns the blocking mint and hops into the shared
//! runtime with `block_on` for the async connect.
//!
//! Per-module isolation: a supervisor only ever touches its own module. Five
//! sessions dying together produce five independent reconnects, and one module
//! giving up permanently leaves the other four serving.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use console::style;

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
/// reaped by process exit, and they re-check the stop flag before touching
/// anything on disk.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Everything a reconnect needs that is identical for every module.
pub(super) struct ReconnectCtx {
    pub dispatch_base: String,
    /// Reused verbatim on every re-register — see the module docs.
    pub internal_secret: String,
    /// Notified on each successful reconnect so the `--share` watcher
    /// re-confirms the session-scoped bundle pointer.
    pub share: Arc<ShareInvalidator>,
}

/// The per-module facts a reconnect replays: who to register as, where the
/// module answers, and which token file to rewrite.
pub(super) struct TunnelTarget {
    pub slug: String,
    pub module_id: String,
    pub local_url: String,
    pub token_file: PathBuf,
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

impl Supervisor {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn service_token(&self) -> String {
        self.handle
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|h| h.service_token.clone()))
            .unwrap_or_default()
    }

    fn set_handle(&self, handle: tunnel::TunnelHandle) {
        if let Ok(mut g) = self.handle.lock() {
            *g = Some(handle);
        }
    }

    /// Signal the currently open session to close. Safe to call when the
    /// session has already ended — the notify simply has no receiver.
    fn close_current(&self) {
        if let Ok(g) = self.handle.lock() {
            if let Some(h) = g.as_ref() {
                h.shutdown();
            }
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
    /// call must never make Ctrl-C feel hung, and a straggler can do no damage
    /// because it re-checks the stop flag before writing anything.
    pub(super) fn shutdown(self) {
        let total = self.supervisors.len();
        for s in &self.supervisors {
            s.stop.store(true, Ordering::SeqCst);
            s.close_current();
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
    // Own a credentials copy per thread. The mint rotates the refresh token,
    // and sharing one mutable copy across five supervisors would serialize
    // them behind a lock for no benefit — the `--share` watcher already loads
    // its own for the same reason.
    let mut creds = match credentials::load_or_login_hint() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} [{}] tunnel auto-reconnect disabled: {e:#}",
                warn_prefix(),
                style(&target.slug).cyan()
            );
            return;
        }
    };

    let mut exit = first_exit;
    loop {
        let why = match runtime.block_on(exit) {
            Ok(tunnel::TunnelExit::Shutdown) => return,
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

        match reconnect(&sup, &target, &ctx, &runtime, &mut creds) {
            Some(session) => {
                sup.set_handle(session.handle);
                exit = session.exit;
            }
            None => {
                // Either teardown raced us, or we gave up. Only the latter
                // deserves a standing complaint.
                if sup.dead.load(Ordering::SeqCst) {
                    nag_until_stopped(&sup, &target);
                }
                return;
            }
        }
    }
}

/// Re-establish one module's tunnel, retrying with jittered exponential
/// backoff. `None` means the caller should stop supervising: either teardown
/// set the stop flag, or the failure is permanent (in which case `sup.dead` is
/// set and the reason has been printed).
fn reconnect(
    sup: &Supervisor,
    target: &TunnelTarget,
    ctx: &ReconnectCtx,
    runtime: &tokio::runtime::Runtime,
    creds: &mut credentials::Credentials,
) -> Option<tunnel::TunnelSession> {
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

        match attempt_reconnect(sup, target, ctx, runtime, creds) {
            Ok(session) => {
                // Teardown may have started while we were connecting. Close
                // what we just opened and touch nothing on disk: `run_outer`
                // deletes the token files right after `shutdown` returns, and
                // rewriting one here would leave a stale secret behind.
                if sup.stopping() {
                    session.handle.shutdown();
                    return None;
                }
                // Rewrite the token file BEFORE announcing success: dispatch
                // starts injecting the new service token the moment the
                // register ack lands, and the module compares every inbound
                // platform call against this file. A stale file trades the
                // loud 503 for a quiet 403 not_proxied on the same pages.
                if let Err(e) = write_platform_token(
                    &target.token_file,
                    &session.handle.service_token,
                    &target.slug,
                ) {
                    eprintln!(
                        "{} [{}] tunnel reconnected but its platform-token file could not be rewritten ({e:#}) — platform→module calls will 403 until `mirrorstack dev` is restarted",
                        warn_prefix(),
                        style(&target.slug).cyan()
                    );
                }
                // The dev-bundle CDN pointer is stored per session and died
                // with the old one; the share watcher's content-hash gate
                // would never notice, since the bytes did not change.
                ctx.share.invalidate(&target.slug);
                eprintln!(
                    "{} [{}] tunnel reconnected (session {})",
                    ok_mark(),
                    style(&target.slug).cyan(),
                    style(&session.handle.session_id).dim()
                );
                return Some(session);
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
    creds: &mut credentials::Credentials,
) -> std::result::Result<tunnel::TunnelSession, AttemptOutcome> {
    let client = http::client(Duration::from_secs(15))
        .map_err(|e| AttemptOutcome::Retry(format!("build HTTP client: {e}")))?;

    // The connect token's server-side TTL is ~60s, so the one that opened the
    // dead session is never reusable — always mint a new one.
    let token = super::mint_tunnel_token(&client, &ctx.dispatch_base, creds)
        .map_err(|e| classify_mint_error(&e))?;

    // Unlike the first register (which precedes `docker compose up`), the
    // module is running now, so carry its real manifest hash. Authenticated
    // with the OLD service token — still what the module's token file holds.
    let previous_token = sup.service_token();
    let manifest_hash = runtime.block_on(tunnel::current_manifest_hash(
        &target.local_url,
        &previous_token,
        Some(&ctx.internal_secret),
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
                        internal_secret: Some(&ctx.internal_secret),
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
    use super::*;

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
    fn sleep_unless_stopped_bails_immediately_when_stopped() {
        let sup = Supervisor {
            slug: "oauth-core".into(),
            handle: Mutex::new(None),
            stop: AtomicBool::new(true),
            dead: AtomicBool::new(false),
        };
        let started = Instant::now();
        assert!(!sleep_unless_stopped(&sup, RECONNECT_BACKOFF_CAP));
        // Teardown must not wait out a 30s backoff.
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn sleep_unless_stopped_completes_a_short_wait() {
        let sup = Supervisor {
            slug: "oauth-core".into(),
            handle: Mutex::new(None),
            stop: AtomicBool::new(false),
            dead: AtomicBool::new(false),
        };
        assert!(sleep_unless_stopped(&sup, Duration::from_millis(50)));
    }
}
