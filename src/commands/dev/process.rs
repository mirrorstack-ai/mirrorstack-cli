//! Spawn the user's module via `go run .` with `MS_LOCAL_DB_URL` injected,
//! line-prefix its stdout/stderr, and kill it on Ctrl-C.
//!
//! No async runtime: we spawn a thread per output stream and rely on
//! `ctrlc` for SIGINT delivery — the whole CLI is otherwise blocking.
//!
//! Ctrl-C calls `child.kill()`, which is SIGKILL on unix and
//! TerminateProcess on windows. A Go server mid-DB-write loses any
//! buffered work; for a dev shell where the user owns the database
//! that's an acceptable trade-off in v1. SIGTERM-first-then-SIGKILL
//! is queued as a follow-up.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use super::line_prefix;

/// Run `go run .` in `dir` with `MS_LOCAL_DB_URL=<db_url>`. Blocks until
/// the child exits, or until Ctrl-C is received and the child has been
/// asked to terminate. Returns Ok on a clean child exit, Err on non-zero
/// status or signal-driven termination.
pub(super) fn run_module(dir: &Path, db_url: &str) -> Result<()> {
    let mut child = Command::new("go")
        .args(["run", "."])
        .current_dir(dir)
        .env("MS_LOCAL_DB_URL", db_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow!("`go` not found on PATH. Install Go 1.26+ before running dev.")
            }
            _ => anyhow!("dev: spawn `go run .`: {e}"),
        })?;

    let stdout = child.stdout.take().context("dev: child stdout")?;
    let stderr = child.stderr.take().context("dev: child stderr")?;
    let stdout_handle = forward_stdout(stdout, "module");
    let stderr_handle = forward_stderr(stderr, "module");

    let (tx, rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        // Best effort: a second Ctrl-C escalates via the kernel default.
        let _ = tx.send(());
    })
    .context("dev: install ctrl-c handler")?;

    let exit_status = wait_or_interrupt(&mut child, rx);

    // Threads exit when their pipe closes (child exited).
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    match exit_status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow!(
            "module exited with status {}",
            s.code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".into())
        )),
        Err(e) => Err(e),
    }
}

/// Wait for the child to exit, or for a Ctrl-C signal to arrive. On signal
/// we ask the child to terminate (kernel-level kill), then wait for it.
fn wait_or_interrupt(
    child: &mut Child,
    rx: mpsc::Receiver<()>,
) -> Result<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().context("dev: try_wait")? {
            return Ok(status);
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(()) => {
                let _ = child.kill();
                let status = child.wait().context("dev: wait after interrupt")?;
                return Ok(status);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return child.wait().context("dev: wait");
            }
        }
    }
}

fn forward_stdout<R: Read + Send + 'static>(
    reader: R,
    label: &'static str,
) -> thread::JoinHandle<()> {
    forward_lines(reader, label, |prefix, line| println!("{prefix} {line}"))
}

fn forward_stderr<R: Read + Send + 'static>(
    reader: R,
    label: &'static str,
) -> thread::JoinHandle<()> {
    forward_lines(reader, label, |prefix, line| eprintln!("{prefix} {line}"))
}

fn forward_lines<R, F>(reader: R, label: &'static str, sink: F) -> thread::JoinHandle<()>
where
    R: Read + Send + 'static,
    F: Fn(&str, &str) + Send + 'static,
{
    thread::spawn(move || {
        let prefix = line_prefix(label);
        let mut buf = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match buf.read_line(&mut line) {
                Ok(0) => return, // EOF
                Ok(_) => sink(&prefix, line.trim_end_matches(['\n', '\r'])),
                Err(_) => return,
            }
        }
    })
}
