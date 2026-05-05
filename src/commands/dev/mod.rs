//! `mirrorstack dev` — run a module locally with the supporting services
//! it needs (Postgres for now; Redis + WSS tunnel client land in later PRs).
//!
//! The lifecycle is:
//!   1. Bootstrap a `docker-compose.yml` in the cwd if missing
//!   2. `docker compose up -d` and wait for Postgres health
//!   3. Spawn `go run .` with `MS_LOCAL_DB_URL` injected
//!   4. Stream the module's stdout/stderr through a labeled prefix
//!   5. On Ctrl-C: graceful SIGTERM the module process, then `compose down`
//!
//! No WSS tunnel yet — the module runs as a normal HTTP server on its own
//! port. Future PR layers the tunnel registration on top.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::Args;
use console::style;

use super::{ok_mark, warn_prefix};

mod compose;
mod process;

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
}

// Matches templates/dev/docker-compose.yml.tmpl: host port 5433 (chosen so
// the bundled compose can coexist with api-platform's own postgres on 5432).
const DEFAULT_DB_URL: &str =
    "postgres://mirrorstack:mirrorstack@localhost:5433/mirrorstack?sslmode=disable";

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

    if !args.no_compose {
        compose::ensure_compose_file(&cwd)?;
        compose::up(&cwd)?;
    }

    eprintln!("{} module running — Ctrl-C to stop", ok_mark());
    let module_status = process::run_module(&cwd, &db_url);

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

    #[test]
    fn resolve_db_url_prefers_explicit_arg() {
        let args = DevArgs {
            dir: None,
            no_compose: false,
            db_url: Some("postgres://x".into()),
        };
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
        let args = DevArgs {
            dir: None,
            no_compose: true,
            db_url: None,
        };
        let err = resolve_db_url(&args).unwrap_err().to_string();
        assert!(err.contains("MS_LOCAL_DB_URL"));
    }

    #[test]
    fn resolve_db_url_compose_default_when_unset() {
        if std::env::var("MS_LOCAL_DB_URL").is_ok() {
            return;
        }
        let args = DevArgs {
            dir: None,
            no_compose: false,
            db_url: None,
        };
        let url = resolve_db_url(&args).unwrap();
        assert!(url.starts_with("postgres://mirrorstack"));
        assert!(url.contains(":5433/"));
    }
}
