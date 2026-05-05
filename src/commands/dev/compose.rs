//! Docker-compose lifecycle for `mirrorstack dev`. We shell out to the
//! `docker compose` CLI rather than use a library — `docker compose` is the
//! canonical front-end and tracking its semantics in a Rust binding has a
//! perpetual maintenance cost we don't want to take on for one subcommand.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow};
use console::style;

use super::super::ok_mark;

const COMPOSE_TEMPLATE: &str = include_str!("../../../templates/dev/docker-compose.yml.tmpl");

/// Write a `docker-compose.yml` into `dir` if absent. Returns whether a new
/// file was written.
pub(super) fn ensure_compose_file(dir: &Path) -> Result<bool> {
    let path = dir.join("docker-compose.yml");
    if path.exists() {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("dev: create {}", path.display()))?;
    f.write_all(COMPOSE_TEMPLATE.as_bytes())
        .with_context(|| format!("dev: write {}", path.display()))?;
    eprintln!(
        "{} bootstrapped {}",
        ok_mark(),
        style(path.display()).cyan().bold()
    );
    Ok(true)
}

/// Bring the bundled services up and block until each healthcheck flips.
/// `--wait` is server-side polling so we don't replicate that loop here;
/// non-zero exit = something failed to come up healthy in time.
pub(super) fn up(dir: &Path) -> Result<()> {
    let status = Command::new("docker")
        .args(["compose", "up", "-d", "--wait"])
        .current_dir(dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow!(
                "`docker` not found on PATH. Install Docker Desktop (or set --no-compose to skip) before running dev."
            ),
            _ => anyhow!("dev: docker compose up: {e}"),
        })?;
    if !status.success() {
        return Err(anyhow!(
            "docker compose up failed (exit {}). Check the output above; \
             `docker compose logs postgres` may explain a stuck healthcheck.",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Tear the bundled services down. Surfaces a non-zero exit so a failed
/// teardown doesn't silently leak containers — the caller decides whether
/// to error out or just warn.
pub(super) fn down(dir: &Path) -> Result<()> {
    let status = Command::new("docker")
        .args(["compose", "down"])
        .current_dir(dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| anyhow!("dev: docker compose down: {e}"))?;
    if !status.success() {
        return Err(anyhow!(
            "docker compose down failed (exit {}). Run `docker compose down` manually to clean up.",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_compose_file_writes_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let written = ensure_compose_file(tmp.path()).unwrap();
        assert!(written);
        let body = fs::read_to_string(tmp.path().join("docker-compose.yml")).unwrap();
        assert!(body.contains("postgres:17-alpine"));
    }

    #[test]
    fn ensure_compose_file_skips_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("docker-compose.yml"), b"# user's own file").unwrap();
        let written = ensure_compose_file(tmp.path()).unwrap();
        assert!(!written);
        let body = fs::read_to_string(tmp.path().join("docker-compose.yml")).unwrap();
        assert_eq!(body, "# user's own file");
    }
}
