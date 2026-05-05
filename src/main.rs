//! Entry point. Argument parsing and top-level command dispatch live in
//! `commands::Cli`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

mod api;
mod auth;
mod browser;
mod commands;
mod credentials;
mod http;

fn main() -> ExitCode {
    load_dotenv();

    let cli = commands::Cli::parse();
    match cli.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Walk from cwd up to the filesystem root looking for the first `.env` and
/// load it. Process env vars still win over `.env` because dotenvy's default
/// is non-overriding. Silently ignored when no `.env` exists anywhere on the
/// path (the common case for installed users).
///
/// Why upward search and not just `dotenvy::dotenv()`: developers run
/// `mirrorstack` from many places inside their workspace — meta-repo root,
/// a module subdirectory, a scaffold target. The cwd-only behavior surprised
/// users by silently missing the workspace `.env` that lived one or two
/// dirs up.
fn load_dotenv() {
    if let Some(path) = find_dotenv_upward() {
        let _ = dotenvy::from_path(&path);
    }
}

fn find_dotenv_upward() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let mut dir: &Path = cwd.as_path();
    loop {
        let candidate = dir.join(".env");
        if candidate.is_file() {
            return Some(candidate);
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => return None,
        }
    }
}
