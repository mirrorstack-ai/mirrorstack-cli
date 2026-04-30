//! Entry point. Argument parsing and top-level command dispatch live in
//! `commands::Cli`.

use std::process::ExitCode;

use clap::Parser;

mod auth;
mod browser;
mod commands;
mod credentials;
mod scaffold;

fn main() -> ExitCode {
    // Load .env from CWD if present. Process env vars still take precedence
    // over .env, so users can override per-invocation. Silently ignored
    // when no .env exists (the common case for installed users).
    let _ = dotenvy::dotenv();

    let cli = commands::Cli::parse();
    match cli.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
