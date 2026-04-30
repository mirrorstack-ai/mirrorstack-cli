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
    let cli = commands::Cli::parse();
    match cli.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}
