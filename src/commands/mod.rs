//! Top-level CLI surface. Each variant of `Command` maps to a subcommand
//! module under this directory.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod app;
mod login;
mod whoami;

/// Official command-line tool for the MirrorStack platform.
#[derive(Parser)]
#[command(name = "mirrorstack", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in to MirrorStack via OAuth.
    Login(login::LoginArgs),
    /// Print the currently signed-in user.
    Whoami(whoami::WhoamiArgs),
    /// App and module management.
    App(app::AppArgs),
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Login(args) => login::run(args),
            Command::Whoami(args) => whoami::run(args),
            Command::App(args) => app::run(args),
        }
    }
}
