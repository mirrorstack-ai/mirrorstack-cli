//! `mirrorstack app ...` — app and module management commands.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::scaffold;

#[derive(Args)]
pub struct AppArgs {
    #[command(subcommand)]
    command: AppCommand,
}

#[derive(Subcommand)]
enum AppCommand {
    /// Module management.
    Module(ModuleArgs),
}

#[derive(Args)]
struct ModuleArgs {
    #[command(subcommand)]
    command: ModuleCommand,
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Scaffold a new module in the current directory.
    Init {
        /// Module name (lowercase alphanumeric + hyphens, 2-40 chars).
        name: String,
    },
}

pub fn run(args: AppArgs) -> Result<()> {
    match args.command {
        AppCommand::Module(m) => match m.command {
            ModuleCommand::Init { name } => scaffold::run_init(&name),
        },
    }
}
