//! Top-level CLI surface. Each variant of `Command` maps to a subcommand
//! module under this directory.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod login;
mod module;
mod whoami;

/// Default api-platform account-service host. Override per-invocation with
/// `MIRRORSTACK_API_URL` (or via `.env`).
pub(crate) const DEFAULT_API_BASE: &str = "https://api.mirrorstack.ai";

/// Default api-platform applications-service host. Modules and apps live
/// on a separate Lambda from the account service, but in prod both are
/// exposed under the same `api.mirrorstack.ai` hostname (path-routed at
/// the ingress). Local dev uses port 8082 — set via `.env`. Override
/// with `MIRRORSTACK_APPS_API_URL`.
pub(crate) const DEFAULT_APPS_API_BASE: &str = "https://api.mirrorstack.ai";

/// Default web-account host. Override with `MIRRORSTACK_WEB_URL`.
pub(crate) const DEFAULT_WEB_BASE: &str = "https://account.mirrorstack.ai";

pub(crate) const ENV_API_URL: &str = "MIRRORSTACK_API_URL";
pub(crate) const ENV_APPS_API_URL: &str = "MIRRORSTACK_APPS_API_URL";
pub(crate) const ENV_WEB_URL: &str = "MIRRORSTACK_WEB_URL";

/// Look up a base URL from `env_var`, falling back to `default` when unset.
pub(crate) fn resolve_base(env_var: &str, default: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.into())
}

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
    /// Manage developer modules (the per-developer reusable units installed
    /// into apps).
    Module(module::ModuleArgs),
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Login(args) => login::run(args),
            Command::Whoami(args) => whoami::run(args),
            Command::Module(args) => module::run(args),
        }
    }
}
