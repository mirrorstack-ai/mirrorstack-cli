//! Top-level CLI surface. Each variant of `Command` maps to a subcommand
//! module under this directory.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use console::{StyledObject, style};

mod dev;
mod login;
mod logout;
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

/// Default api-platform dispatch-service host. The dispatch Lambda is
/// reached under the same `api.mirrorstack.ai` hostname in prod via
/// path-routed ingress. Local dev uses port 8083 — set via `.env`.
/// Override with `MIRRORSTACK_DISPATCH_URL`.
pub(crate) const DEFAULT_DISPATCH_BASE: &str = "https://api.mirrorstack.ai";

pub(crate) const ENV_API_URL: &str = "MIRRORSTACK_API_URL";
pub(crate) const ENV_APPS_API_URL: &str = "MIRRORSTACK_APPS_API_URL";
pub(crate) const ENV_WEB_URL: &str = "MIRRORSTACK_WEB_URL";
pub(crate) const ENV_DISPATCH_URL: &str = "MIRRORSTACK_DISPATCH_URL";

/// Look up a base URL from `env_var`, falling back to `default` when unset.
pub(crate) fn resolve_base(env_var: &str, default: &str) -> String {
    std::env::var(env_var).unwrap_or_else(|_| default.into())
}

/// Green bold "✓" — shared status prefix for success lines across commands.
pub(crate) fn ok_mark() -> StyledObject<&'static str> {
    style("✓").green().bold()
}

/// Yellow bold "warning:" — shared prefix for non-fatal advisory lines.
pub(crate) fn warn_prefix() -> StyledObject<&'static str> {
    style("warning:").yellow().bold()
}

/// Standard error returned by every command that hits a 401 from the
/// platform. Centralized so the wording is identical across `module init`,
/// `dev`, `whoami`, etc. — users see one message, not three slight variants.
pub(crate) fn session_expired() -> anyhow::Error {
    anyhow!("session expired. Run `mirrorstack login` to sign in again.")
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
    /// Sign out: revoke the current session and remove local credentials.
    Logout(logout::LogoutArgs),
    /// Print the currently signed-in user.
    Whoami(whoami::WhoamiArgs),
    /// Manage developer modules (the per-developer reusable units installed
    /// into apps).
    Module(module::ModuleArgs),
    /// Run a module locally with its supporting services (Postgres in v1;
    /// the WSS tunnel layer lands in a follow-up).
    Dev(dev::DevArgs),
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Login(args) => login::run(args),
            Command::Logout(args) => logout::run(args),
            Command::Whoami(args) => whoami::run(args),
            Command::Module(args) => module::run(args),
            Command::Dev(args) => dev::run(args),
        }
    }
}
