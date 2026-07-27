//! Top-level CLI surface. Each variant of `Command` maps to a subcommand
//! module under this directory.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use console::{StyledObject, style};

mod app;
mod dev;
mod login;
mod logout;
mod module;
mod whoami;

/// Default api-platform account-service base. Prod path-routes each service
/// under an API-Gateway mapping key (`/account`, `/apps`, `/dispatch`) — a
/// bare-host request 403s at the edge. Override per-invocation with
/// `MIRRORSTACK_API_URL` (or via `.env`).
pub(crate) const DEFAULT_API_BASE: &str = "https://api.mirrorstack.ai/account";

/// Default api-platform applications-service host. Modules and apps live
/// on a separate Lambda from the account service, but in prod both are
/// exposed under the same `api.mirrorstack.ai` hostname (path-routed at
/// the ingress). Local dev uses port 8082 — set via `.env`. Override
/// with `MIRRORSTACK_APPS_API_URL`.
pub(crate) const DEFAULT_APPS_API_BASE: &str = "https://api.mirrorstack.ai/apps";

/// Default web-account host. Override with `MIRRORSTACK_WEB_URL`.
pub(crate) const DEFAULT_WEB_BASE: &str = "https://account.mirrorstack.ai";

/// Default api-platform dispatch-service host. The dispatch Lambda is
/// reached under the same `api.mirrorstack.ai` hostname in prod via
/// path-routed ingress. Local dev uses port 8083 — set via `.env`.
/// Override with `MIRRORSTACK_DISPATCH_URL`.
pub(crate) const DEFAULT_DISPATCH_BASE: &str = "https://api.mirrorstack.ai/dispatch";

/// Default GitHub Actions OIDC audience. Override with
/// `MIRRORSTACK_OIDC_AUDIENCE`.
pub(crate) const DEFAULT_OIDC_AUDIENCE: &str = "mirrorstack";

pub(crate) const ENV_API_URL: &str = "MIRRORSTACK_API_URL";
pub(crate) const ENV_APPS_API_URL: &str = "MIRRORSTACK_APPS_API_URL";
pub(crate) const ENV_WEB_URL: &str = "MIRRORSTACK_WEB_URL";
pub(crate) const ENV_DISPATCH_URL: &str = "MIRRORSTACK_DISPATCH_URL";
/// GitHub Actions OIDC audience used for app deploy-grant exchange.
pub(crate) const ENV_OIDC_AUDIENCE: &str = "MIRRORSTACK_OIDC_AUDIENCE";

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
    /// Internal: receive an OAuth callback URL from the OS URL-scheme handler
    /// and relay it to the waiting `login` over the per-attempt unix socket.
    #[command(name = "__oauth-deliver", hide = true)]
    OauthDeliver { url: String },
    /// Sign out: revoke the current session and remove local credentials.
    Logout(logout::LogoutArgs),
    /// Print the currently signed-in user.
    Whoami(whoami::WhoamiArgs),
    /// Manage applications on the platform.
    #[command(visible_alias = "app")]
    Apps(app::AppArgs),
    /// Run modules locally with supporting services. Scans go.work for
    /// monorepo mode; falls back to single-module if only main.go exists.
    Dev(dev::DevArgs),
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Login(args) => login::run(args),
            Command::OauthDeliver { url } => crate::scheme::deliver(&url),
            Command::Logout(args) => logout::run(args),
            Command::Whoami(args) => whoami::run(args),
            Command::Apps(args) => app::run(args),
            Command::Dev(args) => dev::run(args),
        }
    }
}
