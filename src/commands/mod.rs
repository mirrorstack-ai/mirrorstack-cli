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
pub(crate) mod release_candidate;
mod whoami;

/// Default api-platform account-service base. Account remains under its
/// `/account` mapping while Applications is exposed on root `/v1/*` routes and
/// Dispatch remains under `/dispatch`. Override per-invocation with
/// `MIRRORSTACK_API_URL` (or via `.env`).
pub(crate) const DEFAULT_API_BASE: &str = "https://api.mirrorstack.ai/account";

/// Default api-platform applications-service host. Modules and apps live
/// on a separate Lambda from the account service, but in prod both are
/// exposed under the same `api.mirrorstack.ai` hostname through bare `/v1/*`
/// ingress routes. Local dev uses port 8082 — set via `.env`. Override with
/// `MIRRORSTACK_APPS_API_URL`.
pub(crate) const DEFAULT_APPS_API_BASE: &str = "https://api.mirrorstack.ai";

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

static DOTENV: std::sync::OnceLock<(std::path::PathBuf, Vec<String>)> = std::sync::OnceLock::new();

/// Remember the `.env` that was loaded and the keys it actually supplied.
pub(crate) fn record_dotenv(path: std::path::PathBuf, keys: Vec<String>) {
    let _ = DOTENV.set((path, keys));
}

/// Where `env_var`'s current value came from, or `None` when it is unset.
pub(crate) fn env_source(env_var: &str) -> Option<String> {
    std::env::var_os(env_var)?;
    Some(match DOTENV.get() {
        Some((path, keys)) if keys.iter().any(|k| k == env_var) => {
            format!(".env file {}", path.display())
        }
        _ => "the process environment".to_string(),
    })
}

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
    /// Manage developer modules and inspect their capability surface.
    Module(module::ModuleArgs),
    /// Run modules locally with supporting services. Scans go.work for
    /// monorepo mode; requires go.work today (single-module fallback is
    /// tracked separately).
    Dev(dev::DevArgs),
    /// Serve a module's review harness on localhost — its real settings or
    /// nav surface in the console's own frame, answered from fixtures.
    ///
    /// No platform, no database, no container: `dev` runs the module, this
    /// renders the page. Needs a `preview` script in the module's
    /// web/package.json.
    Preview(dev::preview::PreviewArgs),
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Command::Login(args) => login::run(args),
            Command::OauthDeliver { url } => crate::scheme::deliver(&url),
            Command::Logout(args) => logout::run(args),
            Command::Whoami(args) => whoami::run(args),
            Command::Apps(args) => app::run(args),
            Command::Module(args) => module::run(args),
            Command::Dev(args) => dev::run(args),
            Command::Preview(args) => dev::preview::run(args),
        }
    }
}

/// Error and hint text name `` `mirrorstack <subcommand...>` `` strings as a
/// guide back to the right invocation. Nothing checks those strings against
/// the actual clap tree, so a renamed or removed subcommand leaves behind a
/// hint pointing at a command that no longer exists.
#[cfg(test)]
mod command_reference_tests {
    use super::Cli;
    use clap::CommandFactory;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Pull `mirrorstack <words>` paths out of backtick-quoted text, stopping
    /// at the first flag, placeholder, or trailing punctuation so
    /// `--from <old-slug>` or `deploy{yes}` don't get swallowed into the path.
    fn command_paths_in(text: &str) -> Vec<Vec<String>> {
        let mut found = Vec::new();
        for (i, segment) in text.split('`').enumerate() {
            if i % 2 == 0 {
                continue; // outside a backtick span
            }
            let mut words = segment.split_whitespace();
            if words.next() != Some("mirrorstack") {
                continue;
            }
            let mut path = Vec::new();
            for word in words {
                let clean_len = word
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .unwrap_or(word.len());
                let token = &word[..clean_len];
                if token.is_empty() || token.starts_with('-') {
                    break;
                }
                path.push(token.to_string());
                if clean_len != word.len() {
                    break;
                }
            }
            found.push(path);
        }
        found
    }

    fn resolves(path: &[String]) -> bool {
        let root = Cli::command();
        let mut cmd = &root;
        for part in path {
            match cmd
                .get_subcommands()
                .find(|sc| sc.get_name() == part || sc.get_all_aliases().any(|a| a == part))
            {
                Some(next) => cmd = next,
                None => return false,
            }
        }
        true
    }

    #[test]
    fn every_hinted_mirrorstack_command_exists() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        collect_rs_files(&manifest_dir.join("src"), &mut files);

        let mut broken = Vec::new();
        for file in files {
            let text = fs::read_to_string(&file).expect("read source file");
            for path in command_paths_in(&text) {
                if !resolves(&path) {
                    broken.push(format!(
                        "{}: `mirrorstack {}`",
                        file.display(),
                        path.join(" ")
                    ));
                }
            }
        }

        assert!(
            broken.is_empty(),
            "hint/error text names a command that does not exist in the clap tree:\n{}",
            broken.join("\n")
        );
    }
}
