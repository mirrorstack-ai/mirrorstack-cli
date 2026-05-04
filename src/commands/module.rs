//! `mirrorstack module …` — developer module management.
//!
//! Today: only `module init` (register a module on the platform). Filesystem
//! scaffolding (templates, SDK pull) is intentionally out of scope per the
//! current product direction — modules are developed locally with whatever
//! tooling the developer prefers, and `mirrorstack dev` (future) opens a WSS
//! tunnel into the platform.

use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};

use crate::api::{self, ApiError, CreateModuleInput};
use crate::credentials::{self, LoadError};

use super::{
    DEFAULT_API_BASE, DEFAULT_APPS_API_BASE, DEFAULT_WEB_BASE, ENV_API_URL, ENV_APPS_API_URL,
    ENV_WEB_URL,
};

#[derive(Args)]
pub struct ModuleArgs {
    #[command(subcommand)]
    command: ModuleCommand,
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Register a new module on the platform. Interactive by default;
    /// pass --yes for non-interactive use.
    Init(InitArgs),
}

#[derive(Args)]
pub struct InitArgs {
    /// Module name (human-readable). When omitted, prompts interactively.
    #[arg(long)]
    name: Option<String>,
    /// URL slug. When omitted, derived from --name. The platform regex is
    /// 3-40 chars, must start with a letter, end with a letter or digit,
    /// lowercase + hyphen only.
    #[arg(long)]
    slug: Option<String>,
    /// Skip prompts. Requires --name; --slug optional (derived from name).
    #[arg(long, short)]
    yes: bool,
    /// If the slug is already registered to you, treat that as success and
    /// continue. Useful for re-running init in CI without conditional logic.
    #[arg(long)]
    used: bool,
}

pub fn run(args: ModuleArgs) -> Result<()> {
    match args.command {
        ModuleCommand::Init(i) => init(i),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let theme = ColorfulTheme::default();

    let creds = match credentials::load() {
        Ok(c) => c,
        Err(LoadError::NotFound) => {
            return Err(anyhow!(
                "not signed in. Run `mirrorstack login` to sign in."
            ));
        }
        Err(e) => return Err(e.into()),
    };

    let api_base = std::env::var(ENV_API_URL).unwrap_or_else(|_| DEFAULT_API_BASE.into());
    let apps_base =
        std::env::var(ENV_APPS_API_URL).unwrap_or_else(|_| DEFAULT_APPS_API_BASE.into());
    let web_base = std::env::var(ENV_WEB_URL).unwrap_or_else(|_| DEFAULT_WEB_BASE.into());

    // The platform stores ownership by user id, but the CLI surfaces the
    // full namespaced `@<username>/<slug>` — so we refuse to POST until the
    // caller has claimed a username, and point them at the web flow.
    let identity = match api::me(&api_base, &creds.access_token) {
        Ok(id) => id,
        Err(ApiError::Unauthenticated) => {
            return Err(anyhow!(
                "session expired. Run `mirrorstack login` to sign in again."
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let Some(username) = identity.slug.as_deref().filter(|s| !s.is_empty()) else {
        return Err(anyhow!(
            "no username set on this account. Visit {web_base}/me to claim one before creating modules."
        ));
    };

    let (name, slug) = collect_name_and_slug(&theme, &args)?;

    if !slug_valid(&slug) {
        return Err(anyhow!(
            "slug '{slug}' is invalid: must be 3-40 chars, start with a letter, end with a letter or digit, lowercase + hyphen only."
        ));
    }

    // Pre-flight: reject early if the caller already owns this slug. Catches
    // the common "I forgot I made this last week" case before we POST.
    // Reserved/invalid still surface server-side from the POST below.
    let pre_check = with_spinner("Checking availability…", || {
        api::get_module(&apps_base, &creds.access_token, &slug)
    });
    match pre_check {
        Ok(Some(existing)) if args.used => {
            print_already_exists(username, &existing.slug, &existing.id);
            return Ok(());
        }
        Ok(Some(_)) => {
            return Err(anyhow!(
                "@{username}/{slug} already exists{hint}",
                hint = slug_error_hint("slug_taken")
            ));
        }
        Ok(None) => {}
        Err(ApiError::Unauthenticated) => {
            return Err(anyhow!(
                "session expired. Run `mirrorstack login` to sign in again."
            ));
        }
        Err(e) => return Err(e.into()),
    }

    if !args.yes {
        eprintln!();
        eprintln!("  {} {}", style("Module:").dim(), style(&name).bold());
        eprintln!(
            "  {}   {}",
            style("Slug:").dim(),
            style(format!("@{username}/{slug}")).cyan().bold()
        );
        let confirmed = Confirm::with_theme(&theme)
            .with_prompt("Create this module?")
            .default(true)
            .interact()?;
        if !confirmed {
            eprintln!("{}", style("aborted.").yellow());
            return Ok(());
        }
    }

    let create_result = with_spinner("Creating module…", || {
        api::create_module(
            &apps_base,
            &creds.access_token,
            &CreateModuleInput {
                name: &name,
                slug: &slug,
            },
        )
    });

    match create_result {
        Ok(m) => {
            print_created(username, &m.slug, &m.id);
            Ok(())
        }
        Err(ApiError::Server { code, .. }) if code == "slug_taken" && args.used => {
            print_already_exists(username, &slug, "(unknown id)");
            Ok(())
        }
        Err(ApiError::Server { code, message, .. }) => Err(anyhow!(
            "{code}: {message}{hint}",
            hint = slug_error_hint(&code)
        )),
        Err(ApiError::Unauthenticated) => Err(anyhow!(
            "session expired. Run `mirrorstack login` to sign in again."
        )),
        Err(e) => Err(e.into()),
    }
}

fn collect_name_and_slug(theme: &ColorfulTheme, args: &InitArgs) -> Result<(String, String)> {
    let name = if let Some(n) = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        n.to_string()
    } else if args.yes {
        return Err(anyhow!(
            "--yes requires --name (cannot prompt in non-interactive mode)"
        ));
    } else {
        Input::<String>::with_theme(theme)
            .with_prompt("Module name")
            .interact_text()?
            .trim()
            .to_string()
    };

    let slug = if let Some(s) = args
        .slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        s.to_string()
    } else {
        let suggested = derive_slug(&name);
        if args.yes {
            // Non-interactive: trust the derivation. If the format check fails
            // downstream the caller sees a clear error.
            suggested
        } else {
            Input::<String>::with_theme(theme)
                .with_prompt("Slug")
                .default(suggested)
                .interact_text()?
                .trim()
                .to_string()
        }
    };

    Ok((name, slug))
}

/// Wrap a blocking call with a tick-driven spinner. Spinner is suppressed
/// when stderr isn't a TTY so CI logs stay clean.
fn with_spinner<T, F>(message: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(message.to_string());
    let result = f();
    pb.finish_and_clear();
    result
}

fn print_created(username: &str, slug: &str, id: &str) {
    eprintln!(
        "{} created {}",
        style("✓").green().bold(),
        style(format!("@{username}/{slug}")).cyan().bold(),
    );
    eprintln!("  {} {}", style("id:").dim(), id);
}

fn print_already_exists(username: &str, slug: &str, id: &str) {
    eprintln!(
        "{} {} already exists; {} continuing.",
        style("✓").green().bold(),
        style(format!("@{username}/{slug}")).cyan().bold(),
        style("--used set,").dim(),
    );
    if id != "(unknown id)" {
        eprintln!("  {} {}", style("id:").dim(), id);
    }
}

/// Same regex as the platform service and api-client-shared:
/// `^[a-z][a-z0-9-]{1,38}[a-z0-9]$`. Inlined as a manual check to avoid a
/// `regex` dependency for one pattern — the rule is small enough.
fn slug_valid(s: &str) -> bool {
    let len = s.len();
    if !(3..=40).contains(&len) {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let last = bytes[len - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Lowercase, replace runs of non-[a-z0-9] with single hyphens, trim leading
/// and trailing hyphens. Mirrors the web client's auto-suggest in
/// `useCreateModuleForm` so CLI users see the same default as web users.
fn derive_slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true; // skip leading hyphens
    for c in name.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_lowercase() || lc.is_ascii_digit() {
            out.push(lc);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn slug_error_hint(code: &str) -> &'static str {
    match code {
        "slug_taken" => " (pass --used to ignore when re-running)",
        "slug_reserved" => " (try a different slug — this name is reserved)",
        "slug_invalid" => "",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_valid_accepts() {
        for s in ["media", "my-mod", "abc123", "a1-b2-c3", "ana-lytics"] {
            assert!(slug_valid(s), "expected {s:?} valid");
        }
    }

    #[test]
    fn slug_valid_rejects() {
        for s in ["", "ab", "AB", "1abc", "media-", "-media", "ab_cd"] {
            assert!(!slug_valid(s), "expected {s:?} invalid");
        }
    }

    #[test]
    fn slug_valid_rejects_too_long() {
        let s = "a".repeat(41);
        assert!(!slug_valid(&s));
    }

    #[test]
    fn derive_slug_basic() {
        assert_eq!(derive_slug("Analytics"), "analytics");
        assert_eq!(derive_slug("My Cool Module"), "my-cool-module");
        assert_eq!(derive_slug("  Media!! "), "media");
        assert_eq!(derive_slug("foo___bar"), "foo-bar");
        assert_eq!(derive_slug("foo--bar"), "foo-bar");
    }

    #[test]
    fn derive_slug_strips_leading_and_trailing_hyphens() {
        assert_eq!(derive_slug("--media"), "media");
        assert_eq!(derive_slug("media--"), "media");
    }

    #[test]
    fn slug_error_hint_for_taken() {
        assert!(slug_error_hint("slug_taken").contains("--used"));
    }
}
