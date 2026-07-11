//! `mirrorstack apps …` — application management.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};

use crate::api::{self, ApiError, CreateAppInput};
use crate::credentials;
use crate::http;

use super::{
    DEFAULT_API_BASE, DEFAULT_APPS_API_BASE, DEFAULT_WEB_BASE, ENV_API_URL, ENV_APPS_API_URL,
    ENV_WEB_URL, ok_mark, resolve_base, session_expired,
};

mod deploy;

#[derive(Args)]
pub struct AppArgs {
    #[command(subcommand)]
    command: AppCommand,
}

#[derive(Subcommand)]
enum AppCommand {
    /// Create a new application on the platform.
    Create(CreateArgs),
    /// Manage the app's web frontend (static hosting on
    /// `https://<slug>.mirrorstack.app`).
    Web(WebArgs),
    /// Manage developer modules (the per-developer reusable units installed
    /// into apps).
    Module(super::module::ModuleArgs),
}

#[derive(Args)]
pub struct WebArgs {
    #[command(subcommand)]
    command: WebCommand,
}

#[derive(Subcommand)]
enum WebCommand {
    /// Deploy a static build directory to app hosting
    /// (`https://<slug>.mirrorstack.app`). Uploads, finalizes, and
    /// activates unless --no-activate.
    Deploy(deploy::DeployArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// Application name (human-readable).
    #[arg(long)]
    name: Option<String>,
    /// URL slug. When omitted, derived from --name.
    #[arg(long)]
    slug: Option<String>,
    /// Skip prompts.
    #[arg(long, short)]
    yes: bool,
}

pub fn run(args: AppArgs) -> Result<()> {
    match args.command {
        AppCommand::Create(c) => create(c),
        AppCommand::Web(w) => match w.command {
            WebCommand::Deploy(d) => deploy::run(d),
        },
        AppCommand::Module(m) => super::module::run(m),
    }
}

fn create(args: CreateArgs) -> Result<()> {
    let theme = ColorfulTheme::default();

    let mut creds = credentials::load_or_login_hint()?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let web_base = resolve_base(ENV_WEB_URL, DEFAULT_WEB_BASE);
    let client = http::client(Duration::from_secs(15))?;

    let identity =
        match credentials::with_refresh_retry(&mut creds, |tok| api::me(&client, &api_base, tok)) {
            Ok(id) => id,
            Err(ApiError::Unauthenticated) => return Err(session_expired()),
            Err(e) => return Err(e.into()),
        };
    let Some(username) = identity.slug.as_deref().filter(|s| !s.is_empty()) else {
        return Err(anyhow!(
            "no username set. Visit {web_base}/me to claim one first."
        ));
    };

    let name = if let Some(n) = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        n.to_string()
    } else if args.yes {
        return Err(anyhow!("--yes requires --name"));
    } else {
        Input::<String>::with_theme(&theme)
            .with_prompt("App name")
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
            suggested
        } else {
            Input::<String>::with_theme(&theme)
                .with_prompt("Slug")
                .default(suggested)
                .interact_text()?
                .trim()
                .to_string()
        }
    };

    if !args.yes {
        eprintln!();
        eprintln!("  {} {}", style("App:").dim(), style(&name).bold());
        eprintln!(
            "  {} {}",
            style("Slug:").dim(),
            style(format!("@{username}/{slug}")).cyan().bold()
        );
        let confirmed = Confirm::with_theme(&theme)
            .with_prompt("Create this app?")
            .default(true)
            .interact()?;
        if !confirmed {
            eprintln!("{}", style("aborted.").yellow());
            return Ok(());
        }
    }

    let result = with_spinner("Creating app…", || {
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::create_app(
                &client,
                &apps_base,
                tok,
                &CreateAppInput {
                    name: &name,
                    slug: &slug,
                },
            )
        })
    });

    match result {
        Ok(app) => {
            eprintln!(
                "{} created {}",
                ok_mark(),
                style(format!("@{username}/{slug}")).cyan().bold()
            );
            eprintln!("  {} {}", style("id:").dim(), app.id);
            Ok(())
        }
        Err(ApiError::Server { code, message, .. }) => Err(anyhow!("{code}: {message}")),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

fn derive_slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true;
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

pub(super) fn with_spinner<T, F>(message: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    if !std::io::stderr().is_terminal() {
        return f();
    }
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
