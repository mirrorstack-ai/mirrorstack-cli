//! `mirrorstack module …` — developer module management.
//!
//! Today: `module init` registers the module on the platform AND scaffolds a
//! local source tree from the SDK template. The scaffolded tree is what
//! `mirrorstack dev` (future) launches and tunnels into the platform.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};

use crate::api::{self, ApiError, CreateModuleInput, SetModuleDeployInput};
use crate::commands::dev::module_meta;
use crate::credentials;
use crate::http;

mod scaffold;

use super::{
    DEFAULT_API_BASE, DEFAULT_APPS_API_BASE, DEFAULT_WEB_BASE, ENV_API_URL, ENV_APPS_API_URL,
    ENV_WEB_URL, ok_mark, resolve_base, session_expired, warn_prefix,
};

#[derive(Args)]
pub struct ModuleArgs {
    #[command(subcommand)]
    command: ModuleCommand,
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Create a new module on the platform and scaffold locally.
    /// Interactive by default; pass --yes for non-interactive use.
    Init(InitArgs),
    /// Register all unregistered modules in the workspace with the
    /// platform. Scans go.work, finds modules with empty IDs, creates
    /// them via the API, and writes the assigned ID back into main.go.
    Register(RegisterArgs),
    /// Point a published module version at a live Lambda invoke target.
    /// Run from the module directory (reads Config.Slug from ./main.go)
    /// or pass --module.
    Deploy(DeployArgs),
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
    /// Skip filesystem scaffolding. Only register the module on the platform.
    #[arg(long)]
    no_scaffold: bool,
    /// Where to scaffold the new module source tree. Defaults to ./<slug>/
    /// in the current directory. Pass `.` to scaffold into the cwd directly.
    #[arg(long)]
    dir: Option<PathBuf>,
}

#[derive(Args)]
pub struct RegisterArgs {
    /// Working directory containing go.work. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Skip confirmation prompts.
    #[arg(long, short)]
    yes: bool,
}

#[derive(Args)]
pub struct DeployArgs {
    /// Version UUID to deploy, as returned by publish. (There is no
    /// list-versions API yet, so version strings can't be resolved.)
    #[arg(long)]
    version_id: String,
    /// Lambda function name or full ARN, with an optional :qualifier.
    #[arg(long)]
    target: String,
    /// Deploy status.
    #[arg(long, value_enum, default_value_t = DeployStatus::Active)]
    status: DeployStatus,
    /// Module slug. Defaults to Config.Slug parsed from ./main.go.
    #[arg(long)]
    module: Option<String>,
    /// Module directory containing main.go. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum DeployStatus {
    Active,
    Draining,
    Disabled,
}

impl DeployStatus {
    fn as_str(self) -> &'static str {
        match self {
            DeployStatus::Active => "active",
            DeployStatus::Draining => "draining",
            DeployStatus::Disabled => "disabled",
        }
    }
}

pub fn run(args: ModuleArgs) -> Result<()> {
    match args.command {
        ModuleCommand::Init(i) => init(i),
        ModuleCommand::Register(r) => register(r),
        ModuleCommand::Deploy(d) => deploy(d),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let theme = ColorfulTheme::default();

    let creds = credentials::load_or_login_hint()?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let web_base = resolve_base(ENV_WEB_URL, DEFAULT_WEB_BASE);
    let client = http::client(Duration::from_secs(15))?;

    // The platform stores ownership by user id, but the CLI surfaces the
    // full namespaced `@<username>/<slug>` — so we refuse to POST until the
    // caller has claimed a username, and point them at the web flow.
    let identity = match api::me(&client, &api_base, &creds.access_token) {
        Ok(id) => id,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
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

    // Pre-flight: scaffold target. If the caller wants scaffolding, fail now
    // (before any remote POST) so we never leave a registered module with no
    // local tree because of e.g. a non-empty target dir.
    let scaffold_target = if args.no_scaffold {
        None
    } else {
        let target = resolve_scaffold_target(args.dir.as_deref(), &slug);
        scaffold::ensure_target_writable(&target)?;
        Some(target)
    };

    // Pre-flight: reject early if the caller already owns this slug. Catches
    // the common "I forgot I made this last week" case before we POST.
    // Reserved/invalid still surface server-side from the POST below.
    let pre_check = with_spinner("Checking availability…", || {
        api::get_module(&client, &apps_base, &creds.access_token, &slug)
    });
    // Capture the platform-assigned module ID so scaffolding can substitute
    // it into Config.ID and the table prefix. Sourced from whichever branch
    // succeeds (`--used` + already-exists, fresh create, or a race-refetch).
    let module_id: String = match pre_check {
        Ok(Some(existing)) if args.used => {
            print_already_exists(username, &existing.slug, Some(&existing.id));
            existing.id
        }
        Ok(Some(_)) => {
            return Err(anyhow!(
                "@{username}/{slug} already exists (pass --used to ignore when re-running)"
            ));
        }
        Ok(None) => {
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
                    &client,
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
                    m.id
                }
                Err(ApiError::Server { code, .. }) if code == "slug_taken" && args.used => {
                    // Race: the slug was free at pre-check but taken by the
                    // time we POST'd. Re-fetch so scaffold still has a real
                    // module ID to substitute.
                    print_already_exists(username, &slug, None);
                    refetch_module_id(&client, &apps_base, &creds.access_token, username, &slug)?
                }
                Err(ApiError::Server { code, message, .. }) => {
                    return Err(anyhow!(
                        "{code}: {message}{hint}",
                        hint = slug_error_hint(&code)
                    ));
                }
                Err(ApiError::Unauthenticated) => return Err(session_expired()),
                Err(e) => return Err(e.into()),
            }
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    scaffold_if_requested(
        scaffold_target.as_deref(),
        &scaffold::Inputs {
            slug: &slug,
            name: &name,
            module_id: &module_id,
        },
    )
}

fn register(args: RegisterArgs) -> Result<()> {
    let cwd = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    let go_work = cwd.join("go.work");
    if !go_work.exists() {
        return Err(anyhow!(
            "no go.work found in {}. Run from a module workspace.",
            cwd.display()
        ));
    }

    let creds = credentials::load_or_login_hint()?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let web_base = resolve_base(ENV_WEB_URL, DEFAULT_WEB_BASE);
    let client = http::client(Duration::from_secs(15))?;

    let identity = match api::me(&client, &api_base, &creds.access_token) {
        Ok(id) => id,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };
    let Some(username) = identity.slug.as_deref().filter(|s| !s.is_empty()) else {
        return Err(anyhow!(
            "no username set. Visit {web_base}/me to claim one first."
        ));
    };

    // Parse go.work to find module directories
    let body = std::fs::read_to_string(&go_work)
        .with_context(|| format!("read {}", go_work.display()))?;
    let module_dirs = parse_go_work_use_dirs(&body);
    if module_dirs.is_empty() {
        return Err(anyhow!("go.work has no `use` directives"));
    }

    let theme = ColorfulTheme::default();
    let mut registered = 0u32;
    let mut skipped = 0u32;

    for rel_dir in &module_dirs {
        let abs_dir = cwd.join(rel_dir);
        let meta = match module_meta::read_module_meta(&abs_dir) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "{} skipping {}: {e}",
                    warn_prefix(),
                    rel_dir
                );
                continue;
            }
        };

        if !meta.id.is_empty() {
            eprintln!(
                "{} {} already registered ({})",
                ok_mark(),
                style(format!("@{username}/{}", meta.slug)).cyan(),
                style(&meta.id).dim()
            );
            skipped += 1;
            continue;
        }

        if !slug_valid(&meta.slug) {
            eprintln!(
                "{} skipping {}: slug '{}' is invalid",
                warn_prefix(),
                rel_dir,
                meta.slug
            );
            continue;
        }

        if !args.yes {
            eprintln!();
            eprintln!(
                "  {} {}",
                style("Module:").dim(),
                style(&meta.name).bold()
            );
            eprintln!(
                "  {}   {}",
                style("Slug:").dim(),
                style(format!("@{username}/{}", meta.slug)).cyan().bold()
            );
            let confirmed = Confirm::with_theme(&theme)
                .with_prompt(format!("Register {}?", meta.slug))
                .default(true)
                .interact()?;
            if !confirmed {
                eprintln!("{}", style("skipped.").yellow());
                continue;
            }
        }

        let result = with_spinner(&format!("Registering {}…", meta.slug), || {
            api::create_module(
                &client,
                &apps_base,
                &creds.access_token,
                &CreateModuleInput {
                    name: &meta.name,
                    slug: &meta.slug,
                },
            )
        });

        let module_id = match result {
            Ok(m) => {
                eprintln!(
                    "{} created {}",
                    ok_mark(),
                    style(format!("@{username}/{}", m.slug)).cyan().bold()
                );
                m.id
            }
            Err(ApiError::Server { code, .. }) if code == "slug_taken" => {
                // Already exists on platform — fetch the ID
                match api::get_module(&client, &apps_base, &creds.access_token, &meta.slug)? {
                    Some(existing) => {
                        eprintln!(
                            "{} {} already exists on platform, using existing ID",
                            ok_mark(),
                            style(format!("@{username}/{}", meta.slug)).cyan()
                        );
                        existing.id
                    }
                    None => {
                        eprintln!(
                            "{} slug '{}' is taken by another user",
                            warn_prefix(),
                            meta.slug
                        );
                        continue;
                    }
                }
            }
            Err(ApiError::Unauthenticated) => return Err(session_expired()),
            Err(e) => {
                eprintln!(
                    "{} failed to register {}: {e}",
                    warn_prefix(),
                    meta.slug
                );
                continue;
            }
        };

        // Write the ID back into main.go
        let sanitized_id = sanitize_module_id(&module_id);
        module_meta::write_module_id(&abs_dir, &sanitized_id)
            .with_context(|| format!("write ID to {}/main.go", rel_dir))?;
        eprintln!(
            "  {} wrote ID {} → {}/main.go",
            style("→").dim(),
            style(&sanitized_id).dim(),
            rel_dir
        );
        registered += 1;
    }

    eprintln!();
    eprintln!(
        "{} done: {} registered, {} already had IDs",
        ok_mark(),
        registered,
        skipped
    );
    Ok(())
}

fn deploy(args: DeployArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    // Resolve the slug: --module wins, else parse Config.Slug from main.go
    // the same way `dev` and `register` do.
    let slug = match args.module {
        Some(s) => s,
        None => module_meta::read_module_meta(&dir)
            .map_err(|e| {
                anyhow!("couldn't resolve the module from {}: {e}. Run from the module directory, or pass --module <slug> / --dir <path>.", dir.display())
            })?
            .slug,
    };
    // The version id is a raw path segment; reject non-UUIDs before they
    // reach the URL (a stray value would POST to a different route and
    // surface an opaque 405).
    if !args.version_id.len().eq(&36)
        || !args
            .version_id
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_hexdigit())
    {
        return Err(anyhow!(
            "--version-id must be the version UUID (36 chars), got '{}'",
            args.version_id
        ));
    }
    if !slug_valid(&slug) {
        return Err(anyhow!(
            "slug '{slug}' is invalid: must be 3-40 chars, start with a letter, end with a letter or digit, lowercase + hyphen only."
        ));
    }

    let creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(Duration::from_secs(15))?;

    // Resolve the platform UUID by slug. main.go's Config.ID is the
    // sanitized `m<hex>` form, not the raw UUID the deploy endpoint takes.
    // GET /v1/modules/{slug} is caller-scoped, so this doubles as an
    // ownership check.
    let module = match api::get_module(&client, &apps_base, &creds.access_token, &slug) {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Err(anyhow!(
                "module '{slug}' not found on the platform (run `mirrorstack module register` first)"
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    let result = with_spinner("Deploying…", || {
        api::set_module_deploy(
            &client,
            &apps_base,
            &creds.access_token,
            &module.id,
            &args.version_id,
            &SetModuleDeployInput {
                invoke_target: &args.target,
                status: Some(args.status.as_str()),
            },
        )
    });

    let deploy = match result {
        Ok(d) => d,
        Err(ApiError::Server { code, message, .. }) => {
            return Err(anyhow!(
                "{code}: {message}{hint}",
                hint = deploy_error_hint(&code)
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    eprintln!("{} deployed {}", ok_mark(), style(&slug).cyan().bold());
    eprintln!("  {} {}", style("version:").dim(), deploy.version_id);
    eprintln!("  {}  {}", style("target:").dim(), deploy.invoke_target);
    eprintln!("  {}  {}", style("status:").dim(), deploy.status);
    Ok(())
}

fn deploy_error_hint(code: &str) -> &'static str {
    match code {
        "not_found" => " (check the version UUID belongs to this module and you own it)",
        "invoke_target_invalid" => {
            " (expected a Lambda function name or full ARN, optional :qualifier, [A-Za-z0-9_-]{1,140})"
        }
        "status_invalid" => " (must be active, draining, or disabled)",
        _ => "",
    }
}

/// Parse `use` directives from go.work content (same logic as workspace.rs
/// but returns raw strings since we don't need abs paths here).
fn parse_go_work_use_dirs(body: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut in_block = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if in_block {
            if trimmed == ")" {
                in_block = false;
                continue;
            }
            if let Some(dir) = clean_go_work_path(trimmed) {
                result.push(dir);
            }
        } else if let Some(rest) = trimmed.strip_prefix("use") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
            } else if let Some(dir) = clean_go_work_path(rest) {
                result.push(dir);
            }
        }
    }
    result
}

fn clean_go_work_path(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.starts_with("//") {
        return None;
    }
    let s = match s.find("//") {
        Some(pos) => s[..pos].trim(),
        None => s,
    };
    let s = s.strip_prefix("./").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

/// Convert platform UUID to SDK-compatible module ID (same as scaffold.rs).
fn sanitize_module_id(uuid: &str) -> String {
    // If it already looks sanitized (starts with 'm', no hyphens), return as-is
    if uuid.starts_with('m') && !uuid.contains('-') {
        return uuid.to_string();
    }
    let mut out = String::with_capacity(33);
    out.push('m');
    for c in uuid.chars() {
        if c == '-' {
            continue;
        }
        out.extend(c.to_lowercase());
    }
    out
}

fn refetch_module_id(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    username: &str,
    slug: &str,
) -> Result<String> {
    let refetch = with_spinner("Resolving existing module…", || {
        api::get_module(client, apps_base, access_token, slug)
    });
    match refetch {
        Ok(Some(m)) => Ok(m.id),
        Ok(None) => Err(anyhow!(
            "module @{username}/{slug} disappeared between create and re-fetch"
        )),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

/// Resolve the target dir for scaffolding. `--dir <path>` wins; otherwise
/// default to `./<slug>/`. Pass `--dir .` to scaffold into the cwd directly.
fn resolve_scaffold_target(dir: Option<&Path>, slug: &str) -> PathBuf {
    match dir {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from(slug),
    }
}

fn scaffold_if_requested(target: Option<&Path>, inputs: &scaffold::Inputs<'_>) -> Result<()> {
    let Some(target) = target else { return Ok(()) };
    scaffold::write_tree(target, inputs)
        .with_context(|| format!("scaffold into {}", target.display()))?;
    print_scaffold_summary(target);
    Ok(())
}

fn print_scaffold_summary(target: &Path) {
    eprintln!(
        "{} scaffolded {}",
        ok_mark(),
        style(target.display()).cyan().bold()
    );
    let next = if is_cwd(target) {
        "go mod tidy && mirrorstack dev".to_string()
    } else {
        format!("cd {} && go mod tidy && mirrorstack dev", target.display())
    };
    eprintln!("  {} {next}", style("next:").dim());
}

/// Robust check for "scaffold into the current dir." Catches both `.` and
/// `./` (and other normalizations of the same path) — bare `target.as_os_str()
/// == "."` would miss `./` and trailing-slash variants.
fn is_cwd(target: &Path) -> bool {
    let mut comps = target.components();
    matches!(comps.next(), Some(std::path::Component::CurDir)) && comps.next().is_none()
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

/// Wrap a blocking call with a tick-driven spinner. Skipped entirely when
/// stderr isn't a TTY so CI logs and piped output stay clean — indicatif
/// can detect a non-tty target but `enable_steady_tick` still spawns the
/// timer thread, so we short-circuit before that.
fn with_spinner<T, F>(message: &str, f: F) -> T
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

fn print_created(username: &str, slug: &str, id: &str) {
    eprintln!(
        "{} created {}",
        ok_mark(),
        style(format!("@{username}/{slug}")).cyan().bold(),
    );
    eprintln!("  {} {}", style("id:").dim(), id);
}

fn print_already_exists(username: &str, slug: &str, id: Option<&str>) {
    eprintln!(
        "{} {} already exists; {} continuing.",
        ok_mark(),
        style(format!("@{username}/{slug}")).cyan().bold(),
        style("--used set,").dim(),
    );
    if let Some(id) = id {
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

    #[test]
    fn deploy_error_hint_for_known_codes() {
        assert!(deploy_error_hint("not_found").contains("version UUID"));
        assert!(deploy_error_hint("invoke_target_invalid").contains("ARN"));
        assert!(deploy_error_hint("status_invalid").contains("draining"));
        assert_eq!(deploy_error_hint("something_else"), "");
    }

    #[test]
    fn deploy_status_as_str_matches_api() {
        assert_eq!(DeployStatus::Active.as_str(), "active");
        assert_eq!(DeployStatus::Draining.as_str(), "draining");
        assert_eq!(DeployStatus::Disabled.as_str(), "disabled");
    }

    #[test]
    fn is_cwd_matches_cwd_variants() {
        assert!(is_cwd(Path::new(".")));
        assert!(is_cwd(Path::new("./")));
    }

    #[test]
    fn is_cwd_rejects_non_cwd_paths() {
        assert!(!is_cwd(Path::new("media")));
        assert!(!is_cwd(Path::new("./media")));
        assert!(!is_cwd(Path::new("a/b")));
        assert!(!is_cwd(Path::new("/tmp")));
    }
}
