//! `mirrorstack app module init` — register a module and scaffold its tree.
//!
//! Split out of a 1468-line mod.rs so the command surface — the Args
//! structs and the run() dispatcher — is readable without scrolling past
//! every verb's implementation.

use super::*;
// Shared with the register verb: init falls back to a refetch when a slug it
// just created was taken in the race window.
use super::register::refetch_module_id;

pub(super) fn run(args: InitArgs) -> Result<()> {
    let theme = ColorfulTheme::default();

    let mut creds = credentials::load_or_login_hint()?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let web_base = resolve_base(ENV_WEB_URL, DEFAULT_WEB_BASE);
    let client = http::client(Duration::from_secs(15))?;

    // The platform stores ownership by user id, but the CLI surfaces the
    // full namespaced `@<username>/<slug>` — so we refuse to POST until the
    // caller has claimed a username, and point them at the web flow.
    let identity =
        match credentials::with_refresh_retry(&mut creds, |tok| api::me(&client, &api_base, tok)) {
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
        return Err(slug_invalid_error(&slug));
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
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::get_module(&client, &apps_base, tok, &slug)
        })
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
                credentials::with_refresh_retry(&mut creds, |tok| {
                    api::create_module(
                        &client,
                        &apps_base,
                        tok,
                        &CreateModuleInput {
                            name: &name,
                            slug: &slug,
                        },
                    )
                })
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
                    refetch_module_id(&client, &apps_base, &mut creds, username, &slug)?
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
pub(super) fn is_cwd(target: &Path) -> bool {
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
