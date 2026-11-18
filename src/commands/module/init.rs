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
    if args.offline {
        // Returns before credentials::load_or_login_hint below: no login,
        // no platform call, no HTTP client.
        return run_offline(&args);
    }
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

/// `init --offline --module-id <uuid>`: write the scaffold tree and nothing
/// else. Never reads credentials, never builds an HTTP client, never prompts
/// (the sandbox runs with an empty HOME and no network).
fn run_offline(args: &InitArgs) -> Result<()> {
    let name = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("--offline requires --name (it never prompts)"))?;
    let slug = match args
        .slug
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(s) => s.to_string(),
        None => derive_slug(name),
    };
    if !slug_valid(&slug) {
        return Err(slug_invalid_error(&slug));
    }
    let module_id = args
        .module_id
        .as_deref()
        .map(str::trim)
        .ok_or_else(|| anyhow!("--offline requires --module-id"))?;
    if !module_id_valid(module_id) {
        return Err(anyhow!(
            "--module-id {module_id:?} is not a UUID (expected 8-4-4-4-12 hex digits)"
        ));
    }
    let target = resolve_scaffold_target(args.dir.as_deref(), &slug);
    scaffold::ensure_target_writable(&target)?;
    scaffold_if_requested(
        Some(&target),
        &scaffold::Inputs {
            slug: &slug,
            name,
            module_id,
        },
    )
}

/// 8-4-4-4-12 hex digits. The ID ends up in `.env` and Config.ID, so a
/// malformed one is refused here rather than at the module's first boot.
fn module_id_valid(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
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
    // go.mod/go.sum ship complete, so no `go mod tidy` step.
    let next = if is_cwd(target) {
        "mirrorstack dev".to_string()
    } else {
        format!("cd {} && mirrorstack dev", target.display())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_id_valid_accepts_uuid_only() {
        assert!(module_id_valid("bb8a3f8b-1234-5678-9abc-def012345678"));
        assert!(!module_id_valid("bb8a3f8b123456789abcdef012345678"));
        assert!(!module_id_valid("bb8a3f8b-1234-5678-9abc-def01234567g"));
        assert!(!module_id_valid(""));
    }
}
