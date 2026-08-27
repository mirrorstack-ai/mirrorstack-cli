//! `mirrorstack app module register` — claim a slug for an existing tree.
//!
//! Split out of a 1468-line mod.rs so the command surface — the Args
//! structs and the run() dispatcher — is readable without scrolling past
//! every verb's implementation.

use super::*;

pub(super) fn run(args: RegisterArgs) -> Result<()> {
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

    // Parse go.work to find module directories
    let body =
        std::fs::read_to_string(&go_work).with_context(|| format!("read {}", go_work.display()))?;
    let module_dirs = parse_go_work_use_dirs(&body);
    if module_dirs.is_empty() {
        return Err(anyhow!("go.work has no `use` directives"));
    }
    // Compute this once against the pre-command workspace. If one old key is
    // stranded, every would-be create deserves the same conservative guard;
    // mutating the set as this loop progresses could make later modules look
    // safer merely because an earlier module was registered.
    let unclaimed_ids = module_meta::unclaimed_module_id_keys(&cwd);

    let theme = ColorfulTheme::default();
    let mut registered = 0u32;
    let mut skipped = 0u32;
    let mut refused_new = 0u32;

    for rel_dir in &module_dirs {
        let abs_dir = cwd.join(rel_dir);
        let meta = match module_meta::read_module_meta(&abs_dir, &cwd) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{} skipping {}: {e}", warn_prefix(), rel_dir);
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

        let mut dangerous_create_confirmed = false;
        if !unclaimed_ids.is_empty() && !args.allow_new {
            print_stranded_id_register_guard(&meta.slug, &unclaimed_ids);
            if args.yes {
                refused_new += 1;
                continue;
            }
            dangerous_create_confirmed = Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Create a NEW ID for {} despite the stranded workspace IDs?",
                    meta.slug
                ))
                .default(false)
                .interact()?;
            if !dangerous_create_confirmed {
                eprintln!(
                    "{} skipped {}. Use `mirrorstack app module rename --from <old-slug> --to {}` to preserve the existing ID.",
                    warn_prefix(),
                    meta.slug,
                    meta.slug
                );
                continue;
            }
        }

        if !args.yes && !dangerous_create_confirmed {
            eprintln!();
            eprintln!("  {} {}", style("Module:").dim(), style(&meta.name).bold());
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
            credentials::with_refresh_retry(&mut creds, |tok| {
                api::create_module(
                    &client,
                    &apps_base,
                    tok,
                    &CreateModuleInput {
                        name: &meta.name,
                        slug: &meta.slug,
                    },
                )
            })
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
                match credentials::with_refresh_retry(&mut creds, |tok| {
                    api::get_module(&client, &apps_base, tok, &meta.slug)
                })? {
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
                eprintln!("{} failed to register {}: {e}", warn_prefix(), meta.slug);
                continue;
            }
        };

        // Write the ID into the workspace root's .env, keyed by this
        // module's slug — a per-environment value, not a main.go literal,
        // so the same source tree can carry a different platform-assigned
        // ID per environment (local dev, prod), and so a monorepo's
        // multiple modules can each keep their own entry in the one root
        // .env instead of scattering a file per module directory.
        let sanitized_id = sanitize_module_id(&module_id);
        let env_key = module_meta::env_key_for_slug(&meta.slug);
        module_meta::write_module_id(&cwd, &meta.slug, &sanitized_id)
            .with_context(|| format!("write {env_key} to {}/.env", cwd.display()))?;
        eprintln!(
            "  {} wrote {}={} → {}/.env",
            style("→").dim(),
            env_key,
            style(&sanitized_id).dim(),
            cwd.display()
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
    if refused_new > 0 {
        return Err(anyhow!(
            "refused to create {refused_new} new module ID(s) while the workspace has unclaimed IDs; use `module rename`, or pass --allow-new only for genuinely brand-new modules"
        ));
    }
    Ok(())
}

fn print_stranded_id_register_guard(slug: &str, unclaimed: &[(String, String)]) {
    eprintln!();
    eprintln!(
        "{} module '{}' has no ID under its current slug, but the workspace .env contains unclaimed module-ID keys:",
        warn_prefix(),
        slug
    );
    for (key, _) in unclaimed {
        eprintln!("  - {key}");
    }
    eprintln!(
        "  This looks like a slug rename. `module register` would mint a NEW ID, create new empty module tables, and leave an existing install pointing at the old ID."
    );
    eprintln!(
        "  Preserve the ID with `mirrorstack app module rename --from <old-slug> --to {slug}`. Use --allow-new only when this really is a brand-new module."
    );
}

pub(super) fn refetch_module_id(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    creds: &mut credentials::Credentials,
    username: &str,
    slug: &str,
) -> Result<String> {
    let refetch = with_spinner("Resolving existing module…", || {
        credentials::with_refresh_retry(creds, |tok| api::get_module(client, apps_base, tok, slug))
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
