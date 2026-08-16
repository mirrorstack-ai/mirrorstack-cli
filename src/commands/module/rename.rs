//! Safe, identity-preserving module slug rename.
//!
//! A module ID is the durable identity behind installs and module-table
//! namespaces; the slug is only its mutable name. This command keeps those two
//! concepts separate and makes each remote/local leg independently re-runnable
//! so an interrupted rename can be completed without minting a replacement ID.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use console::style;
use dialoguer::{Confirm, theme::ColorfulTheme};

use crate::api::{self, ApiError};
use crate::commands::dev::module_meta;
use crate::commands::{
    DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base, session_expired, warn_prefix,
};
use crate::{credentials, http};

use super::{sanitize_module_id, slug_valid};

#[derive(Args)]
pub struct RenameArgs {
    /// New module slug.
    #[arg(long)]
    to: String,
    /// Previous slug. Defaults to Config.Slug in main.go; pass it explicitly
    /// when main.go was already edited but the workspace .env was not.
    #[arg(long)]
    from: Option<String>,
    /// Module directory containing main.go. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Update main.go and the workspace .env without calling the platform.
    #[arg(long)]
    local_only: bool,
    /// Skip the confirmation prompt.
    #[arg(long, short)]
    yes: bool,
}

#[derive(Debug)]
enum PlatformStep {
    LocalOnly,
    AlreadyRenamed,
    Rename { module_id: String },
}

pub(crate) fn run(args: RenameArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("read cwd")?;
    let module_dir = match args.dir {
        Some(dir) if dir.is_absolute() => dir,
        Some(dir) => cwd.join(dir),
        None => cwd,
    };
    let root = workspace_root(&module_dir);
    let meta = module_meta::read_module_meta(&module_dir, &root).map_err(|e| {
        anyhow!(
            "couldn't read the module from {}: {e}. Run from the module directory, or pass --dir <path>.",
            module_dir.display()
        )
    })?;
    let from = args.from.as_deref().unwrap_or(&meta.slug);
    validate_rename(from, &args.to)?;
    if meta.slug != from && meta.slug != args.to {
        return Err(anyhow!(
            "Slug in {}/main.go is {:?}, not {:?} or {:?}",
            module_dir.display(),
            meta.slug,
            from,
            args.to
        ));
    }

    let old_key = module_meta::env_key_for_slug(from);
    let new_key = module_meta::env_key_for_slug(&args.to);
    let old_id = module_meta::read_env_module_id(&root, from);
    let new_id = module_meta::read_env_module_id(&root, &args.to);
    let (carried_id, env_already_renamed) = match (old_id.is_empty(), new_id.is_empty()) {
        (false, true) => (old_id, false),
        (true, false) => (new_id, true),
        (false, false) => {
            return Err(anyhow!(
                "both {old_key} and {new_key} exist in {}; refusing an ambiguous module ID rename",
                root.join(".env").display()
            ));
        }
        (true, true) => {
            return Err(module_meta::missing_module_id_error(
                &module_dir,
                &root,
                &meta.slug,
            ));
        }
    };

    let mut creds = None;
    let platform_step = if args.local_only {
        PlatformStep::LocalOnly
    } else {
        let mut loaded = credentials::load_or_login_hint()?;
        let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
        let client = http::client(Duration::from_secs(15))?;
        let step = resolve_platform_step(
            &client,
            &apps_base,
            &mut loaded,
            from,
            &args.to,
            &carried_id,
        )?;
        creds = Some((loaded, apps_base, client));
        step
    };

    let main_already_renamed = meta.slug == args.to;
    if !args.yes {
        print_plan(
            from,
            &args.to,
            &carried_id,
            &platform_step,
            main_already_renamed,
            env_already_renamed,
        );
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Rename this module slug while keeping its existing ID?")
            .default(true)
            .interact()?;
        if !confirmed {
            eprintln!("{}", style("aborted.").yellow());
            return Ok(());
        }
    }

    // The platform half needs network and auth and is the step most likely to
    // fail for external reasons, so it goes first. The main.go and .env edits
    // are pure local rewrites and idempotent; if either fails, the exact
    // --local-only re-run below safely completes the partial operation.
    match &platform_step {
        PlatformStep::LocalOnly => {
            eprintln!("{} platform rename skipped (--local-only)", ok_mark());
        }
        PlatformStep::AlreadyRenamed => {
            eprintln!("{} platform catalog already uses {}", ok_mark(), args.to);
        }
        PlatformStep::Rename { module_id } => {
            let (loaded, apps_base, client) = creds.as_mut().ok_or_else(|| {
                anyhow!("internal error: missing credentials for platform rename")
            })?;
            let renamed = credentials::with_refresh_retry(loaded, |token| {
                api::rename_module_slug(client, apps_base, token, module_id, &args.to)
            });
            match renamed {
                Ok(module) => eprintln!(
                    "{} platform catalog renamed {} → {} ({})",
                    ok_mark(),
                    from,
                    style(&module.slug).cyan().bold(),
                    style(&carried_id).dim()
                ),
                Err(ApiError::Unauthenticated) => return Err(session_expired()),
                Err(ApiError::Server { code, message, .. }) => {
                    return Err(anyhow!("{code}: {message}"));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    let rerun = rerun_command(from, &args.to, &module_dir);
    if main_already_renamed {
        eprintln!("{} main.go already uses Slug: {:?}", ok_mark(), args.to);
    } else if let Err(e) = module_meta::rename_slug_in_main_go(&module_dir, from, &args.to) {
        return Err(local_failure("update main.go", e, &rerun));
    } else {
        eprintln!(
            "{} updated Slug in {}/main.go",
            ok_mark(),
            module_dir.display()
        );
    }

    if env_already_renamed {
        eprintln!(
            "{} {} already carries {}",
            ok_mark(),
            new_key,
            style(&carried_id).dim()
        );
    } else {
        match module_meta::rename_module_id_key(&root, from, &args.to) {
            Ok(id) => eprintln!(
                "{} renamed {} → {} in {} (same ID: {})",
                ok_mark(),
                old_key,
                new_key,
                root.join(".env").display(),
                style(id).dim()
            ),
            Err(e) => return Err(local_failure("update the workspace .env", e, &rerun)),
        }
    }

    print_untouched_tail(&module_dir, from, &args.to);
    Ok(())
}

fn validate_rename(from: &str, to: &str) -> Result<()> {
    if !slug_valid(to) {
        return Err(anyhow!(
            "slug '{to}' is invalid: must be 3-40 chars, start with a letter, end with a letter or digit, lowercase + hyphen only."
        ));
    }
    if to == from {
        return Err(anyhow!("new slug '{to}' is the same as the old slug"));
    }
    Ok(())
}

/// Find the nearest `go.work` at or above the module directory. A module with
/// no workspace ancestor owns its own `.env`, matching deploy's standalone
/// metadata rule.
fn workspace_root(module_dir: &Path) -> PathBuf {
    module_dir
        .ancestors()
        .find(|dir| dir.join("go.work").is_file())
        .unwrap_or(module_dir)
        .to_path_buf()
}

fn resolve_platform_step(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    creds: &mut credentials::Credentials,
    from: &str,
    to: &str,
    carried_id: &str,
) -> Result<PlatformStep> {
    let target = credentials::with_refresh_retry(creds, |token| {
        api::get_module(client, apps_base, token, to)
    });
    let target = map_api_result(target)?;
    if target
        .as_ref()
        .is_some_and(|module| sanitize_module_id(&module.id) == carried_id)
    {
        return Ok(PlatformStep::AlreadyRenamed);
    }

    let source = credentials::with_refresh_retry(creds, |token| {
        api::get_module(client, apps_base, token, from)
    });
    let Some(source) = map_api_result(source)? else {
        return Err(anyhow!(
            "module '{from}' was not found in the caller's platform catalog, so ownership of ID {carried_id} cannot be proved; no changes were made"
        ));
    };
    let platform_id = sanitize_module_id(&source.id);
    if platform_id != carried_id {
        return Err(anyhow!(
            "workspace ID mismatch: {old_key} carries {carried_id}, but platform module '{from}' has {platform_id}; refusing to compound a mis-wired workspace",
            old_key = module_meta::env_key_for_slug(from)
        ));
    }
    Ok(PlatformStep::Rename {
        module_id: source.id,
    })
}

fn map_api_result<T>(result: Result<T, ApiError>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(ApiError::Server { code, message, .. }) => Err(anyhow!("{code}: {message}")),
        Err(e) => Err(e.into()),
    }
}

fn print_plan(
    from: &str,
    to: &str,
    carried_id: &str,
    platform: &PlatformStep,
    main_already: bool,
    env_already: bool,
) {
    let platform = match platform {
        PlatformStep::LocalOnly => "skip (--local-only)",
        PlatformStep::AlreadyRenamed => "skip (already renamed)",
        PlatformStep::Rename { .. } => "rename catalog slug",
    };
    eprintln!();
    eprintln!(
        "  {} {} → {}",
        style("Slug:").dim(),
        style(from).bold(),
        style(to).cyan().bold()
    );
    eprintln!("  {}   {}", style("ID:").dim(), style(carried_id).bold());
    eprintln!("  {} {platform}", style("Platform:").dim());
    eprintln!(
        "  {} {}",
        style("main.go:").dim(),
        if main_already {
            "skip (already renamed)"
        } else {
            "rewrite Slug literal"
        }
    );
    eprintln!(
        "  {}     {}",
        style(".env:").dim(),
        if env_already {
            "skip (key already renamed)"
        } else {
            "rename key, preserve value"
        }
    );
}

fn rerun_command(from: &str, to: &str, module_dir: &Path) -> String {
    format!(
        "mirrorstack app module rename --from {from} --to {to} --dir {} --local-only --yes",
        shell_quote(&module_dir.to_string_lossy())
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// A local leg failed after the remote leg was done (or deliberately skipped),
/// so the tree is half-renamed. Every step is idempotent, so the fix is always
/// the same `--local-only` re-run rather than any hand repair — and above all
/// never `register`, which is what a half-renamed tree otherwise invites.
fn local_failure(action: &str, error: anyhow::Error, rerun: &str) -> anyhow::Error {
    eprintln!(
        "{} the platform slug is settled, but the CLI could not {action}, so this tree is half-renamed.",
        warn_prefix()
    );
    eprintln!("  Fix the cause, then re-run exactly: `{rerun}`");
    eprintln!("  The module ID is unchanged. Do NOT run `mirrorstack app module register`.");
    error.context(action.to_string())
}

fn print_untouched_tail(module_dir: &Path, from: &str, to: &str) {
    eprintln!();
    eprintln!("What this command did NOT do:");
    if let Some((actual, expected)) = mismatched_web_package_name(module_dir, to) {
        eprintln!(
            "  - {}/web/package.json still names the package {:?}; set `name` to {:?} so build-css.mjs derives CSS scope {:?}.",
            module_dir.display(),
            actual,
            expected,
            to
        );
    }
    eprintln!(
        "  - Other modules that contribute into {to} name it by slug; update and re-register them or the contribution is silently dropped at install time."
    );
    eprintln!(
        "  - The module directory and its go.work entry are untouched by design; local dev routes by directory name, so nothing local breaks."
    );
    eprintln!("  - Old /settings/module/{from} URLs will no longer resolve.");
}

fn mismatched_web_package_name(module_dir: &Path, to: &str) -> Option<(String, String)> {
    let path = module_dir.join("web/package.json");
    if !path.is_file() {
        return None;
    }
    let body = fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&body).ok()?;
    let name = json.get("name")?.as_str()?;
    let (scope, package) = if let Some(scoped) = name.strip_prefix('@') {
        let (scope, package) = scoped.split_once('/')?;
        (Some(format!("@{scope}/")), package)
    } else {
        (None, name)
    };
    let has_web_suffix = package.ends_with("-web");
    let derived = package.strip_suffix("-web").unwrap_or(package);
    if derived == to {
        return None;
    }
    let expected_package = if has_web_suffix {
        format!("{to}-web")
    } else {
        to.to_string()
    };
    let expected = format!("{}{expected_package}", scope.unwrap_or_default());
    Some((name.to_string(), expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_uses_nearest_go_work_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("workspace");
        let module = root.join("modules/media");
        fs::create_dir_all(&module).unwrap();
        fs::write(root.join("go.work"), "go 1.26\n").unwrap();
        assert_eq!(workspace_root(&module), root);
    }

    #[test]
    fn workspace_root_falls_back_to_standalone_module() {
        let tmp = tempfile::tempdir().unwrap();
        let module = tmp.path().join("media");
        fs::create_dir(&module).unwrap();
        assert_eq!(workspace_root(&module), module);
    }

    #[test]
    fn same_from_and_to_is_rejected() {
        let error = validate_rename("oauth-core", "oauth-core")
            .unwrap_err()
            .to_string();
        assert!(error.contains("same as the old slug"), "{error}");
    }

    #[test]
    fn invalid_to_is_rejected_with_deploy_wording() {
        let error = validate_rename("oauth-core", "OAuth_Core")
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "slug 'OAuth_Core' is invalid: must be 3-40 chars, start with a letter, end with a letter or digit, lowercase + hyphen only."
        );
    }
}
