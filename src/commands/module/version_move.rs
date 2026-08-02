//! `mirrorstack module move` — move one app's installed module from the
//! version it is pinned to onto another published version of that module.
//!
//! This is the operator side of per-version module transport: an install
//! points at exactly one published version, and rolling forward (or, with
//! `--allow-downgrade`, back) is a deliberate act on ONE app's install, not
//! a platform-wide flip. The platform re-checks peer dependency constraints
//! and runs the module's app-scope migrations before repinning, so the
//! command is a thin, honest client: resolve → confirm → POST → explain.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Args;
use console::style;
use dialoguer::{Confirm, Select, theme::ColorfulTheme};

use crate::api::{self, ApiError, AppInstall, PublishedVersion, UpdateInstallInput, UpdateOutcome};
use crate::commands::dev::module_meta;
use crate::credentials;
use crate::http;

use super::with_spinner;
use crate::commands::{
    DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base, session_expired, warn_prefix,
};

/// The platform's placeholder for an install with no version pin (a module
/// mounted straight off a dev tunnel). Such an install has nothing to
/// compare a target against, so the downgrade gate can't apply to it.
const DEV_INSTALL: &str = "dev";

/// The move runs the module's app-scope migrations server-side before the
/// pin is written, so it is not a fast request — a 15s timeout (what the
/// other module commands use) would abort a legitimately slow upgrade and
/// leave the operator unsure whether it landed.
const MOVE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Args)]
pub struct MoveArgs {
    /// App whose install is being moved (id or slug).
    #[arg(long)]
    app: String,
    /// Installed module to move — its slug, or its platform UUID when two
    /// installed modules share a slug.
    #[arg(long)]
    module: String,
    /// Target published version (canonical SemVer, e.g. 0.2.0). When
    /// omitted, the module's published versions are listed to pick from.
    #[arg(long)]
    to: Option<String>,
    /// Move BACKWARDS to an older version. Off by default because the move
    /// runs the module's app-scope migrations in REVERSE: a down-migration
    /// routinely drops the columns and tables its up-migration added, which
    /// destroys every row this app wrote through them. Nothing snapshots
    /// them first, so there is no undo.
    #[arg(long)]
    allow_downgrade: bool,
    /// Skip the confirmation prompt.
    #[arg(long, short)]
    yes: bool,
}

pub(super) fn run(args: MoveArgs) -> Result<()> {
    let mut creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(MOVE_TIMEOUT)?;

    // `list_app_installs` resolves the per-app tenant schema from the id, so
    // it needs the UUID — the id-or-slug `--app` is resolved first. The
    // update endpoint itself takes either, but it is given the same
    // canonical id so all three calls talk about one resolved app.
    let app = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::get_app(&client, &apps_base, tok, &args.app)
    }) {
        Ok(Some(app)) => app,
        Ok(None) => {
            return Err(anyhow!(
                "app '{}' not found (or you are not a member)",
                args.app
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    let installs = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::list_app_installs(&client, &apps_base, tok, &app.id)
    }) {
        Ok(installs) => installs,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };
    let install = find_install(&installs, &args.module, &app.slug)?;

    let published = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::list_module_version_history(&client, &apps_base, tok, &install.module_id)
    }) {
        Ok(versions) => versions,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };
    if published.is_empty() {
        return Err(anyhow!(
            "{} has no published versions to move to — its author has to run `mirrorstack app module deploy` first",
            install.slug
        ));
    }

    let target = match args.to.as_deref() {
        Some(requested) => resolve_requested(requested, &published)?,
        None => choose_version(&published, &install.installed_version)?,
    };

    if target == install.installed_version {
        eprintln!(
            "{} {} is already at {} in {} — nothing to move.",
            ok_mark(),
            style(&install.slug).cyan().bold(),
            style(&target).bold(),
            style(&app.slug).cyan()
        );
        return Ok(());
    }

    // Client-side downgrade gate. Advisory — the platform decides — but it
    // is what makes `--allow-downgrade` a real opt-in instead of a flag that
    // only matters once the request has already been sent.
    let backwards = is_backwards(&install.installed_version, &target);
    if backwards && !args.allow_downgrade {
        return Err(anyhow!(
            "{} is installed at {} in {}; {} is older. Pass --allow-downgrade to move backwards — it reverts the module's app-scope migrations, and a reverted migration drops what it created, destroying the rows in it. There is no undo.",
            install.slug,
            install.installed_version,
            app.slug,
            target
        ));
    }

    if !args.yes {
        eprintln!();
        eprintln!("  {}    {}", style("App:").dim(), style(&app.slug).bold());
        eprintln!(
            "  {} {}",
            style("Module:").dim(),
            style(&install.slug).cyan().bold()
        );
        eprintln!(
            "  {}   {} → {}",
            style("Move:").dim(),
            style(&install.installed_version).dim(),
            style(&target).bold()
        );
        if backwards {
            eprintln!(
                "{} this is a DOWNGRADE. Moving {} → {} reverts the module's app-scope migrations; whatever they created is dropped, and the rows in it are destroyed with no undo.",
                warn_prefix(),
                install.installed_version,
                target
            );
        }
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("Move {} to {target}?", install.slug))
            .default(!backwards)
            .interact()?;
        if !confirmed {
            eprintln!("{}", style("aborted.").yellow());
            return Ok(());
        }
    }

    let result = with_spinner("Moving…", || {
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::update_install_version(
                &client,
                &apps_base,
                tok,
                &app.id,
                &install.module_id,
                &UpdateInstallInput {
                    version: &target,
                    allow_downgrade: args.allow_downgrade,
                },
            )
        })
    });

    match result {
        Ok(UpdateOutcome::Updated(updated)) => {
            eprintln!(
                "{} moved {} {} → {}",
                ok_mark(),
                style(&install.slug).cyan().bold(),
                style(&install.installed_version).dim(),
                style(&updated.installed_version).bold()
            );
            eprintln!("  {} {}", style("app:").dim(), app.slug);
            Ok(())
        }
        Ok(UpdateOutcome::Held(blockers)) => Err(held_error(&install.slug, &target, &blockers)),
        Err(ApiError::Server { code, message, .. }) => Err(anyhow!(
            "{code}: {message}{hint}",
            hint = move_error_hint(&code, args.allow_downgrade)
        )),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

/// Locate the install `--module` names. Matching on the module slug is the
/// ergonomic case; the platform UUID is accepted too because two installed
/// modules from different owners can legitimately share a slug, and then the
/// slug alone is not an answer.
fn find_install<'a>(
    installs: &'a [AppInstall],
    module: &str,
    app_slug: &str,
) -> Result<&'a AppInstall> {
    if let Some(exact) = installs.iter().find(|i| i.module_id == module) {
        return Ok(exact);
    }
    let matches: Vec<&AppInstall> = installs.iter().filter(|i| i.slug == module).collect();
    match matches.as_slice() {
        [only] => Ok(only),
        [] => Err(anyhow!(
            "'{module}' is not installed in {app_slug}{installed}",
            installed = installed_list(installs)
        )),
        many => Err(anyhow!(
            "{n} installed modules use the slug '{module}' in {app_slug} — pass --module with the platform UUID instead ({ids})",
            n = many.len(),
            ids = many
                .iter()
                .map(|i| i.module_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn installed_list(installs: &[AppInstall]) -> String {
    if installs.is_empty() {
        return " (no modules are installed in it)".into();
    }
    format!(
        " (installed: {})",
        installs
            .iter()
            .map(|i| i.slug.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Check an explicit `--to` against what the module actually publishes, so a
/// typo is a local error listing the real choices rather than a bare 404.
/// The `v` prefix the SDK uses for its `Config.Versions` keys is tolerated —
/// the wire form is canonical SemVer without it.
fn resolve_requested(requested: &str, published: &[PublishedVersion]) -> Result<String> {
    let wanted = requested.strip_prefix('v').unwrap_or(requested);
    if published.iter().any(|v| v.version == wanted) {
        return Ok(wanted.to_string());
    }
    Err(anyhow!(
        "{requested} is not a published version of this module. Published: {}",
        published
            .iter()
            .map(|v| v.version.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Pick a target when `--to` was omitted. On a TTY that is a prompt over the
/// published versions (newest first, the installed one marked); without one
/// the same list is printed and the command stops — guessing a version on
/// the operator's behalf is not something a non-interactive run should do.
fn choose_version(published: &[PublishedVersion], installed: &str) -> Result<String> {
    let labels: Vec<String> = published
        .iter()
        .map(|v| version_label(v, installed))
        .collect();

    if !std::io::stderr().is_terminal() {
        eprintln!("{}", style("Published versions:").bold());
        for label in &labels {
            eprintln!("  {label}");
        }
        return Err(anyhow!(
            "pass --to <version> to choose one (no terminal to prompt on)"
        ));
    }

    let picked = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Move to which version?")
        .items(&labels)
        .default(0)
        .interact()?;
    Ok(published[picked].version.clone())
}

fn version_label(v: &PublishedVersion, installed: &str) -> String {
    let mut label = v.version.clone();
    // RFC3339 from the platform; the date alone is what an operator scans.
    if let Some(date) = v.published_at.get(..10) {
        label.push_str(&format!("  ({date})"));
    }
    if v.version == installed {
        label.push_str("  ← installed");
    }
    label
}

/// Whether `target` is strictly OLDER than `installed` — the condition
/// `--allow-downgrade` exists for. Equal is deliberately NOT backwards: the
/// platform answers an equal target with its own `version_unchanged`, for
/// which the flag would do nothing, so claiming a downgrade here would
/// demand a flag that cannot help. A dev-mount install (no pin) and any
/// version either side can't parse as SemVer are left to the platform,
/// which is the authority; guessing here would block a legal move.
fn is_backwards(installed: &str, target: &str) -> bool {
    if installed == DEV_INSTALL {
        return false;
    }
    match (
        module_meta::parse_semver(installed),
        module_meta::parse_semver(target),
    ) {
        (Some(from), Some(to)) => to < from,
        _ => false,
    }
}

fn held_error(slug: &str, target: &str, blockers: &[api::UpdateBlocker]) -> anyhow::Error {
    let detail = blockers
        .iter()
        .map(|b| format!("{} needs {}", b.module, b.constraint))
        .collect::<Vec<_>>()
        .join(", ");
    anyhow!(
        "update_held: {slug}@{target} is rejected by {n} installed peer module(s) — {detail}. Move or uninstall the blocking peer(s) first, or pick a version their constraints allow.",
        n = blockers.len()
    )
}

/// Hints for the codes `POST /v1/apps/{ref}/modules/{id}/update` returns.
/// `update_held` never reaches here — its 409 carries a blocker list and is
/// surfaced by [`held_error`] instead.
///
/// Every hint is printed AFTER the platform's own `message`, so a hint may
/// only add what the CLI knows and the platform does not: which flag to
/// re-run with, which command lists the alternatives. None of them may
/// restate WHY the platform refused. That rule is not style — the platform
/// deliberately sends more than one distinct message under a single code,
/// and a hint that names one of the causes is wrong for the others:
///
/// * `downgrade_not_supported` covers a backward SemVer move AND a target
///   whose app-migration counter is lower than the install's watermark. The
///   second reaches a dev-mount install with no pinned version at all, and a
///   target that is SemVer-*newer*. The old hint here said "the target is not
///   newer than the installed version", which is a flat contradiction of the
///   message it was appended to in that case.
/// * `downgrade_failed` means the module answered the revert with an error,
///   and the platform quotes that error verbatim precisely because it cannot
///   classify it (the SDK's downgrade response carries no machine-readable
///   cause). A CLI sentence guessing at "it publishes no rollback for one of
///   these migrations" would put back the exact assertion the platform
///   removed.
///
/// The one case that IS the CLI's to explain is version skew: a platform
/// predating opt-in downgrades drops the unknown `allowDowngrade` key and
/// refuses anyway, so a caller who already passed the flag is told the
/// server is old instead of being told to pass a flag they just passed.
fn move_error_hint(code: &str, allow_downgrade: bool) -> &'static str {
    match code {
        "version_not_found" => {
            " (that version isn't published for this module any more — re-run without --to to list what is)"
        }
        "version_unchanged" => {
            " (nothing moved — re-run without --to to list the other published versions)"
        }
        "downgrade_not_supported" if allow_downgrade => {
            " (this platform refuses backward moves outright — it ignored --allow-downgrade. Update the platform, or pick a version it will accept.)"
        }
        "downgrade_not_supported" => {
            " (re-run with --allow-downgrade to accept it — reverting a migration drops what it created and destroys the rows in it, with no undo)"
        }
        "downgrade_failed" => {
            " (the version pin was NOT moved. The platform does not diagnose this — the text it quotes is the module's own report; take it to the module's author, then re-run.)"
        }
        "not_found" => " (no such app, the module isn't installed in it, or you are not a member)",
        "forbidden" => " (moving an install's version needs the app owner or an admin)",
        "validation_error" | "bad_request" => {
            " (the platform rejected the request body — versions must be canonical SemVer, e.g. 0.2.0)"
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install(module_id: &str, slug: &str, version: &str) -> AppInstall {
        AppInstall {
            module_id: module_id.into(),
            name: slug.into(),
            slug: slug.into(),
            installed_version: version.into(),
            manifest: None,
            serving: "deployed".into(),
        }
    }

    fn published(version: &str) -> PublishedVersion {
        PublishedVersion {
            version: version.into(),
            published_at: "2026-07-30T10:11:12Z".into(),
        }
    }

    #[test]
    fn find_install_matches_slug() {
        let installs = [
            install("m1", "media", "0.1.0"),
            install("m2", "auth", "1.0.0"),
        ];
        assert_eq!(
            find_install(&installs, "auth", "app").unwrap().module_id,
            "m2"
        );
    }

    #[test]
    fn find_install_matches_uuid() {
        let installs = [install("m1", "media", "0.1.0")];
        assert_eq!(find_install(&installs, "m1", "app").unwrap().slug, "media");
    }

    #[test]
    fn find_install_lists_installed_on_miss() {
        let installs = [install("m1", "media", "0.1.0")];
        let err = find_install(&installs, "nope", "my-app")
            .unwrap_err()
            .to_string();
        assert!(err.contains("my-app"), "{err}");
        assert!(err.contains("installed: media"), "{err}");
    }

    #[test]
    fn find_install_refuses_ambiguous_slug() {
        let installs = [
            install("m1", "media", "0.1.0"),
            install("m2", "media", "0.2.0"),
        ];
        let err = find_install(&installs, "media", "my-app")
            .unwrap_err()
            .to_string();
        assert!(err.contains("--module with the platform UUID"), "{err}");
        assert!(err.contains("m1, m2"), "{err}");
    }

    #[test]
    fn resolve_requested_accepts_published_and_strips_v() {
        let versions = [published("0.2.0"), published("0.1.0")];
        assert_eq!(resolve_requested("0.2.0", &versions).unwrap(), "0.2.0");
        assert_eq!(resolve_requested("v0.1.0", &versions).unwrap(), "0.1.0");
    }

    #[test]
    fn resolve_requested_lists_choices_on_miss() {
        let versions = [published("0.2.0"), published("0.1.0")];
        let err = resolve_requested("9.9.9", &versions)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Published: 0.2.0, 0.1.0"), "{err}");
    }

    #[test]
    fn is_backwards_detects_older() {
        assert!(is_backwards("0.2.0", "0.1.0"));
        assert!(is_backwards("1.0.0", "1.0.0-beta.1"));
    }

    #[test]
    fn is_backwards_false_for_forward_and_dev() {
        assert!(!is_backwards("0.1.0", "0.2.0"));
        // Equal is version_unchanged on the platform, not a downgrade —
        // --allow-downgrade would not make it succeed, so don't demand it.
        assert!(!is_backwards("0.2.0", "0.2.0"));
        // A dev-mount install has no pin to compare against, so any published
        // target is a forward move — the same rule the platform applies.
        assert!(!is_backwards(DEV_INSTALL, "0.1.0"));
        // Unparseable either side: defer to the platform rather than block.
        assert!(!is_backwards("not-semver", "0.1.0"));
    }

    #[test]
    fn version_label_marks_installed_and_dates() {
        let label = version_label(&published("0.2.0"), "0.2.0");
        assert!(label.contains("2026-07-30"), "{label}");
        assert!(label.contains("← installed"), "{label}");
        assert!(!version_label(&published("0.1.0"), "0.2.0").contains("installed"));
    }

    #[test]
    fn held_error_names_every_blocker() {
        let blockers = [
            api::UpdateBlocker {
                module: "oauth-google".into(),
                constraint: "^0.1".into(),
            },
            api::UpdateBlocker {
                module: "billing".into(),
                constraint: "~0.1.2".into(),
            },
        ];
        let err = held_error("media", "0.2.0", &blockers).to_string();
        assert!(err.contains("oauth-google needs ^0.1"), "{err}");
        assert!(err.contains("billing needs ~0.1.2"), "{err}");
        assert!(err.contains("2 installed peer module(s)"), "{err}");
    }

    #[test]
    fn move_error_hint_splits_on_the_downgrade_flag() {
        assert!(
            move_error_hint("downgrade_not_supported", false)
                .contains("--allow-downgrade to accept")
        );
        let old_server = move_error_hint("downgrade_not_supported", true);
        assert!(
            old_server.contains("ignored --allow-downgrade"),
            "{old_server}"
        );
    }

    /// `downgrade_not_supported` carries two different platform messages —
    /// a backward SemVer move, and a target with fewer app migrations than
    /// the install has applied (which can be SemVer-FORWARD, or hit a
    /// dev-mount install with no pin at all). The hint may only name the
    /// remedy both share; asserting the SemVer cause would contradict the
    /// message it is appended to in the second case.
    #[test]
    fn downgrade_hint_names_the_remedy_not_a_cause() {
        let hint = move_error_hint("downgrade_not_supported", false);
        assert!(!hint.contains("not newer"), "{hint}");
        assert!(!hint.contains("older than"), "{hint}");
        assert!(hint.contains("--allow-downgrade"), "{hint}");
    }

    /// The platform quotes the module's own error for `downgrade_failed`
    /// because it cannot classify the cause. The hint must not supply one —
    /// no talk of missing down-files or unsupported rollbacks.
    #[test]
    fn downgrade_failed_hint_defers_to_the_module_report() {
        let hint = move_error_hint("downgrade_failed", false);
        assert!(hint.contains("module's own report"), "{hint}");
        assert!(hint.contains("pin was NOT moved"), "{hint}");
        assert!(!hint.contains("down.sql"), "{hint}");
        assert!(!hint.contains("rollback for"), "{hint}");
        // Same hint whether or not the flag was passed — reaching this code
        // means the flag WAS accepted and the revert then failed.
        assert_eq!(hint, move_error_hint("downgrade_failed", true));
    }

    #[test]
    fn move_error_hint_for_other_known_codes() {
        assert!(move_error_hint("version_not_found", false).contains("--to"));
        assert!(move_error_hint("version_unchanged", false).contains("--to"));
        assert!(move_error_hint("forbidden", false).contains("admin"));
        assert!(move_error_hint("not_found", false).contains("member"));
        assert!(move_error_hint("validation_error", false).contains("SemVer"));
        assert!(move_error_hint("bad_request", false).contains("SemVer"));
        assert_eq!(move_error_hint("internal_error", false), "");
        assert_eq!(move_error_hint("something_else", false), "");
    }
}
