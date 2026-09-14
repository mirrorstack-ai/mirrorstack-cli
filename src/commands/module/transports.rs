//! `mirrorstack module transports` — report what each module installed in an
//! app is ACTUALLY serving, read-only.
//!
//! 🔴 THIS IS THE READ HALF OF A RE-STAMP. `module redeploy` requires
//! `--version` on purpose: a re-provision must never guess which version is
//! live. This verb is where that version comes from, so the operator reads it
//! instead of inferring it.
//!
//! Why it is app-scoped rather than module-scoped: the live version is not a
//! module property. Transport resolution runs through the app's INSTALLED
//! version (`module_install.version_id` → `module_deploys`), so "what is
//! module X serving" is only answerable per app. The platform models it that
//! way and so does this command.
//!
//! Why not the substrate: `aws lambda list-aliases` on a module's function
//! returns one `mv-<version uuid>` alias per version EVER provisioned, so it
//! enumerates candidates and cannot name the live one.
//!
//! It is named `transports` and not for taste: migration 036 calls
//! `module_deploys` "the prod-transport registry", and the fleet guard hook
//! refuses any command text matching `mirrorstack module (deploy|move|publish)`
//! — a read-only verb carrying that prefix would trip the guard in commit
//! messages and issue bodies, not merely in use.

use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Args;
use console::style;
use serde::Serialize;

use crate::api::{self, ApiError};
use crate::commands::{
    DEFAULT_APPS_API_BASE, DEFAULT_DISPATCH_BASE, ENV_APPS_API_URL, ENV_DISPATCH_URL, resolve_base,
    session_expired,
};
use crate::{credentials, http};

#[derive(Args)]
pub struct TransportsArgs {
    /// The app whose installed modules to report, as its UUID or slug.
    #[arg(long)]
    app: String,
    /// Emit JSON instead of a table, for scripting a re-stamp run.
    #[arg(long)]
    json: bool,
}

/// One row: what this module is serving in this app.
///
/// `installed` and `serving` are DIFFERENT facts and both are printed. The app
/// pins an installed version; the transport row says which version that pin
/// resolves to. They normally agree, and when they do not, that difference is
/// the thing worth seeing.
#[derive(Debug, Serialize)]
struct Row {
    slug: String,
    module_id: String,
    /// The version this app is pinned to, from the install row.
    installed: String,
    /// The version the transport row points at — the `--version` a re-stamp
    /// takes. Empty when the module has never been deployed.
    serving: String,
    /// `active` | `draining` | `disabled` | `none`.
    status: String,
    tunnel: Option<String>,
    installs: u32,
}

pub(crate) fn run(args: TransportsArgs) -> Result<()> {
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let dispatch_base = resolve_base(ENV_DISPATCH_URL, DEFAULT_DISPATCH_BASE);
    let client = http::client(Duration::from_secs(60))?;
    let mut creds = credentials::load_or_login_hint()?;

    // Resolve the ref first: the status endpoint resolves the app's tenant
    // schema from a UUID, so a slug 404s there and would read as "no such
    // app" rather than "pass the id".
    let app = match credentials::with_refresh_retry(&mut creds, |token| {
        api::get_app(&client, &apps_base, token, &args.app)
    }) {
        Ok(Some(app)) => app,
        Ok(None) => return Err(app_not_visible(&args.app)),
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    let statuses = match credentials::with_refresh_retry(&mut creds, |token| {
        api::list_app_module_status(&client, &dispatch_base, token, &app.id)
    }) {
        Ok(Some(rows)) => rows,
        Ok(None) => return Err(app_not_visible(&args.app)),
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    // The install list carries the slug and the pinned version; the status
    // list carries what that pin is serving. Neither alone answers the
    // question, so they are joined on the module id.
    let installs = match credentials::with_refresh_retry(&mut creds, |token| {
        api::list_app_installs(&client, &apps_base, token, &app.id)
    }) {
        Ok(rows) => rows,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    let rows = join(statuses, installs);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if rows.is_empty() {
        println!(
            "{} has no installed modules, so there is nothing serving.",
            style(&app.slug).bold()
        );
        return Ok(());
    }

    print_table(&app.slug, &rows);
    Ok(())
}

/// Join the two lists on module id and order the result DETERMINISTICALLY.
///
/// 🔴 THE ORDER IS PART OF THE CONTRACT. The reason to run this is to drive a
/// sequence of re-stamps, and "re-stamp in the order it prints" is only a
/// reproducible instruction if the order cannot move between runs. Both source
/// endpoints iterate an unordered id list, so this sorts by slug — and modules
/// with no slug (installed but absent from the install list) sort under their
/// id, never interleaved by chance.
fn join(statuses: Vec<api::AppModuleStatus>, installs: Vec<api::AppInstall>) -> Vec<Row> {
    let mut rows: Vec<Row> = statuses
        .into_iter()
        .map(|s| {
            let install = installs.iter().find(|i| i.module_id == s.module_id);
            Row {
                slug: install
                    .map(|i| i.slug.clone())
                    .filter(|slug| !slug.is_empty())
                    .unwrap_or_else(|| s.module_id.clone()),
                module_id: s.module_id.clone(),
                installed: install.map(|i| i.installed_version.clone()).unwrap_or_default(),
                serving: s.serving_version,
                status: s.deploy_status,
                // A live tunnel declares its OWN version, which is not
                // what is deployed and is frequently ahead of it — that
                // difference is the reason to print it rather than just
                // "online".
                tunnel: s.tunnel_online.then(|| {
                    match (s.version.as_str(), s.local_url.as_str()) {
                        ("", "") => "online".to_string(),
                        ("", url) => url.to_string(),
                        (ver, "") => format!("online {ver}"),
                        (ver, url) => format!("{ver} @ {url}"),
                    }
                }),
                installs: s.installs,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.slug.cmp(&b.slug).then_with(|| a.module_id.cmp(&b.module_id)));
    rows
}

fn print_table(app_slug: &str, rows: &[Row]) {
    println!("{} — {} installed modules\n", style(app_slug).bold(), rows.len());
    println!(
        "  {:22} {:11} {:11} {:9} {}",
        style("MODULE").dim(),
        style("INSTALLED").dim(),
        style("SERVING").dim(),
        style("STATUS").dim(),
        style("TUNNEL").dim()
    );
    for r in rows {
        let serving = if r.serving.is_empty() {
            style("—".to_string()).dim().to_string()
        } else if r.serving == r.installed {
            r.serving.clone()
        } else {
            // A pin that resolves to a different version is not an error, but
            // it is the row an operator must look at before re-stamping.
            style(format!("{} (≠ pin)", r.serving)).yellow().to_string()
        };
        let status = match r.status.as_str() {
            "active" => style(r.status.clone()).green().to_string(),
            "none" => style(r.status.clone()).dim().to_string(),
            _ => style(r.status.clone()).yellow().to_string(),
        };
        println!(
            "  {:22} {:11} {:11} {:9} {}",
            r.slug,
            if r.installed.is_empty() { "—" } else { &r.installed },
            serving,
            status,
            r.tunnel.as_deref().unwrap_or("")
        );
    }
    println!(
        "\n  SERVING is the version a re-provision takes as --version. A module\n  \
         served by a live tunnel is routed there regardless of what is deployed."
    );
}

fn app_not_visible(app_ref: &str) -> anyhow::Error {
    anyhow!(
        "app '{app_ref}' is not visible to this account — it does not exist, or you are not a \
         member of it. The platform answers both the same way on purpose, so this cannot tell \
         you which."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(id: &str, serving: &str, deploy_status: &str) -> api::AppModuleStatus {
        api::AppModuleStatus {
            module_id: id.to_string(),
            tunnel_online: false,
            local_url: String::new(),
            version: String::new(),
            deploy_status: deploy_status.to_string(),
            serving_version: serving.to_string(),
            installs: 1,
        }
    }

    fn install(id: &str, slug: &str, installed: &str) -> api::AppInstall {
        api::AppInstall {
            module_id: id.to_string(),
            name: slug.to_string(),
            slug: slug.to_string(),
            installed_version: installed.to_string(),
            manifest: None,
            serving: String::new(),
        }
    }

    /// 🔴 THE PROPERTY THIS VERB EXISTS TO GUARANTEE: it is read-only. It sits
    /// next to `redeploy`, shares its credential handling, and names versions
    /// that are about to be re-provisioned — so a write reachable from here
    /// would provision production from a command an operator ran to LOOK.
    /// This walks the source because no unit test can observe a call that is
    /// absent, the same reason redeploy's own guard is a source test.
    #[test]
    fn transports_never_writes_anything() {
        let body = include_str!("transports.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("source before the test module");

        for forbidden in [
            "set_module_deploy",
            "record_module_version",
            "publish_version",
            "create_module_artifact_upload",
            "finalize_module_artifact",
            "create_module",
            "rename_module_slug",
            "update_install",
            "create_app_deploy",
        ] {
            assert!(
                !body.contains(forbidden),
                "transports reaches {forbidden} — a read-only report must not write, \
                 provision, record or move anything"
            );
        }
        // And it must actually read the serving state, or the guard above
        // would pass on a command that reports nothing at all.
        assert!(
            body.contains("list_app_module_status"),
            "transports does not call list_app_module_status — it would have no serving state \
             to report and the write guard above would be vacuous"
        );
    }

    /// The order is part of the contract: "re-stamp in the order it prints" is
    /// only reproducible if two runs cannot disagree. Both source endpoints
    /// iterate an unordered id list, so the join must impose the order.
    #[test]
    fn rows_are_ordered_by_slug_not_by_arrival() {
        let rows = join(
            vec![
                status("id-video", "1.0.3", "active"),
                status("id-ai", "1.0.0", "active"),
                status("id-user", "2.1.0", "active"),
            ],
            vec![
                install("id-video", "video-core", "1.0.3"),
                install("id-ai", "ai-assistant", "1.0.0"),
                install("id-user", "user-core", "2.1.0"),
            ],
        );
        let order: Vec<&str> = rows.iter().map(|r| r.slug.as_str()).collect();
        assert_eq!(order, vec!["ai-assistant", "user-core", "video-core"]);

        // Reversing the input must not change the output.
        let reversed = join(
            vec![
                status("id-user", "2.1.0", "active"),
                status("id-ai", "1.0.0", "active"),
                status("id-video", "1.0.3", "active"),
            ],
            vec![
                install("id-user", "user-core", "2.1.0"),
                install("id-ai", "ai-assistant", "1.0.0"),
                install("id-video", "video-core", "1.0.3"),
            ],
        );
        let reversed_order: Vec<&str> = reversed.iter().map(|r| r.slug.as_str()).collect();
        assert_eq!(reversed_order, order, "the join's order depends on arrival order");
    }

    /// A module in the status list but absent from the install list still has
    /// to appear — it is installed by definition, the pin just did not come
    /// back — and it must sort under its id rather than land wherever the
    /// iteration happened to put it.
    #[test]
    fn a_module_missing_from_the_install_list_still_appears_and_sorts() {
        let rows = join(
            vec![status("zz-orphan", "1.0.0", "active"), status("id-ai", "1.0.0", "active")],
            vec![install("id-ai", "ai-assistant", "1.0.0")],
        );
        assert_eq!(rows.len(), 2, "an unjoined module was dropped from the report");
        assert_eq!(rows[0].slug, "ai-assistant");
        assert_eq!(rows[1].slug, "zz-orphan", "fell back to something other than the id");
        assert_eq!(rows[1].installed, "", "invented a pin for a module with no install row");
    }

    /// `deploy_status: none` is a real, expected state — a tunnel-only module
    /// that has never been deployed — and must not be reported as a version.
    #[test]
    fn a_never_deployed_module_reports_no_serving_version() {
        let rows = join(
            vec![status("id-ai", "", "none")],
            vec![install("id-ai", "ai-assistant", "1.0.0")],
        );
        assert_eq!(rows[0].serving, "");
        assert_eq!(rows[0].status, "none");
        assert_eq!(
            rows[0].installed, "1.0.0",
            "the app's pin is a separate fact from what is serving and must survive"
        );
    }

    /// The platform collapses "no such app" and "not a member" on purpose, so
    /// the message must not claim to know which one happened.
    #[test]
    fn app_not_visible_names_both_causes_without_choosing() {
        let err = app_not_visible("twkpa-edu").to_string();
        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains("not a \nmember") || err.contains("not a member"), "{err}");
        assert!(err.contains("twkpa-edu"), "{err}");
    }

    /// --app is required: an app-scoped report that defaulted to some app
    /// would answer a question the operator did not ask.
    #[test]
    fn app_is_required() {
        use clap::CommandFactory;
        let err = crate::commands::Cli::command()
            .try_get_matches_from(vec!["mirrorstack", "module", "transports"])
            .expect_err("--app is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }
}
