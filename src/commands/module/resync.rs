//! `mirrorstack app module resync` — force the platform to re-read one
//! installed module's current manifest and re-project its facts into the
//! app, without a hand-rolled `curl` and without uninstall/reinstall.
//!
//! The platform projects a module's contribution payload into its host only
//! at install time. A dev-mounted module whose manifest gains or changes a
//! contribution keeps its host serving the old payload — through a hot
//! rebuild and even a full `mirrorstack dev --tunnel` restart — until
//! something forces a re-read. This is that something.

use std::time::Duration;

use anyhow::{Result, anyhow};
use console::style;

use crate::api::{self, ApiError};
use crate::credentials;
use crate::http;

use super::version_move::find_install;
use super::with_spinner;
use crate::commands::{
    DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base, session_expired,
};

use clap::Args;

/// Resync re-reads a manifest rather than touching code or a deploy, so it
/// should answer quickly; this only bounds a wedged platform call rather than
/// a legitimately slow operation like `move`'s migrations.
const RESYNC_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Args)]
pub struct ResyncArgs {
    /// App the module is installed in (id or slug).
    #[arg(long)]
    app: String,
    /// Installed module to resync — its slug, or its platform UUID when two
    /// installed modules share a slug.
    #[arg(long)]
    module: String,
}

pub(super) fn run(args: ResyncArgs) -> Result<()> {
    let mut creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(RESYNC_TIMEOUT)?;

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

    let result = with_spinner("Resyncing…", || {
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::resync_app_module(&client, &apps_base, tok, &app.id, &install.module_id)
        })
    });

    match result {
        Ok(()) => {
            eprintln!(
                "{} resynced {} in {} — the platform re-read its manifest and re-projected its facts",
                ok_mark(),
                style(&install.slug).cyan().bold(),
                style(&app.slug).cyan()
            );
            Ok(())
        }
        Err(ApiError::Server { code, message, .. }) => Err(anyhow!(
            "resync of {} in {} failed — {code}: {message}{hint}",
            install.slug,
            app.slug,
            hint = resync_error_hint(&code)
        )),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(anyhow!(
            "resync of {} in {} failed — {e}. The manifest change has NOT reached the host; it is still serving whatever it projected last.",
            install.slug,
            app.slug
        )),
    }
}

/// Hints for the codes `POST /v1/apps/{ref}/modules/{id}/resync` returns,
/// appended after the platform's own `message`.
fn resync_error_hint(code: &str) -> &'static str {
    match code {
        "not_found" => " (no such app, the module isn't installed in it, or you are not a member)",
        "forbidden" => " (resyncing an install needs the app owner or an admin)",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resync_error_hint_for_known_codes() {
        assert!(resync_error_hint("not_found").contains("member"));
        assert!(resync_error_hint("forbidden").contains("admin"));
        assert_eq!(resync_error_hint("internal_error"), "");
        assert_eq!(resync_error_hint("something_else"), "");
    }
}
