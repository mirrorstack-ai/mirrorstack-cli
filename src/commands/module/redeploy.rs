//! `mirrorstack module redeploy` — re-provision a module version that is
//! ALREADY deployed, recording nothing new.
//!
//! 🔴 A MODULE LAMBDA'S ENVIRONMENT IS WRITTEN ONLY BY A DEPLOY, and this is
//! the verb for wanting just that. `modulehost.moduleEnvironment()` is reached
//! from exactly one place — `AWSProvisioner.Provision`, called by
//! `SetModuleDeploy` — so the platform re-stamps a module's injected
//! environment (its per-module credential, its dispatch URL) only when the
//! version is deployed again. The handler's own doc says it "registers (or
//! RE-registers) the prod transport for a published version", so this is a
//! supported operation rather than a trick.
//!
//! 🔴 AND AN OUT-OF-BAND `aws lambda update-function-configuration` IS NOT AN
//! ALTERNATIVE. Dispatch invokes the immutable per-module-VERSION alias, and a
//! published Lambda version's configuration is a frozen snapshot, so poking the
//! environment lands on $LATEST and is never served. Publishing a new version
//! and moving the alias is the only path — which is what a deploy does.
//!
//! Why this is not `module deploy`: that verb deploys "the version your code
//! declares", recording the version and uploading an artifact on the way. A
//! re-stamp must do neither — a recorded version can never be re-cut (the
//! platform answers 409), and a re-stamp that accidentally recorded one would
//! turn an operational fix into a release. This command takes the version
//! EXPLICITLY and only POSTs the deploy.

use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Args;
use console::style;

use crate::api::{self, ApiError, ModuleDeployMode, SetModuleDeployInput};
use crate::commands::dev::module_meta;
use crate::commands::{
    DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base, session_expired,
};
use crate::{credentials, http};

use super::rename::workspace_root;

#[derive(Args)]
pub struct RedeployArgs {
    /// Module slug. Defaults to Config.Slug parsed from ./main.go.
    #[arg(long)]
    module: Option<String>,
    /// The already-deployed version to re-provision, as the version string
    /// ("1.0.0") or its UUID. Required: a re-stamp must never guess which
    /// version is live.
    #[arg(long)]
    version: String,
    /// Module directory containing main.go, used only to default --module.
    #[arg(long)]
    dir: Option<std::path::PathBuf>,
    /// Deploy transport status. Defaults to "active" — the status a live
    /// module already has.
    #[arg(long, value_parser = ["active", "draining", "disabled"])]
    status: Option<String>,
}

pub(crate) fn run(args: RedeployArgs) -> Result<()> {
    let slug = match args.module.clone() {
        Some(slug) => slug,
        None => {
            let cwd = std::env::current_dir()?;
            let dir = match args.dir.clone() {
                Some(d) if d.is_absolute() => d,
                Some(d) => cwd.join(d),
                None => cwd,
            };
            let root = workspace_root(&dir);
            module_meta::read_module_meta(&dir, &root)
                .map_err(|e| {
                    anyhow!(
                        "couldn't read the module from {}: {e}. Pass --module <slug>, or run from the module directory.",
                        dir.display()
                    )
                })?
                .slug
        }
    };

    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(Duration::from_secs(60))?;
    let mut creds = credentials::load_or_login_hint()?;

    // GET /v1/modules/{slug} is caller-scoped, so resolving the UUID is also
    // the ownership check — the deploy endpoint collapses a mismatch to 404,
    // which would otherwise read as "no such version".
    let module = {
        let resolved = credentials::with_refresh_retry(&mut creds, |token| {
            api::get_module(&client, &apps_base, token, &slug)
        });
        match resolved {
            Ok(Some(m)) => m,
            Ok(None) => return Err(module_not_in_catalog(&slug)),
            Err(ApiError::Unauthenticated) => return Err(session_expired()),
            Err(e) => return Err(e.into()),
        }
    };

    let status = args.status.as_deref();
    let deployed = credentials::with_refresh_retry(&mut creds, |token| {
        api::set_module_deploy(
            &client,
            &apps_base,
            token,
            &module.id,
            &args.version,
            &SetModuleDeployInput {
                // Artifact mode only. A re-stamp of a deployed module is
                // production by definition; local_simulation is a different
                // operation and must be asked for by name.
                mode: ModuleDeployMode::Artifact,
                status,
            },
        )
    })
    .map_err(redeploy_error)?;

    // 🔴 PRINT WHAT IT LANDED ON, NOT "OK". The reason to run this is to move
    // a module onto a new injected environment, and the only proof that
    // happened is a NEW Lambda version behind the per-version alias. A success
    // line without these numbers cannot be told from a no-op.
    println!(
        "{} {} {} re-provisioned",
        ok_mark(),
        style(&slug).bold(),
        args.version
    );
    println!("  invoke target : {}", deployed.invoke_target);
    println!(
        "  lambda version: {}",
        deployed
            .lambda_version
            .as_deref()
            .unwrap_or("(none reported)")
    );
    println!(
        "  code sha256   : {}",
        deployed
            .lambda_code_sha256
            .as_deref()
            .unwrap_or("(none reported)")
    );
    println!("  status / mode : {} / {}", deployed.status, deployed.mode);
    Ok(())
}

fn module_not_in_catalog(slug: &str) -> anyhow::Error {
    anyhow!(
        "module '{slug}' is not in the caller's platform catalog, so there is nothing deployed to re-provision"
    )
}

/// Turn the platform's deploy refusals into the sentence that names the cause.
///
/// These are the ones a re-stamp actually hits: the artifact that the recorded
/// version points at must still be byte-identical in storage, because the
/// provisioner re-verifies its size, ETag and SHA256 before it will touch the
/// function. That check failing is the useful outcome, not an inconvenience —
/// it means the thing about to be deployed is not the thing that was released.
fn redeploy_error(err: ApiError) -> anyhow::Error {
    match err {
        ApiError::Unauthenticated => session_expired(),
        ApiError::Server { code, message, .. } => match code.as_str() {
            "module_artifact_changed" | "module_artifact_code_mismatch" => anyhow!(
                "the recorded version's artifact no longer matches what is in storage ({code}: {message}). \
                 A re-provision deploys the ORIGINAL artifact by design, so this must be investigated \
                 rather than retried."
            ),
            "module_artifact_not_ready" => anyhow!(
                "the version has no ready artifact ({message}) — it was never deployed in artifact mode, \
                 so there is nothing to re-provision"
            ),
            "not_found" => anyhow!(
                "no such version for this module ({message}). Pass --version as the version string \
                 already deployed (e.g. 1.0.0) or its UUID."
            ),
            _ => anyhow!("deploy refused ({code}): {message}"),
        },
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// 🔴 THE ONE PROPERTY THIS COMMAND EXISTS TO GUARANTEE: it records
    /// nothing. `module deploy` records a version and uploads an artifact on
    /// the way; a recorded version can never be re-cut (the platform answers
    /// 409), so a re-stamp that reached the record or upload endpoints would
    /// turn an operational fix into a failed release. This walks the source
    /// rather than the behaviour, because no unit test can observe a call that
    /// is absent — the same reason the ingress timing guard is a source test.
    #[test]
    fn redeploy_never_records_a_version_or_uploads_an_artifact() {
        let src = include_str!("redeploy.rs");
        let body = src
            .split("#[cfg(test)]")
            .next()
            .expect("source before the test module");

        for forbidden in [
            "publish_version",
            "record_module_version",
            "create_module_artifact_upload",
            "finalize_module_artifact",
            "create_module",
        ] {
            assert!(
                !body.contains(forbidden),
                "redeploy calls {forbidden} — a re-provision must not record or upload anything"
            );
        }
        // And it must reach the deploy endpoint, or the guard above would pass
        // on a command that does nothing at all.
        assert!(
            body.contains("set_module_deploy"),
            "redeploy does not call set_module_deploy — it would re-provision nothing"
        );
    }

    /// A re-stamp must never guess which version is live: `--version` is
    /// required by the parser, so the mistake is impossible rather than
    /// discouraged.
    #[test]
    fn version_is_required() {
        use clap::CommandFactory;
        let err = crate::commands::Cli::command()
            .try_get_matches_from(vec!["mirrorstack", "module", "redeploy", "--module", "x"])
            .expect_err("--version is required");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// Artifact mode is not a default anyone can drift: local_simulation is a
    /// different operation and this command does not offer it.
    #[test]
    fn mode_is_always_artifact() {
        let body = include_str!("redeploy.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("source");
        assert!(body.contains("ModuleDeployMode::Artifact"));
        assert!(
            !body.contains("LocalSimulation"),
            "redeploy offers local simulation — a production re-stamp must not"
        );
    }

    /// The refusals a re-stamp actually hits must each name their cause. An
    /// artifact that no longer matches storage is the useful outcome, not an
    /// inconvenience: it means the thing about to be deployed is not the thing
    /// that was released.
    #[test]
    fn artifact_drift_is_explained_and_not_presented_as_retryable() {
        let err = redeploy_error(ApiError::Server {
            status: 409,
            code: "module_artifact_changed".into(),
            message: "etag mismatch".into(),
        })
        .to_string();
        assert!(err.contains("no longer matches"), "{err}");
        assert!(
            err.contains("investigated"),
            "the message invites a retry instead of an investigation: {err}"
        );

        let missing = redeploy_error(ApiError::Server {
            status: 404,
            code: "not_found".into(),
            message: "no such version".into(),
        })
        .to_string();
        assert!(missing.contains("--version"), "{missing}");

        // An unmapped code still surfaces the platform's own words rather than
        // a generic failure.
        let other = redeploy_error(ApiError::Server {
            status: 400,
            code: "status_invalid".into(),
            message: "bad status".into(),
        })
        .to_string();
        assert!(
            other.contains("status_invalid") && other.contains("bad status"),
            "{other}"
        );
    }

    /// --module defaults from main.go, so the 12 re-stamps can be driven from
    /// a module directory without repeating the slug.
    #[test]
    fn module_defaults_to_the_slug_in_main_go() {
        let tmp = TempDir::new().expect("tempdir");
        fs::write(
            tmp.path().join("go.work"),
            "go 1.24\n\nuse (\n\t./user-approval\n)\n",
        )
        .expect("go.work");
        let dir = tmp.path().join("user-approval");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(
            dir.join("main.go"),
            "package main\n// Slug: \"user-approval\"\n",
        )
        .expect("main.go");

        let root = workspace_root(&dir);
        let meta = module_meta::read_module_meta(&dir, &root).expect("meta");
        assert_eq!(meta.slug, "user-approval");
    }
}
