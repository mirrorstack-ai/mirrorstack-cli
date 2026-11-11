//! `mirrorstack app module client-publish` — ship a version's client library
//! without re-cutting the release.
//!
//! 🔴 WHY THIS EXISTS. The client used to be reachable only through
//! `module deploy`, and only on the branch that uploads a fresh Go artifact.
//! A version whose artifact was ALREADY stored therefore had no way to gain
//! one, so a release that was interrupted after its artifact — the exact shape
//! of user-core v1.0.3 on 2026-09-09 — could never publish the client an app
//! needs in order to stop running a dev tunnel.
//!
//! `deploy` now ships it on the way to Deploy, which covers the whole-release
//! path. This command covers the other half: an operator who needs the client
//! alone, without rebuilding, re-attesting, or risking the immutable record.
//! It performs NO release mutation — it uploads an object and records its
//! digest — and it refuses once a version has been deployed, because that
//! version is public and its client is what consumers have already pinned.

use super::*;
use crate::api::ApiError;

#[derive(Args)]
pub(super) struct ClientPublishArgs {
    /// Module slug. Defaults to Config.Slug parsed from ./main.go
    #[arg(long)]
    module: Option<String>,
    /// Module directory containing main.go and the client project. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Version to publish the client for. Defaults to the newest
    /// Config.Versions key in ./main.go, the same key `deploy` targets.
    #[arg(long)]
    version: Option<String>,
}

pub(super) fn run(args: ClientPublishArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let meta = read_meta(&dir)?;
    let slug = args.module.clone().unwrap_or_else(|| meta.slug.clone());
    if !slug_valid(&slug) {
        return Err(slug_invalid_error(&slug));
    }
    let version = match &args.version {
        Some(explicit) => canonical_version(explicit)?,
        None => canonical_version(&code_version(&meta, &dir)?)?,
    };

    // Refuse before any credential use when there is nothing to ship: a module
    // with no client project has no business calling this, and one whose client
    // did not BUILD must not be told the upload merely "found nothing".
    let Some(output_dir) = version_client::locate(&dir)? else {
        return Err(anyhow!(
            "{slug} declares no client project, so there is no client to publish"
        ));
    };

    let creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(Duration::from_secs(15))?;
    let module = get_owned_module(&client, &apps_base, &creds.access_token, &slug)?;

    // 🔴 THE PUBLISHED BOUNDARY. A deployed version is serving, and consumers
    // pin its client by revision; replacing those bytes changes what an already
    // frozen lockfile resolves to. Unpublished versions are ours to complete.
    let state = with_spinner("Reading owner release state…", || {
        api::get_module_release_state(
            &client,
            &apps_base,
            &creds.access_token,
            &module.id,
            &version,
        )
    })
    .map_err(|error: ApiError| match error {
        ApiError::Server { status: 404, .. } => anyhow!(
            "{slug}@{version} is not recorded — publish a client only for a version the platform already holds"
        ),
        other => anyhow!("{other}"),
    })?;
    if let Some(deploy) = state.release_receipt.deploy.as_ref() {
        return Err(anyhow!(
            "{slug}@{version} is already deployed ({} / {}) — its client is public and immutable. Cut a new version instead.",
            deploy.mode,
            deploy.status
        ));
    }

    eprintln!(
        "  {} {} → {}",
        style("Publishing client:").dim(),
        style(output_dir.display()).bold(),
        style(format!("{slug}@{version}")).cyan().bold(),
    );

    match version_client::ship(
        &client,
        &apps_base,
        &creds.access_token,
        &module.id,
        &version,
        &output_dir,
    )? {
        version_client::VersionClientOutcome::Shipped {
            revision,
            size_bytes,
        } => {
            eprintln!("{} published module client ({size_bytes} bytes)", ok_mark());
            // Printed on STDOUT, alone, so it can be piped straight into a
            // consumer's mirrorstack.modules.json pin.
            println!("{revision}");
            Ok(())
        }
        version_client::VersionClientOutcome::StorageUnconfigured => Err(anyhow!(
            "this platform has no module artifact storage configured, so no client can be published"
        )),
        version_client::VersionClientOutcome::EndpointsMissing => Err(anyhow!(
            "this platform predates the version-client routes, so no client can be published"
        )),
    }
}
