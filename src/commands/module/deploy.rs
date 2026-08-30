//! `mirrorstack app module deploy` — record a version and ship it.
//!
//! Split out of a 1468-line mod.rs so the command surface (the Args structs
//! and the run() dispatcher) is readable without scrolling past every verb's
//! implementation.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::commands::release_candidate::{
    self, CandidateRequest, ReleaseCandidate, ReleaseCandidateReceipt,
};

const MAX_VERSION_CREATE_BYTES: usize = 2 * 1024 * 1024;

pub(super) fn run(args: DeployArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    // The version always comes from code, so main.go is read even when
    // --module overrides the slug.
    let meta = read_meta(&dir)?;
    let slug = args.module.clone().unwrap_or_else(|| meta.slug.clone());
    if !slug_valid(&slug) {
        return Err(slug_invalid_error(&slug));
    }

    let raw = code_version(&meta, &dir)?;
    // `-dev` marks local iteration (scaffold convention). Interactively we
    // offer to promote (rename the Versions key, dropping the tag); with
    // --yes the caller must rename it in code first.
    let (target_raw, promote_from) = match promotion_target(&raw, args.yes)? {
        Some(promoted) => (promoted.to_string(), Some(raw.clone())),
        None => (raw.clone(), None),
    };
    let version = canonical_version(&target_raw)?;

    // Promotion changes a canonical release input. It is therefore a
    // preparation-only command: update source and exit before credentials,
    // ownership reads, candidate builds, or any remote mutation. The rerun
    // snapshots and attests the final version key from scratch.
    if let Some(from) = &promote_from {
        eprintln!();
        eprintln!("  {} {}", style("Module:").dim(), style(&slug).bold());
        eprintln!(
            "  {} {}",
            style("Version:").dim(),
            style(&version).cyan().bold()
        );
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Promote {from} → {target_raw} in main.go, then exit so the final source can be rebuilt?"
            ))
            .default(true)
            .interact()?;
        if !confirmed {
            eprintln!("{}", style("aborted.").yellow());
            return Ok(());
        }
        module_meta::promote_version(&dir, from, &target_raw)?;
        eprintln!(
            "{} promoted {} → {} in main.go",
            ok_mark(),
            style(from).dim(),
            style(&target_raw).bold()
        );
        eprintln!(
            "  rerun `mirrorstack app module deploy{yes}` to build and attest the final release candidate",
            yes = if args.yes { " --yes" } else { "" }
        );
        return Ok(());
    }

    let creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(Duration::from_secs(15))?;
    let module = get_owned_module(&client, &apps_base, &creds.access_token, &slug)?;

    let candidate = with_spinner("Preparing attested release candidate…", || {
        release_candidate::build(CandidateRequest {
            module_dir: &dir,
            slug: &slug,
            module_id: &module.id,
            version: &version,
            source_version_key: &raw,
        })
    })?;
    let zip_path = candidate.artifact_path();
    let artifact_size = candidate.receipt().artifact.size_bytes;

    eprintln!(
        "  {} {} → {} (arm64 bundle, {})",
        style("Deploying:").dim(),
        style(dir.display()).bold(),
        style(format!("{slug}@{version}")).cyan().bold(),
        artifact::human_bytes(artifact_size)
    );

    let recorded_state = ensure_version_recorded(
        &client,
        &apps_base,
        &creds.access_token,
        &module,
        &slug,
        &version,
        &candidate,
    )?;

    // The candidate owns the temporary archive until this function returns,
    // so the exact bytes attested on version-create remain available for the
    // upload. Only an explicit create-upload storage-unconfigured response may
    // select the server-gated local simulator; missing legacy routes and every
    // later artifact failure remain fatal.
    candidate.verify_artifact()?;
    let shipped = artifact::ship_artifact(
        &client,
        &apps_base,
        &creds.access_token,
        &module.id,
        &version,
        zip_path,
        candidate.receipt(),
        &recorded_state.version.id,
    )?;
    let deploy_mode = match shipped {
        artifact::ShipOutcome::Shipped => {
            eprintln!(
                "{} uploaded {} ({})",
                ok_mark(),
                style(format!("{slug}@{version}")).cyan().bold(),
                artifact::human_bytes(artifact_size)
            );
            api::ModuleDeployMode::Artifact
        }
        artifact::ShipOutcome::StorageUnconfigured => {
            eprintln!(
                "{} artifact storage is explicitly unconfigured for {}; requesting the server-gated local simulator only.",
                warn_prefix(),
                style(format!("{slug}@{version}")).cyan().bold(),
            );
            api::ModuleDeployMode::LocalSimulation
        }
    };

    let result = with_spinner("Deploying…", || {
        api::set_module_deploy(
            &client,
            &apps_base,
            &creds.access_token,
            &module.id,
            &version,
            &SetModuleDeployInput {
                mode: deploy_mode,
                status: args.status.as_deref(),
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

    verify_deploy_response(
        &deploy,
        &recorded_state.version.id,
        &module.id,
        &slug,
        &version,
        candidate.receipt(),
        deploy_mode,
        args.status.as_deref().unwrap_or("active"),
    )?;
    let final_state = read_existing_release_state(
        &client,
        &apps_base,
        &creds.access_token,
        &module.id,
        &version,
    )?
    .ok_or_else(|| {
        anyhow!(
            "deployed {slug}@{version}, but its owner release state disappeared on final reread"
        )
    })?;
    verify_final_release_state(
        &final_state,
        &module.id,
        &slug,
        &version,
        candidate.receipt(),
        deploy_mode,
        &deploy,
    )?;

    eprintln!(
        "{} deployed {}",
        ok_mark(),
        style(format!("{slug}@{version}")).cyan().bold()
    );
    eprintln!("  {} {}", style("target:").dim(), deploy.invoke_target);
    eprintln!("  {} {}", style("status:").dim(), deploy.status);
    Ok(())
}

fn promotion_target(raw: &str, non_interactive: bool) -> Result<Option<&str>> {
    let Some(promoted) = raw.strip_suffix("-dev") else {
        return Ok(None);
    };
    if non_interactive {
        return Err(anyhow!(
            "Config version '{raw}' is a -dev prerelease. Rename the Versions key in main.go (e.g. \"{promoted}\") before deploying with --yes."
        ));
    }
    Ok(Some(promoted))
}

/// Make sure `version` exists as a recorded module_versions row before the
/// deploy row is written. Recording is just that — an immutable snapshot +
/// changelog with no visibility semantics ("publish" is the future
/// marketplace listing act, not a prerequisite to run).
///
/// The record attempt is 409-tolerant so no pre-flight existence check is
/// needed and concurrent deploys can't race. A `version_exists` response is
/// success only after an owner-state reread proves the immutable stored
/// source, exact manifest bytes, web descriptor, and expected artifact tuple
/// equal this local candidate. A legacy or merely same-artifact row fails
/// closed before artifact/deploy mutation.
#[allow(clippy::too_many_arguments)]
fn ensure_version_recorded(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    module: &api::Module,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidate,
) -> Result<api::ModuleReleaseState> {
    let dir = candidate.source_module_dir();
    let entry = match changelog::lint(&dir, version) {
        Ok(entry) => entry,
        Err(lint_err) => {
            if let Some(state) =
                read_existing_release_state(client, apps_base, access_token, &module.id, version)?
            {
                let state = ensure_candidate_web_capture(
                    client,
                    apps_base,
                    access_token,
                    &module.id,
                    slug,
                    version,
                    candidate.receipt(),
                    Some(state),
                )?;
                print_already_recorded(slug, version);
                return Ok(state);
            }
            return Err(lint_err);
        }
    };

    // README files are the module's long-form description — optional and
    // free-form (no lint). `README.md` is the `default`; `README.<tag>.md`
    // adds a locale translation. They're frozen on the version row alongside
    // the changelog, so they're read here on the fresh-record path only; an
    // empty map (no README files) is omitted from the request.
    let readme = readme::read(&dir)?;
    candidate
        .verify_live_source()
        .context("release candidate: live source changed before immutable version recording")?;
    let release_candidate = serde_json::to_value(candidate.receipt())
        .context("release candidate: encode immutable version-create receipt")?;
    let input = RecordModuleVersionInput {
        version,
        changelog: &entry.map,
        readme: &readme.map,
        // Candidate web evidence lives inside the immutable receipt; the
        // request type cannot represent a duplicate legacy tuple.
        declaration: api::ModuleVersionDeclaration::ReleaseCandidate {
            release_candidate: &release_candidate,
        },
    };
    guard_version_create_size(&input)?;

    let result = with_spinner("Recording version…", || {
        api::record_module_version(client, apps_base, access_token, &module.id, &input)
    });

    let (initial_state, created_id) = match result {
        Ok(recorded) => {
            verify_recorded_version_response(
                &recorded,
                &module.id,
                slug,
                version,
                candidate.receipt(),
            )?;
            // Warnings describe the changelog/readme just frozen; on the
            // already-recorded path they'd be noise about files the platform
            // no longer reads.
            for w in &entry.warnings {
                eprintln!("{} {w}", warn_prefix());
            }
            if readme.truncated {
                eprintln!(
                    "{} a README file exceeded {} bytes and was truncated for the version record",
                    warn_prefix(),
                    readme::MAX_README_BYTES
                );
            }
            eprintln!(
                "{} recorded {}",
                ok_mark(),
                style(format!("{slug}@{version}")).cyan().bold()
            );
            eprintln!("  {} {}", style("id:").dim(), recorded.id);
            // `default` (CHANGELOG.md) is always present after a clean lint.
            for line in changelog_preview(&entry.map["default"], 3) {
                eprintln!("  {} {line}", style("│").dim());
            }
            (None, Some(recorded.id))
        }
        Err(ApiError::Server { code, .. }) if code == "version_exists" => {
            let state = verify_version_exists_candidate(
                client,
                apps_base,
                access_token,
                &module.id,
                slug,
                version,
                candidate.receipt(),
            )?;
            print_already_recorded(slug, version);
            (Some(state), None)
        }
        Err(ApiError::Server { code, message, .. }) => {
            return Err(anyhow!(
                "{code}: {message}{hint}",
                hint = record_error_hint(&code)
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    let state = ensure_candidate_web_capture(
        client,
        apps_base,
        access_token,
        &module.id,
        slug,
        version,
        candidate.receipt(),
        initial_state,
    )?;
    if created_id
        .as_deref()
        .is_some_and(|id| id != state.version.id)
    {
        return Err(anyhow!(
            "recorded {slug}@{version}, but its owner release-state id did not match the version-create response; no artifact or deploy write was attempted"
        ));
    }
    Ok(state)
}

fn verify_recorded_version_response(
    recorded: &api::ModuleVersion,
    module_id: &str,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
) -> Result<()> {
    let mismatch = || {
        anyhow!(
            "version create returned an identity/web receipt that does not match the immutable {slug}@{version} candidate; no artifact or deploy write was attempted"
        )
    };
    if recorded.id.is_empty() || recorded.module_id != module_id || recorded.version != version {
        return Err(mismatch());
    }
    match candidate.web.as_ref() {
        Some(web)
            if recorded.web_bundle_sha256 == web.sha256
                && recorded.web_bundle_size_bytes == web.size_bytes => {}
        None if recorded.web_bundle_sha256.is_empty()
            && recorded.web_bundle_size_bytes == 0
            && recorded.web_bundle_url.is_empty() => {}
        _ => return Err(mismatch()),
    }
    Ok(())
}

fn verify_version_exists_candidate(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
) -> Result<api::ModuleReleaseState> {
    let state = read_existing_release_state(
        client,
        apps_base,
        access_token,
        module_id,
        version,
    )?
    .ok_or_else(|| {
        anyhow!(
            "version_exists: the platform reported {slug}@{version} already exists, but its owner release state could not be reread; no artifact or deploy write was attempted"
        )
    })?;
    verify_existing_release_candidate(&state, module_id, slug, version, candidate)?;
    Ok(state)
}

#[allow(clippy::too_many_arguments)]
fn ensure_candidate_web_capture(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
    initial_state: Option<api::ModuleReleaseState>,
) -> Result<api::ModuleReleaseState> {
    let mut state = match initial_state {
        Some(state) => state,
        None => read_existing_release_state(client, apps_base, access_token, module_id, version)?
            .ok_or_else(|| {
                anyhow!(
                    "recorded {slug}@{version}, but its owner release state could not be reread; no artifact or deploy write was attempted"
                )
            })?,
    };
    verify_existing_release_candidate(&state, module_id, slug, version, candidate)?;

    let Some(local_web) = candidate.web.as_ref() else {
        // The exact comparator already proved the stored receipt also has no
        // web tuple. Backend-only versions never call the capture endpoint.
        return Ok(state);
    };
    let stored_web = state
        .release_receipt
        .web
        .as_ref()
        .expect("exact candidate comparison proved web evidence");

    // Capture is deliberately unconditional for web candidates. Its
    // nonempty-URL branch is an idempotent VerifyPinned operation, so this
    // proves the destination still contains the exact frozen bytes before an
    // artifact upload begins instead of deferring corruption detection to
    // deploy time.
    let capture = with_spinner("Verifying pinned web bundle…", || {
        api::capture_module_version_bundle(client, apps_base, access_token, module_id, version)
    });
    let capture = match capture {
        Ok(capture) => capture,
        Err(ApiError::Server { code, message, .. }) => {
            return Err(anyhow!("{code}: {message}"));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(error) => return Err(error.into()),
    };
    if !release_candidate::module_ids_equal(&capture.module_id, module_id)
        || capture.version_id != state.version.id
        || capture.version != version
        || capture.web_bundle_sha256 != local_web.sha256
        || capture.web_bundle_size_bytes != local_web.size_bytes
        || capture.web_bundle_url.is_empty()
        || (!stored_web.url.is_empty() && capture.web_bundle_url != stored_web.url)
    {
        return Err(anyhow!(
            "web bundle capture returned a descriptor that does not match the immutable {slug}@{version} candidate; no artifact or deploy write was attempted"
        ));
    }

    // Never trust the mutation response as the postcondition. The owner state
    // is the durable source of truth and must expose the same pinned URL and
    // exact descriptor before artifact upload begins.
    state = read_existing_release_state(client, apps_base, access_token, module_id, version)?
        .ok_or_else(|| {
            anyhow!(
                "captured {slug}@{version} web bundle, but its owner release state disappeared on reread"
            )
        })?;
    verify_existing_release_candidate(&state, module_id, slug, version, candidate)?;
    let captured_web = state
        .release_receipt
        .web
        .as_ref()
        .expect("exact candidate comparison proved web evidence");
    if captured_web.url.is_empty() || captured_web.url != capture.web_bundle_url {
        return Err(anyhow!(
            "web bundle capture for {slug}@{version} did not persist its pinned URL; no artifact or deploy write was attempted"
        ));
    }
    Ok(state)
}

fn guard_version_create_size(input: &RecordModuleVersionInput<'_>) -> Result<()> {
    let size = serde_json::to_vec(input)
        .context("release candidate: encode bounded version-create request")?
        .len();
    if size > MAX_VERSION_CREATE_BYTES {
        return Err(anyhow!(
            "release candidate: version-create request is {size} bytes (cap: {MAX_VERSION_CREATE_BYTES}); trim changelog/README locale content"
        ));
    }
    Ok(())
}

/// Read an existing immutable row without turning the owner-hidden 404 into
/// success. Callers decide whether absence means the original local lint
/// error or a contradictory `version_exists` race.
fn read_existing_release_state(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version: &str,
) -> Result<Option<api::ModuleReleaseState>> {
    let state = with_spinner("Checking recorded version receipt…", || {
        api::get_module_release_state(client, apps_base, access_token, module_id, version)
    });
    match state {
        Ok(state) => Ok(Some(state)),
        Err(ApiError::Server {
            status: 404, code, ..
        }) if code == "not_found" => Ok(None),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

fn verify_existing_release_candidate(
    state: &api::ModuleReleaseState,
    module_id: &str,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
) -> Result<()> {
    let mismatch = |field: &str| {
        anyhow!(
            "existing {slug}@{version} is immutable and its {field} does not match this attested release candidate; bump the Versions key in main.go before deploying different bytes"
        )
    };

    if candidate.protocol != release_candidate::CANDIDATE_PROTOCOL {
        return Err(mismatch("candidate protocol"));
    }
    if !release_candidate::module_ids_equal(&candidate.module_id, module_id)
        || candidate.slug != slug
        || candidate.version != version
    {
        return Err(mismatch("local identity"));
    }
    if !release_candidate::module_ids_equal(&state.version.module_id, module_id)
        || state.version.version != version
    {
        return Err(mismatch("stored identity"));
    }
    if state.version.yanked_at.is_some() {
        return Err(mismatch("yanked state"));
    }

    let receipt = &state.release_receipt;
    if receipt.state != "bound"
        || receipt.protocol.as_deref() != Some(candidate.protocol.as_str())
        || receipt.source_sha256.as_deref() != Some(candidate.source_sha256.as_str())
        || !receipt.coherent
    {
        return Err(mismatch("bound source receipt"));
    }

    let candidate_manifest = decode_manifest_evidence(
        &candidate.manifest.sha256,
        &candidate.manifest.base64,
        "local manifest",
    )?;
    let manifest_id = candidate_manifest
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| mismatch("manifest module id"))?;
    let manifest_slug = candidate_manifest
        .get("slug")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| mismatch("manifest slug"))?;
    if !release_candidate::module_ids_equal(manifest_id, module_id) || manifest_slug != slug {
        return Err(mismatch("manifest identity"));
    }

    let stored_manifest = receipt
        .manifest
        .as_ref()
        .ok_or_else(|| mismatch("stored exact manifest receipt"))?;
    if stored_manifest.sha256 != candidate.manifest.sha256
        || stored_manifest.base64 != candidate.manifest.base64
    {
        return Err(mismatch("exact manifest bytes"));
    }
    let stored_manifest_value = decode_manifest_evidence(
        &stored_manifest.sha256,
        &stored_manifest.base64,
        "stored manifest",
    )?;
    if stored_manifest_value != candidate_manifest || state.version.manifest != candidate_manifest {
        return Err(mismatch("semantic manifest"));
    }

    match (&candidate.web, &receipt.web) {
        (None, None) => {}
        (Some(local), Some(stored))
            if local.sha256 == stored.sha256 && local.size_bytes == stored.size_bytes => {}
        _ => return Err(mismatch("web bundle receipt")),
    }

    let artifact = receipt
        .artifact
        .as_ref()
        .ok_or_else(|| mismatch("expected artifact receipt"))?;
    if !matches!(artifact.status.as_str(), "missing" | "pending" | "ready")
        || artifact.source_sha256.as_deref() != Some(candidate.source_sha256.as_str())
        || artifact.manifest_sha256.as_deref() != Some(candidate.manifest.sha256.as_str())
        || artifact.sha256 != candidate.artifact.sha256
        || artifact.size_bytes != candidate.artifact.size_bytes
        || artifact.os != candidate.artifact.os
        || artifact.arch != candidate.artifact.arch
        || artifact.format != candidate.artifact.format
    {
        return Err(mismatch("artifact receipt"));
    }
    Ok(())
}

/// Prove that one operational mutation was bound to the same immutable
/// candidate as version creation. The operation receipt is deliberately
/// redacted (no exact manifest bytes or web session), so callers must still
/// perform the final owner-state reread before declaring deployment success.
pub(super) fn verify_operation_release_receipt(
    receipt: &api::ModuleOperationReleaseReceipt,
    candidate: &ReleaseCandidateReceipt,
    slug: &str,
    version: &str,
    operation: &str,
) -> Result<()> {
    let mismatch = |field: &str| {
        anyhow!(
            "{operation} returned a {field} that does not match the immutable {slug}@{version} release candidate"
        )
    };
    if receipt.protocol != candidate.protocol
        || receipt.protocol != release_candidate::CANDIDATE_PROTOCOL
    {
        return Err(mismatch("candidate protocol"));
    }
    if receipt.source_sha256 != candidate.source_sha256
        || receipt.manifest_sha256 != candidate.manifest.sha256
    {
        return Err(mismatch("source/manifest receipt"));
    }

    let artifact_size = u64::try_from(receipt.artifact.size_bytes)
        .map_err(|_| mismatch("artifact size receipt"))?;
    if receipt.artifact.sha256 != candidate.artifact.sha256
        || artifact_size != candidate.artifact.size_bytes
        || receipt.artifact.os != candidate.artifact.os
        || receipt.artifact.arch != candidate.artifact.arch
        || receipt.artifact.format != candidate.artifact.format
    {
        return Err(mismatch("artifact receipt"));
    }

    match (&receipt.web, &candidate.web) {
        (None, None) => {}
        (Some(stored), Some(local))
            if stored.sha256 == local.sha256
                && u64::try_from(stored.size_bytes).ok() == Some(local.size_bytes) => {}
        _ => return Err(mismatch("web bundle receipt")),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_deploy_response(
    deploy: &api::ModuleDeploy,
    version_id: &str,
    module_id: &str,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
    mode: api::ModuleDeployMode,
    expected_status: &str,
) -> Result<()> {
    let mismatch = |field: &str| {
        anyhow!(
            "deploy returned a {field} that does not match the immutable {slug}@{version} release candidate"
        )
    };
    if deploy.version_id != version_id || deploy.module_id != module_id {
        return Err(mismatch("version identity"));
    }
    if deploy.mode != mode.as_str()
        || deploy.source_sha256 != candidate.source_sha256
        || deploy.manifest_sha256 != candidate.manifest.sha256
    {
        return Err(mismatch("deploy mode/source/manifest receipt"));
    }
    if deploy.status != expected_status
        || !matches!(deploy.status.as_str(), "active" | "draining" | "disabled")
        || deploy.invoke_target.is_empty()
        || deploy.created_at.is_empty()
        || deploy.updated_at.is_empty()
    {
        return Err(mismatch("operational state"));
    }
    verify_operation_release_receipt(&deploy.release_receipt, candidate, slug, version, "deploy")?;

    match mode {
        api::ModuleDeployMode::Artifact => {
            if deploy.artifact_sha256.as_deref() != Some(candidate.artifact.sha256.as_str())
                || deploy.lambda_version.as_deref().is_none_or(str::is_empty)
                || deploy.lambda_code_sha256.as_deref() != Some(candidate.artifact.sha256.as_str())
            {
                return Err(mismatch("artifact/Lambda evidence"));
            }
        }
        api::ModuleDeployMode::LocalSimulation => {
            if deploy.artifact_sha256.is_some()
                || deploy.lambda_version.is_some()
                || deploy.lambda_code_sha256.is_some()
            {
                return Err(mismatch("local-simulation evidence"));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_final_release_state(
    state: &api::ModuleReleaseState,
    module_id: &str,
    slug: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
    mode: api::ModuleDeployMode,
    response: &api::ModuleDeploy,
) -> Result<()> {
    verify_existing_release_candidate(state, module_id, slug, version, candidate)?;
    let mismatch = |field: &str| {
        anyhow!(
            "final owner state for {slug}@{version} has {field} that does not match the completed deploy"
        )
    };
    if !state.release_receipt.ready {
        return Err(mismatch("ready=false"));
    }
    if candidate.web.is_some()
        && state
            .release_receipt
            .web
            .as_ref()
            .is_none_or(|web| web.url.is_empty())
    {
        return Err(mismatch("no pinned web URL"));
    }
    let artifact = state
        .release_receipt
        .artifact
        .as_ref()
        .expect("exact candidate comparison proved expected artifact receipt");
    let deploy = state
        .release_receipt
        .deploy
        .as_ref()
        .ok_or_else(|| mismatch("no deploy receipt"))?;
    if deploy.mode != mode.as_str()
        || deploy.status != response.status
        || deploy.source_sha256.as_deref() != Some(candidate.source_sha256.as_str())
        || deploy.manifest_sha256.as_deref() != Some(candidate.manifest.sha256.as_str())
        || deploy.created_at.as_deref() != Some(response.created_at.as_str())
        || deploy.updated_at.as_deref() != Some(response.updated_at.as_str())
    {
        return Err(mismatch("a different deploy receipt"));
    }

    match mode {
        api::ModuleDeployMode::Artifact => {
            if artifact.status != "ready"
                || deploy.artifact_sha256.as_deref() != Some(candidate.artifact.sha256.as_str())
                || deploy.lambda_version != response.lambda_version
                || deploy.lambda_code_sha256 != response.lambda_code_sha256
            {
                return Err(mismatch("incoherent artifact/Lambda evidence"));
            }
        }
        api::ModuleDeployMode::LocalSimulation => {
            if deploy.artifact_sha256.is_some()
                || deploy.lambda_version.is_some()
                || deploy.lambda_code_sha256.is_some()
            {
                return Err(mismatch("incoherent local-simulation evidence"));
            }
        }
    }
    Ok(())
}

fn decode_manifest_evidence(sha256: &str, encoded: &str, label: &str) -> Result<serde_json::Value> {
    let bytes = STANDARD
        .decode(encoded)
        .with_context(|| format!("existing release: decode {label} base64"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(anyhow!(
            "existing release: {label} is not canonical standard padded base64"
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = format!("{:x}", hasher.finalize());
    if actual != sha256 {
        return Err(anyhow!(
            "existing release: {label} hash mismatch (declared {sha256}, actual {actual})"
        ));
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("existing release: parse exact {label} JSON"))
}

fn print_already_recorded(slug: &str, version: &str) {
    eprintln!(
        "{} {} is already recorded — its changelog is frozen. Bump the Versions key in main.go to ship a new entry.",
        ok_mark(),
        style(format!("{slug}@{version}")).cyan()
    );
}

/// First `max_lines` non-empty changelog lines for the record summary,
/// with a trailing ellipsis when the section continues.
pub(super) fn changelog_preview(body: &str, max_lines: usize) -> Vec<String> {
    let mut nonempty = body.lines().filter(|l| !l.trim().is_empty());
    let mut out: Vec<String> = nonempty
        .by_ref()
        .take(max_lines)
        .map(|l| l.trim().to_string())
        .collect();
    if nonempty.next().is_some() {
        out.push("…".to_string());
    }
    out
}

/// Hints for the record step. `version_exists` never reaches here — deploy
/// treats it as "already recorded" and proceeds.
pub(super) fn record_error_hint(code: &str) -> &'static str {
    match code {
        "version_invalid" => " (versions must be canonical SemVer, e.g. 1.2.0 or 1.2.0-beta.1)",
        "changelog_too_large" => " (trim this version's CHANGELOG.md section to 16KB)",
        "readme_too_large" => " (trim README.md to 64KB)",
        _ => "",
    }
}

pub(super) fn deploy_error_hint(code: &str) -> &'static str {
    match code {
        // Three routes collapse onto this one code, and api-platform#440
        // gives each its own message ("module not found", "version not found
        // for this module", "artifact upload not found"), so the hint must
        // not name a cause the message hasn't. It only carries the remedy,
        // which is the same for all three except when the module itself is
        // the missing record.
        "not_found" => {
            " (the message says which record the platform couldn't find — re-run `mirrorstack app module deploy` to re-create the version record and its upload; if the module is what's missing, `mirrorstack app module register` it first)"
        }
        // The platform derives invoke_target from the module's own slug and
        // only sanity-checks that derivation — this can't be triggered by
        // anything the CLI sends, but the code is still surfaced if the
        // platform ever rejects a slug shape.
        "invoke_target_invalid" => {
            " (the platform couldn't derive a valid deploy target from this module's slug — this is a platform-side issue, not something to fix locally)"
        }
        "status_invalid" => " (--status must be one of: active, draining, disabled)",
        "artifact_missing" => {
            " (the upload didn't land in object storage — re-run `mirrorstack module deploy`)"
        }
        // The platform's finalize check is a non-empty object under its size
        // ceiling whose first four bytes are the ZIP local-file magic — it
        // does NOT open the archive, so don't claim it verified a `bootstrap`
        // entry. (The CLI is what guarantees the executable root entry, in
        // `artifact::zip_bootstrap`.)
        "artifact_invalid" => {
            " (the platform rejected the uploaded object — it must be a non-empty ZIP under 250.0 MB)"
        }
        // Not reachable from the deploy call itself: the deploy gate is
        // conditional on the platform having an artifact store, and the
        // upload step already downgrades this code to a warning. Kept so the
        // code never surfaces bare if another leg starts returning it.
        "artifact_storage_unconfigured" => {
            " (only create-time storage-unconfigured from the platform can select the server-gated local simulator; any later occurrence leaves the artifact unproved and fails closed)"
        }
        // 409 from finalize only. A second `module deploy` of this same
        // version presigned a fresh upload while this one was verifying, so
        // the platform refuses to certify a readiness verdict for bytes that
        // are no longer the ones behind the key.
        "artifact_superseded" => {
            " (another deploy of this version started a new upload — let that one finish, or re-run `mirrorstack module deploy` to upload and finalize again)"
        }
        // What `httputil.Conflict` emits when a deploy is attempted for a
        // version whose artifact never finalized.
        "conflict" => {
            " (the artifact for this version isn't finalized — re-run `mirrorstack module deploy` so the upload completes before the deploy)"
        }
        // The platform's catch-all 500. Nothing local produced it — a presign
        // failure or a database error behind the artifact row would both land
        // here — so rebuilding and re-uploading changes nothing.
        "internal_error" => {
            " (the platform failed on its side — retry; if it persists it is a platform issue, not something to fix locally)"
        }
        _ => "",
    }
}

#[cfg(test)]
mod release_preparation_tests {
    use super::*;

    use std::io::{Read, Write};
    use std::net::TcpListener;

    const MODULE_ID: &str = "11111111-1111-1111-1111-111111111111";
    const SDK_MODULE_ID: &str = "m11111111111111111111111111111111";
    const SLUG: &str = "media";
    const VERSION: &str = "1.2.3";

    fn manifest_evidence(manifest: &serde_json::Value) -> release_candidate::ManifestEvidence {
        let mut bytes = serde_json::to_vec(manifest).unwrap();
        bytes.push(b'\n');
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        release_candidate::ManifestEvidence {
            sha256: format!("{:x}", hasher.finalize()),
            base64: STANDARD.encode(bytes),
        }
    }

    fn candidate() -> ReleaseCandidateReceipt {
        let manifest = serde_json::json!({
            "id": SDK_MODULE_ID,
            "slug": SLUG,
            "versions": {"v1.2.3": {"app": "0001"}}
        });
        ReleaseCandidateReceipt {
            protocol: release_candidate::CANDIDATE_PROTOCOL.to_string(),
            module_id: MODULE_ID.to_string(),
            slug: SLUG.to_string(),
            version: VERSION.to_string(),
            source_sha256: "a".repeat(64),
            manifest: manifest_evidence(&manifest),
            web: Some(release_candidate::WebEvidence {
                session_id: "session-one".to_string(),
                sha256: "b".repeat(64),
                size_bytes: 422,
            }),
            artifact: release_candidate::ArtifactEvidence {
                sha256: "c".repeat(64),
                size_bytes: 2048,
                os: "linux".to_string(),
                arch: "arm64".to_string(),
                format: "lambda-bootstrap-zip".to_string(),
            },
        }
    }

    fn matching_state(candidate: &ReleaseCandidateReceipt) -> api::ModuleReleaseState {
        let manifest = decode_manifest_evidence(
            &candidate.manifest.sha256,
            &candidate.manifest.base64,
            "test manifest",
        )
        .unwrap();
        api::ModuleReleaseState {
            version: api::ModuleReleaseStateVersion {
                id: "version-id".to_string(),
                module_id: MODULE_ID.to_string(),
                version: VERSION.to_string(),
                manifest,
                yanked_at: None,
            },
            release_receipt: api::ModuleReleaseReceipt {
                state: "bound".to_string(),
                protocol: Some(candidate.protocol.clone()),
                source_sha256: Some(candidate.source_sha256.clone()),
                manifest: Some(api::ModuleReleaseManifestEvidence {
                    sha256: candidate.manifest.sha256.clone(),
                    base64: candidate.manifest.base64.clone(),
                }),
                web: candidate
                    .web
                    .as_ref()
                    .map(|web| api::ModuleReleaseWebEvidence {
                        sha256: web.sha256.clone(),
                        size_bytes: web.size_bytes,
                        url: "https://cdn.example.test/media/index.js".to_string(),
                    }),
                artifact: Some(api::ModuleReleaseArtifactEvidence {
                    status: "missing".to_string(),
                    source_sha256: Some(candidate.source_sha256.clone()),
                    manifest_sha256: Some(candidate.manifest.sha256.clone()),
                    sha256: candidate.artifact.sha256.clone(),
                    size_bytes: candidate.artifact.size_bytes,
                    os: candidate.artifact.os.clone(),
                    arch: candidate.artifact.arch.clone(),
                    format: candidate.artifact.format.clone(),
                    created_at: None,
                    updated_at: None,
                    finalized_at: None,
                }),
                deploy: None,
                coherent: true,
                ready: false,
            },
        }
    }

    fn matching_state_json_with_url(
        candidate: &ReleaseCandidateReceipt,
        web_url: &str,
    ) -> serde_json::Value {
        let manifest = decode_manifest_evidence(
            &candidate.manifest.sha256,
            &candidate.manifest.base64,
            "test manifest",
        )
        .unwrap();
        serde_json::json!({
            "version": {
                "id": "version-id",
                "module_id": MODULE_ID,
                "version": VERSION,
                "manifest": manifest,
                "yanked_at": null
            },
            "release_receipt": {
                "state": "bound",
                "protocol": candidate.protocol,
                "source_sha256": candidate.source_sha256,
                "manifest": candidate.manifest,
                "web": candidate.web.as_ref().map(|web| serde_json::json!({
                    "sha256": web.sha256,
                    "size_bytes": web.size_bytes,
                    "url": web_url
                })),
                "artifact": {
                    "status": "missing",
                    "source_sha256": candidate.source_sha256,
                    "manifest_sha256": candidate.manifest.sha256,
                    "sha256": candidate.artifact.sha256,
                    "size_bytes": candidate.artifact.size_bytes,
                    "os": candidate.artifact.os,
                    "arch": candidate.artifact.arch,
                    "format": candidate.artifact.format,
                    "created_at": null,
                    "updated_at": null,
                    "finalized_at": null
                },
                "deploy": null,
                "coherent": true,
                "ready": false
            }
        })
    }

    fn matching_state_json(candidate: &ReleaseCandidateReceipt) -> serde_json::Value {
        matching_state_json_with_url(candidate, "")
    }

    fn capture_json(candidate: &ReleaseCandidateReceipt, url: &str) -> serde_json::Value {
        let web = candidate.web.as_ref().expect("web candidate");
        serde_json::json!({
            "module_id": MODULE_ID,
            "version_id": "version-id",
            "version": VERSION,
            "web_bundle_url": url,
            "web_bundle_sha256": web.sha256,
            "web_bundle_size_bytes": web.size_bytes
        })
    }

    fn operation_receipt_json(candidate: &ReleaseCandidateReceipt) -> serde_json::Value {
        serde_json::json!({
            "protocol": candidate.protocol,
            "source_sha256": candidate.source_sha256,
            "manifest_sha256": candidate.manifest.sha256,
            "artifact": {
                "sha256": candidate.artifact.sha256,
                "size_bytes": candidate.artifact.size_bytes,
                "os": candidate.artifact.os,
                "arch": candidate.artifact.arch,
                "format": candidate.artifact.format
            },
            "web": candidate.web.as_ref().map(|web| serde_json::json!({
                "sha256": web.sha256,
                "size_bytes": web.size_bytes
            }))
        })
    }

    fn deploy_response(
        candidate: &ReleaseCandidateReceipt,
        mode: api::ModuleDeployMode,
    ) -> api::ModuleDeploy {
        let artifact_mode = mode == api::ModuleDeployMode::Artifact;
        serde_json::from_value(serde_json::json!({
            "version_id": "version-id",
            "module_id": MODULE_ID,
            "invoke_target": "mirrorstack-module-media",
            "status": "active",
            "mode": mode.as_str(),
            "source_sha256": candidate.source_sha256,
            "manifest_sha256": candidate.manifest.sha256,
            "artifact_sha256": artifact_mode.then_some(candidate.artifact.sha256.clone()),
            "lambda_version": artifact_mode.then_some("7"),
            "lambda_code_sha256": artifact_mode.then_some(candidate.artifact.sha256.clone()),
            "created_at": "2026-08-31T00:00:00Z",
            "updated_at": "2026-08-31T00:00:01Z",
            "release_receipt": operation_receipt_json(candidate)
        }))
        .unwrap()
    }

    fn deploy_state(
        candidate: &ReleaseCandidateReceipt,
        mode: api::ModuleDeployMode,
        response: &api::ModuleDeploy,
    ) -> api::ModuleReleaseState {
        let mut state = matching_state(candidate);
        state.release_receipt.ready = true;
        state.release_receipt.artifact.as_mut().unwrap().status = match mode {
            api::ModuleDeployMode::Artifact => "ready",
            api::ModuleDeployMode::LocalSimulation => "missing",
        }
        .to_string();
        state.release_receipt.deploy = Some(api::ModuleReleaseDeployEvidence {
            mode: mode.as_str().to_string(),
            status: response.status.clone(),
            source_sha256: Some(candidate.source_sha256.clone()),
            manifest_sha256: Some(candidate.manifest.sha256.clone()),
            artifact_sha256: response.artifact_sha256.clone(),
            lambda_version: response.lambda_version.clone(),
            lambda_code_sha256: response.lambda_code_sha256.clone(),
            created_at: Some(response.created_at.clone()),
            updated_at: Some(response.updated_at.clone()),
        });
        state
    }

    fn spawn_http_sequence(
        expected: Vec<(&'static str, &'static str, u16, String)>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for (method, path, status, body) in expected {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0, "request ended before headers");
                    request.extend_from_slice(&chunk[..count]);
                }
                let request = String::from_utf8_lossy(&request);
                assert!(
                    request.starts_with(&format!("{method} {path} HTTP/1.1\r\n")),
                    "unexpected request: {request}"
                );
                let reason = if status == 200 { "OK" } else { "Error" };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        (url, handle)
    }

    #[test]
    fn dev_suffix_is_preparation_only_and_noninteractive_never_promotes() {
        assert_eq!(promotion_target("v1.2.3", false).unwrap(), None);
        assert_eq!(
            promotion_target("v1.2.3-dev", false).unwrap(),
            Some("v1.2.3")
        );
        let error = promotion_target("v1.2.3-dev", true).unwrap_err();
        assert!(error.to_string().contains("before deploying with --yes"));
    }

    #[test]
    fn fresh_version_response_must_echo_candidate_identity_and_web_tuple() {
        let candidate = candidate();
        let web = candidate.web.as_ref().unwrap();
        let mut recorded = api::ModuleVersion {
            id: "version-id".to_string(),
            module_id: MODULE_ID.to_string(),
            version: VERSION.to_string(),
            channel: Some("stable".to_string()),
            published_at: None,
            web_bundle_url: String::new(),
            web_bundle_sha256: web.sha256.clone(),
            web_bundle_size_bytes: web.size_bytes,
        };
        verify_recorded_version_response(&recorded, MODULE_ID, SLUG, VERSION, &candidate).unwrap();

        recorded.web_bundle_sha256 = "d".repeat(64);
        assert!(
            verify_recorded_version_response(&recorded, MODULE_ID, SLUG, VERSION, &candidate)
                .unwrap_err()
                .to_string()
                .contains("identity/web receipt")
        );

        let mut backend = candidate;
        backend.web = None;
        recorded.web_bundle_sha256.clear();
        recorded.web_bundle_size_bytes = 0;
        verify_recorded_version_response(&recorded, MODULE_ID, SLUG, VERSION, &backend).unwrap();
    }

    #[test]
    fn exact_existing_candidate_is_accepted_in_every_artifact_lifecycle_state() {
        let candidate = candidate();
        for status in ["missing", "pending", "ready"] {
            let mut state = matching_state(&candidate);
            state.release_receipt.artifact.as_mut().unwrap().status = status.to_string();
            verify_existing_release_candidate(&state, MODULE_ID, SLUG, VERSION, &candidate)
                .unwrap();
        }
    }

    #[test]
    fn operational_receipt_must_match_every_redacted_candidate_field() {
        let candidate = candidate();
        let receipt: api::ModuleOperationReleaseReceipt =
            serde_json::from_value(operation_receipt_json(&candidate)).unwrap();
        verify_operation_release_receipt(&receipt, &candidate, SLUG, VERSION, "artifact create")
            .unwrap();

        let mut wrong_source = operation_receipt_json(&candidate);
        wrong_source["source_sha256"] = serde_json::Value::String("d".repeat(64));
        let wrong_source = serde_json::from_value(wrong_source).unwrap();
        assert!(
            verify_operation_release_receipt(
                &wrong_source,
                &candidate,
                SLUG,
                VERSION,
                "artifact create"
            )
            .unwrap_err()
            .to_string()
            .contains("source/manifest")
        );

        let mut missing_web = operation_receipt_json(&candidate);
        missing_web["web"] = serde_json::Value::Null;
        let missing_web = serde_json::from_value(missing_web).unwrap();
        assert!(
            verify_operation_release_receipt(
                &missing_web,
                &candidate,
                SLUG,
                VERSION,
                "artifact finalize"
            )
            .unwrap_err()
            .to_string()
            .contains("web bundle")
        );
    }

    #[test]
    fn deploy_response_and_final_owner_state_prove_artifact_and_local_modes() {
        let candidate = candidate();
        for mode in [
            api::ModuleDeployMode::Artifact,
            api::ModuleDeployMode::LocalSimulation,
        ] {
            let response = deploy_response(&candidate, mode);
            verify_deploy_response(
                &response,
                "version-id",
                MODULE_ID,
                SLUG,
                VERSION,
                &candidate,
                mode,
                "active",
            )
            .unwrap();
            let state = deploy_state(&candidate, mode, &response);
            verify_final_release_state(
                &state, MODULE_ID, SLUG, VERSION, &candidate, mode, &response,
            )
            .unwrap();

            if mode == api::ModuleDeployMode::LocalSimulation {
                for existing_status in ["pending", "ready"] {
                    let mut state = deploy_state(&candidate, mode, &response);
                    state.release_receipt.artifact.as_mut().unwrap().status =
                        existing_status.to_string();
                    verify_final_release_state(
                        &state, MODULE_ID, SLUG, VERSION, &candidate, mode, &response,
                    )
                    .unwrap();
                }
            }
        }
    }

    #[test]
    fn deploy_or_final_state_evidence_mismatch_fails_closed() {
        let candidate = candidate();
        let mut response = deploy_response(&candidate, api::ModuleDeployMode::Artifact);
        response.artifact_sha256 = Some("d".repeat(64));
        assert!(
            verify_deploy_response(
                &response,
                "version-id",
                MODULE_ID,
                SLUG,
                VERSION,
                &candidate,
                api::ModuleDeployMode::Artifact,
                "active"
            )
            .is_err()
        );

        let response = deploy_response(&candidate, api::ModuleDeployMode::Artifact);
        let mut state = deploy_state(&candidate, api::ModuleDeployMode::Artifact, &response);
        state
            .release_receipt
            .deploy
            .as_mut()
            .unwrap()
            .lambda_code_sha256 = Some("different".to_string());
        assert!(
            verify_final_release_state(
                &state,
                MODULE_ID,
                SLUG,
                VERSION,
                &candidate,
                api::ModuleDeployMode::Artifact,
                &response
            )
            .is_err()
        );

        let mut uncaptured = deploy_state(&candidate, api::ModuleDeployMode::Artifact, &response);
        uncaptured.release_receipt.web.as_mut().unwrap().url.clear();
        assert!(
            verify_final_release_state(
                &uncaptured,
                MODULE_ID,
                SLUG,
                VERSION,
                &candidate,
                api::ModuleDeployMode::Artifact,
                &response
            )
            .unwrap_err()
            .to_string()
            .contains("pinned web URL")
        );
    }

    #[test]
    fn same_artifact_with_changed_source_or_manifest_is_rejected() {
        let stored_candidate = candidate();
        let state = matching_state(&stored_candidate);

        let mut changed_source = stored_candidate.clone();
        changed_source.source_sha256 = "d".repeat(64);
        let source_error =
            verify_existing_release_candidate(&state, MODULE_ID, SLUG, VERSION, &changed_source)
                .unwrap_err();
        assert!(
            source_error.to_string().contains("bound source receipt"),
            "{source_error:#}"
        );
        assert_eq!(changed_source.artifact, stored_candidate.artifact);

        let mut changed_manifest = stored_candidate.clone();
        changed_manifest.manifest = manifest_evidence(&serde_json::json!({
            "id": SDK_MODULE_ID,
            "slug": SLUG,
            "description": "changed without changing the artifact fixture",
            "versions": {"v1.2.3": {"app": "0001"}}
        }));
        let manifest_error =
            verify_existing_release_candidate(&state, MODULE_ID, SLUG, VERSION, &changed_manifest)
                .unwrap_err();
        assert!(
            manifest_error.to_string().contains("exact manifest bytes"),
            "{manifest_error:#}"
        );
        assert_eq!(changed_manifest.artifact, stored_candidate.artifact);
    }

    #[test]
    fn same_artifact_with_changed_web_evidence_is_rejected() {
        let stored_candidate = candidate();
        let state = matching_state(&stored_candidate);
        let mut changed = stored_candidate.clone();
        changed.web.as_mut().unwrap().sha256 = "d".repeat(64);

        let error = verify_existing_release_candidate(&state, MODULE_ID, SLUG, VERSION, &changed)
            .unwrap_err();
        assert!(
            error.to_string().contains("web bundle receipt"),
            "{error:#}"
        );
        assert_eq!(changed.artifact, stored_candidate.artifact);
    }

    #[test]
    fn legacy_incoherent_and_yanked_existing_versions_fail_closed() {
        let candidate = candidate();

        let mut legacy = matching_state(&candidate);
        legacy.release_receipt.state = "legacy_unbound".to_string();
        legacy.release_receipt.protocol = None;
        assert!(
            verify_existing_release_candidate(&legacy, MODULE_ID, SLUG, VERSION, &candidate)
                .unwrap_err()
                .to_string()
                .contains("bound source receipt")
        );

        let mut incoherent = matching_state(&candidate);
        incoherent.release_receipt.coherent = false;
        assert!(
            verify_existing_release_candidate(&incoherent, MODULE_ID, SLUG, VERSION, &candidate)
                .is_err()
        );

        let mut yanked = matching_state(&candidate);
        yanked.version.yanked_at = Some("2026-08-31T00:00:00Z".to_string());
        assert!(
            verify_existing_release_candidate(&yanked, MODULE_ID, SLUG, VERSION, &candidate)
                .unwrap_err()
                .to_string()
                .contains("yanked state")
        );
    }

    #[test]
    fn concurrent_version_exists_reread_rejects_a_different_candidate() {
        let stored_candidate = candidate();
        let mut local_candidate = stored_candidate.clone();
        local_candidate.source_sha256 = "d".repeat(64);

        let mut server = mockito::Server::new();
        let reread = server
            .mock(
                "GET",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3",
            )
            .with_status(200)
            .with_body(matching_state_json(&stored_candidate).to_string())
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let error = verify_version_exists_candidate(
            &client,
            &server.url(),
            "access-token",
            MODULE_ID,
            SLUG,
            VERSION,
            &local_candidate,
        )
        .unwrap_err();

        reread.assert();
        assert!(
            error.to_string().contains("bound source receipt"),
            "{error:#}"
        );
    }

    #[test]
    fn fresh_version_rereads_then_recovers_web_before_artifact_writes() {
        let candidate = candidate();
        let pinned = "https://cdn.example.test/media/index.js";
        let path = "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3";
        let (base, server) = spawn_http_sequence(vec![
            (
                "GET",
                path,
                200,
                matching_state_json(&candidate).to_string(),
            ),
            (
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
                200,
                capture_json(&candidate, pinned).to_string(),
            ),
            (
                "GET",
                path,
                200,
                matching_state_json_with_url(&candidate, pinned).to_string(),
            ),
        ]);
        let client = http::client(Duration::from_secs(15)).unwrap();
        let state = ensure_candidate_web_capture(
            &client,
            &base,
            "access-token",
            MODULE_ID,
            SLUG,
            VERSION,
            &candidate,
            None,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(
            state.release_receipt.web.unwrap().url,
            "https://cdn.example.test/media/index.js"
        );
    }

    #[test]
    fn version_exists_with_empty_web_url_recovers_and_rereads_exact_state() {
        let candidate = candidate();
        let mut initial = matching_state(&candidate);
        initial.release_receipt.web.as_mut().unwrap().url.clear();
        let pinned = "https://cdn.example.test/media/index.js";
        let mut server = mockito::Server::new();
        let capture = server
            .mock(
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
            )
            .match_body("")
            .with_status(200)
            .with_body(capture_json(&candidate, pinned).to_string())
            .create();
        let reread = server
            .mock(
                "GET",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3",
            )
            .with_status(200)
            .with_body(matching_state_json_with_url(&candidate, pinned).to_string())
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let state = ensure_candidate_web_capture(
            &client,
            &server.url(),
            "access-token",
            MODULE_ID,
            SLUG,
            VERSION,
            &candidate,
            Some(initial),
        )
        .unwrap();
        capture.assert();
        reread.assert();
        assert_eq!(state.release_receipt.web.unwrap().url, pinned);
    }

    #[test]
    fn existing_pinned_web_is_still_verified_before_artifact_writes() {
        let candidate = candidate();
        let initial = matching_state(&candidate);
        let pinned = initial.release_receipt.web.as_ref().unwrap().url.clone();
        let mut server = mockito::Server::new();
        let capture = server
            .mock(
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
            )
            .with_status(200)
            .with_body(capture_json(&candidate, &pinned).to_string())
            .create();
        let reread = server
            .mock(
                "GET",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3",
            )
            .with_status(200)
            .with_body(matching_state_json_with_url(&candidate, &pinned).to_string())
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        ensure_candidate_web_capture(
            &client,
            &server.url(),
            "access-token",
            MODULE_ID,
            SLUG,
            VERSION,
            &candidate,
            Some(initial),
        )
        .unwrap();
        capture.assert();
        reread.assert();
    }

    #[test]
    fn backend_only_candidate_never_calls_web_capture() {
        let mut candidate = candidate();
        candidate.web = None;
        let state = matching_state(&candidate);
        let client = http::client(Duration::from_secs(1)).unwrap();
        let verified = ensure_candidate_web_capture(
            &client,
            "http://127.0.0.1:1",
            "access-token",
            MODULE_ID,
            SLUG,
            VERSION,
            &candidate,
            Some(state),
        )
        .unwrap();
        assert!(verified.release_receipt.web.is_none());
    }

    #[test]
    fn mismatched_capture_response_fails_before_owner_reread_or_artifact_write() {
        let candidate = candidate();
        let mut initial = matching_state(&candidate);
        initial.release_receipt.web.as_mut().unwrap().url.clear();
        let mut wrong = capture_json(&candidate, "https://cdn.example.test/media/index.js");
        wrong["web_bundle_sha256"] = serde_json::Value::String("d".repeat(64));
        let mut server = mockito::Server::new();
        let capture = server
            .mock(
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
            )
            .with_status(200)
            .with_body(wrong.to_string())
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let error = ensure_candidate_web_capture(
            &client,
            &server.url(),
            "access-token",
            MODULE_ID,
            SLUG,
            VERSION,
            &candidate,
            Some(initial),
        )
        .unwrap_err();
        capture.assert();
        assert!(error.to_string().contains("does not match"), "{error:#}");
    }

    #[test]
    fn version_create_request_is_bounded_at_the_api_envelope() {
        let manifest = serde_json::json!({"versions": {"v1.2.3": {}}});
        let changelog = std::collections::BTreeMap::new();
        let mut readme = std::collections::BTreeMap::from([("default".to_string(), String::new())]);
        let base = serde_json::to_vec(&RecordModuleVersionInput {
            version: "1.2.3",
            changelog: &changelog,
            readme: &readme,
            declaration: api::ModuleVersionDeclaration::Manifest {
                manifest: &manifest,
                web_bundle: None,
            },
        })
        .unwrap()
        .len();
        readme.insert(
            "default".to_string(),
            "A".repeat(MAX_VERSION_CREATE_BYTES - base),
        );
        let at_cap = RecordModuleVersionInput {
            version: "1.2.3",
            changelog: &changelog,
            readme: &readme,
            declaration: api::ModuleVersionDeclaration::Manifest {
                manifest: &manifest,
                web_bundle: None,
            },
        };
        assert_eq!(
            serde_json::to_vec(&at_cap).unwrap().len(),
            MAX_VERSION_CREATE_BYTES
        );
        guard_version_create_size(&at_cap).unwrap();

        readme.get_mut("default").unwrap().push('A');
        let over_cap = RecordModuleVersionInput {
            version: "1.2.3",
            changelog: &changelog,
            readme: &readme,
            declaration: api::ModuleVersionDeclaration::Manifest {
                manifest: &manifest,
                web_bundle: None,
            },
        };
        let error = guard_version_create_size(&over_cap).unwrap_err();
        assert!(
            error.to_string().contains("version-create request is"),
            "{error:#}"
        );
    }
}
