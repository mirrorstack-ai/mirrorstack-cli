//! `mirrorstack app module deploy` — record a version and ship it.
//!
//! Split out of a 1468-line mod.rs so the command surface (the Args structs
//! and the run() dispatcher) is readable without scrolling past every verb's
//! implementation.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::release_plan::{
    self, Action, LocalRelease, RemoteArtifact, RemoteDeploy, RemoteRelease, RemoteVersion,
};
use crate::commands::release_candidate::{
    self, CandidateRequest, ReleaseCandidate, ReleaseCandidateReceipt,
};

const MAX_VERSION_CREATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RELEASE_TRANSITIONS: usize = 16;
const AMBIGUOUS_DEPLOY_SETTLE_POLLS: usize = 5;
const VERSION_TITLE: &str = "";
const VERSION_CHANNEL: &str = "stable";

struct ReleaseMetadata {
    changelog: BTreeMap<String, String>,
    readme: BTreeMap<String, String>,
    migration_app: i64,
    migration_module: i64,
    changelog_warnings: Vec<String>,
    readme_truncated: bool,
}

trait CandidateEvidence {
    fn receipt(&self) -> &ReleaseCandidateReceipt;
    fn verify_live_source(&self) -> Result<()>;
    fn verify_artifact(&self) -> Result<()>;
}

impl CandidateEvidence for ReleaseCandidate {
    fn receipt(&self) -> &ReleaseCandidateReceipt {
        ReleaseCandidate::receipt(self)
    }

    fn verify_live_source(&self) -> Result<()> {
        ReleaseCandidate::verify_live_source(self)
    }

    fn verify_artifact(&self) -> Result<()> {
        ReleaseCandidate::verify_artifact(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationOutcome {
    /// The endpoint returned success. The next owner-state read must prove the
    /// complete postcondition before another write is allowed.
    Applied,
    /// A server-confirmed atomic race, or an ambiguous non-deploy action that
    /// is safe to retry only after an authoritative reread and fresh plan.
    Replan,
    /// Version create returned the exact atomic `409 version_exists`. The
    /// next owner-state read must prove a present immutable row; absence is a
    /// contradiction and must not trigger another create POST.
    VersionExists,
    /// A deploy may still commit after its response was lost. Only bounded
    /// reads may follow; this process must never issue a second deploy POST.
    AmbiguousDeploy,
    /// Artifact create explicitly proved that storage is not configured.
    /// This authorizes one server-gated local-simulation attempt in this run.
    StorageUnconfigured,
}

trait ReleaseOperations {
    fn read_state(&mut self) -> Result<RemoteRelease>;
    fn record_version(&mut self) -> Result<MutationOutcome>;
    fn capture_web_bundle(&mut self) -> Result<MutationOutcome>;
    fn upload_artifact(&mut self) -> Result<MutationOutcome>;
    fn deploy(&mut self, mode: api::ModuleDeployMode) -> Result<MutationOutcome>;
    fn wait_before_deploy_settlement_read(&mut self, _poll: usize) {}
}

#[derive(Debug)]
struct DriveResult {
    release: RemoteVersion,
    attempts: Vec<Action>,
}

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
    let metadata = collect_release_metadata(&candidate, &version)?;

    eprintln!(
        "  {} {} → {} (arm64 bundle)",
        style("Deploying:").dim(),
        style(dir.display()).bold(),
        style(format!("{slug}@{version}")).cyan().bold(),
    );

    // The candidate owns the temporary archive until this function returns.
    // Recheck it before the first owner-state read so even the no-op path is
    // based on the exact attested bytes, then let the pure planner select one
    // mutation at a time from authoritative state.
    candidate.verify_artifact()?;
    let local = LocalRelease {
        source_sha256: candidate.receipt().source_sha256.clone(),
        manifest_sha256: candidate.receipt().manifest.sha256.clone(),
        artifact_sha256: candidate.receipt().artifact.sha256.clone(),
        artifact_size_bytes: candidate.receipt().artifact.size_bytes,
        web_required: candidate.receipt().web.is_some(),
        web_verified: false,
        local_simulation_authorized: false,
        desired_deploy_status: args.status.as_deref().unwrap_or("active").to_string(),
    };
    let mut remote = ApiReleaseOperations {
        client: &client,
        apps_base: &apps_base,
        access_token: &creds.access_token,
        module: &module,
        slug: &slug,
        version: &version,
        candidate: &candidate,
        metadata: &metadata,
        zip_path,
        desired_deploy_status: local.desired_deploy_status.clone(),
        last_version_id: None,
        observed_web_url: None,
        expected_capture_url: None,
        last_deploy: None,
    };
    let completed = drive_release(&mut remote, local)?;
    let deploy = completed
        .release
        .deploy
        .as_ref()
        .expect("planner Done always includes a proven deploy");

    if completed.attempts.is_empty() {
        eprintln!(
            "{} {} already has the exact source, manifest, web, artifact, and deploy receipt — no POST was sent",
            ok_mark(),
            style(format!("{slug}@{version}")).cyan().bold()
        );
    } else {
        let steps = completed
            .attempts
            .iter()
            .map(|action| match action {
                Action::RecordVersion => "record",
                Action::CaptureWebBundle => "capture-web",
                Action::UploadArtifact => "upload",
                Action::Deploy => "deploy",
                Action::Done => unreachable!("Done is never a mutation attempt"),
            })
            .collect::<Vec<_>>()
            .join(" → ");
        eprintln!(
            "{} deployed {} ({steps})",
            ok_mark(),
            style(format!("{slug}@{version}")).cyan().bold()
        );
    }
    eprintln!("  {} verified", style("artifact:").dim());
    if let Some(target) = remote
        .last_deploy
        .as_ref()
        .map(|deploy| &deploy.invoke_target)
    {
        eprintln!("  {} {}", style("target:").dim(), target);
    }
    eprintln!("  {} {}", style("mode:").dim(), deploy.mode);
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

fn collect_release_metadata(
    candidate: &ReleaseCandidate,
    version: &str,
) -> Result<ReleaseMetadata> {
    let dir = candidate.source_module_dir();
    let changelog = changelog::lint(&dir, version)?;
    let readme = readme::read(&dir)?;
    let manifest = decode_manifest_evidence(
        &candidate.receipt().manifest.sha256,
        &candidate.receipt().manifest.base64,
        "local manifest",
    )?;
    Ok(ReleaseMetadata {
        changelog: normalize_locale_map(changelog.map),
        readme: normalize_locale_map(readme.map),
        migration_app: manifest_migration_counter(&manifest, "app")?,
        migration_module: manifest_migration_counter(&manifest, "module")?,
        changelog_warnings: changelog.warnings,
        readme_truncated: readme.truncated,
    })
}

fn normalize_locale_map(input: BTreeMap<String, String>) -> BTreeMap<String, String> {
    input
        .into_iter()
        .filter_map(|(locale, body)| {
            let body = body.trim().to_string();
            (!body.is_empty()).then_some((locale, body))
        })
        .collect()
}

fn manifest_migration_counter(manifest: &serde_json::Value, scope: &str) -> Result<i64> {
    let Some(value) = manifest.get("migration").and_then(|value| value.get(scope)) else {
        return Ok(0);
    };
    let Some(raw) = value.as_str() else {
        return Err(anyhow!(
            "manifest.migration.{scope} must be a non-negative integer string"
        ));
    };
    if raw.is_empty() {
        return Ok(0);
    }
    raw.parse::<i64>()
        .ok()
        .filter(|counter| *counter >= 0)
        .ok_or_else(|| anyhow!("manifest.migration.{scope} must be a non-negative integer string"))
}

fn drive_release(
    operations: &mut impl ReleaseOperations,
    mut local: LocalRelease,
) -> Result<DriveResult> {
    let mut state = operations.read_state()?;
    let mut attempts = Vec::new();
    for _ in 0..MAX_RELEASE_TRANSITIONS {
        let action = release_plan::plan(&local, &state)?;
        if action == Action::Done {
            let RemoteRelease::Present(release) = state else {
                unreachable!("Done requires a present release")
            };
            return Ok(DriveResult {
                release: *release,
                attempts,
            });
        }

        attempts.push(action);
        let outcome = match action {
            Action::RecordVersion => operations.record_version()?,
            Action::CaptureWebBundle => operations.capture_web_bundle()?,
            Action::UploadArtifact => operations.upload_artifact()?,
            Action::Deploy => {
                let mode = deploy_mode_for(&state, local.local_simulation_authorized)?;
                operations.deploy(mode)?
            }
            Action::Done => unreachable!(),
        };
        if action == Action::CaptureWebBundle && outcome == MutationOutcome::Applied {
            local.web_verified = true;
        }
        if outcome == MutationOutcome::StorageUnconfigured {
            local.local_simulation_authorized = true;
        }

        let mut reread = operations.read_state()?;
        if action != Action::RecordVersion && matches!(reread, RemoteRelease::Absent) {
            return Err(anyhow!(
                "owner release state disappeared after {action:?}; an immutable version cannot become absent, so refusing any follow-up write"
            ));
        }
        if action == Action::Deploy && outcome == MutationOutcome::AmbiguousDeploy {
            reread = settle_ambiguous_deploy(operations, &local, reread)?;
        }
        if matches!(
            outcome,
            MutationOutcome::Applied
                | MutationOutcome::VersionExists
                | MutationOutcome::StorageUnconfigured
        ) {
            let next = release_plan::plan(&local, &reread)?;
            let postcondition_holds = match action {
                Action::RecordVersion => next != Action::RecordVersion,
                Action::CaptureWebBundle => {
                    matches!(&reread, RemoteRelease::Present(_)) && next != Action::CaptureWebBundle
                }
                Action::UploadArtifact => matches!(next, Action::Deploy | Action::Done),
                Action::Deploy => next == Action::Done,
                Action::Done => unreachable!(),
            };
            if !postcondition_holds {
                return Err(anyhow!(
                    "platform accepted {action:?}, but the owner release-state reread did not prove its complete postcondition (next action remained {next:?}); refusing another write"
                ));
            }
        }
        state = reread;
    }
    Err(anyhow!(
        "release state did not converge after {MAX_RELEASE_TRANSITIONS} authoritative rereads; refusing further writes"
    ))
}

fn deploy_mode_for(
    state: &RemoteRelease,
    local_simulation_authorized: bool,
) -> Result<api::ModuleDeployMode> {
    let RemoteRelease::Present(version) = state else {
        return Err(anyhow!("cannot deploy an absent version"));
    };
    if version
        .artifact
        .as_ref()
        .is_some_and(|artifact| artifact.status == "ready")
    {
        return Ok(api::ModuleDeployMode::Artifact);
    }
    if local_simulation_authorized {
        return Ok(api::ModuleDeployMode::LocalSimulation);
    }
    Err(anyhow!(
        "planner selected deploy without a ready artifact or a current storage-unconfigured authorization"
    ))
}

/// A deploy POST can continue provisioning after the client loses its
/// response. An old snapshot therefore never authorizes another POST: only
/// bounded owner-state reads may prove completion in this process.
fn settle_ambiguous_deploy(
    operations: &mut impl ReleaseOperations,
    local: &LocalRelease,
    mut state: RemoteRelease,
) -> Result<RemoteRelease> {
    for poll in 0..=AMBIGUOUS_DEPLOY_SETTLE_POLLS {
        let next = release_plan::plan(local, &state)?;
        if next == Action::Done {
            return Ok(state);
        }
        if next != Action::Deploy {
            return Err(anyhow!(
                "deploy response was ambiguous and owner state changed to {next:?}; refusing any follow-up write because the original provisioning request may still commit"
            ));
        }
        if poll == AMBIGUOUS_DEPLOY_SETTLE_POLLS {
            break;
        }
        operations.wait_before_deploy_settlement_read(poll);
        state = operations.read_state()?;
    }
    Err(anyhow!(
        "deploy response was ambiguous and {reads} bounded owner-state reads did not prove completion; refusing a second deploy POST in this command. Wait for platform state to settle, then retry",
        reads = AMBIGUOUS_DEPLOY_SETTLE_POLLS + 1
    ))
}

struct ApiReleaseOperations<'a> {
    client: &'a reqwest::blocking::Client,
    apps_base: &'a str,
    access_token: &'a str,
    module: &'a api::Module,
    slug: &'a str,
    version: &'a str,
    candidate: &'a dyn CandidateEvidence,
    metadata: &'a ReleaseMetadata,
    zip_path: &'a Path,
    desired_deploy_status: String,
    last_version_id: Option<String>,
    observed_web_url: Option<String>,
    expected_capture_url: Option<String>,
    last_deploy: Option<api::ModuleDeploy>,
}

impl ApiReleaseOperations<'_> {
    fn convert_state(&self, state: &api::ModuleReleaseState) -> RemoteRelease {
        let receipt = &state.release_receipt;
        let version = &state.version;
        RemoteRelease::Present(Box::new(RemoteVersion {
            immutable_mismatches: immutable_metadata_mismatches(version, self.metadata),
            yanked: version.yanked_at.is_some(),
            coherent: receipt.coherent,
            ready: receipt.ready,
            web_bundle_url: receipt
                .web
                .as_ref()
                .map_or_else(String::new, |web| web.url.clone()),
            artifact: receipt.artifact.as_ref().map(|artifact| RemoteArtifact {
                status: artifact.status.clone(),
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256.clone(),
                created: present_timestamp(&artifact.created_at),
                updated: present_timestamp(&artifact.updated_at),
                finalized: present_timestamp(&artifact.finalized_at),
            }),
            deploy: receipt.deploy.as_ref().map(|deploy| RemoteDeploy {
                mode: deploy.mode.clone(),
                status: deploy.status.clone(),
                source_sha256: deploy.source_sha256.clone(),
                manifest_sha256: deploy.manifest_sha256.clone(),
                artifact_sha256: deploy.artifact_sha256.clone(),
                lambda_version: deploy.lambda_version.clone(),
                lambda_code_sha256: deploy.lambda_code_sha256.clone(),
                created: present_timestamp(&deploy.created_at),
                updated: present_timestamp(&deploy.updated_at),
            }),
        }))
    }
}

fn mutation_error(
    error: ApiError,
    race_codes: &[&str],
    hint: fn(&str) -> &'static str,
    deploy: bool,
) -> Result<MutationOutcome> {
    match error {
        ApiError::Server {
            status: 409,
            ref code,
            ..
        } if race_codes.contains(&code.as_str()) => Ok(MutationOutcome::Replan),
        ApiError::Server { code, message, .. } if code == "artifact_storage_unconfigured" => {
            Err(anyhow!("{code}: {message}{suffix}", suffix = hint(&code)))
        }
        ApiError::Http(_)
        | ApiError::Decode(_)
        | ApiError::Unexpected { status: 500.., .. }
        | ApiError::Server { status: 500.., .. } => {
            if deploy {
                Ok(MutationOutcome::AmbiguousDeploy)
            } else {
                Ok(MutationOutcome::Replan)
            }
        }
        ApiError::Unauthenticated => Err(session_expired()),
        ApiError::Server { code, message, .. } => {
            Err(anyhow!("{code}: {message}{suffix}", suffix = hint(&code)))
        }
        other => Err(other.into()),
    }
}

fn immutable_metadata_mismatches(
    version: &api::ModuleReleaseStateVersion,
    metadata: &ReleaseMetadata,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    if version.title != VERSION_TITLE {
        mismatches.push("title".into());
    }
    if version.description.is_some() {
        mismatches.push("description".into());
    }
    if version.channel != VERSION_CHANNEL {
        mismatches.push("channel".into());
    }
    if version.changelog != metadata.changelog {
        mismatches.push("changelog".into());
    }
    if version.readme != metadata.readme {
        mismatches.push("readme".into());
    }
    if version.migration_app != metadata.migration_app {
        mismatches.push("migration.app".into());
    }
    if version.migration_module != metadata.migration_module {
        mismatches.push("migration.module".into());
    }
    mismatches
}

fn present_timestamp(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

impl ReleaseOperations for ApiReleaseOperations<'_> {
    fn read_state(&mut self) -> Result<RemoteRelease> {
        let result = with_spinner("Reading owner release state…", || {
            api::get_module_release_state(
                self.client,
                self.apps_base,
                self.access_token,
                &self.module.id,
                self.version,
            )
        });
        let state = match result {
            Ok(state) => state,
            Err(ApiError::Server {
                status: 404, code, ..
            }) if code == "not_found" => {
                self.last_version_id = None;
                self.observed_web_url = None;
                return Ok(RemoteRelease::Absent);
            }
            Err(ApiError::Unexpected { status: 404, .. }) => {
                return Err(anyhow!(
                    "the platform does not expose the structured owner release-state contract required for safe retries; refusing the legacy blind-deploy path"
                ));
            }
            Err(ApiError::Unauthenticated) => return Err(session_expired()),
            Err(error) => return Err(error.into()),
        };
        verify_existing_release_candidate(
            &state,
            &self.module.id,
            self.slug,
            self.version,
            self.candidate.receipt(),
        )?;
        let actual_web_url = state
            .release_receipt
            .web
            .as_ref()
            .map_or_else(String::new, |web| web.url.clone());
        if self
            .observed_web_url
            .as_deref()
            .is_some_and(|previous| !previous.trim().is_empty() && previous != actual_web_url)
        {
            return Err(anyhow!(
                "owner release state moved the immutable pinned web URL for {}@{}; refusing any artifact or deploy write",
                self.slug,
                self.version
            ));
        }
        if let Some(expected_url) = self.expected_capture_url.as_deref()
            && (actual_web_url != expected_url || actual_web_url.is_empty())
        {
            return Err(anyhow!(
                "web capture for {}@{} returned success, but the owner-state reread did not preserve the same pinned URL",
                self.slug,
                self.version
            ));
        }
        if let Some(response) = self.last_deploy.as_ref() {
            let mode = match response.mode.as_str() {
                "artifact" => api::ModuleDeployMode::Artifact,
                "local_simulation" => api::ModuleDeployMode::LocalSimulation,
                _ => {
                    return Err(anyhow!(
                        "deploy response returned unknown mode {:?}",
                        response.mode
                    ));
                }
            };
            verify_final_release_state(
                &state,
                &self.module.id,
                self.slug,
                self.version,
                self.candidate.receipt(),
                mode,
                response,
            )?;
        }
        self.last_version_id = Some(state.version.id.clone());
        self.observed_web_url = Some(actual_web_url);
        Ok(self.convert_state(&state))
    }

    fn record_version(&mut self) -> Result<MutationOutcome> {
        self.candidate
            .verify_live_source()
            .context("release candidate: live source changed before immutable version recording")?;
        let release_candidate = serde_json::to_value(self.candidate.receipt())
            .context("release candidate: encode immutable version-create receipt")?;
        let input = RecordModuleVersionInput {
            version: self.version,
            changelog: &self.metadata.changelog,
            readme: &self.metadata.readme,
            declaration: api::ModuleVersionDeclaration::ReleaseCandidate {
                release_candidate: &release_candidate,
            },
        };
        guard_version_create_size(&input)?;
        let result = with_spinner("Recording version…", || {
            api::record_module_version(
                self.client,
                self.apps_base,
                self.access_token,
                &self.module.id,
                &input,
            )
        });
        match result {
            Ok(recorded) => {
                verify_recorded_version_response(
                    &recorded,
                    &self.module.id,
                    self.slug,
                    self.version,
                    self.candidate.receipt(),
                )?;
                for warning in &self.metadata.changelog_warnings {
                    eprintln!("{} {warning}", warn_prefix());
                }
                if self.metadata.readme_truncated {
                    eprintln!(
                        "{} a README file exceeded {} bytes and was truncated for the version record",
                        warn_prefix(),
                        readme::MAX_README_BYTES
                    );
                }
                eprintln!(
                    "{} recorded {}",
                    ok_mark(),
                    style(format!("{}@{}", self.slug, self.version))
                        .cyan()
                        .bold()
                );
                eprintln!("  {} {}", style("id:").dim(), recorded.id);
                for line in changelog_preview(&self.metadata.changelog["default"], 3) {
                    eprintln!("  {} {line}", style("│").dim());
                }
                Ok(MutationOutcome::Applied)
            }
            Err(ApiError::Server {
                status: 409, code, ..
            }) if code == "version_exists" => Ok(MutationOutcome::VersionExists),
            Err(error) => mutation_error(error, &[], record_error_hint, false),
        }
    }

    fn capture_web_bundle(&mut self) -> Result<MutationOutcome> {
        let local_web = self.candidate.receipt().web.as_ref().ok_or_else(|| {
            anyhow!("planner requested web capture for a backend-only release candidate")
        })?;
        let version_id = self.last_version_id.as_deref().ok_or_else(|| {
            anyhow!("planner requested web capture before a version id was proven")
        })?;
        let result = with_spinner("Verifying pinned web bundle…", || {
            api::capture_module_version_bundle(
                self.client,
                self.apps_base,
                self.access_token,
                &self.module.id,
                self.version,
            )
        });
        match result {
            Ok(capture) => {
                verify_bundle_capture_response(
                    &capture,
                    &self.module.id,
                    version_id,
                    self.slug,
                    self.version,
                    local_web,
                    self.observed_web_url.as_deref(),
                )?;
                self.expected_capture_url = Some(capture.web_bundle_url);
                Ok(MutationOutcome::Applied)
            }
            Err(error) => mutation_error(error, &[], bundle_capture_error_hint, false),
        }
    }

    fn upload_artifact(&mut self) -> Result<MutationOutcome> {
        let version_id = self.last_version_id.as_deref().ok_or_else(|| {
            anyhow!("planner requested artifact upload before a version id was proven")
        })?;
        self.candidate.verify_artifact()?;
        match artifact::ship_artifact(
            self.client,
            self.apps_base,
            self.access_token,
            &self.module.id,
            self.version,
            self.zip_path,
            self.candidate.receipt(),
            version_id,
        )? {
            artifact::ShipOutcome::Shipped => {
                eprintln!(
                    "{} uploaded {}",
                    ok_mark(),
                    style(format!("{}@{}", self.slug, self.version))
                        .cyan()
                        .bold()
                );
                Ok(MutationOutcome::Applied)
            }
            artifact::ShipOutcome::StorageUnconfigured => {
                eprintln!(
                    "{} artifact storage is explicitly unconfigured for {}; requesting the server-gated local simulator only",
                    warn_prefix(),
                    style(format!("{}@{}", self.slug, self.version))
                        .cyan()
                        .bold()
                );
                Ok(MutationOutcome::StorageUnconfigured)
            }
            artifact::ShipOutcome::Replan => Ok(MutationOutcome::Replan),
        }
    }

    fn deploy(&mut self, mode: api::ModuleDeployMode) -> Result<MutationOutcome> {
        let version_id = self
            .last_version_id
            .as_deref()
            .ok_or_else(|| anyhow!("planner requested deploy before a version id was proven"))?;
        let result = with_spinner("Deploying…", || {
            api::set_module_deploy(
                self.client,
                self.apps_base,
                self.access_token,
                &self.module.id,
                self.version,
                &SetModuleDeployInput {
                    mode,
                    status: Some(&self.desired_deploy_status),
                },
            )
        });
        match result {
            Ok(deploy) => {
                verify_deploy_response(
                    &deploy,
                    version_id,
                    &self.module.id,
                    self.slug,
                    self.version,
                    self.candidate.receipt(),
                    mode,
                    &self.desired_deploy_status,
                )?;
                self.last_deploy = Some(deploy);
                Ok(MutationOutcome::Applied)
            }
            Err(error) => mutation_error(error, &["artifact_not_ready"], deploy_error_hint, true),
        }
    }

    fn wait_before_deploy_settlement_read(&mut self, poll: usize) {
        let seconds = (1_u64 << poll.min(4)).min(15);
        std::thread::sleep(Duration::from_secs(seconds));
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_bundle_capture_response(
    capture: &api::ModuleBundleCapture,
    module_id: &str,
    version_id: &str,
    slug: &str,
    version: &str,
    local_web: &release_candidate::WebEvidence,
    observed_web_url: Option<&str>,
) -> Result<()> {
    if !release_candidate::module_ids_equal(&capture.module_id, module_id)
        || capture.version_id != version_id
        || capture.version != version
        || capture.web_bundle_sha256 != local_web.sha256
        || capture.web_bundle_size_bytes != local_web.size_bytes
        || capture.web_bundle_url.trim().is_empty()
    {
        return Err(anyhow!(
            "web bundle capture returned evidence that does not match the immutable {slug}@{version} candidate"
        ));
    }
    if observed_web_url
        .filter(|url| !url.trim().is_empty())
        .is_some_and(|url| url != capture.web_bundle_url)
    {
        return Err(anyhow!(
            "web bundle capture tried to move the immutable pinned URL for {slug}@{version}; refusing any artifact or deploy write"
        ));
    }
    Ok(())
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
    if state.version.id.trim().is_empty()
        || !release_candidate::module_ids_equal(&state.version.module_id, module_id)
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

fn bundle_capture_error_hint(code: &str) -> &'static str {
    match code {
        "not_found" => " (the module version is unavailable to this owner)",
        "bundle_capture_unavailable" => {
            " (the platform's pinned bundle publisher or storage is unavailable)"
        }
        "bundle_source_missing" => {
            " (run `mirrorstack dev --tunnel --share --watch=false` and wait for its release receipt, then retry)"
        }
        "bundle_source_invalid" => {
            " (the frozen dev bundle failed origin, key, type, size, or SHA-256 validation; rebuild a one-shot release candidate)"
        }
        "bundle_capture_conflict" => {
            " (the immutable pinned destination contains different or unverifiable bytes; investigate or bump the version)"
        }
        "bundle_capture_transient" => {
            " (the platform could not complete deterministic capture; no artifact or deploy mutation was attempted)"
        }
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
        "artifact_already_ready" => {
            " (a concurrent deploy finalized the immutable artifact; owner state will be reread before the planner continues)"
        }
        "artifact_not_ready" => {
            " (the artifact is not ready; owner state will be reread before any upload or deploy retry)"
        }
        "artifact_code_mismatch" => {
            " (the Lambda version does not contain the exact immutable artifact SHA-256; deployment failed closed)"
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

    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const MODULE_ID: &str = "11111111-1111-1111-1111-111111111111";
    const SDK_MODULE_ID: &str = "m11111111111111111111111111111111";
    const SLUG: &str = "media";
    const VERSION: &str = "1.2.3";

    struct TestCandidate {
        receipt: ReleaseCandidateReceipt,
    }

    impl CandidateEvidence for TestCandidate {
        fn receipt(&self) -> &ReleaseCandidateReceipt {
            &self.receipt
        }

        fn verify_live_source(&self) -> Result<()> {
            Ok(())
        }

        fn verify_artifact(&self) -> Result<()> {
            Ok(())
        }
    }

    fn test_metadata() -> ReleaseMetadata {
        ReleaseMetadata {
            changelog: BTreeMap::new(),
            readme: BTreeMap::new(),
            migration_app: 0,
            migration_module: 0,
            changelog_warnings: Vec::new(),
            readme_truncated: false,
        }
    }

    fn test_module() -> api::Module {
        api::Module {
            id: MODULE_ID.to_string(),
            name: "Media".to_string(),
            slug: SLUG.to_string(),
            owner_id: None,
            created_at: None,
        }
    }

    fn test_api_operations<'a>(
        client: &'a reqwest::blocking::Client,
        apps_base: &'a str,
        module: &'a api::Module,
        candidate: &'a dyn CandidateEvidence,
        metadata: &'a ReleaseMetadata,
    ) -> ApiReleaseOperations<'a> {
        ApiReleaseOperations {
            client,
            apps_base,
            access_token: "access-token",
            module,
            slug: SLUG,
            version: VERSION,
            candidate,
            metadata,
            zip_path: Path::new("unused-test-artifact.zip"),
            desired_deploy_status: "active".to_string(),
            last_version_id: None,
            observed_web_url: None,
            expected_capture_url: None,
            last_deploy: None,
        }
    }

    struct FakeOperations {
        reads: VecDeque<RemoteRelease>,
        outcomes: VecDeque<(Action, MutationOutcome)>,
        attempts: Vec<Action>,
        deploy_modes: Vec<api::ModuleDeployMode>,
        settlement_polls: Vec<usize>,
    }

    impl FakeOperations {
        fn new(reads: Vec<RemoteRelease>, outcomes: Vec<(Action, MutationOutcome)>) -> Self {
            Self {
                reads: reads.into(),
                outcomes: outcomes.into(),
                attempts: Vec::new(),
                deploy_modes: Vec::new(),
                settlement_polls: Vec::new(),
            }
        }

        fn mutate(&mut self, action: Action) -> Result<MutationOutcome> {
            self.attempts.push(action);
            let (expected, outcome) = self
                .outcomes
                .pop_front()
                .ok_or_else(|| anyhow!("unexpected mutation {action:?}"))?;
            if expected != action {
                return Err(anyhow!("expected mutation {expected:?}, got {action:?}"));
            }
            Ok(outcome)
        }
    }

    impl ReleaseOperations for FakeOperations {
        fn read_state(&mut self) -> Result<RemoteRelease> {
            self.reads
                .pop_front()
                .ok_or_else(|| anyhow!("unexpected owner-state read"))
        }

        fn record_version(&mut self) -> Result<MutationOutcome> {
            self.mutate(Action::RecordVersion)
        }

        fn capture_web_bundle(&mut self) -> Result<MutationOutcome> {
            self.mutate(Action::CaptureWebBundle)
        }

        fn upload_artifact(&mut self) -> Result<MutationOutcome> {
            self.mutate(Action::UploadArtifact)
        }

        fn deploy(&mut self, mode: api::ModuleDeployMode) -> Result<MutationOutcome> {
            self.deploy_modes.push(mode);
            self.mutate(Action::Deploy)
        }

        fn wait_before_deploy_settlement_read(&mut self, poll: usize) {
            self.settlement_polls.push(poll);
        }
    }

    fn planner_local(web_required: bool) -> LocalRelease {
        LocalRelease {
            source_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
            artifact_sha256: "a".repeat(64),
            artifact_size_bytes: 42,
            web_required,
            web_verified: false,
            local_simulation_authorized: false,
            desired_deploy_status: "active".into(),
        }
    }

    fn planner_artifact(status: &str) -> RemoteArtifact {
        let persisted = status != "missing";
        RemoteArtifact {
            status: status.into(),
            size_bytes: 42,
            sha256: "a".repeat(64),
            created: persisted,
            updated: persisted,
            finalized: status == "ready",
        }
    }

    fn planner_deploy(mode: &str, status: &str) -> RemoteDeploy {
        let artifact_mode = mode == "artifact";
        RemoteDeploy {
            mode: mode.into(),
            status: status.into(),
            source_sha256: Some("c".repeat(64)),
            manifest_sha256: Some("d".repeat(64)),
            artifact_sha256: artifact_mode.then(|| "a".repeat(64)),
            lambda_version: artifact_mode.then(|| "17".into()),
            lambda_code_sha256: artifact_mode.then(|| "a".repeat(64)),
            created: true,
            updated: true,
        }
    }

    fn planner_state(artifact_status: &str, deploy: Option<RemoteDeploy>) -> RemoteRelease {
        let ready = artifact_status == "ready"
            || deploy
                .as_ref()
                .is_some_and(|deploy| deploy.mode == "local_simulation");
        RemoteRelease::Present(Box::new(RemoteVersion {
            immutable_mismatches: Vec::new(),
            yanked: false,
            coherent: true,
            ready,
            web_bundle_url: String::new(),
            artifact: Some(planner_artifact(artifact_status)),
            deploy,
        }))
    }

    #[test]
    fn driver_matrix_noops_resumes_and_converges_atomic_races() {
        let done = planner_state("ready", Some(planner_deploy("artifact", "active")));
        let mut noop = FakeOperations::new(vec![done.clone()], vec![]);
        let result = drive_release(&mut noop, planner_local(false)).unwrap();
        assert!(result.attempts.is_empty());
        assert!(noop.attempts.is_empty());

        let ready = planner_state("ready", None);
        let mut resume = FakeOperations::new(
            vec![ready, done.clone()],
            vec![(Action::Deploy, MutationOutcome::Applied)],
        );
        let result = drive_release(&mut resume, planner_local(false)).unwrap();
        assert_eq!(result.attempts, vec![Action::Deploy]);
        assert_eq!(resume.deploy_modes, vec![api::ModuleDeployMode::Artifact]);

        let missing = planner_state("missing", None);
        let ready = planner_state("ready", None);
        let mut race = FakeOperations::new(
            vec![missing, ready, done],
            vec![
                (Action::UploadArtifact, MutationOutcome::Replan),
                (Action::Deploy, MutationOutcome::Applied),
            ],
        );
        let result = drive_release(&mut race, planner_local(false)).unwrap();
        assert_eq!(
            result.attempts,
            vec![Action::UploadArtifact, Action::Deploy]
        );
    }

    #[test]
    fn version_exists_must_be_visible_before_any_second_write() {
        let mut operations = FakeOperations::new(
            vec![RemoteRelease::Absent, RemoteRelease::Absent],
            vec![(Action::RecordVersion, MutationOutcome::VersionExists)],
        );
        let error = drive_release(&mut operations, planner_local(false))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("did not prove its complete postcondition"),
            "{error}"
        );
        assert_eq!(operations.attempts, vec![Action::RecordVersion]);
    }

    #[test]
    fn present_version_cannot_disappear_after_capture_or_upload_replan() {
        for (action, web_required) in [
            (Action::CaptureWebBundle, true),
            (Action::UploadArtifact, false),
        ] {
            let mut operations = FakeOperations::new(
                vec![planner_state("missing", None), RemoteRelease::Absent],
                vec![(action, MutationOutcome::Replan)],
            );
            let error = drive_release(&mut operations, planner_local(web_required))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("cannot become absent"),
                "{action:?}: {error}"
            );
            assert_eq!(operations.attempts, vec![action]);
        }
    }

    #[test]
    fn storage_unconfigured_is_the_only_local_simulation_authorization() {
        let missing = planner_state("missing", None);
        let done = planner_state(
            "missing",
            Some(planner_deploy("local_simulation", "active")),
        );
        let mut operations = FakeOperations::new(
            vec![missing.clone(), missing, done],
            vec![
                (Action::UploadArtifact, MutationOutcome::StorageUnconfigured),
                (Action::Deploy, MutationOutcome::Applied),
            ],
        );
        let result = drive_release(&mut operations, planner_local(false)).unwrap();
        assert_eq!(
            result.attempts,
            vec![Action::UploadArtifact, Action::Deploy]
        );
        assert_eq!(
            operations.deploy_modes,
            vec![api::ModuleDeployMode::LocalSimulation]
        );
    }

    #[test]
    fn ambiguous_deploy_only_polls_and_never_posts_twice() {
        let ready = planner_state("ready", None);
        let done = planner_state("ready", Some(planner_deploy("artifact", "active")));
        let mut delayed = FakeOperations::new(
            vec![ready.clone(), ready.clone(), ready.clone(), done],
            vec![(Action::Deploy, MutationOutcome::AmbiguousDeploy)],
        );
        let result = drive_release(&mut delayed, planner_local(false)).unwrap();
        assert_eq!(result.attempts, vec![Action::Deploy]);
        assert_eq!(delayed.attempts, vec![Action::Deploy]);
        assert_eq!(delayed.settlement_polls, vec![0, 1]);

        let mut never_settles = FakeOperations::new(
            std::iter::repeat_n(ready, AMBIGUOUS_DEPLOY_SETTLE_POLLS + 2).collect(),
            vec![(Action::Deploy, MutationOutcome::AmbiguousDeploy)],
        );
        let error = drive_release(&mut never_settles, planner_local(false))
            .unwrap_err()
            .to_string();
        assert!(error.contains("refusing a second deploy POST"), "{error}");
        assert_eq!(never_settles.attempts, vec![Action::Deploy]);
        assert_eq!(
            never_settles.settlement_polls,
            (0..AMBIGUOUS_DEPLOY_SETTLE_POLLS).collect::<Vec<_>>()
        );
    }

    #[test]
    fn only_exact_409_is_a_confirmed_deploy_race() {
        let race = mutation_error(
            ApiError::Server {
                status: 409,
                code: "artifact_not_ready".into(),
                message: "not ready".into(),
            },
            &["artifact_not_ready"],
            deploy_error_hint,
            true,
        )
        .unwrap();
        assert_eq!(race, MutationOutcome::Replan);

        let ambiguous = mutation_error(
            ApiError::Server {
                status: 500,
                code: "artifact_not_ready".into(),
                message: "wrong status".into(),
            },
            &["artifact_not_ready"],
            deploy_error_hint,
            true,
        )
        .unwrap();
        assert_eq!(ambiguous, MutationOutcome::AmbiguousDeploy);

        assert!(
            mutation_error(
                ApiError::Server {
                    status: 409,
                    code: "artifact_code_mismatch".into(),
                    message: "wrong bytes".into(),
                },
                &["artifact_not_ready"],
                deploy_error_hint,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn bad_remote_state_with_missing_web_performs_zero_writes() {
        let mut mismatched = planner_state("ready", None);
        let RemoteRelease::Present(version) = &mut mismatched else {
            unreachable!()
        };
        version.artifact.as_mut().unwrap().sha256 = "b".repeat(64);
        let mut operations = FakeOperations::new(vec![mismatched], vec![]);
        let error = drive_release(&mut operations, planner_local(true))
            .unwrap_err()
            .to_string();
        assert!(error.contains("different artifact"), "{error}");
        assert!(operations.attempts.is_empty());
    }

    #[test]
    fn immutable_metadata_comparison_matches_server_normalization() {
        let normalized = normalize_locale_map(BTreeMap::from([
            ("default".into(), "  - ship it\n".into()),
            ("empty".into(), " \n ".into()),
        ]));
        assert_eq!(
            normalized,
            BTreeMap::from([("default".into(), "- ship it".into())])
        );
        let manifest = serde_json::json!({
            "migration": {"app": "0008", "module": "0003"}
        });
        assert_eq!(manifest_migration_counter(&manifest, "app").unwrap(), 8);
        assert_eq!(manifest_migration_counter(&manifest, "module").unwrap(), 3);

        let mut state = matching_state(&candidate());
        let metadata = ReleaseMetadata {
            changelog: normalized,
            readme: BTreeMap::from([("default".into(), "# Media".into())]),
            migration_app: 8,
            migration_module: 3,
            changelog_warnings: Vec::new(),
            readme_truncated: false,
        };
        state.version.changelog = metadata.changelog.clone();
        state.version.readme = metadata.readme.clone();
        state.version.migration_app = 8;
        state.version.migration_module = 3;
        assert!(immutable_metadata_mismatches(&state.version, &metadata).is_empty());

        state
            .version
            .readme
            .insert("default".into(), "changed".into());
        state.version.channel = "beta".into();
        assert_eq!(
            immutable_metadata_mismatches(&state.version, &metadata),
            vec!["channel".to_string(), "readme".to_string()]
        );
    }

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
                title: String::new(),
                description: None,
                channel: VERSION_CHANNEL.to_string(),
                changelog: BTreeMap::new(),
                readme: BTreeMap::new(),
                migration_app: 0,
                migration_module: 0,
                manifest,
                published_at: "2026-08-31T00:00:00Z".to_string(),
                yanked_at: None,
                created_at: "2026-08-31T00:00:00Z".to_string(),
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
                "title": "",
                "description": null,
                "channel": VERSION_CHANNEL,
                "changelog": {},
                "readme": {},
                "migration_app": 0,
                "migration_module": 0,
                "manifest": manifest,
                "published_at": "2026-08-31T00:00:00Z",
                "yanked_at": null,
                "created_at": "2026-08-31T00:00:00Z"
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
        let base = server.url();
        let module = test_module();
        let metadata = test_metadata();
        let candidate = TestCandidate {
            receipt: local_candidate,
        };
        let mut operations = test_api_operations(&client, &base, &module, &candidate, &metadata);
        let error = operations.read_state().unwrap_err();

        reread.assert();
        assert!(
            error.to_string().contains("bound source receipt"),
            "{error:#}"
        );
    }

    #[test]
    fn fresh_version_rereads_then_recovers_web_before_artifact_writes() {
        let receipt = candidate();
        let pinned = "https://cdn.example.test/media/index.js";
        let path = "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3";
        let (base, server) = spawn_http_sequence(vec![
            ("GET", path, 200, matching_state_json(&receipt).to_string()),
            (
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
                200,
                capture_json(&receipt, pinned).to_string(),
            ),
            (
                "GET",
                path,
                200,
                matching_state_json_with_url(&receipt, pinned).to_string(),
            ),
        ]);
        let client = http::client(Duration::from_secs(15)).unwrap();
        let module = test_module();
        let metadata = test_metadata();
        let candidate = TestCandidate { receipt };
        let mut operations = test_api_operations(&client, &base, &module, &candidate, &metadata);
        assert!(matches!(
            operations.read_state().unwrap(),
            RemoteRelease::Present(_)
        ));
        assert_eq!(
            operations.capture_web_bundle().unwrap(),
            MutationOutcome::Applied
        );
        let state = operations.read_state().unwrap();
        server.join().unwrap();
        let RemoteRelease::Present(state) = state else {
            panic!("captured release disappeared")
        };
        assert_eq!(state.web_bundle_url, pinned);
    }

    #[test]
    fn existing_pinned_web_is_still_verified_before_artifact_writes() {
        let receipt = candidate();
        let pinned = "https://cdn.example.test/media/index.js";
        let state_path = "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3";
        let (base, server) = spawn_http_sequence(vec![
            (
                "GET",
                state_path,
                200,
                matching_state_json_with_url(&receipt, pinned).to_string(),
            ),
            (
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
                200,
                capture_json(&receipt, pinned).to_string(),
            ),
            (
                "GET",
                state_path,
                200,
                matching_state_json_with_url(&receipt, pinned).to_string(),
            ),
        ]);
        let client = http::client(Duration::from_secs(15)).unwrap();
        let module = test_module();
        let metadata = test_metadata();
        let candidate = TestCandidate { receipt };
        let mut operations = test_api_operations(&client, &base, &module, &candidate, &metadata);
        operations.read_state().unwrap();
        assert_eq!(
            operations.capture_web_bundle().unwrap(),
            MutationOutcome::Applied
        );
        operations.read_state().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn production_capture_validation_never_moves_an_observed_pinned_url() {
        let receipt = candidate();
        let pinned = "https://cdn.example.test/media/index.js";
        let moved = "https://cdn.example.test/media/replacement.js";
        let (base, server) = spawn_http_sequence(vec![
            (
                "GET",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3",
                200,
                matching_state_json_with_url(&receipt, pinned).to_string(),
            ),
            (
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
                200,
                capture_json(&receipt, moved).to_string(),
            ),
        ]);
        let client = http::client(Duration::from_secs(15)).unwrap();
        let module = test_module();
        let metadata = test_metadata();
        let candidate = TestCandidate { receipt };
        let mut operations = test_api_operations(&client, &base, &module, &candidate, &metadata);
        operations.read_state().unwrap();
        let error = operations.capture_web_bundle().unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("move the immutable pinned URL"));
    }

    #[test]
    fn mismatched_capture_response_fails_before_owner_reread_or_artifact_write() {
        let receipt = candidate();
        let mut wrong = capture_json(&receipt, "https://cdn.example.test/media/index.js");
        wrong["web_bundle_sha256"] = serde_json::Value::String("d".repeat(64));
        let (base, server) = spawn_http_sequence(vec![
            (
                "GET",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3",
                200,
                matching_state_json(&receipt).to_string(),
            ),
            (
                "POST",
                "/v1/modules/11111111-1111-1111-1111-111111111111/versions/1.2.3/bundle/capture",
                200,
                wrong.to_string(),
            ),
        ]);
        let client = http::client(Duration::from_secs(15)).unwrap();
        let module = test_module();
        let metadata = test_metadata();
        let candidate = TestCandidate { receipt };
        let mut operations = test_api_operations(&client, &base, &module, &candidate, &metadata);
        operations.read_state().unwrap();
        let error = operations.capture_web_bundle().unwrap_err();
        server.join().unwrap();
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
