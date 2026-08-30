//! Pure release-state planning for `module deploy`.
//!
//! The command turns one authoritative owner-state snapshot into exactly one
//! safe action. HTTP and filesystem code stay outside this module so every
//! zero-write, resume, and contradiction branch is table-testable.

use thiserror::Error;

/// Local facts attested before any release mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalRelease {
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub web_required: bool,
    /// The current command has called the idempotent capture endpoint and a
    /// later owner-state read proved the same non-empty pinned URL.
    pub web_verified: bool,
    /// Set only after artifact create explicitly returns
    /// `artifact_storage_unconfigured` in this command.
    pub local_simulation_authorized: bool,
    pub desired_deploy_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RemoteRelease {
    Absent,
    Present(Box<RemoteVersion>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteVersion {
    /// Immutable candidate fields that differ from local evidence. Production
    /// conversion normally rejects these before planning; retaining the list
    /// here makes the planner itself fail closed and directly testable.
    pub immutable_mismatches: Vec<String>,
    pub yanked: bool,
    pub coherent: bool,
    pub ready: bool,
    pub web_bundle_url: String,
    /// Bound #665 releases always expose their expected artifact tuple, even
    /// before an upload row exists. `None` is legacy/incomplete state.
    pub artifact: Option<RemoteArtifact>,
    pub deploy: Option<RemoteDeploy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteArtifact {
    pub status: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub created: bool,
    pub updated: bool,
    pub finalized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteDeploy {
    pub mode: String,
    pub status: String,
    pub source_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub artifact_sha256: Option<String>,
    pub lambda_version: Option<String>,
    pub lambda_code_sha256: Option<String>,
    pub created: bool,
    pub updated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    RecordVersion,
    CaptureWebBundle,
    UploadArtifact,
    Deploy,
    Done,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(super) enum PlanError {
    #[error("local artifact evidence is invalid: {0}")]
    InvalidLocalEvidence(String),
    #[error(
        "version is already recorded with different immutable evidence ({fields}); versions are immutable — bump the version before deploying different bytes"
    )]
    ImmutableMismatch { fields: String },
    #[error(
        "version is yanked; refusing to mutate an immutable release that the owner has withdrawn"
    )]
    YankedVersion,
    #[error(
        "version expects a different artifact ({remote_size} bytes, sha256:{remote_sha256}); local ZIP is {local_size} bytes, sha256:{local_sha256} — bump the version instead of replacing immutable bytes"
    )]
    ArtifactMismatch {
        remote_size: u64,
        remote_sha256: String,
        local_size: u64,
        local_sha256: String,
    },
    #[error("unknown artifact state {0:?}; refusing to mutate an ambiguous release")]
    UnknownArtifactState(String),
    #[error("unknown deploy state {0:?}; refusing to mutate an ambiguous release")]
    UnknownDeployState(String),
    #[error("contradictory release state: {0}; refusing to write")]
    ContradictoryState(String),
}

/// Return one safe next action from an authoritative snapshot.
pub(super) fn plan(local: &LocalRelease, remote: &RemoteRelease) -> Result<Action, PlanError> {
    validate_local(local)?;

    let RemoteRelease::Present(version) = remote else {
        return Ok(Action::RecordVersion);
    };
    if !version.immutable_mismatches.is_empty() {
        return Err(PlanError::ImmutableMismatch {
            fields: version.immutable_mismatches.join(", "),
        });
    }
    if version.yanked {
        return Err(PlanError::YankedVersion);
    }
    if !version.coherent {
        return Err(PlanError::ContradictoryState(
            "the platform marked the bound release receipt incoherent".into(),
        ));
    }

    // Validate every artifact/deploy field before choosing capture. Capture
    // is a write too; missing web evidence cannot mask unsafe Lambda state.
    let next = plan_artifact_and_deploy(local, version)?;
    validate_ready_flag(local, version)?;
    if local.web_required {
        if version.web_bundle_url.trim().is_empty() {
            return Ok(Action::CaptureWebBundle);
        }
        // A fully deployed exact release is a true zero-POST success. Before
        // any other mutation, however, re-run capture's VerifyPinned branch
        // once in this process and prove its result by owner-state reread.
        if next != Action::Done && !local.web_verified {
            return Ok(Action::CaptureWebBundle);
        }
    }
    Ok(next)
}

fn plan_artifact_and_deploy(
    local: &LocalRelease,
    version: &RemoteVersion,
) -> Result<Action, PlanError> {
    let artifact = version.artifact.as_ref().ok_or_else(|| {
        PlanError::ContradictoryState(
            "a bound version has no immutable expected artifact receipt".into(),
        )
    })?;
    validate_artifact(local, artifact)?;
    if let Some(deploy) = version.deploy.as_ref() {
        validate_deploy(local, artifact, deploy)?;
        if deploy.status == local.desired_deploy_status {
            return Ok(Action::Done);
        }
    }

    if artifact.status == "ready" {
        return Ok(Action::Deploy);
    }
    if local.local_simulation_authorized {
        return Ok(Action::Deploy);
    }
    Ok(Action::UploadArtifact)
}

fn validate_ready_flag(local: &LocalRelease, version: &RemoteVersion) -> Result<(), PlanError> {
    let web_ready = !local.web_required || !version.web_bundle_url.trim().is_empty();
    let material_ready = version
        .artifact
        .as_ref()
        .is_some_and(|artifact| artifact.status == "ready")
        || version
            .deploy
            .as_ref()
            .is_some_and(|deploy| deploy.mode == "local_simulation");
    let expected = web_ready && material_ready;
    if version.ready != expected {
        return Err(PlanError::ContradictoryState(format!(
            "platform ready={} disagrees with exact web/artifact/deploy evidence (expected {expected})",
            version.ready
        )));
    }
    Ok(())
}

fn validate_artifact(local: &LocalRelease, artifact: &RemoteArtifact) -> Result<(), PlanError> {
    if artifact.size_bytes != local.artifact_size_bytes || artifact.sha256 != local.artifact_sha256
    {
        return Err(PlanError::ArtifactMismatch {
            remote_size: artifact.size_bytes,
            remote_sha256: artifact.sha256.clone(),
            local_size: local.artifact_size_bytes,
            local_sha256: local.artifact_sha256.clone(),
        });
    }
    match artifact.status.as_str() {
        "missing" => {
            if artifact.created || artifact.updated || artifact.finalized {
                return Err(PlanError::ContradictoryState(
                    "a missing artifact carries persisted lifecycle timestamps".into(),
                ));
            }
        }
        "pending" => {
            if !artifact.created || !artifact.updated || artifact.finalized {
                return Err(PlanError::ContradictoryState(
                    "a pending artifact lacks created/updated evidence or is already finalized"
                        .into(),
                ));
            }
        }
        "ready" => {
            if !artifact.created || !artifact.updated || !artifact.finalized {
                return Err(PlanError::ContradictoryState(
                    "a ready artifact lacks complete lifecycle evidence".into(),
                ));
            }
        }
        other => return Err(PlanError::UnknownArtifactState(other.to_string())),
    }
    Ok(())
}

fn validate_deploy(
    local: &LocalRelease,
    artifact: &RemoteArtifact,
    deploy: &RemoteDeploy,
) -> Result<(), PlanError> {
    if !deploy.created || !deploy.updated {
        return Err(PlanError::ContradictoryState(
            "a deploy lacks created/updated evidence".into(),
        ));
    }
    if deploy.source_sha256.as_deref() != Some(local.source_sha256.as_str())
        || deploy.manifest_sha256.as_deref() != Some(local.manifest_sha256.as_str())
    {
        return Err(PlanError::ContradictoryState(
            "deploy is not bound to the exact source and manifest evidence".into(),
        ));
    }
    if !matches!(
        deploy.status.as_str(),
        "active" | "draining" | "disabled" | "failed"
    ) {
        return Err(PlanError::UnknownDeployState(deploy.status.clone()));
    }

    match deploy.mode.as_str() {
        "artifact" => {
            if artifact.status != "ready" {
                return Err(PlanError::ContradictoryState(
                    "an artifact-mode deploy exists without a ready artifact".into(),
                ));
            }
            if deploy.artifact_sha256.as_deref() != Some(local.artifact_sha256.as_str())
                || deploy.lambda_version.as_deref().is_none_or(str::is_empty)
                || deploy.lambda_code_sha256.as_deref() != Some(local.artifact_sha256.as_str())
            {
                return Err(PlanError::ContradictoryState(
                    "artifact deploy is not bound to the exact ready ZIP and Lambda code".into(),
                ));
            }
        }
        "local_simulation" => {
            if deploy.artifact_sha256.is_some()
                || deploy.lambda_version.is_some()
                || deploy.lambda_code_sha256.is_some()
            {
                return Err(PlanError::ContradictoryState(
                    "local-simulation deploy carries artifact or Lambda evidence".into(),
                ));
            }
        }
        other => return Err(PlanError::UnknownDeployState(other.to_string())),
    }
    Ok(())
}

fn validate_local(local: &LocalRelease) -> Result<(), PlanError> {
    if local.artifact_size_bytes == 0 {
        return Err(PlanError::InvalidLocalEvidence(
            "ZIP size must be greater than zero".into(),
        ));
    }
    if !valid_sha256(&local.source_sha256)
        || !valid_sha256(&local.manifest_sha256)
        || !valid_sha256(&local.artifact_sha256)
    {
        return Err(PlanError::InvalidLocalEvidence(
            "source, manifest, and artifact SHA-256 values must be 64 lowercase hexadecimal characters"
                .into(),
        ));
    }
    if !matches!(
        local.desired_deploy_status.as_str(),
        "active" | "draining" | "disabled"
    ) {
        return Err(PlanError::InvalidLocalEvidence(format!(
            "unknown desired deploy status {:?}",
            local.desired_deploy_status
        )));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn local() -> LocalRelease {
        LocalRelease {
            source_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
            artifact_sha256: SHA.into(),
            artifact_size_bytes: 42,
            web_required: false,
            web_verified: false,
            local_simulation_authorized: false,
            desired_deploy_status: "active".into(),
        }
    }

    fn artifact(status: &str) -> RemoteArtifact {
        let persisted = status != "missing";
        RemoteArtifact {
            status: status.into(),
            size_bytes: 42,
            sha256: SHA.into(),
            created: persisted,
            updated: persisted,
            finalized: status == "ready",
        }
    }

    fn deploy(mode: &str, status: &str) -> RemoteDeploy {
        let artifact_mode = mode == "artifact";
        RemoteDeploy {
            mode: mode.into(),
            status: status.into(),
            source_sha256: Some("c".repeat(64)),
            manifest_sha256: Some("d".repeat(64)),
            artifact_sha256: artifact_mode.then(|| SHA.into()),
            lambda_version: artifact_mode.then(|| "17".into()),
            lambda_code_sha256: artifact_mode.then(|| SHA.into()),
            created: true,
            updated: true,
        }
    }

    fn present(artifact: Option<RemoteArtifact>, deploy: Option<RemoteDeploy>) -> RemoteRelease {
        RemoteRelease::Present(Box::new(RemoteVersion {
            immutable_mismatches: Vec::new(),
            yanked: false,
            coherent: true,
            ready: artifact
                .as_ref()
                .is_some_and(|artifact| artifact.status == "ready")
                || deploy
                    .as_ref()
                    .is_some_and(|deploy| deploy.mode == "local_simulation"),
            web_bundle_url: String::new(),
            artifact,
            deploy,
        }))
    }

    #[test]
    fn action_matrix_covers_bound_lifecycle_and_exact_noop() {
        let cases = [
            ("absent", RemoteRelease::Absent, Action::RecordVersion),
            (
                "missing",
                present(Some(artifact("missing")), None),
                Action::UploadArtifact,
            ),
            (
                "pending",
                present(Some(artifact("pending")), None),
                Action::UploadArtifact,
            ),
            (
                "ready",
                present(Some(artifact("ready")), None),
                Action::Deploy,
            ),
            (
                "failed deploy",
                present(Some(artifact("ready")), Some(deploy("artifact", "failed"))),
                Action::Deploy,
            ),
            (
                "different status",
                present(
                    Some(artifact("ready")),
                    Some(deploy("artifact", "draining")),
                ),
                Action::Deploy,
            ),
            (
                "exact artifact deploy",
                present(Some(artifact("ready")), Some(deploy("artifact", "active"))),
                Action::Done,
            ),
            (
                "exact local deploy",
                present(
                    Some(artifact("missing")),
                    Some(deploy("local_simulation", "active")),
                ),
                Action::Done,
            ),
        ];
        for (name, state, want) in cases {
            assert_eq!(plan(&local(), &state), Ok(want), "{name}");
        }
    }

    #[test]
    fn web_capture_precedes_mutation_but_not_exact_noop() {
        let mut release = local();
        release.web_required = true;
        let mut uncaptured = present(Some(artifact("ready")), None);
        let RemoteRelease::Present(version) = &mut uncaptured else {
            unreachable!()
        };
        version.ready = false;
        assert_eq!(plan(&release, &uncaptured), Ok(Action::CaptureWebBundle));

        let mut ready = present(Some(artifact("ready")), None);
        let RemoteRelease::Present(version) = &mut ready else {
            unreachable!()
        };
        version.web_bundle_url = "https://cdn.example/module.js".into();
        assert_eq!(plan(&release, &ready), Ok(Action::CaptureWebBundle));
        release.web_verified = true;
        assert_eq!(plan(&release, &ready), Ok(Action::Deploy));

        let mut done = present(Some(artifact("ready")), Some(deploy("artifact", "active")));
        let RemoteRelease::Present(version) = &mut done else {
            unreachable!()
        };
        version.web_bundle_url = "https://cdn.example/module.js".into();
        release.web_verified = false;
        assert_eq!(plan(&release, &done), Ok(Action::Done));
    }

    #[test]
    fn required_web_never_masks_bad_remote_state() {
        let mut release = local();
        release.web_required = true;
        let cases = [
            present(
                Some(RemoteArtifact {
                    sha256: OTHER_SHA.into(),
                    ..artifact("ready")
                }),
                None,
            ),
            present(Some(artifact("mystery")), None),
            present(None, Some(deploy("artifact", "active"))),
            present(Some(artifact("ready")), Some(deploy("artifact", "mystery"))),
        ];
        for state in cases {
            assert!(plan(&release, &state).is_err(), "{state:?}");
        }
    }

    #[test]
    fn local_fallback_requires_current_explicit_authorization() {
        let state = present(Some(artifact("missing")), None);
        assert_eq!(plan(&local(), &state), Ok(Action::UploadArtifact));
        let mut authorized = local();
        authorized.local_simulation_authorized = true;
        assert_eq!(plan(&authorized, &state), Ok(Action::Deploy));
    }

    #[test]
    fn immutable_yanked_mismatch_unknown_and_contradictory_states_fail() {
        let mut mismatch = present(Some(artifact("missing")), None);
        let RemoteRelease::Present(version) = &mut mismatch else {
            unreachable!()
        };
        version.immutable_mismatches = vec!["manifest".into()];
        assert!(matches!(
            plan(&local(), &mismatch),
            Err(PlanError::ImmutableMismatch { .. })
        ));

        let mut yanked = present(Some(artifact("missing")), None);
        let RemoteRelease::Present(version) = &mut yanked else {
            unreachable!()
        };
        version.yanked = true;
        assert_eq!(plan(&local(), &yanked), Err(PlanError::YankedVersion));

        let cases = [
            present(Some(artifact("mystery")), None),
            present(None, None),
            present(
                Some(artifact("pending")),
                Some(deploy("artifact", "active")),
            ),
            present(
                Some(artifact("ready")),
                Some(RemoteDeploy {
                    artifact_sha256: Some(OTHER_SHA.into()),
                    ..deploy("artifact", "active")
                }),
            ),
        ];
        for state in cases {
            assert!(plan(&local(), &state).is_err(), "{state:?}");
        }
    }

    #[test]
    fn malformed_local_or_lifecycle_evidence_is_rejected() {
        let mut malformed = local();
        malformed.artifact_sha256 = SHA.to_uppercase();
        assert!(matches!(
            plan(&malformed, &RemoteRelease::Absent),
            Err(PlanError::InvalidLocalEvidence(_))
        ));

        let mut bad_ready = artifact("ready");
        bad_ready.finalized = false;
        assert!(matches!(
            plan(&local(), &present(Some(bad_ready), None)),
            Err(PlanError::ContradictoryState(_))
        ));

        let mut false_ready = present(Some(artifact("ready")), None);
        let RemoteRelease::Present(version) = &mut false_ready else {
            unreachable!()
        };
        version.ready = false;
        assert!(matches!(
            plan(&local(), &false_ready),
            Err(PlanError::ContradictoryState(_))
        ));

        let mut false_unready = present(Some(artifact("missing")), None);
        let RemoteRelease::Present(version) = &mut false_unready else {
            unreachable!()
        };
        version.ready = true;
        assert!(matches!(
            plan(&local(), &false_unready),
            Err(PlanError::ContradictoryState(_))
        ));
    }
}
