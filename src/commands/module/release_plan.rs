//! Pure release-state planning for `module deploy`.
//!
//! The command never infers that a timed-out write succeeded. It reads the
//! owner-only version aggregate, asks this module for exactly one next action,
//! performs that action, and reads again. Keeping the decision table free of
//! HTTP and filesystem concerns makes every zero-write and recovery path
//! directly testable.

use thiserror::Error;

/// Facts computed from the exact local ZIP and requested deploy shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalRelease {
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub web_required: bool,
    pub desired_deploy_status: String,
}

/// The owner release-state route either proves absence or returns the whole
/// version/artifact/deploy aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RemoteRelease {
    Absent,
    Present(RemoteVersion),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteVersion {
    /// Immutable request-derived fields that differ from the local release.
    /// Empty means semantic manifest + normalized metadata are exact.
    pub immutable_mismatches: Vec<String>,
    pub yanked: bool,
    pub web_bundle_url: String,
    pub artifact: Option<RemoteArtifact>,
    pub deploy: Option<RemoteDeploy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteArtifact {
    pub status: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RemoteDeploy {
    pub status: String,
    pub invoke_target: String,
    pub artifact_sha256: Option<String>,
}

/// Exactly one safe next mutation, or `Done` when no POST is needed.
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
        "version is already recorded with different immutable metadata ({fields}); versions are immutable — bump the version before deploying these bytes"
    )]
    ImmutableMismatch { fields: String },
    #[error(
        "version is yanked; refusing to upload or deploy an immutable release that the owner has withdrawn"
    )]
    YankedVersion,
    #[error(
        "version already has a different ready artifact ({remote_size} bytes, sha256:{remote_sha256}); local ZIP is {local_size} bytes, sha256:{local_sha256} — bump the version instead of replacing immutable bytes"
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

    // Validate the entire artifact/deploy snapshot before choosing capture.
    // Capture is a write too: a missing web URL must never mask a mismatched,
    // unknown, or contradictory Lambda state and earn that bad release a POST.
    let next = plan_artifact_and_deploy(local, version)?;

    // Once all existing remote evidence is known-safe, bundle capture still
    // precedes either artifact or deploy mutation for a web module.
    if local.web_required && version.web_bundle_url.trim().is_empty() {
        return Ok(Action::CaptureWebBundle);
    }

    Ok(next)
}

fn plan_artifact_and_deploy(
    local: &LocalRelease,
    version: &RemoteVersion,
) -> Result<Action, PlanError> {
    let Some(artifact) = &version.artifact else {
        if version.deploy.is_some() {
            return Err(PlanError::ContradictoryState(
                "a deploy exists without an artifact".into(),
            ));
        }
        return Ok(Action::UploadArtifact);
    };

    match artifact.status.as_str() {
        "pending" => {
            if version.deploy.is_some() {
                return Err(PlanError::ContradictoryState(
                    "a deploy exists while its artifact is pending".into(),
                ));
            }
            if artifact.size_bytes != 0 || !artifact.sha256.is_empty() {
                return Err(PlanError::ContradictoryState(
                    "a pending artifact carries ready-only size or SHA-256 evidence".into(),
                ));
            }
            Ok(Action::UploadArtifact)
        }
        "ready" => plan_ready(local, artifact, version.deploy.as_ref()),
        other => Err(PlanError::UnknownArtifactState(other.to_string())),
    }
}

fn plan_ready(
    local: &LocalRelease,
    artifact: &RemoteArtifact,
    deploy: Option<&RemoteDeploy>,
) -> Result<Action, PlanError> {
    if artifact.size_bytes == 0 || !valid_sha256(&artifact.sha256) {
        return Err(PlanError::ContradictoryState(
            "a ready artifact lacks valid size/SHA-256 evidence".into(),
        ));
    }
    if artifact.size_bytes != local.artifact_size_bytes || artifact.sha256 != local.artifact_sha256
    {
        return Err(PlanError::ArtifactMismatch {
            remote_size: artifact.size_bytes,
            remote_sha256: artifact.sha256.clone(),
            local_size: local.artifact_size_bytes,
            local_sha256: local.artifact_sha256.clone(),
        });
    }

    let Some(deploy) = deploy else {
        return Ok(Action::Deploy);
    };

    // A failed provisioning attempt may be retried, but if it carries a
    // binding it still may not name different bytes.
    if deploy.status == "failed" {
        if deploy
            .artifact_sha256
            .as_deref()
            .is_some_and(|sha| sha != local.artifact_sha256)
        {
            return Err(PlanError::ContradictoryState(
                "the failed deploy is bound to a different artifact SHA-256".into(),
            ));
        }
        return Ok(Action::Deploy);
    }

    if !matches!(deploy.status.as_str(), "active" | "draining" | "disabled") {
        return Err(PlanError::UnknownDeployState(deploy.status.clone()));
    }
    if deploy.invoke_target.trim().is_empty() {
        return Err(PlanError::ContradictoryState(
            "a deployed release has an empty invoke target".into(),
        ));
    }
    if deploy.artifact_sha256.as_deref() != Some(local.artifact_sha256.as_str()) {
        return Err(PlanError::ContradictoryState(
            "the deploy is not bound to the exact ready artifact SHA-256".into(),
        ));
    }

    if deploy.status == local.desired_deploy_status {
        Ok(Action::Done)
    } else {
        Ok(Action::Deploy)
    }
}

fn validate_local(local: &LocalRelease) -> Result<(), PlanError> {
    if local.artifact_size_bytes == 0 {
        return Err(PlanError::InvalidLocalEvidence(
            "ZIP size must be greater than zero".into(),
        ));
    }
    if !valid_sha256(&local.artifact_sha256) {
        return Err(PlanError::InvalidLocalEvidence(
            "SHA-256 must be 64 lowercase hexadecimal characters".into(),
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
            artifact_sha256: SHA.into(),
            artifact_size_bytes: 42,
            web_required: false,
            desired_deploy_status: "active".into(),
        }
    }

    fn version(artifact: Option<RemoteArtifact>, deploy: Option<RemoteDeploy>) -> RemoteRelease {
        RemoteRelease::Present(RemoteVersion {
            immutable_mismatches: Vec::new(),
            yanked: false,
            web_bundle_url: String::new(),
            artifact,
            deploy,
        })
    }

    fn ready() -> RemoteArtifact {
        RemoteArtifact {
            status: "ready".into(),
            size_bytes: 42,
            sha256: SHA.into(),
        }
    }

    fn deployed(status: &str) -> RemoteDeploy {
        RemoteDeploy {
            status: status.into(),
            invoke_target: "ms-module-id:mv-version-id".into(),
            artifact_sha256: Some(SHA.into()),
        }
    }

    #[test]
    fn action_matrix_covers_absent_pending_ready_and_deployed_states() {
        let pending = RemoteArtifact {
            status: "pending".into(),
            size_bytes: 0,
            sha256: String::new(),
        };
        let failed = RemoteDeploy {
            status: "failed".into(),
            invoke_target: String::new(),
            artifact_sha256: None,
        };
        let cases = [
            ("absent", RemoteRelease::Absent, Action::RecordVersion),
            (
                "missing artifact",
                version(None, None),
                Action::UploadArtifact,
            ),
            (
                "pending artifact",
                version(Some(pending), None),
                Action::UploadArtifact,
            ),
            (
                "ready artifact",
                version(Some(ready()), None),
                Action::Deploy,
            ),
            (
                "failed deploy",
                version(Some(ready()), Some(failed)),
                Action::Deploy,
            ),
            (
                "different known status",
                version(Some(ready()), Some(deployed("draining"))),
                Action::Deploy,
            ),
            (
                "exact deployed",
                version(Some(ready()), Some(deployed("active"))),
                Action::Done,
            ),
        ];

        for (name, remote, want) in cases {
            assert_eq!(plan(&local(), &remote), Ok(want), "{name}");
        }
    }

    #[test]
    fn required_web_bundle_is_recovered_before_artifact_or_deploy_writes() {
        let mut release = local();
        release.web_required = true;
        let remote = version(Some(ready()), Some(deployed("active")));
        assert_eq!(plan(&release, &remote), Ok(Action::CaptureWebBundle));

        let RemoteRelease::Present(mut captured) = remote else {
            unreachable!()
        };
        captured.web_bundle_url = "https://cdn.example/module.js".into();
        assert_eq!(
            plan(&release, &RemoteRelease::Present(captured)),
            Ok(Action::Done)
        );
    }

    #[test]
    fn required_web_capture_never_masks_bad_artifact_or_deploy_state() {
        let mut release = local();
        release.web_required = true;
        let cases = [
            version(
                Some(RemoteArtifact {
                    sha256: OTHER_SHA.into(),
                    ..ready()
                }),
                None,
            ),
            version(
                Some(RemoteArtifact {
                    status: "mystery".into(),
                    size_bytes: 0,
                    sha256: String::new(),
                }),
                None,
            ),
            version(None, Some(deployed("active"))),
            version(Some(ready()), Some(deployed("mystery"))),
        ];

        for remote in cases {
            assert!(
                plan(&release, &remote).is_err(),
                "missing web evidence masked bad remote state: {remote:?}"
            );
        }
    }

    #[test]
    fn immutable_mismatch_fails_before_any_action() {
        let mut remote = version(None, None);
        let RemoteRelease::Present(version) = &mut remote else {
            unreachable!()
        };
        version.immutable_mismatches = vec!["manifest".into(), "readme".into()];
        assert!(matches!(
            plan(&local(), &remote),
            Err(PlanError::ImmutableMismatch { fields })
                if fields == "manifest, readme"
        ));
    }

    #[test]
    fn yanked_version_fails_before_any_action() {
        let mut remote = version(None, None);
        let RemoteRelease::Present(version) = &mut remote else {
            unreachable!()
        };
        version.yanked = true;
        assert_eq!(plan(&local(), &remote), Err(PlanError::YankedVersion));
    }

    #[test]
    fn ready_artifact_sha_or_size_mismatch_fails_closed() {
        for artifact in [
            RemoteArtifact {
                sha256: OTHER_SHA.into(),
                ..ready()
            },
            RemoteArtifact {
                size_bytes: 43,
                ..ready()
            },
        ] {
            assert!(matches!(
                plan(&local(), &version(Some(artifact), None)),
                Err(PlanError::ArtifactMismatch { .. })
            ));
        }
    }

    #[test]
    fn unknown_and_contradictory_states_fail_closed() {
        let cases = [
            version(
                Some(RemoteArtifact {
                    status: "mystery".into(),
                    size_bytes: 0,
                    sha256: String::new(),
                }),
                None,
            ),
            version(Some(ready()), Some(deployed("mystery"))),
            version(None, Some(deployed("active"))),
            version(
                Some(RemoteArtifact {
                    status: "pending".into(),
                    size_bytes: 42,
                    sha256: SHA.into(),
                }),
                None,
            ),
            version(
                Some(ready()),
                Some(RemoteDeploy {
                    artifact_sha256: Some(OTHER_SHA.into()),
                    ..deployed("active")
                }),
            ),
        ];

        for remote in cases {
            assert!(plan(&local(), &remote).is_err(), "{remote:?}");
        }
    }

    #[test]
    fn malformed_local_or_ready_evidence_is_rejected() {
        let mut malformed = local();
        malformed.artifact_sha256 = SHA.to_uppercase();
        assert!(matches!(
            plan(&malformed, &RemoteRelease::Absent),
            Err(PlanError::InvalidLocalEvidence(_))
        ));

        let malformed_ready = RemoteArtifact {
            status: "ready".into(),
            size_bytes: 42,
            sha256: "short".into(),
        };
        assert!(matches!(
            plan(&local(), &version(Some(malformed_ready), None)),
            Err(PlanError::ContradictoryState(_))
        ));
    }
}
