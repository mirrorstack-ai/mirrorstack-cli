//! Build one immutable, locally attested module release candidate.
//!
//! Manifest, web, and Linux artifact evidence are all produced from one
//! frozen Git working-set stage. The live worktree is checked again after the
//! builds, and a web module must match the exact bundle confirmed for this
//! workspace's current one-shot tunnel session.

use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

use super::dev::release_session::{ConfirmedWeb, load_for_module};
use super::dev::{WebPipeline, web_pipeline};
use super::module::artifact;

mod process;
pub(crate) mod source;
mod web_dependencies;

use process::{ProcessOutput, ProcessRunner, ProcessSpec, SystemRunner};
use source::{BuildView, SourceSnapshot};

pub(crate) const CANDIDATE_PROTOCOL: &str = "mirrorstack.release-candidate/v1";
const MANIFEST_PROTOCOL: &str = "mirrorstack.release-manifest/v1";
const MANIFEST_TOOL_MODE: &str = "release-manifest-v1";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_STDOUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_WEB_BYTES: u64 = 32 * 1024 * 1024;
// The #665 version-create envelope is capped at 2 MiB. A 1 MiB manifest
// expands to ~1.34 MiB in padded base64, so this leaves room for the remaining
// candidate fields and version documentation in the outer request.
const MAX_CANDIDATE_RECEIPT_BYTES: usize = 1536 * 1024;

pub(crate) struct CandidateRequest<'a> {
    pub module_dir: &'a Path,
    pub slug: &'a str,
    pub module_id: &'a str,
    /// Canonical platform SemVer, without `v`.
    pub version: &'a str,
    /// Exact key declared in `Config.Versions`, normally `v<version>`.
    pub source_version_key: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestEvidence {
    pub sha256: String,
    /// Standard padded base64 of the SDK's exact canonical served bytes,
    /// including its trailing newline. #665 must consume these bytes rather
    /// than a reserialized JSON value.
    pub base64: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebEvidence {
    pub session_id: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactEvidence {
    pub sha256: String,
    pub size_bytes: u64,
    pub os: String,
    pub arch: String,
    pub format: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseCandidateReceipt {
    pub protocol: String,
    pub module_id: String,
    pub slug: String,
    pub version: String,
    pub source_sha256: String,
    pub manifest: ManifestEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<WebEvidence>,
    pub artifact: ArtifactEvidence,
}

/// Owns every temporary path referenced by the receipt. Dropping the value
/// invalidates the ZIP, so deploy keeps it alive through upload/finalize.
pub(crate) struct ReleaseCandidate {
    source: SourceSnapshot,
    artifact_dir: TempDir,
    receipt: ReleaseCandidateReceipt,
    artifact_path: PathBuf,
    _receipt_path: PathBuf,
}

impl ReleaseCandidate {
    pub(crate) fn receipt(&self) -> &ReleaseCandidateReceipt {
        &self.receipt
    }

    pub(crate) fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    #[cfg(test)]
    fn receipt_path(&self) -> &Path {
        &self._receipt_path
    }

    pub(crate) fn source_module_dir(&self) -> PathBuf {
        self.source.module_dir()
    }

    pub(crate) fn verify_live_source(&self) -> Result<()> {
        self.source.verify_unchanged()
    }

    pub(crate) fn verify_artifact(&self) -> Result<()> {
        let relative = self
            .artifact_path
            .strip_prefix(self.artifact_dir.path())
            .map_err(|_| anyhow!("release candidate: artifact escaped its owned directory"))?;
        let bytes = source::read_regular_bounded(
            self.artifact_dir.path(),
            relative,
            self.receipt.artifact.size_bytes,
            "packaged Linux artifact",
        )?;
        let actual = sha256_hex(&bytes);
        if bytes.len() as u64 != self.receipt.artifact.size_bytes
            || actual != self.receipt.artifact.sha256
        {
            return Err(anyhow!(
                "release candidate: packaged artifact changed after attestation (expected {}, {} bytes; current {actual}, {} bytes)",
                self.receipt.artifact.sha256,
                self.receipt.artifact.size_bytes,
                bytes.len()
            ));
        }
        Ok(())
    }
}

pub(crate) fn build(request: CandidateRequest<'_>) -> Result<ReleaseCandidate> {
    build_with(&SystemRunner, request)
}

fn build_with(
    runner: &dyn ProcessRunner,
    request: CandidateRequest<'_>,
) -> Result<ReleaseCandidate> {
    let source = SourceSnapshot::create(request.module_dir)?;
    let replace_view = source.fresh_view("replace-check")?;
    let replace_go = GoEnvironment::new("replace-check")?;
    validate_local_replaces(runner, &replace_view, &replace_go)?;
    replace_view
        .verify_inputs()
        .context("release candidate: local-replace inspection changed its frozen phase inputs")?;

    let manifest_view = source.fresh_view("manifest")?;
    let manifest_go = GoEnvironment::new("manifest")?;
    let (manifest_evidence, manifest) = run_manifest_probe(
        runner,
        &manifest_view.module_dir(),
        &manifest_go,
        source.source_sha256(),
        request.source_version_key,
        request.module_id,
    )?;
    validate_manifest_identity(&manifest, request.module_id, request.slug)?;
    manifest_view
        .verify_inputs()
        .context("release candidate: SDK manifest probe changed its frozen phase inputs")?;

    let web_view = source.fresh_web_view()?;
    let web = build_web(runner, &web_view, &request, &manifest)?;
    web_view
        .verify_inputs()
        .context("release candidate: web build changed its frozen canonical inputs")?;

    let artifact_view = source.fresh_view("artifact")?;
    let artifact_go = GoEnvironment::new("artifact")?;
    let (artifact_dir, artifact_path, artifact_evidence) =
        build_linux_artifact(runner, &artifact_view.module_dir(), &artifact_go)?;
    artifact_view
        .verify_inputs()
        .context("release candidate: Go build changed its frozen phase inputs")?;

    source.verify_unchanged().context(
        "release candidate: live source changed during manifest/web/artifact preparation",
    )?;

    let receipt = ReleaseCandidateReceipt {
        protocol: CANDIDATE_PROTOCOL.to_string(),
        module_id: request.module_id.to_string(),
        slug: request.slug.to_string(),
        version: request.version.to_string(),
        source_sha256: source.source_sha256().to_string(),
        manifest: manifest_evidence,
        web,
        artifact: artifact_evidence,
    };
    let receipt_path = write_candidate_receipt(artifact_dir.path(), &receipt)?;
    Ok(ReleaseCandidate {
        source,
        artifact_dir,
        receipt,
        artifact_path,
        _receipt_path: receipt_path,
    })
}

#[derive(Deserialize)]
struct GoModEdit {
    #[serde(rename = "Replace", default)]
    replace: Option<Vec<GoReplace>>,
}

#[derive(Deserialize)]
struct GoReplace {
    #[serde(rename = "New")]
    new: GoModuleRef,
}

#[derive(Deserialize)]
struct GoModuleRef {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Version", default)]
    version: String,
}

fn validate_local_replaces(
    runner: &dyn ProcessRunner,
    view: &BuildView,
    go: &GoEnvironment,
) -> Result<()> {
    let spec = go_spec("go", view.module_dir(), go)
        .args(["mod", "edit", "-json"])
        .limits(1024 * 1024, 256 * 1024);
    let output = run_checked(runner, &spec, "go mod edit")?;
    let edit: GoModEdit = serde_json::from_slice(&output.stdout)
        .context("release candidate: parse `go mod edit -json`")?;
    for replacement in edit.replace.unwrap_or_default() {
        if !replacement.new.version.is_empty() {
            continue;
        }
        let path = Path::new(&replacement.new.path);
        if path.is_absolute() {
            return Err(anyhow!(
                "release candidate: absolute local Go replace `{}` is not allowed; use a relative path inside the Git worktree",
                replacement.new.path
            ));
        }
        let resolved = resolve_inside(view.root(), &view.module_dir(), path, "local Go replace")?;
        if !resolved.join("go.mod").is_file() {
            return Err(anyhow!(
                "release candidate: local Go replace `{}` does not name a staged module inside {}",
                replacement.new.path,
                view.root().display()
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestInput<'a> {
    source_sha256: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEnvelope {
    protocol: String,
    source_sha256: String,
    manifest_sha256: String,
    manifest_base64: String,
}

fn run_manifest_probe(
    runner: &dyn ProcessRunner,
    module_dir: &Path,
    go: &GoEnvironment,
    source_sha256: &str,
    source_version_key: &str,
    module_id: &str,
) -> Result<(ManifestEvidence, serde_json::Value)> {
    validate_sha256(source_sha256, "source sha256")?;
    let stdin = serde_json::to_vec(&ManifestInput { source_sha256 })
        .context("release candidate: encode SDK manifest input")?;
    let spec = go_spec("go", module_dir.to_path_buf(), go)
        .args(["run", "-trimpath", "-buildvcs=false", "."])
        .env("MS_SDK_TOOL_MODE", MANIFEST_TOOL_MODE)
        // Module mains conventionally read Config.ID from this variable. Pin
        // the owned platform UUID into the SDK's canonical m<32-hex> form so
        // an empty or unrelated ambient value cannot change the manifest.
        .env("MS_MODULE_ID", sdk_module_id(module_id)?)
        .stdin(stdin)
        .timeout(Duration::from_secs(180))
        .limits(MAX_MANIFEST_STDOUT_BYTES, 1024 * 1024);
    let output = run_checked(runner, &spec, "SDK release manifest probe")?;
    parse_manifest_output(&output.stdout, source_sha256, source_version_key)
}

fn validate_manifest_identity(
    manifest: &serde_json::Value,
    module_id: &str,
    slug: &str,
) -> Result<()> {
    let manifest_id = manifest
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("release candidate: SDK manifest has no module id"))?;
    let manifest_slug = manifest
        .get("slug")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("release candidate: SDK manifest has no slug"))?;
    if !module_ids_equal(manifest_id, module_id) {
        return Err(anyhow!(
            "release candidate: SDK manifest module id {manifest_id} does not match owned module {module_id}"
        ));
    }
    if manifest_slug != slug {
        return Err(anyhow!(
            "release candidate: SDK manifest slug {manifest_slug} does not match deploy slug {slug}"
        ));
    }
    Ok(())
}

fn parse_manifest_output(
    stdout: &[u8],
    source_sha256: &str,
    source_version_key: &str,
) -> Result<(ManifestEvidence, serde_json::Value)> {
    let line = exact_one_line(stdout)?;
    let envelope: ManifestEnvelope =
        serde_json::from_slice(line).context("release candidate: parse SDK manifest envelope")?;
    if envelope.protocol != MANIFEST_PROTOCOL {
        return Err(anyhow!(
            "release candidate: SDK manifest protocol is `{}`, expected `{MANIFEST_PROTOCOL}`",
            envelope.protocol
        ));
    }
    if envelope.source_sha256 != source_sha256 {
        return Err(anyhow!(
            "release candidate: SDK echoed source sha256 {}, expected {source_sha256}",
            envelope.source_sha256
        ));
    }
    validate_sha256(&envelope.manifest_sha256, "manifest sha256")?;
    let bytes = STANDARD
        .decode(&envelope.manifest_base64)
        .context("release candidate: decode SDK manifest_base64")?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(anyhow!(
            "release candidate: SDK manifest is {} bytes (cap: {MAX_MANIFEST_BYTES})",
            bytes.len()
        ));
    }
    if STANDARD.encode(&bytes) != envelope.manifest_base64 {
        return Err(anyhow!(
            "release candidate: SDK manifest_base64 is not canonical standard padded base64"
        ));
    }
    let actual = sha256_hex(&bytes);
    if actual != envelope.manifest_sha256 {
        return Err(anyhow!(
            "release candidate: SDK manifest hash mismatch (declared {}, actual {actual})",
            envelope.manifest_sha256
        ));
    }
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)
        .context("release candidate: SDK manifest bytes are not JSON")?;
    let versions = manifest
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("release candidate: SDK manifest has no versions object"))?;
    if !versions.contains_key(source_version_key) {
        return Err(anyhow!(
            "release candidate: SDK manifest does not contain final source version key {source_version_key:?}"
        ));
    }
    Ok((
        ManifestEvidence {
            sha256: envelope.manifest_sha256,
            base64: envelope.manifest_base64,
        },
        manifest,
    ))
}

fn build_web(
    runner: &dyn ProcessRunner,
    view: &BuildView,
    request: &CandidateRequest<'_>,
    manifest: &serde_json::Value,
) -> Result<Option<WebEvidence>> {
    let module_dir = view.module_dir();
    let web_dir = module_dir.join("web");
    let Some(pipeline) = web_pipeline(&web_dir, false) else {
        let package = web_dir.join("package.json");
        let declared_surface = manifest.get("ui").is_some_and(|surface| !surface.is_null());
        if package.is_file() || declared_surface {
            let reason = if package.is_file() {
                format!("{} exists", package.display())
            } else {
                "the SDK manifest declares a UI surface".to_string()
            };
            return Err(anyhow!(
                "release candidate: {reason}, but {} has no runnable one-shot release pipeline; declare a non-empty package.json scripts.build or provide esbuild.config.mjs",
                web_dir.display()
            ));
        }
        return Ok(None);
    };

    let manager = package_manager(&web_dir)?;
    web_dependencies::validate(view, &web_dir, manager)?;
    let install = web_spec(manager.program(), &web_dir, manager)
        // Dependency installation needs the module's devDependencies (the
        // shared CSS compiler and esbuild live there), independent of an
        // ambient production shell.
        .env("NODE_ENV", "development")
        .args(manager.install_args())
        .timeout(Duration::from_secs(600))
        .limits(1024 * 1024, 1024 * 1024);
    run_checked(runner, &install, "frozen web dependency install")?;

    let build = match pipeline {
        WebPipeline::DeclaredScript(script) => web_spec(manager.program(), &web_dir, manager)
            .env("NODE_ENV", "production")
            .args(manager.run_args(script)),
        WebPipeline::LegacyEsbuild => web_spec("node", &web_dir, manager)
            .env("NODE_ENV", "production")
            .args([OsString::from("esbuild.config.mjs")]),
    }
    .timeout(Duration::from_secs(600))
    .limits(1024 * 1024, 1024 * 1024);
    run_checked(runner, &build, "one-shot web release build")?;

    let dist = web_dir.join("dist/index.js");
    let dist_relative = dist.strip_prefix(view.root()).map_err(|_| {
        anyhow!(
            "release candidate: web bundle {} escaped its phase view",
            dist.display()
        )
    })?;
    let bytes =
        source::read_regular_bounded(view.root(), dist_relative, MAX_WEB_BYTES, "web bundle")?;
    if bytes.is_empty() {
        return Err(anyhow!(
            "release candidate: one-shot web build produced an empty {}",
            dist.display()
        ));
    }
    let sha256 = sha256_hex(&bytes);
    let session = load_for_module(request.module_dir, request.slug)?;
    if session.watch || !session.share {
        return Err(anyhow!(
            "release candidate: current tunnel for {} is watch={} share={}; restart it with `mirrorstack dev --tunnel --share --watch=false`",
            request.slug,
            session.watch,
            session.share
        ));
    }
    if !module_ids_equal(&session.module_id, request.module_id) {
        return Err(anyhow!(
            "release candidate: current tunnel module id {} does not match owned module {}",
            session.module_id,
            request.module_id
        ));
    }
    let ConfirmedWeb {
        session_id,
        sha256: confirmed_sha,
        size_bytes,
    } = session.web.ok_or_else(|| {
        anyhow!(
            "release candidate: current tunnel session {} has not confirmed a web bundle yet",
            session.session_id
        )
    })?;
    if confirmed_sha != sha256 || size_bytes != bytes.len() as u64 {
        return Err(anyhow!(
            "release candidate: one-shot staged web bundle ({sha256}, {} bytes) does not match current-session confirmation ({confirmed_sha}, {size_bytes} bytes)",
            bytes.len()
        ));
    }
    Ok(Some(WebEvidence {
        session_id,
        sha256,
        size_bytes,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageManager {
    Pnpm,
    Npm(NpmLockfile),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NpmLockfile {
    PackageLock,
    Shrinkwrap,
}

impl PackageManager {
    fn program(self) -> &'static str {
        match self {
            Self::Pnpm => "pnpm",
            Self::Npm(_) => "npm",
        }
    }

    fn install_args(self) -> Vec<OsString> {
        match self {
            Self::Pnpm => [
                "install",
                "--frozen-lockfile",
                "--prod=false",
                "--ignore-scripts=false",
                "--ignore-workspace",
                "--ignore-pnpmfile",
                "--lockfile=true",
                "--lockfile-dir=.",
                "--merge-git-branch-lockfiles=false",
                "--fix-lockfile=false",
                "--modules-dir=node_modules",
                "--virtual-store-dir=node_modules/.pnpm",
                "--store-dir=.tmp/release-pnpm-store",
                "--package-import-method=copy",
                "--verify-store-integrity=true",
                "--side-effects-cache=false",
            ]
            .into_iter()
            .map(Into::into)
            .collect(),
            Self::Npm(_) => vec![
                "ci".into(),
                "--include=dev".into(),
                "--ignore-scripts=false".into(),
                "--workspaces=false".into(),
                "--package-lock=true".into(),
            ],
        }
    }

    fn run_args(self, script: &str) -> Vec<OsString> {
        match self {
            // `--ignore-pnpmfile` is install-only in pnpm 10. The equivalent
            // forced environment setting remains active for run commands.
            Self::Pnpm => vec!["--ignore-workspace".into(), "run".into(), script.into()],
            Self::Npm(_) => vec!["--workspaces=false".into(), "run".into(), script.into()],
        }
    }

    fn lockfile(self) -> &'static str {
        match self {
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Npm(NpmLockfile::PackageLock) => "package-lock.json",
            Self::Npm(NpmLockfile::Shrinkwrap) => "npm-shrinkwrap.json",
        }
    }
}

fn package_manager(web_dir: &Path) -> Result<PackageManager> {
    let pnpm = web_dir.join("pnpm-lock.yaml").is_file();
    let package_lock = web_dir.join("package-lock.json").is_file();
    let shrinkwrap = web_dir.join("npm-shrinkwrap.json").is_file();
    match (pnpm, package_lock, shrinkwrap) {
        (true, false, false) => Ok(PackageManager::Pnpm),
        (false, true, false) => Ok(PackageManager::Npm(NpmLockfile::PackageLock)),
        (false, false, true) => Ok(PackageManager::Npm(NpmLockfile::Shrinkwrap)),
        (false, false, false) => Err(anyhow!(
            "release candidate: web module needs pnpm-lock.yaml, package-lock.json, or npm-shrinkwrap.json for a frozen one-shot build"
        )),
        _ => Err(anyhow!(
            "release candidate: web module has conflicting package-manager lockfiles; keep exactly one of pnpm-lock.yaml, package-lock.json, or npm-shrinkwrap.json"
        )),
    }
}

fn build_linux_artifact(
    runner: &dyn ProcessRunner,
    module_dir: &Path,
    go: &GoEnvironment,
) -> Result<(TempDir, PathBuf, ArtifactEvidence)> {
    let artifact_dir = tempfile::Builder::new()
        .prefix("mirrorstack-release-artifact-")
        .tempdir()
        .context("release candidate: create artifact directory")?;
    let bootstrap = artifact_dir.path().join("bootstrap");
    let spec = go_spec("go", module_dir.to_path_buf(), go)
        .args([
            OsString::from("build"),
            OsString::from("-trimpath"),
            OsString::from("-buildvcs=false"),
            OsString::from("-o"),
            bootstrap.as_os_str().to_os_string(),
            OsString::from("."),
        ])
        .env("GOOS", "linux")
        .env("GOARCH", "arm64")
        .env("GOARM64", "v8.0")
        .env("CGO_ENABLED", "0")
        .timeout(Duration::from_secs(600))
        .limits(256 * 1024, 1024 * 1024);
    run_checked(runner, &spec, "Linux/arm64 module build")?;
    artifact::assert_aarch64_elf(&bootstrap)?;
    let zip = artifact::zip_bootstrap(&bootstrap)?;
    let size_bytes = artifact::packaged_size(&zip)?;
    let bytes = fs::read(&zip)
        .with_context(|| format!("release candidate: read artifact {}", zip.display()))?;
    if bytes.len() as u64 != size_bytes {
        return Err(anyhow!(
            "release candidate: artifact size changed while hashing {}",
            zip.display()
        ));
    }
    Ok((
        artifact_dir,
        zip,
        ArtifactEvidence {
            sha256: sha256_hex(&bytes),
            size_bytes,
            os: "linux".to_string(),
            arch: "arm64".to_string(),
            format: "lambda-bootstrap-zip".to_string(),
        },
    ))
}

struct GoEnvironment {
    _root: TempDir,
    module_cache: PathBuf,
    build_cache: PathBuf,
}

impl GoEnvironment {
    fn new(phase: &str) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix(&format!("mirrorstack-release-go-{phase}-"))
            .tempdir()
            .with_context(|| format!("release candidate: create {phase} Go environment"))?;
        let module_cache = root.path().join("modcache");
        let build_cache = root.path().join("buildcache");
        fs::create_dir_all(&module_cache)
            .context("release candidate: create isolated Go module cache")?;
        fs::create_dir_all(&build_cache)
            .context("release candidate: create isolated Go build cache")?;
        Ok(Self {
            _root: root,
            module_cache,
            build_cache,
        })
    }
}

fn go_spec(program: &str, cwd: PathBuf, go: &GoEnvironment) -> ProcessSpec {
    let spec = ProcessSpec::new(program, cwd)
        // Deliberate public-module release policy: one fixed proxy and the
        // public checksum database, no private/no-sum bypasses, no inherited
        // workspace/toolchain/experiment/architecture knobs, and isolated
        // per-phase caches. This is reproducible input policy, not a sandbox
        // for a malicious same-UID local toolchain.
        .env("GOWORK", "off")
        .env("GOENV", "off")
        .env("GOFLAGS", "-mod=readonly")
        .env("GO111MODULE", "on")
        .env("GOPROXY", "https://proxy.golang.org")
        .env("GOSUMDB", "sum.golang.org")
        .env("GOPRIVATE", "")
        .env("GONOSUMDB", "")
        .env("GONOPROXY", "")
        .env("GOINSECURE", "")
        .env("GOTOOLCHAIN", "local")
        .env("GOEXPERIMENT", "")
        .env("GOMODCACHE", go.module_cache.as_os_str())
        .env("GOCACHE", go.build_cache.as_os_str())
        .env("CGO_ENABLED", "0")
        .env_remove("GOOS")
        .env_remove("GOARCH")
        .env_remove("GOARM64")
        .env_remove("GOROOT");
    [
        "GOCACHEPROG",
        "GOFIPS140",
        "GODEBUG",
        "GOAMD64",
        "GO386",
        "GOARM",
        "GOMIPS",
        "GOMIPS64",
        "GOPPC64",
        "GORISCV64",
        "GOWASM",
    ]
    .into_iter()
    .fold(spec, ProcessSpec::env_remove)
}

fn web_spec(program: &str, cwd: &Path, manager: PackageManager) -> ProcessSpec {
    let isolated_config_home = cwd.join(".tmp/release-package-config");
    let isolated_user_config = isolated_config_home.join("npm-user.rc");
    let isolated_global_config = isolated_config_home.join("npm-global.rc");
    let disabled_pnpmfile = isolated_config_home.join("disabled-pnpmfile.cjs");
    let spec = ProcessSpec::new(program, cwd)
        .env("CI", "true")
        // Do not consult a publisher's mutable user/global npm or pnpm
        // configuration. Project .npmrc files inside the snapshot are
        // separately checked for provenance-affecting selectors.
        .env("npm_config_userconfig", isolated_user_config.as_os_str())
        .env("NPM_CONFIG_USERCONFIG", isolated_user_config.as_os_str())
        .env(
            "npm_config_globalconfig",
            isolated_global_config.as_os_str(),
        )
        .env(
            "NPM_CONFIG_GLOBALCONFIG",
            isolated_global_config.as_os_str(),
        )
        // Pnpm reads its own global rc independently of npm's user/global
        // config selectors. XDG_CONFIG_HOME is its highest-priority config
        // root on every supported platform, including Windows.
        .env("XDG_CONFIG_HOME", isolated_config_home.as_os_str())
        // Keep both the top-level command and ordinary nested package-manager
        // calls in lifecycle scripts out of any ambient/ancestor workspace.
        .env("npm_config_workspaces", "false")
        .env("NPM_CONFIG_WORKSPACES", "false")
        .env("npm_config_package_lock", "true")
        .env("NPM_CONFIG_PACKAGE_LOCK", "true");
    let spec = match manager {
        PackageManager::Pnpm => spec
            .env("npm_config_pnpmfile", disabled_pnpmfile.as_os_str())
            .env("NPM_CONFIG_PNPMFILE", disabled_pnpmfile.as_os_str())
            .env("npm_config_global_pnpmfile", disabled_pnpmfile.as_os_str())
            .env("NPM_CONFIG_GLOBAL_PNPMFILE", disabled_pnpmfile.as_os_str())
            .env("npm_config_ignore_workspace", "true")
            .env("NPM_CONFIG_IGNORE_WORKSPACE", "true")
            .env("npm_config_ignore_pnpmfile", "true")
            .env("NPM_CONFIG_IGNORE_PNPMFILE", "true")
            .env("npm_config_lockfile", "true")
            .env("NPM_CONFIG_LOCKFILE", "true")
            .env("npm_config_lockfile_dir", ".")
            .env("NPM_CONFIG_LOCKFILE_DIR", ".")
            .env("npm_config_git_branch_lockfile", "false")
            .env("NPM_CONFIG_GIT_BRANCH_LOCKFILE", "false")
            .env("npm_config_merge_git_branch_lockfiles", "false")
            .env("NPM_CONFIG_MERGE_GIT_BRANCH_LOCKFILES", "false")
            .env("npm_config_modules_dir", "node_modules")
            .env("NPM_CONFIG_MODULES_DIR", "node_modules")
            .env("npm_config_virtual_store_dir", "node_modules/.pnpm")
            .env("NPM_CONFIG_VIRTUAL_STORE_DIR", "node_modules/.pnpm")
            .env("npm_config_store_dir", ".tmp/release-pnpm-store")
            .env("NPM_CONFIG_STORE_DIR", ".tmp/release-pnpm-store")
            .env("npm_config_package_import_method", "copy")
            .env("NPM_CONFIG_PACKAGE_IMPORT_METHOD", "copy")
            .env("npm_config_verify_store_integrity", "true")
            .env("NPM_CONFIG_VERIFY_STORE_INTEGRITY", "true")
            .env("npm_config_side_effects_cache", "false")
            .env("NPM_CONFIG_SIDE_EFFECTS_CACHE", "false"),
        PackageManager::Npm(_) => spec,
    };
    [
        "NODE_OPTIONS",
        "npm_config_node_options",
        "NPM_CONFIG_NODE_OPTIONS",
        "pnpm_config_node_options",
        "PNPM_CONFIG_NODE_OPTIONS",
        "npm_config_script_shell",
        "NPM_CONFIG_SCRIPT_SHELL",
        "pnpm_config_script_shell",
        "PNPM_CONFIG_SCRIPT_SHELL",
        "NODE_PATH",
        "ESBUILD_BINARY_PATH",
        "INIT_CWD",
        "npm_config_prefix",
        "NPM_CONFIG_PREFIX",
        "npm_config_omit",
        "NPM_CONFIG_OMIT",
        "npm_config_production",
        "NPM_CONFIG_PRODUCTION",
        "pnpm_config_production",
        "PNPM_CONFIG_PRODUCTION",
        "npm_config_ignore_scripts",
        "NPM_CONFIG_IGNORE_SCRIPTS",
        "pnpm_config_ignore_scripts",
        "PNPM_CONFIG_IGNORE_SCRIPTS",
        "npm_config_include",
        "NPM_CONFIG_INCLUDE",
    ]
    .into_iter()
    .fold(spec, ProcessSpec::env_remove)
}

fn run_checked(
    runner: &dyn ProcessRunner,
    spec: &ProcessSpec,
    label: &str,
) -> Result<ProcessOutput> {
    let output = runner.run(spec)?;
    if output.success {
        return Ok(output);
    }
    Err(anyhow!(
        "release candidate: {label} failed:\n{}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn exact_one_line(stdout: &[u8]) -> Result<&[u8]> {
    let line = stdout.strip_suffix(b"\n").ok_or_else(|| {
        anyhow!(
            "release candidate: SDK manifest stdout must be exactly one newline-terminated JSON line"
        )
    })?;
    if line.is_empty() || line.contains(&b'\n') || line.contains(&b'\r') {
        return Err(anyhow!(
            "release candidate: SDK manifest stdout contained extra output"
        ));
    }
    Ok(line)
}

fn resolve_inside(root: &Path, base: &Path, relative: &Path, label: &str) -> Result<PathBuf> {
    let base_relative = base
        .strip_prefix(root)
        .map_err(|_| anyhow!("release candidate: {label} base escaped the source stage"))?;
    let mut parts = base_relative
        .components()
        .map(|component| component.as_os_str().to_os_string())
        .collect::<Vec<_>>();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => parts.push(value.to_os_string()),
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(anyhow!(
                        "release candidate: {label} `{}` escapes the frozen Git worktree",
                        relative.display()
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(anyhow!(
                    "release candidate: {label} `{}` must be relative",
                    relative.display()
                ));
            }
        }
    }
    let mut resolved = root.to_path_buf();
    for part in parts {
        resolved.push(part);
    }
    Ok(resolved)
}

pub(crate) fn module_ids_equal(left: &str, right: &str) -> bool {
    match (normalize_module_id(left), normalize_module_id(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn sdk_module_id(value: &str) -> Result<String> {
    normalize_module_id(value)
        .map(|hex| format!("m{hex}"))
        .ok_or_else(|| anyhow!("release candidate: owned module id {value} is not canonical"))
}

fn normalize_module_id(value: &str) -> Option<String> {
    if let Some(hex) = value.strip_prefix('m') {
        return (hex.len() == 32 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| hex.to_ascii_lowercase());
    }
    let bytes = value.as_bytes();
    if bytes.len() != 36
        || [8, 13, 18, 23]
            .into_iter()
            .any(|index| bytes[index] != b'-')
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| ![8, 13, 18, 23].contains(&index) && !byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(
        value
            .bytes()
            .filter(|byte| *byte != b'-')
            .map(|byte| (byte as char).to_ascii_lowercase())
            .collect(),
    )
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(anyhow!(
            "release candidate: {label} must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn write_candidate_receipt(root: &Path, receipt: &ReleaseCandidateReceipt) -> Result<PathBuf> {
    let mut bytes =
        serde_json::to_vec(receipt).context("release candidate: encode candidate receipt")?;
    bytes.push(b'\n');
    if bytes.len() > MAX_CANDIDATE_RECEIPT_BYTES {
        return Err(anyhow!(
            "release candidate: receipt exceeds {MAX_CANDIDATE_RECEIPT_BYTES} bytes"
        ));
    }
    let mut temporary = NamedTempFile::new_in(root)
        .context("release candidate: create atomic candidate receipt")?;
    use std::io::Write;
    temporary
        .write_all(&bytes)
        .context("release candidate: write candidate receipt")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("release candidate: sync candidate receipt")?;
    let path = root.join("release-candidate.json");
    temporary.persist(&path).map_err(|error| {
        anyhow!(
            "release candidate: publish receipt {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Command;
    use std::sync::Mutex;

    use super::*;
    use crate::commands::dev::release_session::{ReleaseSessionStore, SessionOpen};

    const MODULE_ID: &str = "11111111-1111-1111-1111-111111111111";
    const SDK_MODULE_ID: &str = "m11111111111111111111111111111111";
    const VERSION_KEY: &str = "v1.2.3";
    const WEB_BYTES: &[u8] = b"export default { release: true };\n";

    #[derive(Debug)]
    struct SeenSpec {
        program: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
        removed: Vec<String>,
    }

    struct FakeRunner {
        seen: Mutex<Vec<SeenSpec>>,
        manifest_extra_stdout: bool,
        manifest_wrong_hash: bool,
        manifest_declares_ui: bool,
        mutate_manifest_view: bool,
        mutate_live_on_artifact: Option<PathBuf>,
        replaces: serde_json::Value,
    }

    struct RealNpmRunner {
        fake: FakeRunner,
    }

    impl ProcessRunner for RealNpmRunner {
        fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput> {
            if spec.program == std::ffi::OsStr::new("npm") {
                SystemRunner.run(spec)
            } else {
                self.fake.run(spec)
            }
        }
    }

    impl Default for FakeRunner {
        fn default() -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                manifest_extra_stdout: false,
                manifest_wrong_hash: false,
                manifest_declares_ui: false,
                mutate_manifest_view: false,
                mutate_live_on_artifact: None,
                replaces: serde_json::json!(null),
            }
        }
    }

    impl ProcessRunner for FakeRunner {
        fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput> {
            let program = spec.program.to_string_lossy().into_owned();
            let args = spec
                .args
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            self.seen.lock().unwrap().push(SeenSpec {
                program: program.clone(),
                args: args.clone(),
                env: spec
                    .env
                    .iter()
                    .map(|(key, value)| {
                        (
                            key.to_string_lossy().into_owned(),
                            value.to_string_lossy().into_owned(),
                        )
                    })
                    .collect(),
                removed: spec
                    .env_remove
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            });

            if program == "go" && args.starts_with(&["mod".into(), "edit".into()]) {
                return success(
                    serde_json::to_vec(&serde_json::json!({"Replace": self.replaces})).unwrap(),
                );
            }
            if program == "go" && args.first().is_some_and(|arg| arg == "run") {
                let input: serde_json::Value = serde_json::from_slice(&spec.stdin).unwrap();
                let source = input["source_sha256"].as_str().unwrap();
                let mut manifest_value = serde_json::json!({
                    "id": SDK_MODULE_ID,
                    "slug": "user-core",
                    "versions": {VERSION_KEY: {"app": "0001", "module": "0002"}}
                });
                if self.manifest_declares_ui {
                    manifest_value["ui"] = serde_json::json!({"pages": [], "components": []});
                }
                let mut manifest = serde_json::to_vec(&manifest_value).unwrap();
                manifest.push(b'\n');
                let hash = if self.manifest_wrong_hash {
                    "f".repeat(64)
                } else {
                    sha256_hex(&manifest)
                };
                let envelope = serde_json::json!({
                    "protocol": MANIFEST_PROTOCOL,
                    "source_sha256": source,
                    "manifest_sha256": hash,
                    "manifest_base64": STANDARD.encode(&manifest)
                });
                let mut stdout = serde_json::to_vec(&envelope).unwrap();
                stdout.push(b'\n');
                if self.manifest_extra_stdout {
                    stdout.extend_from_slice(b"debug output\n");
                }
                if self.mutate_manifest_view {
                    fs::write(
                        spec.cwd.join("main.go"),
                        "package main\n// mutated by manifest phase\n",
                    )
                    .unwrap();
                }
                return success(stdout);
            }
            if program == "go" && args.first().is_some_and(|arg| arg == "build") {
                let output = args
                    .windows(2)
                    .find_map(|pair| (pair[0] == "-o").then_some(PathBuf::from(&pair[1])))
                    .expect("artifact output");
                write_aarch64_elf(&output);
                if let Some(path) = &self.mutate_live_on_artifact {
                    fs::write(path, "package main\n// live drift\n").unwrap();
                }
                return success(Vec::new());
            }
            if matches!(program.as_str(), "pnpm" | "npm") {
                if args.iter().any(|arg| arg == "run") {
                    let dist = spec.cwd.join("dist/index.js");
                    fs::create_dir_all(dist.parent().unwrap()).unwrap();
                    fs::write(dist, WEB_BYTES).unwrap();
                }
                return success(Vec::new());
            }
            Err(anyhow!("unexpected fake command: {program} {args:?}"))
        }
    }

    fn success(stdout: Vec<u8>) -> Result<ProcessOutput> {
        Ok(ProcessOutput {
            success: true,
            stdout,
            stderr: Vec::new(),
        })
    }

    fn write_aarch64_elf(path: &Path) {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
        fs::write(path, bytes).unwrap();
    }

    fn git(root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }

    fn fixture(web: bool, watch: bool) -> (TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-q"]);
        let module = root.path().join("module");
        fs::create_dir_all(&module).unwrap();
        fs::write(
            module.join("go.mod"),
            "module example.com/module\n\ngo 1.23\n",
        )
        .unwrap();
        fs::write(module.join("main.go"), "package main\n").unwrap();
        fs::write(
            module.join("CHANGELOG.md"),
            "# Changelog\n\n## 1.2.3\n\n- release\n",
        )
        .unwrap();
        fs::write(
            root.path().join(".gitignore"),
            ".secret/\nnode_modules/\ndist/\n.tmp/\n",
        )
        .unwrap();
        if web {
            fs::create_dir_all(module.join("web")).unwrap();
            fs::write(
                module.join("web/package.json"),
                serde_json::json!({
                    "scripts": if watch {
                        serde_json::json!({"build": "build-release", "watch": "build-watch"})
                    } else {
                        serde_json::json!({"build": "build-release"})
                    }
                })
                .to_string(),
            )
            .unwrap();
            fs::write(
                module.join("web/pnpm-lock.yaml"),
                "lockfileVersion: '9.0'\n",
            )
            .unwrap();
        }
        git(root.path(), &["add", "."]);
        (root, module)
    }

    fn npm_dev_dependency_fixture() -> (TempDir, PathBuf) {
        let (root, module) = fixture(false, false);
        let web = module.join("web");
        let tool = web.join("build-tool");
        fs::create_dir_all(&tool).unwrap();
        fs::write(
            web.join("package.json"),
            serde_json::json!({
                "name": "release-web-fixture",
                "version": "1.0.0",
                "private": true,
                "scripts": {
                    "build": "build-tool",
                    "watch": "build-tool"
                },
                "devDependencies": {
                    "build-tool": "file:build-tool"
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            tool.join("package.json"),
            serde_json::json!({
                "name": "build-tool",
                "version": "1.0.0",
                "bin": {"build-tool": "build.js"}
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            tool.join("build.js"),
            format!(
                "#!/usr/bin/env node\nconst fs=require('fs');fs.mkdirSync('src/__generated__',{{recursive:true}});fs.writeFileSync('src/__generated__/styles.ts',\"export const styles = 'release';\\n\");fs.mkdirSync('dist',{{recursive:true}});fs.writeFileSync('dist/index.js',{});\n",
                serde_json::to_string(std::str::from_utf8(WEB_BYTES).unwrap()).unwrap()
            ),
        )
        .unwrap();
        fs::write(
            web.join("package-lock.json"),
            serde_json::json!({
                "name": "release-web-fixture",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": true,
                "packages": {
                    "": {
                        "name": "release-web-fixture",
                        "version": "1.0.0",
                        "devDependencies": {"build-tool": "file:build-tool"}
                    },
                    "build-tool": {
                        "name": "build-tool",
                        "version": "1.0.0",
                        "dev": true,
                        "bin": {"build-tool": "build.js"}
                    },
                    "node_modules/build-tool": {
                        "resolved": "build-tool",
                        "link": true
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        git(
            root.path(),
            &[
                "update-index",
                "--chmod=+x",
                "module/web/build-tool/build.js",
            ],
        );
        (root, module)
    }

    struct EnvRestore(Vec<(&'static str, Option<OsString>)>);

    impl EnvRestore {
        fn set(values: &[(&'static str, &'static str)]) -> Self {
            let previous = values
                .iter()
                .map(|(name, value)| {
                    let previous = std::env::var_os(name);
                    // SAFETY: every environment-mutating CLI test holds the
                    // shared test mutex for the guard's full lifetime.
                    unsafe { std::env::set_var(name, value) };
                    (*name, previous)
                })
                .collect();
            Self(previous)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (name, previous) in self.0.drain(..).rev() {
                // SAFETY: the shared test mutex remains held while this guard
                // restores the process-global environment.
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    fn session(root: &Path, module: &Path, watch: bool) -> ReleaseSessionStore {
        let store = ReleaseSessionStore::new(root).unwrap();
        store
            .install(SessionOpen {
                slug: "user-core",
                module_id: SDK_MODULE_ID,
                session_id: "session-release",
                local_url: "http://127.0.0.1:9080/_m/user-core",
                module_dir: module,
                watch,
                share: true,
            })
            .unwrap();
        if !watch {
            store
                .confirm_web(
                    "user-core",
                    "session-release",
                    &sha256_hex(WEB_BYTES),
                    WEB_BYTES.len() as u64,
                )
                .unwrap();
        }
        store
    }

    fn request(module: &Path) -> CandidateRequest<'_> {
        CandidateRequest {
            module_dir: module,
            slug: "user-core",
            module_id: MODULE_ID,
            version: "1.2.3",
            source_version_key: VERSION_KEY,
        }
    }

    fn sized_manifest(size: usize) -> Vec<u8> {
        let mut bytes =
            format!("{{\"versions\":{{\"{VERSION_KEY}\":{{}}}},\"padding\":\"").into_bytes();
        let suffix = b"\"}\n";
        assert!(size >= bytes.len() + suffix.len());
        bytes.resize(size - suffix.len(), b'a');
        bytes.extend_from_slice(suffix);
        bytes
    }

    fn manifest_stdout(bytes: &[u8], source_sha256: &str) -> Vec<u8> {
        let mut stdout = serde_json::to_vec(&serde_json::json!({
            "protocol": MANIFEST_PROTOCOL,
            "source_sha256": source_sha256,
            "manifest_sha256": sha256_hex(bytes),
            "manifest_base64": STANDARD.encode(bytes),
        }))
        .unwrap();
        stdout.push(b'\n');
        stdout
    }

    fn receipt_with_manifest_base64(base64: String) -> ReleaseCandidateReceipt {
        ReleaseCandidateReceipt {
            protocol: CANDIDATE_PROTOCOL.into(),
            module_id: MODULE_ID.into(),
            slug: "user-core".into(),
            version: "1.2.3".into(),
            source_sha256: "a".repeat(64),
            manifest: ManifestEvidence {
                sha256: "b".repeat(64),
                base64,
            },
            web: None,
            artifact: ArtifactEvidence {
                sha256: "c".repeat(64),
                size_bytes: 42,
                os: "linux".into(),
                arch: "arm64".into(),
                format: "lambda-bootstrap-zip".into(),
            },
        }
    }

    #[test]
    fn manifest_and_receipt_caps_match_the_version_create_envelope() {
        let source_sha256 = "d".repeat(64);
        let at_cap = sized_manifest(MAX_MANIFEST_BYTES);
        let (evidence, _) = parse_manifest_output(
            &manifest_stdout(&at_cap, &source_sha256),
            &source_sha256,
            VERSION_KEY,
        )
        .unwrap();
        assert_eq!(
            STANDARD.decode(evidence.base64).unwrap().len(),
            MAX_MANIFEST_BYTES
        );

        let over_cap = sized_manifest(MAX_MANIFEST_BYTES + 1);
        let error = parse_manifest_output(
            &manifest_stdout(&over_cap, &source_sha256),
            &source_sha256,
            VERSION_KEY,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SDK manifest is"), "{error:#}");

        let mut receipt = receipt_with_manifest_base64(String::new());
        let base_size = serde_json::to_vec(&receipt).unwrap().len() + 1;
        receipt.manifest.base64 = "A".repeat(MAX_CANDIDATE_RECEIPT_BYTES - base_size);
        assert_eq!(
            serde_json::to_vec(&receipt).unwrap().len() + 1,
            MAX_CANDIDATE_RECEIPT_BYTES
        );
        let root = tempfile::tempdir().unwrap();
        write_candidate_receipt(root.path(), &receipt).unwrap();

        receipt.manifest.base64.push('A');
        let error = write_candidate_receipt(root.path(), &receipt).unwrap_err();
        assert!(error.to_string().contains("receipt exceeds"), "{error:#}");
    }

    #[test]
    fn module_id_equivalence_accepts_only_canonical_sdk_and_uuid_shapes() {
        assert!(module_ids_equal(MODULE_ID, SDK_MODULE_ID));
        assert!(module_ids_equal(
            "11111111-1111-1111-1111-11111111111A",
            "m1111111111111111111111111111111a"
        ));
        for malformed in [
            "11111111111111111111111111111111",
            "m-11111111111111111111111111111111",
            "module-11111111111111111111111111111111",
            "m1111111111111111111111111111111g",
            "m1111",
        ] {
            assert!(!module_ids_equal(MODULE_ID, malformed), "{malformed}");
        }
    }

    #[test]
    fn candidate_binds_one_source_to_exact_manifest_web_and_linux_artifact() {
        let (root, module) = fixture(true, true);
        let _session = session(root.path(), &module, false);
        let runner = FakeRunner::default();
        let candidate = build_with(&runner, request(&module)).unwrap();

        assert_eq!(candidate.receipt.protocol, CANDIDATE_PROTOCOL);
        assert_eq!(candidate.receipt.source_sha256.len(), 64);
        assert_eq!(candidate.receipt.manifest.sha256.len(), 64);
        let manifest = STANDARD.decode(&candidate.receipt.manifest.base64).unwrap();
        assert!(manifest.ends_with(b"\n"));
        assert_eq!(sha256_hex(&manifest), candidate.receipt.manifest.sha256);
        assert_eq!(
            candidate.receipt.web.as_ref().unwrap().session_id,
            "session-release"
        );
        assert_eq!(
            candidate.receipt.web.as_ref().unwrap().sha256,
            sha256_hex(WEB_BYTES)
        );
        assert_eq!(candidate.receipt.artifact.os, "linux");
        assert_eq!(candidate.receipt.artifact.arch, "arm64");
        candidate.verify_artifact().unwrap();
        let persisted: ReleaseCandidateReceipt =
            serde_json::from_slice(&fs::read(candidate.receipt_path()).unwrap()).unwrap();
        assert_eq!(persisted, candidate.receipt);

        let seen = runner.seen.lock().unwrap();
        assert!(seen.iter().any(|spec| {
            spec.program == "go"
                && spec.args.first().is_some_and(|arg| arg == "run")
                && spec.env.get("MS_SDK_TOOL_MODE").map(String::as_str) == Some(MANIFEST_TOOL_MODE)
                && spec.env.get("MS_MODULE_ID").map(String::as_str) == Some(SDK_MODULE_ID)
        }));
        assert!(seen.iter().any(|spec| {
            spec.program == "pnpm"
                && spec.args == ["--ignore-workspace", "run", "build"]
                && spec.env.get("NODE_ENV").map(String::as_str) == Some("production")
                && spec
                    .removed
                    .contains(&"NPM_CONFIG_IGNORE_SCRIPTS".to_string())
        }));
        assert!(seen.iter().any(|spec| {
            spec.program == "pnpm"
                && spec.args
                    == [
                        "install",
                        "--frozen-lockfile",
                        "--prod=false",
                        "--ignore-scripts=false",
                        "--ignore-workspace",
                        "--ignore-pnpmfile",
                        "--lockfile=true",
                        "--lockfile-dir=.",
                        "--merge-git-branch-lockfiles=false",
                        "--fix-lockfile=false",
                        "--modules-dir=node_modules",
                        "--virtual-store-dir=node_modules/.pnpm",
                        "--store-dir=.tmp/release-pnpm-store",
                        "--package-import-method=copy",
                        "--verify-store-integrity=true",
                        "--side-effects-cache=false",
                    ]
                && spec.env.get("NODE_ENV").map(String::as_str) == Some("development")
        }));
    }

    #[test]
    fn manifest_identity_must_match_the_owned_module_and_requested_slug() {
        let exact = serde_json::json!({"id": SDK_MODULE_ID, "slug": "user-core"});
        validate_manifest_identity(&exact, MODULE_ID, "user-core").unwrap();
        assert_eq!(sdk_module_id(MODULE_ID).unwrap(), SDK_MODULE_ID);

        let wrong_id = serde_json::json!({
            "id": "m22222222222222222222222222222222",
            "slug": "user-core"
        });
        let error = validate_manifest_identity(&wrong_id, MODULE_ID, "user-core").unwrap_err();
        assert!(error.to_string().contains("does not match owned module"));

        let wrong_slug = serde_json::json!({"id": SDK_MODULE_ID, "slug": "other"});
        let error = validate_manifest_identity(&wrong_slug, MODULE_ID, "user-core").unwrap_err();
        assert!(error.to_string().contains("does not match deploy slug"));

        assert!(sdk_module_id("not-a-module-id").is_err());
    }

    #[test]
    fn fresh_stage_installs_dev_build_tool_under_ambient_production_omit_policy() {
        let _environment = crate::credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _restore = EnvRestore::set(&[
            ("NODE_ENV", "production"),
            ("npm_config_omit", "dev"),
            ("NPM_CONFIG_PRODUCTION", "true"),
            ("npm_config_ignore_scripts", "true"),
            (
                "npm_config_node_options",
                "--require=/mirrorstack-missing/inject.cjs",
            ),
            (
                "NPM_CONFIG_NODE_OPTIONS",
                "--require=/mirrorstack-missing/upper.cjs",
            ),
            ("npm_config_script_shell", "/mirrorstack-missing/shell"),
            (
                "NPM_CONFIG_SCRIPT_SHELL",
                "/mirrorstack-missing/upper-shell",
            ),
        ]);
        let (root, module) = npm_dev_dependency_fixture();
        let _session = session(root.path(), &module, false);
        let candidate = build_with(
            &RealNpmRunner {
                fake: FakeRunner::default(),
            },
            request(&module),
        )
        .unwrap();
        assert_eq!(
            candidate.receipt.web.as_ref().unwrap().sha256,
            sha256_hex(WEB_BYTES)
        );
    }

    #[test]
    fn watch_session_cannot_attest_release_web_bytes() {
        let (root, module) = fixture(true, true);
        let _session = session(root.path(), &module, true);
        let error = build_with(&FakeRunner::default(), request(&module))
            .err()
            .expect("watch session rejected");
        assert!(error.to_string().contains("watch=true"), "{error:#}");
    }

    #[test]
    fn one_shot_release_web_pipeline_does_not_require_a_watch_peer() {
        let (root, module) = fixture(true, false);
        let _session = session(root.path(), &module, false);
        let candidate = build_with(&FakeRunner::default(), request(&module)).unwrap();
        assert!(candidate.receipt.web.is_some());
    }

    #[test]
    fn web_package_without_a_runnable_release_pipeline_fails_closed() {
        let (_root, module) = fixture(true, false);
        fs::write(
            module.join("web/package.json"),
            r#"{"scripts":{"watch":"build-watch"}}"#,
        )
        .unwrap();

        let error = build_with(&FakeRunner::default(), request(&module))
            .err()
            .expect("web package without a build pipeline rejected");
        let message = format!("{error:#}");
        assert!(message.contains("package.json"), "{message}");
        assert!(message.contains("no runnable one-shot"), "{message}");
    }

    #[test]
    fn declared_ui_without_a_runnable_release_pipeline_fails_closed() {
        let (_root, module) = fixture(false, false);
        let error = build_with(
            &FakeRunner {
                manifest_declares_ui: true,
                ..FakeRunner::default()
            },
            request(&module),
        )
        .err()
        .expect("declared UI without a build pipeline rejected");
        let message = format!("{error:#}");
        assert!(message.contains("SDK manifest declares a UI"), "{message}");
        assert!(message.contains("no runnable one-shot"), "{message}");
    }

    #[test]
    fn module_without_web_package_or_declared_ui_has_no_web_evidence() {
        let (_root, module) = fixture(false, false);
        let candidate = build_with(&FakeRunner::default(), request(&module)).unwrap();
        assert!(candidate.receipt.web.is_none());
    }

    #[test]
    fn manifest_extra_stdout_hash_mismatch_and_phase_mutation_fail_closed() {
        let (_root, module) = fixture(false, false);
        for runner in [
            FakeRunner {
                manifest_extra_stdout: true,
                ..FakeRunner::default()
            },
            FakeRunner {
                manifest_wrong_hash: true,
                ..FakeRunner::default()
            },
            FakeRunner {
                mutate_manifest_view: true,
                ..FakeRunner::default()
            },
        ] {
            assert!(build_with(&runner, request(&module)).is_err());
        }
    }

    #[test]
    fn live_drift_during_artifact_build_discards_the_candidate() {
        let (_root, module) = fixture(false, false);
        let runner = FakeRunner {
            mutate_live_on_artifact: Some(module.join("main.go")),
            ..FakeRunner::default()
        };
        let error = build_with(&runner, request(&module))
            .err()
            .expect("live drift rejected");
        assert!(format!("{error:#}").contains("source drift"), "{error:#}");
    }

    #[test]
    fn escaping_and_absolute_local_replaces_are_rejected() {
        for replacement in ["../../../outside", "/tmp/outside"] {
            let (_root, module) = fixture(false, false);
            let runner = FakeRunner {
                replaces: serde_json::json!([{"New": {"Path": replacement, "Version": ""}}]),
                ..FakeRunner::default()
            };
            let error = build_with(&runner, request(&module))
                .err()
                .expect("local replace rejected");
            assert!(error.to_string().contains("Go replace"), "{error:#}");
        }
    }

    #[test]
    fn release_tool_environments_remove_ambient_build_selectors() {
        let go = GoEnvironment::new("env-test").unwrap();
        let spec = go_spec("go", PathBuf::from("."), &go);
        assert_eq!(
            spec.env.get(std::ffi::OsStr::new("GOFLAGS")).unwrap(),
            "-mod=readonly"
        );
        assert_eq!(
            spec.env.get(std::ffi::OsStr::new("CGO_ENABLED")).unwrap(),
            "0"
        );
        assert_eq!(
            spec.env.get(std::ffi::OsStr::new("GOINSECURE")).unwrap(),
            ""
        );
        for name in ["GOROOT", "GOCACHEPROG", "GOAMD64", "GOARM64", "GODEBUG"] {
            assert!(
                spec.env_remove.contains(std::ffi::OsStr::new(name)),
                "{name}"
            );
        }

        let web =
            web_spec("pnpm", Path::new("."), PackageManager::Pnpm).env("NODE_ENV", "production");
        assert_eq!(
            web.env.get(std::ffi::OsStr::new("NODE_ENV")).unwrap(),
            "production"
        );
        for (name, relative) in [
            ("npm_config_userconfig", "npm-user.rc"),
            ("NPM_CONFIG_USERCONFIG", "npm-user.rc"),
            ("npm_config_globalconfig", "npm-global.rc"),
            ("NPM_CONFIG_GLOBALCONFIG", "npm-global.rc"),
            ("npm_config_global_pnpmfile", "disabled-pnpmfile.cjs"),
            ("NPM_CONFIG_GLOBAL_PNPMFILE", "disabled-pnpmfile.cjs"),
        ] {
            assert_eq!(
                web.env.get(std::ffi::OsStr::new(name)).unwrap(),
                Path::new(".")
                    .join(".tmp/release-package-config")
                    .join(relative)
                    .as_os_str(),
                "{name}"
            );
            assert!(
                !web.env_remove.contains(std::ffi::OsStr::new(name)),
                "{name}"
            );
        }
        assert_eq!(
            web.env
                .get(std::ffi::OsStr::new("XDG_CONFIG_HOME"))
                .unwrap(),
            Path::new(".")
                .join(".tmp/release-package-config")
                .as_os_str()
        );
        for name in [
            "NODE_PATH",
            "ESBUILD_BINARY_PATH",
            "npm_config_node_options",
            "NPM_CONFIG_NODE_OPTIONS",
            "npm_config_script_shell",
            "NPM_CONFIG_SCRIPT_SHELL",
            "npm_config_omit",
            "npm_config_ignore_scripts",
            "PNPM_CONFIG_IGNORE_SCRIPTS",
        ] {
            assert!(
                web.env_remove.contains(std::ffi::OsStr::new(name)),
                "{name}"
            );
        }
    }
}
