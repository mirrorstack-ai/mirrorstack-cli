//! Build and publish installable module-client artifacts for `dev --tunnel`.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    process::CommandExt,
};

use anyhow::{Context, Result, anyhow};
use console::style;
use flate2::{Compression, GzBuilder};
use fs2::FileExt;
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::blocking::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::{Builder, Header};

use super::module_meta;
use super::supervisor::{SessionSnapshot, SessionTracker};
use super::workspace;
use super::{ok_mark, warn_prefix};
use crate::api::{self, ApiError, DevClientConfirmInput, DevClientPresignInput};
use crate::credentials::{self, Credentials};
use crate::http;

const PACKAGE_MANIFEST: &[u8] = b"{\"type\":\"module\",\"exports\":{\".\":{\"types\":\"./dist/index.d.ts\",\"import\":\"./dist/index.js\"}}}\n";
const MAX_COMPRESSED_BYTES: usize = 10 << 20;
const MAX_EXPANDED_BYTES: u64 = 32 << 20;
const MAX_ENTRIES: usize = 1_024;
const MAX_PATH_BYTES: usize = 240;
const ALLOWED_OUTPUT_SUFFIXES: [&str; 9] = [
    ".js", ".mjs", ".cjs", ".d.ts", ".d.mts", ".d.cts", ".json", ".map", ".css",
];
const FORMAT_VERSION: u8 = 1;
const RUNNER_PROTOCOL_VERSION: u8 = 1;
const BUILD_POLL: Duration = Duration::from_millis(200);
const BUILD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const RUNNER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const RUNNER_POLL: Duration = Duration::from_secs(1);
const PUBLISH_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const PUBLISH_RETRY_CAP: Duration = Duration::from_secs(60);
// Verified dev artifacts are short-lived S3 leases. Reconfirming unchanged
// bytes refreshes the lease well before the platform's two-day expiry while
// also garbage-collecting the prior verified object.
const PUBLISH_RENEW_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const RUN_ID_FILE: &str = "ms-client-run-id";
const RUNNER_FILE_PREFIX: &str = "ms-client-runner-";
const WORKSPACE_LOCK_FILE: &str = "ms-dev-workspace.lock";
const WATCH_MODE_FILE: &str = "ms-dev-watch-mode";
const MAX_STATUS_BYTES: usize = 64 * 1024;
const MAX_PACKAGE_JSON_BYTES: usize = 64 * 1024;
const MAX_SOURCE_FILE_BYTES: u64 = 32 * 1024 * 1024;
const COMPOSE_RUNNING_RUNNER_PS_ARGS: [&str; 6] =
    ["compose", "ps", "--status", "running", "--quiet", "runner"];
const COMPOSE_ALL_RUNNER_PS_ARGS: [&str; 5] = ["compose", "ps", "--all", "--quiet", "runner"];

#[derive(Debug)]
struct ClientArtifact {
    bytes: Vec<u8>,
    sha256: String,
}

struct OutputFile {
    archive_path: String,
    bytes: Vec<u8>,
}

/// Package a built client output directory into the canonical v1 artifact.
/// Module-authored package metadata is never copied: the platform assigns
/// identity and version when the artifact is installed.
fn package_client(output_dir: &Path) -> Result<ClientArtifact> {
    let output_metadata = fs::symlink_metadata(output_dir)
        .with_context(|| format!("module client output is missing: {}", output_dir.display()))?;
    if output_metadata.file_type().is_symlink() || !output_metadata.is_dir() {
        return Err(anyhow!(
            "module client output must be a regular directory: {}",
            output_dir.display()
        ));
    }
    let mut files = Vec::new();
    let mut expanded = PACKAGE_MANIFEST.len() as u64;
    collect_output_files(output_dir, output_dir, &mut files, &mut expanded)?;
    files.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    if files.len() + 1 > MAX_ENTRIES {
        return Err(anyhow!(
            "module client contains {} entries; maximum is {MAX_ENTRIES}",
            files.len() + 1
        ));
    }
    for required in ["package/dist/index.js", "package/dist/index.d.ts"] {
        let Some(file) = files.iter().find(|file| file.archive_path == required) else {
            return Err(anyhow!("module client requires {}", &required[8..]));
        };
        if file.bytes.is_empty() {
            return Err(anyhow!(
                "module client requires non-empty file {}",
                &required[8..]
            ));
        }
    }

    let gzip = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut archive = Builder::new(gzip);
    append_bytes(&mut archive, "package/package.json", PACKAGE_MANIFEST)?;
    for file in files {
        append_bytes(&mut archive, &file.archive_path, &file.bytes)?;
    }
    let gzip = archive
        .into_inner()
        .context("dev: finalize module client tar")?;
    let bytes = gzip.finish().context("dev: finalize module client gzip")?;
    if bytes.len() > MAX_COMPRESSED_BYTES {
        return Err(anyhow!(
            "module client archive is {} bytes; maximum is {MAX_COMPRESSED_BYTES}",
            bytes.len()
        ));
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok(ClientArtifact { bytes, sha256 })
}

fn collect_output_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<OutputFile>,
    expanded: &mut u64,
) -> Result<()> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("dev: read client output directory {}", directory.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "dev: read client output entry under {}",
                directory.display()
            )
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("dev: inspect client output {}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| anyhow!("client output escaped declared directory"))?;
        let relative_text = portable_relative_path(relative)?;

        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "module client output {relative_text} is a symbolic link"
            ));
        }
        if metadata.is_dir() {
            if relative.components().any(|part| {
                part.as_os_str()
                    .to_str()
                    .is_some_and(|part| part.eq_ignore_ascii_case("node_modules"))
            }) {
                return Err(anyhow!(
                    "module client output {relative_text} contains bundled dependencies"
                ));
            }
            collect_output_files(root, &path, output, expanded)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(anyhow!(
                "module client output {relative_text} is not a regular file"
            ));
        }
        if relative.components().any(|part| {
            part.as_os_str()
                .to_str()
                .is_some_and(|part| part.eq_ignore_ascii_case("node_modules"))
        }) || !ALLOWED_OUTPUT_SUFFIXES
            .iter()
            .any(|suffix| relative_text.ends_with(suffix))
        {
            return Err(anyhow!(
                "module client output {relative_text} is not allowed"
            ));
        }
        let archive_path = format!("package/dist/{relative_text}");
        if archive_path.len() > MAX_PATH_BYTES {
            return Err(anyhow!(
                "module client output path {relative_text} exceeds {MAX_PATH_BYTES} bytes"
            ));
        }
        let remaining = MAX_EXPANDED_BYTES.saturating_sub(*expanded);
        let bytes = read_regular_file_limited(
            &path,
            usize::try_from(remaining).unwrap_or(usize::MAX),
            "module client output",
        )?;
        *expanded = expanded
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow!("module client expanded size overflow"))?;
        output.push(OutputFile {
            archive_path,
            bytes,
        });
        if output.len() + 1 > MAX_ENTRIES {
            return Err(anyhow!(
                "module client contains more than {MAX_ENTRIES} entries"
            ));
        }
    }
    Ok(())
}

/// Open one regular file without following a final-component symlink on Unix,
/// then bound the read from the opened handle. O_NONBLOCK prevents a raced
/// FIFO/device from hanging before the handle metadata check can reject it.
fn open_regular_file(path: &Path, label: &str) -> Result<(fs::File, fs::Metadata)> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("dev: inspect {label} {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(anyhow!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);

    let file = options
        .open(path)
        .with_context(|| format!("dev: open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("dev: inspect opened {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(anyhow!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    Ok((file, metadata))
}

fn read_regular_file_limited(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let (mut file, metadata) = open_regular_file(path, label)?;
    if metadata.len() > max_bytes as u64 {
        return Err(anyhow!(
            "{label} {} exceeds {max_bytes} bytes",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("dev: read {label} {}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(anyhow!(
            "{label} {} exceeds {max_bytes} bytes",
            path.display()
        ));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(anyhow!(
            "{label} {} changed while it was being read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn portable_relative_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| anyhow!("module client output paths must be UTF-8"))?;
                if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
                    return Err(anyhow!("module client output path is not portable"));
                }
                parts.push(part);
            }
            _ => return Err(anyhow!("module client output path is not relative")),
        }
    }
    if parts.is_empty() {
        return Err(anyhow!("module client output path is empty"));
    }
    Ok(parts.join("/"))
}

fn append_bytes<W: std::io::Write>(
    archive: &mut Builder<W>,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive
        .append_data(&mut header, path, Cursor::new(bytes))
        .with_context(|| format!("dev: append {path} to module client archive"))
}

#[derive(Clone)]
struct ClientTarget {
    slug: String,
    module_id: String,
    client_dir: PathBuf,
    output_dir: PathBuf,
    state_root: PathBuf,
}

impl ClientTarget {
    fn status_file(&self, run_id: &str) -> PathBuf {
        self.state_root
            .join(format!("ms-client-status-{run_id}-{}.json", self.slug))
    }

    fn artifact_file(&self, run_id: &str) -> PathBuf {
        self.state_root
            .join(format!("ms-client-artifact-{run_id}-{}.tgz", self.slug))
    }

    fn active_file(&self, run_id: &str) -> PathBuf {
        self.state_root.join(format!("ms-client-active-{run_id}"))
    }

    fn build_lock_file(&self) -> PathBuf {
        self.state_root
            .join(format!("ms-client-build-{}.lock", self.slug))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RunnerHandshake {
    run_id: String,
    protocol_version: u8,
    cli_version: String,
}

/// One outer `dev --tunnel` invocation. Drop only removes status belonging to
/// this run, so an interrupted predecessor cannot erase a successor's state.
pub(super) struct ClientRun {
    run_id: String,
    active_file: PathBuf,
    targets: Vec<ClientTarget>,
}

impl ClientRun {
    pub(super) fn prepare(
        root: &Path,
        modules: &[workspace::WorkspaceModule],
    ) -> Result<Option<Self>> {
        let mut targets = Vec::new();
        for module in modules {
            if let Some(target) = client_target(root, module)? {
                targets.push(target);
            }
        }
        if targets.is_empty() {
            disable(root)?;
            return Ok(None);
        }
        validate_runner_binary(root)?;

        fs::create_dir_all(root.join(".secret"))
            .context("dev: create .secret directory for module client state")?;
        disable(root)?;
        let run_id = random_run_id()?;
        let active_file = client_active_file(root, &run_id);
        fs::write(&active_file, b"active").context("dev: write module client run lease")?;
        fs::write(root.join(".secret").join(RUN_ID_FILE), &run_id)
            .context("dev: write module client run id")?;
        Ok(Some(Self {
            run_id,
            active_file,
            targets,
        }))
    }

    pub(super) fn run_id(&self) -> &str {
        &self.run_id
    }

    fn runner_file(&self) -> PathBuf {
        self.active_file
            .parent()
            .expect("client active file has a parent")
            .join(format!("{RUNNER_FILE_PREFIX}{}.json", self.run_id))
    }
}

fn client_target(root: &Path, module: &workspace::WorkspaceModule) -> Result<Option<ClientTarget>> {
    let meta = module_meta::read_module_meta(&module.abs_dir, root)?;
    if meta.id.is_empty() {
        return Ok(None);
    }
    let Some(client) = meta.client else {
        return Ok(None);
    };
    let slug = module
        .dir
        .file_name()
        .ok_or_else(|| anyhow!("module directory has no name: {}", module.dir.display()))?
        .to_string_lossy()
        .to_string();
    let module_root = fs::canonicalize(&module.abs_dir)
        .with_context(|| format!("dev: resolve module root {}", module.abs_dir.display()))?;
    let declared_client_dir = module.abs_dir.join(client.dir);
    let client_dir = fs::canonicalize(&declared_client_dir).with_context(|| {
        format!(
            "dev: declared client directory is missing for [{slug}]: {}",
            declared_client_dir.display()
        )
    })?;
    if !client_dir.starts_with(&module_root) || !client_dir.is_dir() {
        return Err(anyhow!(
            "dev: declared client directory for [{slug}] must resolve inside the module root"
        ));
    }
    let output_dir = client_dir.join(client.output_dir);
    Ok(Some(ClientTarget {
        slug,
        module_id: meta.id,
        client_dir,
        output_dir,
        state_root: root.join(".secret"),
    }))
}

impl Drop for ClientRun {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.active_file);
        let _ = fs::remove_file(self.runner_file());
        for target in &self.targets {
            let _ = fs::remove_file(target.status_file(&self.run_id));
            let _ = fs::remove_file(target.artifact_file(&self.run_id));
        }
    }
}

fn random_run_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .context("dev: generate module client run id")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Ensure a plain `mirrorstack dev` cannot consume a lease left by a crashed
/// tunnel command. The workspace lock's startup sweep handles all run-scoped
/// residue; this also makes an explicit mode transition immediately visible.
pub(super) fn disable(root: &Path) -> Result<()> {
    if !root.join(".secret").exists() {
        return Ok(());
    }
    let pointer = root.join(".secret").join(RUN_ID_FILE);
    if let Ok(run_id) = read_regular_file_limited(&pointer, 128, "module client run pointer") {
        let run_id = String::from_utf8_lossy(&run_id);
        let run_id = run_id.trim();
        if valid_run_id(run_id) {
            let _ = fs::remove_file(client_active_file(root, run_id));
        }
    }
    match fs::remove_file(&pointer) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("dev: clear stale module client run id"),
    }
}

/// Lifetime guard for the single compose project rooted at one workspace.
/// Every outer dev mode holds it until compose and its runner have stopped,
/// so no plain/tunnel or tunnel/tunnel pair can consume each other's files.
#[derive(Debug)]
pub(super) struct WorkspaceRunLock {
    _file: fs::File,
}

/// Run-scoped host-to-runner propagation for `--watch`. Existing compose
/// files invoke `mirrorstack dev --all --watch` directly and intentionally do
/// not forward arbitrary host environment, so the workspace bind mount is the
/// only backwards-compatible control channel. The workspace lock guarantees
/// that a live run owns this single marker; Drop and the next startup sweep
/// remove crash residue.
#[derive(Debug)]
pub(super) struct WatchModeGuard {
    path: PathBuf,
}

impl WatchModeGuard {
    pub(super) fn publish(root: &Path, watch: bool) -> Result<Self> {
        let state_root = root.join(".secret");
        fs::create_dir_all(&state_root)
            .context("dev: create .secret directory for dev watch mode")?;
        let path = state_root.join(WATCH_MODE_FILE);
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        write_atomic_regular(
            &path,
            &temporary,
            if watch { b"1" } else { b"0" },
            "dev watch mode",
        )?;
        Ok(Self { path })
    }
}

impl Drop for WatchModeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Resolve the host-selected watch mode inside the compose runner. Direct
/// `mirrorstack dev --all` invocations have no marker and retain their own
/// CLI flag, while an outer invocation overrides a compose file that may have
/// hardcoded `--watch` for compatibility with older CLIs.
pub(super) fn effective_watch(root: &Path, requested: bool) -> Result<bool> {
    let path = root.join(".secret").join(WATCH_MODE_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(requested),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("dev: inspect watch mode marker {}", path.display()));
        }
        Ok(_) => {}
    }
    let bytes = read_regular_file_limited(&path, 1, "dev watch mode marker")?;
    match bytes.as_slice() {
        b"1" => Ok(true),
        b"0" => Ok(false),
        _ => Err(anyhow!(
            "dev watch mode marker is invalid: {}",
            path.display()
        )),
    }
}

pub(super) fn lock_workspace(root: &Path) -> Result<WorkspaceRunLock> {
    fs::create_dir_all(root.join(".secret"))
        .context("dev: create .secret directory for dev workspace state")?;
    let path = root.join(".secret").join(WORKSPACE_LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("dev: open module client session lock {}", path.display()))?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            cleanup_stale_client_state(root)?;
            Ok(WorkspaceRunLock { _file: file })
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(anyhow!(
            "another `mirrorstack dev` process is already using this workspace"
        )),
        Err(error) => Err(error)
            .with_context(|| format!("dev: lock module client session {}", path.display())),
    }
}

fn cleanup_stale_client_state(root: &Path) -> Result<()> {
    let state_root = root.join(".secret");
    for (name, label) in [
        (RUN_ID_FILE, "module client run pointer"),
        (WATCH_MODE_FILE, "dev watch mode marker"),
    ] {
        match fs::remove_file(state_root.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("dev: remove stale {label}"));
            }
        }
    }
    for entry in fs::read_dir(&state_root).context("dev: scan stale module client state")? {
        let entry = entry.context("dev: read stale module client state entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let stale = [
            "ms-client-active-",
            "ms-client-status-",
            "ms-client-artifact-",
            RUNNER_FILE_PREFIX,
            WATCH_MODE_FILE,
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix));
        if stale {
            fs::remove_file(entry.path()).with_context(|| {
                format!(
                    "dev: remove stale module client state {}",
                    entry.path().display()
                )
            })?;
        }
    }
    Ok(())
}

fn valid_run_id(run_id: &str) -> bool {
    run_id.len() == 32
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn client_active_file(root: &Path, run_id: &str) -> PathBuf {
    root.join(".secret")
        .join(format!("ms-client-active-{run_id}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BuildStatus {
    run_id: String,
    state: BuildState,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BuildState {
    Building,
    Ready,
    Error,
}

fn read_status(target: &ClientTarget, run_id: &str) -> Option<BuildStatus> {
    let bytes = read_regular_file_limited(
        &target.status_file(run_id),
        MAX_STATUS_BYTES,
        "module client build status",
    )
    .ok()?;
    let status: BuildStatus = serde_json::from_slice(&bytes).ok()?;
    (status.run_id == run_id).then_some(status)
}

fn write_status(path: &Path, status: &BuildStatus) -> Result<()> {
    let bytes = serde_json::to_vec(status).context("dev: encode module client status")?;
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    write_atomic_regular(path, &temporary, &bytes, "module client build status")
}

fn write_atomic_regular(path: &Path, temporary: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
        let mut file = options
            .open(temporary)
            .with_context(|| format!("dev: create {label} {}", temporary.display()))?;
        // These files are the non-secret host↔runner control boundary (watch
        // mode, handshake, build status, and generated client archive). A
        // rootful Linux runner must leave them readable by the host CLI. Token
        // and internal-secret files use separate private writers.
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .with_context(|| format!("dev: set {label} permissions {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("dev: write {label} {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("dev: sync {label} {}", temporary.display()))?;
        drop(file);
        fs::rename(temporary, path)
            .with_context(|| format!("dev: publish {label} {}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn runner_file(root: &Path, run_id: &str) -> PathBuf {
    root.join(".secret")
        .join(format!("{RUNNER_FILE_PREFIX}{run_id}.json"))
}

fn write_runner_handshake(root: &Path, run_id: &str) -> Result<()> {
    let path = runner_file(root, run_id);
    let temporary = path.with_extension(format!("json.tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec(&RunnerHandshake {
        run_id: run_id.to_string(),
        protocol_version: RUNNER_PROTOCOL_VERSION,
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    })
    .context("dev: encode module client runner handshake")?;
    write_atomic_regular(&path, &temporary, &bytes, "module client runner handshake")
}

fn runner_compatibility_error(root: &Path, detail: &str) -> anyhow::Error {
    anyhow!(
        "module client runner is incompatible: {detail}. The compose runner's bind-mounted `{}` is missing or was built from a different mirrorstack-cli release. Build a Linux `mirrorstack` binary from this mirrorstack-cli checkout, replace that file, then rerun `mirrorstack dev --tunnel`",
        root.join(".mirrorstack-linux").display()
    )
}

fn validate_runner_binary(root: &Path) -> Result<()> {
    let path = root.join(".mirrorstack-linux");
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        let detail = if error.kind() == std::io::ErrorKind::NotFound {
            "the compose runner binary does not exist".to_string()
        } else {
            format!("the compose runner binary cannot be inspected: {error}")
        };
        runner_compatibility_error(root, &detail)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(runner_compatibility_error(
            root,
            "the compose runner bind source must be a regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(runner_compatibility_error(
            root,
            "the compose runner bind source is not executable",
        ));
    }
    Ok(())
}

/// Snapshot every existing compose `runner` container, including one that is
/// created but not yet running. The outer
/// process captures this before `compose up --force-recreate`, then waits for
/// a new container id. That distinction prevents a runner left by a crashed
/// predecessor from starting the short compatibility deadline while Docker is
/// still performing a legitimate cold image build.
pub(super) fn existing_runner_instances(root: &Path) -> Result<BTreeSet<String>> {
    runner_instances(root, COMPOSE_ALL_RUNNER_PS_ARGS)
}

fn running_runner_instances(root: &Path) -> Result<BTreeSet<String>> {
    runner_instances(root, COMPOSE_RUNNING_RUNNER_PS_ARGS)
}

fn runner_instances<const N: usize>(root: &Path, args: [&str; N]) -> Result<BTreeSet<String>> {
    let output = Command::new("docker")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow!("`docker` not found on PATH. Install Docker Desktop before running dev.")
            }
            _ => anyhow!("dev: inspect existing compose runner: {error}"),
        })?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "dev: inspect existing compose runner: docker {}{}",
            output.status,
            if detail.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", detail.trim())
            }
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

/// Prove that the newly recreated bind-mounted inner binary understands the
/// run-scoped client protocol before waiting for builds. Compose receives the
/// full build budget to create and start a new runner; only after that new
/// container appears does the short stale-binary handshake deadline begin.
pub(super) fn await_runner(
    run: &ClientRun,
    compose: &mut Child,
    root: &Path,
    previous_instances: &BTreeSet<String>,
) -> Result<()> {
    await_runner_with_probe(
        run,
        compose,
        root,
        previous_instances,
        RunnerWaitBudget {
            startup: BUILD_TIMEOUT,
            handshake: RUNNER_HANDSHAKE_TIMEOUT,
            poll: RUNNER_POLL,
        },
        || running_runner_instances(root),
    )
}

#[derive(Debug, Clone, Copy)]
struct RunnerWaitBudget {
    startup: Duration,
    handshake: Duration,
    poll: Duration,
}

fn await_runner_with_probe(
    run: &ClientRun,
    compose: &mut Child,
    root: &Path,
    previous_instances: &BTreeSet<String>,
    budget: RunnerWaitBudget,
    mut running_instances: impl FnMut() -> Result<BTreeSet<String>>,
) -> Result<()> {
    let startup_deadline = Instant::now() + budget.startup;
    let mut handshake_deadline = None;
    loop {
        if let Some(status) = compose.try_wait().context("dev: inspect docker compose")? {
            return Err(runner_compatibility_error(
                root,
                &format!(
                    "docker compose exited with {status} before acknowledging protocol v{RUNNER_PROTOCOL_VERSION}"
                ),
            ));
        }
        let path = run.runner_file();
        if handshake_deadline.is_some() && path.exists() {
            let bytes = read_regular_file_limited(
                &path,
                MAX_STATUS_BYTES,
                "module client runner handshake",
            )
            .map_err(|error| {
                runner_compatibility_error(
                    root,
                    &format!("the acknowledgement is unsafe: {error:#}"),
                )
            })?;
            let handshake: RunnerHandshake = serde_json::from_slice(&bytes).map_err(|error| {
                runner_compatibility_error(
                    root,
                    &format!("the acknowledgement is invalid: {error}"),
                )
            })?;
            if handshake.run_id != run.run_id {
                return Err(runner_compatibility_error(
                    root,
                    "the inner runner acknowledged a different dev run",
                ));
            }
            if handshake.protocol_version != RUNNER_PROTOCOL_VERSION {
                return Err(runner_compatibility_error(
                    root,
                    &format!(
                        "the inner runner reported protocol v{} but this CLI requires v{RUNNER_PROTOCOL_VERSION}",
                        handshake.protocol_version
                    ),
                ));
            }
            if handshake.cli_version != env!("CARGO_PKG_VERSION") {
                return Err(runner_compatibility_error(
                    root,
                    &format!(
                        "the inner runner reported CLI {} but this host requires CLI {}",
                        handshake.cli_version,
                        env!("CARGO_PKG_VERSION")
                    ),
                ));
            }
            return Ok(());
        }

        match handshake_deadline {
            None => {
                let instances = running_instances()?;
                let observed_at = Instant::now();
                if instances
                    .iter()
                    .any(|instance| !previous_instances.contains(instance))
                {
                    handshake_deadline = Some(observed_at + budget.handshake);
                } else if observed_at >= startup_deadline {
                    return Err(anyhow!(
                        "timed out waiting for the compose runner to start after {}s; inspect the docker compose build and dependency health checks",
                        budget.startup.as_secs()
                    ));
                }
            }
            Some(deadline) if Instant::now() >= deadline => {
                return Err(runner_compatibility_error(
                    root,
                    &format!(
                        "the new runner started, but no protocol v{RUNNER_PROTOCOL_VERSION} acknowledgement arrived within {}s",
                        budget.handshake.as_secs()
                    ),
                ));
            }
            Some(_) => {}
        }
        if !budget.poll.is_zero() {
            thread::sleep(budget.poll);
        }
    }
}

/// Build declared clients inside the Docker runner. The run-id file is the
/// host-to-container opt-in: local-only `dev` keeps its old behavior, while a
/// tunnel run gets an initial all-or-nothing build plus source watchers.
pub(super) fn build_in_runner(
    root: &Path,
    modules: &[workspace::WorkspaceModule],
    watch: bool,
    stop: Arc<AtomicBool>,
) -> Result<Vec<thread::JoinHandle<()>>> {
    let run_id_file = root.join(".secret").join(RUN_ID_FILE);
    let Ok(run_id) = read_regular_file_limited(&run_id_file, 128, "module client run pointer")
    else {
        return Ok(Vec::new());
    };
    let run_id = String::from_utf8_lossy(&run_id).trim().to_string();
    if !valid_run_id(&run_id) {
        return Err(anyhow!("dev: module client run id is invalid"));
    }
    if !client_active_file(root, &run_id).is_file() {
        return Ok(Vec::new());
    }
    write_runner_handshake(root, &run_id)?;

    let mut builders = Vec::new();
    let mut failures = Vec::new();
    for module in modules {
        let Some(target) = client_target(root, module)? else {
            continue;
        };
        // Capture before the initial build. Watchers start only after every
        // module has built, so using a later baseline could swallow edits to
        // an early client while a later client's npm build is still running.
        let source_before_build = source_signature(&target.client_dir, &target.output_dir);
        let slug = target.slug.clone();
        let status_file = target.status_file(&run_id);
        write_status(
            &status_file,
            &BuildStatus {
                run_id: run_id.clone(),
                state: BuildState::Building,
                generation: 0,
                sha256: None,
                size_bytes: None,
                message: None,
            },
        )?;
        let active_file = target.active_file(&run_id);
        match build_once(&target, &active_file, &stop) {
            Ok(artifact) => {
                ensure_active_run(&active_file)?;
                write_artifact(&target, &run_id, &artifact)?;
                ensure_active_run(&active_file)?;
                write_status(
                    &status_file,
                    &BuildStatus {
                        run_id: run_id.clone(),
                        state: BuildState::Ready,
                        generation: 1,
                        sha256: Some(artifact.sha256),
                        size_bytes: Some(artifact.bytes.len() as u64),
                        message: None,
                    },
                )?;
                eprintln!(
                    "{} [{}] module client built",
                    ok_mark(),
                    style(&slug).cyan()
                );
                builders.push((target, source_before_build));
            }
            Err(error) => {
                ensure_active_run(&active_file)?;
                let message = error.to_string();
                write_status(
                    &status_file,
                    &BuildStatus {
                        run_id: run_id.clone(),
                        state: BuildState::Error,
                        generation: 0,
                        sha256: None,
                        size_bytes: None,
                        message: Some(message.clone()),
                    },
                )?;
                failures.push(format!("[{slug}] {message}"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(anyhow!(
            "module client initial build failed:\n{}",
            failures.join("\n")
        ));
    }
    if !watch {
        return Ok(Vec::new());
    }

    Ok(builders
        .into_iter()
        .map(|(target, source_before_build)| {
            let run_id = run_id.clone();
            let stop = stop.clone();
            thread::spawn(move || watch_client_source(target, run_id, source_before_build, stop))
        })
        .collect())
}

fn build_once(
    target: &ClientTarget,
    active_file: &Path,
    stop: &AtomicBool,
) -> Result<ClientArtifact> {
    build_once_with(target, active_file, stop, Path::new("npm"), BUILD_TIMEOUT)
}

fn build_once_with(
    target: &ClientTarget,
    active_file: &Path,
    stop: &AtomicBool,
    build_program: &Path,
    timeout: Duration,
) -> Result<ClientArtifact> {
    let started = Instant::now();
    let build_lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(target.build_lock_file())
        .with_context(|| format!("dev: open module client build lock for [{}]", target.slug))?;
    loop {
        if let Some(error) = build_abort_reason(target, active_file, stop, started, timeout) {
            return Err(error);
        }
        match FileExt::try_lock_exclusive(&build_lock) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("dev: lock module client build for [{}]", target.slug)
                });
            }
        }
    }
    ensure_active_run(active_file)?;

    let package_path = target.client_dir.join("package.json");
    let package_bytes =
        read_regular_file_limited(&package_path, MAX_PACKAGE_JSON_BYTES, "client package.json")
            .with_context(|| {
                format!(
                    "client package is missing or unsafe {}",
                    package_path.display()
                )
            })?;
    let package: serde_json::Value = serde_json::from_slice(&package_bytes)
        .with_context(|| format!("client package is invalid JSON: {}", package_path.display()))?;
    if !package
        .pointer("/scripts/build")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|script| !script.trim().is_empty())
    {
        return Err(anyhow!(
            "{} must declare a non-empty scripts.build; install dependencies locally, then make `npm run build` produce the declared output",
            package_path.display()
        ));
    }

    let mut command = Command::new(build_program);
    command
        .args(["run", "build"])
        .current_dir(&target.client_dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // npm scripts routinely spawn shells and bundlers. Give the build its own
    // process group so timeout/cancellation can terminate the build tree.
    // Output stays attached to the runner instead of using reader threads: a
    // detached descendant must not keep a pipe open and defeat the deadline.
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("run npm build in {}", target.client_dir.display()))?;

    let (status, build_error) = loop {
        if let Some(error) = build_abort_reason(target, active_file, stop, started, timeout) {
            terminate_build(&mut child);
            break (None, Some(error));
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // A build script can exit after spawning a background watcher.
                // Tear down the whole build tree even when npm itself succeeded.
                terminate_build(&mut child);
                break (Some(status), None);
            }
            Ok(None) => {}
            Err(error) => {
                terminate_build(&mut child);
                break (
                    None,
                    Some(anyhow!(error).context("dev: inspect npm client build process")),
                );
            }
        }
        thread::sleep(Duration::from_millis(50));
    };
    if let Some(error) = build_error {
        return Err(error);
    }
    let status = status.expect("completed client build has an exit status");
    if !status.success() {
        return Err(anyhow!(
            "npm run build failed in {} ({status})",
            target.client_dir.display(),
        ));
    }
    ensure_active_run(active_file)?;
    let artifact = package_target(target)?;
    ensure_active_run(active_file)?;
    Ok(artifact)
}

fn build_abort_reason(
    target: &ClientTarget,
    active_file: &Path,
    stop: &AtomicBool,
    started: Instant,
    timeout: Duration,
) -> Option<anyhow::Error> {
    if stop.load(Ordering::SeqCst) {
        return Some(anyhow!("module client build was cancelled"));
    }
    if !active_file.is_file() {
        return Some(anyhow!(
            "module client build was superseded by another dev run"
        ));
    }
    (started.elapsed() >= timeout).then(|| {
        anyhow!(
            "npm run build timed out in {} after {}s",
            target.client_dir.display(),
            timeout.as_secs()
        )
    })
}

fn terminate_build(child: &mut Child) {
    #[cfg(unix)]
    {
        // The child is its process-group leader (see `process_group(0)`). A
        // negative pid addresses the entire group, including shell-spawned
        // bundlers that inherited the captured pipes.
        if let Ok(pid) = i32::try_from(child.id()) {
            // SAFETY: kill is called with a process-group id created for this
            // child and SIGKILL has no Rust memory-safety implications.
            let _ = unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
    }
    #[cfg(windows)]
    {
        // `Child::kill` only terminates npm itself on Windows. `taskkill /T`
        // closes the script shell and bundler descendants too, ensuring their
        // inherited stdout/stderr handles cannot keep the reader joins alive.
        let pid = child.id().to_string();
        let _ = Command::new("taskkill")
            .args(["/PID", pid.as_str(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn ensure_active_run(active_file: &Path) -> Result<()> {
    if active_file.is_file() {
        Ok(())
    } else {
        Err(anyhow!(
            "module client build was superseded by another dev run"
        ))
    }
}

fn write_artifact(target: &ClientTarget, run_id: &str, artifact: &ClientArtifact) -> Result<()> {
    let artifact_file = target.artifact_file(run_id);
    let temporary = artifact_file.with_extension(format!("tgz.tmp-{}", std::process::id()));
    write_atomic_regular(
        &artifact_file,
        &temporary,
        &artifact.bytes,
        &format!("module client snapshot for [{}]", target.slug),
    )
}

/// Read the runner's immutable artifact snapshot and prove it still belongs
/// to the same ready generation. The runner renames the tgz before publishing
/// status, so the host never traverses a `dist` tree that a rebuild can mutate.
fn read_ready_artifact(
    target: &ClientTarget,
    run_id: &str,
    status: &BuildStatus,
) -> Result<Option<ClientArtifact>> {
    if status.state != BuildState::Ready {
        return Ok(None);
    }
    let expected_sha = status
        .sha256
        .as_deref()
        .ok_or_else(|| anyhow!("ready client status omitted sha256"))?;
    let expected_size = status
        .size_bytes
        .ok_or_else(|| anyhow!("ready client status omitted size_bytes"))?;
    if expected_size == 0 || expected_size > MAX_COMPRESSED_BYTES as u64 {
        return Err(anyhow!("ready client status has invalid artifact size"));
    }

    for _ in 0..3 {
        let artifact_file = target.artifact_file(run_id);
        let bytes = match read_regular_file_limited(
            &artifact_file,
            expected_size as usize,
            "module client snapshot",
        ) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                thread::sleep(BUILD_POLL);
                continue;
            }
            Err(error) => {
                return Err(error).context(format!(
                    "dev: read module client snapshot for [{}]",
                    target.slug
                ));
            }
        };
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        if bytes.len() as u64 == expected_size && sha256 == expected_sha {
            if read_status(target, run_id).as_ref() == Some(status) {
                return Ok(Some(ClientArtifact { bytes, sha256 }));
            }
            return Ok(None);
        }
        if read_status(target, run_id).as_ref() != Some(status) {
            return Ok(None);
        }
        thread::sleep(BUILD_POLL);
    }
    Err(anyhow!(
        "module client snapshot for [{}] does not match its ready status",
        target.slug
    ))
}

fn package_target(target: &ClientTarget) -> Result<ClientArtifact> {
    let client_dir = fs::canonicalize(&target.client_dir)
        .with_context(|| format!("dev: resolve client directory for [{}]", target.slug))?;
    let output_dir = fs::canonicalize(&target.output_dir)
        .with_context(|| format!("dev: resolve client output for [{}]", target.slug))?;
    if !output_dir.starts_with(&client_dir) {
        return Err(anyhow!(
            "module client output for [{}] resolves outside its client directory",
            target.slug
        ));
    }
    package_client(&target.output_dir)
}

type SourceSignature = Vec<(PathBuf, [u8; 32])>;

fn source_signature(client_dir: &Path, output_dir: &Path) -> SourceSignature {
    fn digest(path: &Path) -> Option<[u8; 32]> {
        let (mut file, metadata) = open_regular_file(path, "module client source").ok()?;
        let mut hasher = Sha256::new();
        if metadata.len() > MAX_SOURCE_FILE_BYTES {
            hasher.update(b"mirrorstack:oversized-source\0");
            hasher.update(metadata.len().to_le_bytes());
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .unwrap_or_default();
            hasher.update(modified.as_nanos().to_le_bytes());
            return Some(hasher.finalize().into());
        }
        let mut limited = (&mut file).take(MAX_SOURCE_FILE_BYTES + 1);
        let mut buffer = [0u8; 16 * 1024];
        let mut total = 0u64;
        loop {
            let read = limited.read(&mut buffer).ok()?;
            if read == 0 {
                return (total == metadata.len()).then(|| hasher.finalize().into());
            }
            total = total.saturating_add(read as u64);
            if total > MAX_SOURCE_FILE_BYTES {
                return None;
            }
            hasher.update(&buffer[..read]);
        }
    }

    fn walk(directory: &Path, output_dir: &Path, signature: &mut SourceSignature) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == output_dir {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                let name = entry.file_name();
                if matches!(
                    name.to_str(),
                    Some("node_modules" | ".git" | ".cache" | ".turbo" | ".vite" | "coverage")
                ) {
                    continue;
                }
                walk(&path, output_dir, signature);
            } else if kind.is_file() {
                if path
                    .extension()
                    .is_some_and(|extension| extension == "tsbuildinfo")
                {
                    continue;
                }
                if let Some(hash) = digest(&path) {
                    signature.push((path, hash));
                }
            }
        }
    }

    let mut signature = Vec::new();
    walk(client_dir, output_dir, &mut signature);
    signature.sort();
    signature
}

fn watch_client_source(
    target: ClientTarget,
    run_id: String,
    mut previous: SourceSignature,
    stop: Arc<AtomicBool>,
) {
    let mut generation = 1u64;
    let active_file = target.active_file(&run_id);
    while !stop.load(Ordering::SeqCst) {
        thread::sleep(BUILD_POLL);
        if !active_file.is_file() {
            return;
        }
        let next = source_signature(&target.client_dir, &target.output_dir);
        if next == previous {
            continue;
        }
        eprintln!(
            "{} [{}] module client changed — rebuilding…",
            ok_mark(),
            style(&target.slug).cyan()
        );
        let building = BuildStatus {
            run_id: run_id.clone(),
            state: BuildState::Building,
            generation,
            sha256: None,
            size_bytes: None,
            message: None,
        };
        let status_file = target.status_file(&run_id);
        if let Err(error) = write_status(&status_file, &building) {
            eprintln!(
                "{} [{}] publish client build status: {error:#}",
                warn_prefix(),
                style(&target.slug).cyan()
            );
            continue;
        }
        let status = match build_once(&target, &active_file, &stop).and_then(|artifact| {
            ensure_active_run(&active_file)?;
            write_artifact(&target, &run_id, &artifact)?;
            Ok(artifact)
        }) {
            Ok(artifact) => {
                generation = generation.saturating_add(1);
                BuildStatus {
                    run_id: run_id.clone(),
                    state: BuildState::Ready,
                    generation,
                    sha256: Some(artifact.sha256),
                    size_bytes: Some(artifact.bytes.len() as u64),
                    message: None,
                }
            }
            Err(error) => BuildStatus {
                run_id: run_id.clone(),
                state: BuildState::Error,
                generation,
                sha256: None,
                size_bytes: None,
                message: Some(error.to_string()),
            },
        };
        if !active_file.is_file() {
            return;
        }
        if let Err(error) = write_status(&status_file, &status) {
            eprintln!(
                "{} [{}] publish client build status: {error:#}",
                warn_prefix(),
                style(&target.slug).cyan()
            );
            continue;
        }
        previous = next;
        if status.state == BuildState::Error {
            eprintln!(
                "{} [{}] client rebuild failed; retaining last confirmed artifact: {}",
                warn_prefix(),
                style(&target.slug).cyan(),
                status.message.as_deref().unwrap_or("unknown build error")
            );
        }
    }
}

pub(super) struct PublishedTarget {
    target: ClientTarget,
    artifact: ClientArtifact,
    build_generation: u64,
    confirmed_sha256: String,
    confirmed_session_generation: u64,
    last_build_warning: Option<String>,
    last_publish_warning: Option<String>,
    retry_sha256: String,
    retry_session_generation: u64,
    publish_failures: u32,
    next_publish_attempt: Instant,
    next_renewal: Instant,
}

/// Wait for the runner's initial builds, then synchronously confirm every
/// declared client. Each confirmed target is handed to the already-running
/// publisher immediately, so its session-bound pointer stays supervised while
/// later targets are still building. Returning an error is a startup failure;
/// the caller kills compose and tears down the tunnels before surfacing it.
pub(super) fn publish_initial(
    run: &ClientRun,
    sessions: &SessionTracker,
    compose: &mut Child,
    apps_base: &str,
    publisher: &PublisherHandle,
) -> Result<()> {
    let api_client = http::client(Duration::from_secs(15))?;
    let upload_client = http::client(UPLOAD_TIMEOUT)?;
    let mut context = InitialPublishContext {
        run_id: &run.run_id,
        sessions,
        compose,
        apps_base,
        credentials: &publisher.credentials,
        api_client: &api_client,
        upload_client: &upload_client,
    };
    publish_targets_sequentially(
        &run.targets,
        BUILD_TIMEOUT,
        |target, deadline| publish_initial_target(target, &mut context, deadline),
        |published| {
            let slug = published.target.slug.clone();
            let confirmed_sha256 = published.confirmed_sha256.clone();
            publisher.track(published)?;
            eprintln!(
                "{} [{}] module client ready ({})",
                ok_mark(),
                style(slug).cyan(),
                style(format!("sha256:{confirmed_sha256}")).dim()
            );
            Ok(())
        },
    )
}

/// Sequential startup deliberately tracks each confirmed target before the
/// next target begins, and gives every target its own full build budget. This
/// keeps the first target's session pointer supervised while a later cold npm
/// build is still pending, without making later targets inherit time already
/// spent on earlier builds.
fn publish_targets_sequentially<T, U>(
    targets: &[T],
    timeout: Duration,
    mut publish: impl FnMut(&T, Instant) -> Result<U>,
    mut track: impl FnMut(U) -> Result<()>,
) -> Result<()> {
    for target in targets {
        let published = publish(target, Instant::now() + timeout)?;
        track(published)?;
    }
    Ok(())
}

struct InitialPublishContext<'a> {
    run_id: &'a str,
    sessions: &'a SessionTracker,
    compose: &'a mut Child,
    apps_base: &'a str,
    credentials: &'a Mutex<Credentials>,
    api_client: &'a HttpClient,
    upload_client: &'a HttpClient,
}

fn publish_initial_target(
    target: &ClientTarget,
    context: &mut InitialPublishContext<'_>,
    deadline: Instant,
) -> Result<PublishedTarget> {
    loop {
        if let Some(status) = context
            .compose
            .try_wait()
            .context("dev: inspect docker compose")?
        {
            return Err(anyhow!(
                "docker compose exited with {status} before [{}] client became ready",
                target.slug
            ));
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for [{}] module client build after {}s",
                target.slug,
                BUILD_TIMEOUT.as_secs()
            ));
        }
        let Some(status) = read_status(target, context.run_id) else {
            thread::sleep(BUILD_POLL);
            continue;
        };
        if status.state == BuildState::Error {
            return Err(anyhow!(
                "[{}] client build failed: {}",
                target.slug,
                status.message.as_deref().unwrap_or("unknown build error")
            ));
        }
        if status.state == BuildState::Building {
            thread::sleep(BUILD_POLL);
            continue;
        }
        let Some(artifact) = read_ready_artifact(target, context.run_id, &status)
            .with_context(|| format!("[{}] read built module client", target.slug))?
        else {
            thread::sleep(BUILD_POLL);
            continue;
        };
        let session = context
            .sessions
            .current(&target.slug)
            .ok_or_else(|| anyhow!("[{}] tunnel session is unavailable", target.slug))?;
        match upload_and_confirm_shared(
            context.api_client,
            context.upload_client,
            context.apps_base,
            context.credentials,
            target,
            &session,
            &artifact,
        ) {
            Ok(()) => {
                let confirmed_sha256 = artifact.sha256.clone();
                return Ok(PublishedTarget {
                    target: target.clone(),
                    confirmed_sha256,
                    build_generation: status.generation,
                    confirmed_session_generation: session.generation,
                    last_build_warning: None,
                    last_publish_warning: None,
                    retry_sha256: artifact.sha256.clone(),
                    retry_session_generation: session.generation,
                    publish_failures: 0,
                    next_publish_attempt: Instant::now(),
                    next_renewal: Instant::now() + PUBLISH_RENEW_INTERVAL,
                    artifact,
                });
            }
            Err(ApiError::Server { code, .. })
                if code == "tunnel_session_superseded" || code == "tunnel_session_expired" =>
            {
                thread::sleep(BUILD_POLL);
            }
            Err(error) => {
                return Err(anyhow!(
                    "[{}] publish initial module client: {error}",
                    target.slug
                ));
            }
        }
    }
}

pub(super) struct PublisherHandle {
    stop: Arc<AtomicBool>,
    additions: mpsc::Sender<PublishedTarget>,
    credentials: Arc<Mutex<Credentials>>,
    handle: thread::JoinHandle<()>,
}

struct PublisherRuntime {
    run_id: String,
    additions: mpsc::Receiver<PublishedTarget>,
    sessions: Arc<SessionTracker>,
    apps_base: String,
    stop: Arc<AtomicBool>,
    credentials: Arc<Mutex<Credentials>>,
    api_client: HttpClient,
    upload_client: HttpClient,
}

impl PublisherHandle {
    fn track(&self, target: PublishedTarget) -> Result<()> {
        self.additions
            .send(target)
            .map_err(|_| anyhow!("module client publisher stopped during startup"))
    }

    pub(super) fn shutdown(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.handle.join();
    }
}

pub(super) fn spawn_publisher(
    run_id: String,
    sessions: Arc<SessionTracker>,
    apps_base: String,
) -> Result<PublisherHandle> {
    let credentials = Arc::new(Mutex::new(credentials::load_or_login_hint()?));
    let api_client = http::client(Duration::from_secs(15))?;
    let upload_client = http::client(UPLOAD_TIMEOUT)?;
    let (additions, receiver) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let runtime = PublisherRuntime {
        run_id,
        additions: receiver,
        sessions,
        apps_base,
        stop: stop.clone(),
        credentials: credentials.clone(),
        api_client,
        upload_client,
    };
    let handle = thread::spawn(move || run_publisher(runtime));
    Ok(PublisherHandle {
        stop,
        additions,
        credentials,
        handle,
    })
}

fn run_publisher(runtime: PublisherRuntime) {
    let mut targets = Vec::new();
    let mut last_scan = Instant::now() - PUBLISH_SCAN_INTERVAL;

    while !runtime.stop.load(Ordering::SeqCst) {
        if drain_published_targets(&runtime.additions, &mut targets) > 0 {
            // A target may have reconnected in the tiny confirm→enqueue
            // window. Scan it now instead of waiting for the regular interval.
            last_scan = Instant::now() - PUBLISH_SCAN_INTERVAL;
        }
        if last_scan.elapsed() < PUBLISH_SCAN_INTERVAL {
            thread::sleep(BUILD_POLL);
            continue;
        }
        last_scan = Instant::now();
        for state in &mut targets {
            if let Some(status) = read_status(&state.target, &runtime.run_id) {
                if status.state == BuildState::Ready && status.generation > state.build_generation {
                    match read_ready_artifact(&state.target, &runtime.run_id, &status) {
                        Ok(Some(artifact)) => {
                            state.artifact = artifact;
                            state.build_generation = status.generation;
                            state.last_build_warning = None;
                        }
                        Ok(None) => {}
                        Err(error) => warn_build_once(
                            state,
                            format!("snapshot generation {}: {error:#}", status.generation),
                        ),
                    }
                } else if status.state == BuildState::Error {
                    warn_build_once(
                        state,
                        format!(
                            "build generation {}: {}",
                            status.generation,
                            status.message.as_deref().unwrap_or("unknown build error")
                        ),
                    );
                }
            }
            let Some(session) = runtime.sessions.current(&state.target.slug) else {
                continue;
            };
            let publish_target_changed = state.retry_sha256 != state.artifact.sha256
                || state.retry_session_generation != session.generation;
            if publish_target_changed {
                state.retry_sha256 = state.artifact.sha256.clone();
                state.retry_session_generation = session.generation;
                state.publish_failures = 0;
                state.next_publish_attempt = Instant::now();
                state.last_publish_warning = None;
            }
            if !publication_due(
                &state.confirmed_sha256,
                &state.artifact.sha256,
                state.confirmed_session_generation,
                session.generation,
                state.next_renewal,
                Instant::now(),
            ) {
                continue;
            }
            if Instant::now() < state.next_publish_attempt {
                continue;
            }
            match upload_and_confirm_shared(
                &runtime.api_client,
                &runtime.upload_client,
                &runtime.apps_base,
                &runtime.credentials,
                &state.target,
                &session,
                &state.artifact,
            ) {
                Ok(()) => {
                    state.confirmed_sha256 = state.artifact.sha256.clone();
                    state.confirmed_session_generation = session.generation;
                    state.publish_failures = 0;
                    state.next_publish_attempt = Instant::now();
                    state.next_renewal = Instant::now() + PUBLISH_RENEW_INTERVAL;
                    state.last_publish_warning = None;
                    eprintln!(
                        "{} [{}] module client published ({})",
                        ok_mark(),
                        style(&state.target.slug).cyan(),
                        style(format!("sha256:{}", state.artifact.sha256)).dim()
                    );
                }
                Err(error) => {
                    state.publish_failures = state.publish_failures.saturating_add(1);
                    state.next_publish_attempt =
                        Instant::now() + publish_retry_delay(state.publish_failures);
                    warn_publish_once(state, format!("publish: {error}"));
                }
            }
        }
    }
}

fn drain_published_targets(
    additions: &mpsc::Receiver<PublishedTarget>,
    targets: &mut Vec<PublishedTarget>,
) -> usize {
    let before = targets.len();
    targets.extend(additions.try_iter());
    targets.len() - before
}

fn publish_retry_delay(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(5);
    let base_ms = (PUBLISH_SCAN_INTERVAL.as_millis() as u64).saturating_mul(1u64 << shift);
    let jitter_percent = 75 + OsRng.try_next_u64().unwrap_or(25) % 51;
    Duration::from_millis(
        base_ms
            .saturating_mul(jitter_percent)
            .saturating_div(100)
            .min(PUBLISH_RETRY_CAP.as_millis() as u64),
    )
}

fn publication_due(
    confirmed_sha256: &str,
    artifact_sha256: &str,
    confirmed_session_generation: u64,
    session_generation: u64,
    next_renewal: Instant,
    now: Instant,
) -> bool {
    confirmed_sha256 != artifact_sha256
        || confirmed_session_generation != session_generation
        || now >= next_renewal
}

fn warn_build_once(state: &mut PublishedTarget, warning: String) {
    if state.last_build_warning.as_deref() == Some(&warning) {
        return;
    }
    eprintln!(
        "{} [{}] module client {warning}; retaining last confirmed revision",
        warn_prefix(),
        style(&state.target.slug).cyan()
    );
    state.last_build_warning = Some(warning);
}

fn warn_publish_once(state: &mut PublishedTarget, warning: String) {
    if state.last_publish_warning.as_deref() == Some(&warning) {
        return;
    }
    eprintln!(
        "{} [{}] module client {warning}; retaining last confirmed revision",
        warn_prefix(),
        style(&state.target.slug).cyan()
    );
    state.last_publish_warning = Some(warning);
}

fn upload_and_confirm(
    api_client: &HttpClient,
    upload_client: &HttpClient,
    apps_base: &str,
    credentials: &mut Credentials,
    target: &ClientTarget,
    session: &SessionSnapshot,
    artifact: &ClientArtifact,
) -> Result<(), ApiError> {
    retry_with_rotated_credentials(credentials, |credentials| {
        upload_and_confirm_once(
            api_client,
            upload_client,
            apps_base,
            credentials,
            target,
            session,
            artifact,
        )
    })
}

fn upload_and_confirm_shared(
    api_client: &HttpClient,
    upload_client: &HttpClient,
    apps_base: &str,
    credentials: &Mutex<Credentials>,
    target: &ClientTarget,
    session: &SessionSnapshot,
    artifact: &ClientArtifact,
) -> Result<(), ApiError> {
    let mut credentials = credentials
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    upload_and_confirm(
        api_client,
        upload_client,
        apps_base,
        &mut credentials,
        target,
        session,
        artifact,
    )
}

fn retry_with_rotated_credentials<T>(
    credentials: &mut Credentials,
    mut operation: impl FnMut(&mut Credentials) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    match operation(credentials) {
        Err(ApiError::Unauthenticated) if credentials::adopt_rotated(credentials) => {
            operation(credentials)
        }
        result => result,
    }
}

fn upload_and_confirm_once(
    api_client: &HttpClient,
    upload_client: &HttpClient,
    apps_base: &str,
    credentials: &mut Credentials,
    target: &ClientTarget,
    session: &SessionSnapshot,
    artifact: &ClientArtifact,
) -> Result<(), ApiError> {
    let module_id = module_meta::catalog_uuid(&target.module_id);
    let presign = credentials::with_refresh_retry(credentials, |token| {
        api::presign_dev_client(
            api_client,
            apps_base,
            token,
            &module_id,
            &DevClientPresignInput {
                session_id: &session.session_id,
                size_bytes: artifact.bytes.len() as u64,
                sha256: &artifact.sha256,
                format_version: FORMAT_VERSION,
            },
        )
    })?;
    put_artifact(
        upload_client,
        &presign.upload_url,
        &presign.headers,
        &artifact.bytes,
    )?;
    let confirmed = credentials::with_refresh_retry(credentials, |token| {
        api::confirm_dev_client(
            api_client,
            apps_base,
            token,
            &module_id,
            &DevClientConfirmInput {
                key: &presign.key,
                session_id: &session.session_id,
                size_bytes: artifact.bytes.len() as u64,
                sha256: &artifact.sha256,
                format_version: FORMAT_VERSION,
            },
        )
    })?;
    if confirmed.source != "tunnel"
        || confirmed.sha256 != artifact.sha256
        || confirmed.size_bytes != artifact.bytes.len() as u64
        || confirmed.revision != format!("sha256:{}", artifact.sha256)
    {
        return Err(ApiError::Unexpected {
            status: 200,
            body: "dev-client confirm returned mismatched artifact metadata".into(),
        });
    }
    Ok(())
}

fn put_artifact(
    client: &HttpClient,
    upload_url: &str,
    headers: &std::collections::BTreeMap<String, String>,
    bytes: &[u8],
) -> Result<(), ApiError> {
    let mut request = client.put(upload_url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let response = request
        .body(bytes.to_vec())
        .send()
        .map_err(|error| ApiError::Http(error.without_url()))?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    // The response body is intentionally discarded: a storage gateway may
    // echo the request URI, whose query string is the upload credential.
    Err(ApiError::Unexpected {
        status: status.as_u16(),
        body: "module client upload failed".into(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Read;
    use std::time::Duration;

    use flate2::read::GzDecoder;
    use mockito::Server;

    use super::*;

    fn valid_dist() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let dist = temp.path().join("dist");
        fs::create_dir_all(dist.join("chunks")).unwrap();
        fs::write(dist.join("index.js"), b"export default () => ({})\n").unwrap();
        fs::write(
            dist.join("index.d.ts"),
            b"declare const plugin: () => object;\nexport default plugin;\n",
        )
        .unwrap();
        fs::write(dist.join("chunks/helper.js"), b"export const ok = true;\n").unwrap();
        temp
    }

    fn test_target(root: &Path) -> ClientTarget {
        ClientTarget {
            slug: "media".into(),
            module_id: "module-id".into(),
            client_dir: root.join("client"),
            output_dir: root.join("client/dist"),
            state_root: root.to_path_buf(),
        }
    }

    #[test]
    fn canonical_package_is_byte_identical_and_has_required_layout() {
        let temp = valid_dist();

        let first = package_client(&temp.path().join("dist")).unwrap();
        let second = package_client(&temp.path().join("dist")).unwrap();

        assert_eq!(first.sha256, second.sha256);
        assert_eq!(first.bytes, second.bytes);

        let decoder = GzDecoder::new(first.bytes.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let mut paths = Vec::new();
        let mut manifest = String::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "package/package.json" {
                entry.read_to_string(&mut manifest).unwrap();
            }
            paths.push(path);
        }
        assert_eq!(
            paths,
            vec![
                "package/package.json",
                "package/dist/chunks/helper.js",
                "package/dist/index.d.ts",
                "package/dist/index.js",
            ]
        );
        assert_eq!(
            manifest,
            "{\"type\":\"module\",\"exports\":{\".\":{\"types\":\"./dist/index.d.ts\",\"import\":\"./dist/index.js\"}}}\n"
        );
    }

    #[test]
    fn canonical_package_requires_root_javascript_and_types() {
        for missing in ["index.js", "index.d.ts"] {
            let temp = valid_dist();
            fs::remove_file(temp.path().join("dist").join(missing)).unwrap();

            let error = package_client(&temp.path().join("dist"))
                .expect_err("missing root entry must fail")
                .to_string();

            assert!(error.contains(missing), "{error}");
        }
    }

    #[test]
    fn canonical_package_rejects_empty_root_entries() {
        for empty in ["index.js", "index.d.ts"] {
            let temp = valid_dist();
            fs::write(temp.path().join("dist").join(empty), b"").unwrap();

            let error = package_client(&temp.path().join("dist"))
                .expect_err("empty root entry must fail")
                .to_string();

            assert!(error.contains("non-empty"), "{empty}: {error}");
        }
    }

    #[test]
    fn canonical_package_bounds_opened_output_files() {
        let temp = valid_dist();
        OpenOptions::new()
            .write(true)
            .open(temp.path().join("dist/index.js"))
            .unwrap()
            .set_len(MAX_EXPANDED_BYTES + 1)
            .unwrap();

        let error = package_client(&temp.path().join("dist"))
            .expect_err("oversized output must fail before it is read")
            .to_string();

        assert!(error.contains("exceeds"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn canonical_package_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = valid_dist();
        symlink("index.js", temp.path().join("dist/alias.js")).unwrap();

        let error = package_client(&temp.path().join("dist"))
            .expect_err("symlink must fail")
            .to_string();

        assert!(error.contains("symbolic link"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn canonical_package_rejects_special_files_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let temp = valid_dist();
        let fifo = temp.path().join("dist/stream.css");
        let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_path is a valid NUL-terminated path owned for the call.
        let result = unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let error = package_client(&temp.path().join("dist"))
            .expect_err("special output file must fail")
            .to_string();

        assert!(error.contains("not a regular file"), "{error}");
    }

    #[test]
    fn canonical_package_rejects_native_addons_and_bundled_dependencies() {
        for (relative, expected) in [
            ("native.node", "native.node"),
            ("node_modules/pkg/index.js", "node_modules"),
            ("Node_Modules/pkg/index.js", "Node_Modules"),
            ("logo.svg", "logo.svg"),
        ] {
            let temp = valid_dist();
            let path = temp.path().join("dist").join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"nope").unwrap();

            let error = package_client(&temp.path().join("dist"))
                .expect_err("unsafe output must fail")
                .to_string();

            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn build_status_ignores_another_dev_run() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let status = BuildStatus {
            run_id: "run-a".into(),
            state: BuildState::Ready,
            generation: 3,
            sha256: Some("a".repeat(64)),
            size_bytes: Some(10),
            message: None,
        };

        write_status(&target.status_file("run-a"), &status).unwrap();

        assert_eq!(read_status(&target, "run-a"), Some(status));
        assert_eq!(read_status(&target, "run-b"), None);
    }

    #[test]
    fn build_status_rejects_oversized_control_files() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        fs::write(
            target.status_file("run-a"),
            vec![b'x'; MAX_STATUS_BYTES + 1],
        )
        .unwrap();

        assert_eq!(read_status(&target, "run-a"), None);
    }

    #[test]
    fn initial_publish_supervises_each_target_and_resets_its_deadline() {
        use std::cell::RefCell;

        let tracked = RefCell::new(Vec::new());
        let deadlines = RefCell::new(Vec::new());
        publish_targets_sequentially(
            &["first", "later"],
            Duration::from_secs(10),
            |target, deadline| {
                if *target == "later" {
                    assert_eq!(
                        tracked.borrow().as_slice(),
                        ["first"],
                        "the first confirmed target must be supervised before the later build starts"
                    );
                }
                deadlines.borrow_mut().push(deadline);
                thread::sleep(Duration::from_millis(5));
                Ok(*target)
            },
            |target| {
                tracked.borrow_mut().push(target);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(tracked.into_inner(), ["first", "later"]);
        let deadlines = deadlines.into_inner();
        assert!(
            deadlines[1] > deadlines[0],
            "each target must receive a fresh outer build deadline"
        );
    }

    #[cfg(unix)]
    #[test]
    fn runner_boundary_files_are_host_readable_on_rootful_linux() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("status.json");
        let temporary = temp.path().join("status.json.tmp");

        write_atomic_regular(&path, &temporary, b"{}", "test status").unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn compose_runner_preflight_requires_a_regular_executable_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(".mirrorstack-linux");

        let missing = validate_runner_binary(temp.path())
            .expect_err("a missing bind source must fail before compose")
            .to_string();
        assert!(missing.contains("does not exist"), "{missing}");

        fs::create_dir(&path).unwrap();
        let directory = validate_runner_binary(temp.path())
            .expect_err("Docker must not receive a directory bind source")
            .to_string();
        assert!(directory.contains("regular file"), "{directory}");
        fs::remove_dir(&path).unwrap();

        fs::write(&path, b"linux binary").unwrap();
        let not_executable = validate_runner_binary(temp.path())
            .expect_err("the runner must be executable in its Linux container")
            .to_string();
        assert!(
            not_executable.contains("not executable"),
            "{not_executable}"
        );

        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        validate_runner_binary(temp.path()).unwrap();
    }

    #[cfg(unix)]
    fn hanging_build_fixture() -> (tempfile::TempDir, ClientTarget, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        fs::create_dir_all(&target.client_dir).unwrap();
        fs::write(
            target.client_dir.join("package.json"),
            r#"{"scripts":{"build":"ignored"}}"#,
        )
        .unwrap();
        let active = target.active_file("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        fs::write(&active, b"active").unwrap();
        let program = temp.path().join("hanging-build");
        fs::write(&program, "#!/bin/sh\nsleep 30 &\nwait\n").unwrap();
        let mut permissions = fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&program, permissions).unwrap();
        (temp, target, active, program)
    }

    #[test]
    fn npm_build_timeout_includes_waiting_for_the_per_target_lock() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        fs::create_dir_all(&target.client_dir).unwrap();
        let active = target.active_file("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        fs::write(&active, b"active").unwrap();
        let held = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(target.build_lock_file())
            .unwrap();
        FileExt::lock_exclusive(&held).unwrap();
        let started = Instant::now();

        let error = build_once_with(
            &target,
            &active,
            &AtomicBool::new(false),
            Path::new("build-program-must-not-run"),
            Duration::from_millis(100),
        )
        .expect_err("the build budget must cover lock contention")
        .to_string();

        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn npm_build_timeout_kills_the_process_group_and_returns() {
        let (_temp, target, active, program) = hanging_build_fixture();
        let started = Instant::now();

        let error = build_once_with(
            &target,
            &active,
            &AtomicBool::new(false),
            &program,
            Duration::from_millis(100),
        )
        .expect_err("a hanging build must time out")
        .to_string();

        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn successful_npm_parent_cannot_leave_pipe_holding_descendants() {
        use std::os::unix::fs::PermissionsExt;

        let (temp, target, active, program) = hanging_build_fixture();
        fs::create_dir_all(&target.output_dir).unwrap();
        fs::write(target.output_dir.join("index.js"), "export default {}\n").unwrap();
        fs::write(
            target.output_dir.join("index.d.ts"),
            "declare const value: object; export default value;\n",
        )
        .unwrap();
        fs::write(&program, "#!/bin/sh\nsleep 30 &\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(&program).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&program, permissions).unwrap();
        let started = Instant::now();

        let artifact = build_once_with(
            &target,
            &active,
            &AtomicBool::new(false),
            &program,
            Duration::from_secs(30),
        )
        .expect("a completed build must reap its background process tree");

        assert!(!artifact.bytes.is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(temp);
    }

    #[cfg(unix)]
    #[test]
    fn npm_build_cancellation_unblocks_the_watcher_join() {
        let (temp, target, active, program) = hanging_build_fixture();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let handle = thread::spawn(move || {
            let _keep_fixture_alive = temp;
            build_once_with(
                &target,
                &active,
                &thread_stop,
                &program,
                Duration::from_secs(30),
            )
        });
        thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        stop.store(true, Ordering::SeqCst);

        let error = handle
            .join()
            .expect("build thread")
            .expect_err("a cancelled build must stop")
            .to_string();

        assert!(error.contains("cancelled"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn ready_artifact_is_bound_to_the_exact_status_generation() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let artifact = ClientArtifact {
            bytes: b"immutable snapshot".to_vec(),
            sha256: format!("{:x}", Sha256::digest(b"immutable snapshot")),
        };
        write_artifact(&target, run_id, &artifact).unwrap();
        let status = BuildStatus {
            run_id: run_id.into(),
            state: BuildState::Ready,
            generation: 1,
            sha256: Some(artifact.sha256.clone()),
            size_bytes: Some(artifact.bytes.len() as u64),
            message: None,
        };
        write_status(&target.status_file(run_id), &status).unwrap();

        let read = read_ready_artifact(&target, run_id, &status)
            .unwrap()
            .expect("matching snapshot");
        assert_eq!(read.bytes, artifact.bytes);

        let mut successor = status.clone();
        successor.generation = 2;
        write_status(&target.status_file(run_id), &successor).unwrap();
        assert!(
            read_ready_artifact(&target, run_id, &status)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ready_artifact_rejects_a_snapshot_larger_than_its_bound() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(target.artifact_file(run_id))
            .unwrap()
            .set_len(MAX_COMPRESSED_BYTES as u64 + 1)
            .unwrap();
        let status = BuildStatus {
            run_id: run_id.into(),
            state: BuildState::Ready,
            generation: 1,
            sha256: Some("a".repeat(64)),
            size_bytes: Some(MAX_COMPRESSED_BYTES as u64),
            message: None,
        };

        let error = format!(
            "{:#}",
            read_ready_artifact(&target, run_id, &status)
                .expect_err("oversized snapshot must fail before allocation")
        );

        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn client_run_cleanup_cannot_delete_a_successor_run() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let run_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        for run_id in [run_a, run_b] {
            fs::write(target.active_file(run_id), b"active").unwrap();
            fs::write(target.status_file(run_id), b"status").unwrap();
            fs::write(target.artifact_file(run_id), b"artifact").unwrap();
            fs::write(
                target
                    .active_file(run_id)
                    .parent()
                    .unwrap()
                    .join(format!("{RUNNER_FILE_PREFIX}{run_id}.json")),
                b"runner",
            )
            .unwrap();
        }

        drop(ClientRun {
            run_id: run_a.into(),
            active_file: target.active_file(run_a),
            targets: vec![target.clone()],
        });

        assert!(!target.active_file(run_a).exists());
        assert!(!target.status_file(run_a).exists());
        assert!(!target.artifact_file(run_a).exists());
        assert!(
            !target
                .active_file(run_a)
                .parent()
                .unwrap()
                .join(format!("{RUNNER_FILE_PREFIX}{run_a}.json"))
                .exists()
        );
        assert!(target.active_file(run_b).is_file());
        assert!(target.status_file(run_b).is_file());
        assert!(target.artifact_file(run_b).is_file());
        assert!(
            target
                .active_file(run_b)
                .parent()
                .unwrap()
                .join(format!("{RUNNER_FILE_PREFIX}{run_b}.json"))
                .is_file()
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_compose_runner_fails_fast_with_a_rebuild_diagnostic() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(target.active_file(run_id), b"active").unwrap();
        let run = ClientRun {
            run_id: run_id.into(),
            active_file: target.active_file(run_id),
            targets: vec![target],
        };
        let mut compose = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .spawn()
            .unwrap();

        let error = await_runner_with_probe(
            &run,
            &mut compose,
            temp.path(),
            &BTreeSet::new(),
            RunnerWaitBudget {
                startup: Duration::from_secs(1),
                handshake: Duration::from_millis(50),
                poll: Duration::from_millis(5),
            },
            || Ok(BTreeSet::from(["new-runner".to_string()])),
        )
        .expect_err("an old runner never acknowledges the protocol")
        .to_string();
        let _ = compose.kill();
        let _ = compose.wait();

        assert!(error.contains(".mirrorstack-linux"), "{error}");
        assert!(error.contains("mirrorstack-cli checkout"), "{error}");
        assert!(error.contains("protocol v1"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn handshake_from_a_preexisting_runner_is_not_accepted() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(target.active_file(run_id), b"active").unwrap();
        let run = ClientRun {
            run_id: run_id.into(),
            active_file: target.active_file(run_id),
            targets: vec![target],
        };
        fs::write(
            run.runner_file(),
            serde_json::to_vec(&RunnerHandshake {
                run_id: run_id.into(),
                protocol_version: RUNNER_PROTOCOL_VERSION,
                cli_version: env!("CARGO_PKG_VERSION").into(),
            })
            .unwrap(),
        )
        .unwrap();
        let mut compose = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .spawn()
            .unwrap();
        let old = BTreeSet::from(["old-runner".to_string()]);

        let error = await_runner_with_probe(
            &run,
            &mut compose,
            temp.path(),
            &old,
            RunnerWaitBudget {
                startup: Duration::from_millis(50),
                handshake: Duration::from_secs(1),
                poll: Duration::from_millis(5),
            },
            || Ok(old.clone()),
        )
        .expect_err("only a recreated runner may satisfy the new run handshake")
        .to_string();
        let _ = compose.kill();
        let _ = compose.wait();

        assert!(error.contains("compose runner to start"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn cold_compose_start_does_not_consume_the_handshake_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(target.active_file(run_id), b"active").unwrap();
        let run = ClientRun {
            run_id: run_id.into(),
            active_file: target.active_file(run_id),
            targets: vec![target],
        };
        let mut compose = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .spawn()
            .unwrap();
        let previous = BTreeSet::from(["old-runner".to_string()]);
        let mut probes = 0;
        let handshake_path = run.runner_file();
        let started = Instant::now();

        await_runner_with_probe(
            &run,
            &mut compose,
            temp.path(),
            &previous,
            RunnerWaitBudget {
                startup: Duration::from_millis(500),
                handshake: Duration::from_millis(50),
                poll: Duration::from_millis(10),
            },
            || {
                probes += 1;
                if probes == 8 {
                    fs::write(
                        &handshake_path,
                        serde_json::to_vec(&RunnerHandshake {
                            run_id: run_id.into(),
                            protocol_version: RUNNER_PROTOCOL_VERSION,
                            cli_version: env!("CARGO_PKG_VERSION").into(),
                        })
                        .unwrap(),
                    )
                    .unwrap();
                }
                Ok(if probes >= 8 {
                    BTreeSet::from(["new-runner".to_string()])
                } else {
                    BTreeSet::from(["old-runner".to_string()])
                })
            },
        )
        .expect("cold startup gets its own budget before the compatibility timer");
        let _ = compose.kill();
        let _ = compose.wait();

        assert!(probes >= 8, "the probe must observe the replacement runner");
        assert!(
            started.elapsed() >= Duration::from_millis(50),
            "the synthetic cold start must outlive the 50ms handshake budget"
        );
    }

    #[cfg(unix)]
    #[test]
    fn runner_handshake_rejects_a_different_protocol_version() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(target.active_file(run_id), b"active").unwrap();
        let run = ClientRun {
            run_id: run_id.into(),
            active_file: target.active_file(run_id),
            targets: vec![target],
        };
        fs::write(
            run.runner_file(),
            serde_json::to_vec(&RunnerHandshake {
                run_id: run_id.into(),
                protocol_version: RUNNER_PROTOCOL_VERSION + 1,
                cli_version: "future".into(),
            })
            .unwrap(),
        )
        .unwrap();
        let mut compose = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .spawn()
            .unwrap();

        let error = await_runner_with_probe(
            &run,
            &mut compose,
            temp.path(),
            &BTreeSet::new(),
            RunnerWaitBudget {
                startup: Duration::from_secs(1),
                handshake: Duration::from_secs(1),
                poll: Duration::from_millis(5),
            },
            || Ok(BTreeSet::from(["new-runner".to_string()])),
        )
        .expect_err("a different runner protocol must fail")
        .to_string();
        let _ = compose.kill();
        let _ = compose.wait();

        assert!(error.contains("reported protocol v2"), "{error}");
        assert!(error.contains("requires v1"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn runner_handshake_rejects_a_different_cli_release() {
        let temp = tempfile::tempdir().unwrap();
        let target = test_target(temp.path());
        let run_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(target.active_file(run_id), b"active").unwrap();
        let run = ClientRun {
            run_id: run_id.into(),
            active_file: target.active_file(run_id),
            targets: vec![target],
        };
        fs::write(
            run.runner_file(),
            serde_json::to_vec(&RunnerHandshake {
                run_id: run_id.into(),
                protocol_version: RUNNER_PROTOCOL_VERSION,
                cli_version: "0.0.0-stale".into(),
            })
            .unwrap(),
        )
        .unwrap();
        let mut compose = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .spawn()
            .unwrap();

        let error = await_runner_with_probe(
            &run,
            &mut compose,
            temp.path(),
            &BTreeSet::new(),
            RunnerWaitBudget {
                startup: Duration::from_secs(1),
                handshake: Duration::from_secs(1),
                poll: Duration::from_millis(5),
            },
            || Ok(BTreeSet::from(["new-runner".to_string()])),
        )
        .expect_err("a different runner CLI release must fail")
        .to_string();
        let _ = compose.kill();
        let _ = compose.wait();

        assert!(error.contains("reported CLI 0.0.0-stale"), "{error}");
        assert!(error.contains(env!("CARGO_PKG_VERSION")), "{error}");
    }

    #[test]
    fn workspace_lock_rejects_a_second_dev_process_for_the_workspace() {
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join(".secret");
        fs::create_dir(&secret).unwrap();
        for name in [
            RUN_ID_FILE,
            WATCH_MODE_FILE,
            "ms-dev-watch-mode.tmp-1",
            "ms-client-active-dead-run",
            "ms-client-status-dead-run-media.json.tmp-1",
            "ms-client-artifact-dead-run-media.tgz",
            "ms-client-runner-dead-run.json",
        ] {
            fs::write(secret.join(name), b"crash residue").unwrap();
        }
        fs::write(secret.join("ms-client-build-media.lock"), b"").unwrap();
        fs::write(secret.join("unrelated-secret"), b"keep").unwrap();

        let _first = lock_workspace(temp.path()).unwrap();

        assert!(!secret.join(RUN_ID_FILE).exists());
        assert!(!secret.join(WATCH_MODE_FILE).exists());
        assert!(!secret.join("ms-dev-watch-mode.tmp-1").exists());
        assert!(!secret.join("ms-client-active-dead-run").exists());
        assert!(
            !secret
                .join("ms-client-status-dead-run-media.json.tmp-1")
                .exists()
        );
        assert!(
            !secret
                .join("ms-client-artifact-dead-run-media.tgz")
                .exists()
        );
        assert!(!secret.join("ms-client-runner-dead-run.json").exists());
        assert!(secret.join("ms-client-build-media.lock").is_file());
        assert!(secret.join("unrelated-secret").is_file());

        let error = lock_workspace(temp.path())
            .expect_err("a second dev run must not replace the active pointer")
            .to_string();

        assert!(error.contains("another `mirrorstack dev`"), "{error}");
    }

    #[test]
    fn outer_watch_mode_overrides_hardcoded_inner_flags_and_cleans_up() {
        let temp = tempfile::tempdir().unwrap();
        let _workspace_lock = lock_workspace(temp.path()).unwrap();

        assert!(effective_watch(temp.path(), true).unwrap());
        assert!(!effective_watch(temp.path(), false).unwrap());

        let disabled = WatchModeGuard::publish(temp.path(), false).unwrap();
        assert!(
            !effective_watch(temp.path(), true).unwrap(),
            "host --watch=false must override compose's hardcoded --watch"
        );
        drop(disabled);
        assert!(
            effective_watch(temp.path(), true).unwrap(),
            "a direct inner invocation keeps its own flag when no outer marker exists"
        );

        let enabled = WatchModeGuard::publish(temp.path(), true).unwrap();
        assert!(
            effective_watch(temp.path(), false).unwrap(),
            "an explicit host --watch must override an inner false flag"
        );
        drop(enabled);
        assert!(!temp.path().join(".secret").join(WATCH_MODE_FILE).exists());
    }

    #[test]
    fn disable_revokes_only_the_pointed_run_lease() {
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join(".secret");
        fs::create_dir(&secret).unwrap();
        let run_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let run_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        fs::write(secret.join(RUN_ID_FILE), run_a).unwrap();
        fs::write(client_active_file(temp.path(), run_a), b"active").unwrap();
        fs::write(client_active_file(temp.path(), run_b), b"active").unwrap();

        disable(temp.path()).unwrap();

        assert!(!secret.join(RUN_ID_FILE).exists());
        assert!(!client_active_file(temp.path(), run_a).exists());
        assert!(client_active_file(temp.path(), run_b).is_file());
    }

    #[test]
    fn runner_rejects_invalid_or_inactive_run_pointers() {
        let temp = tempfile::tempdir().unwrap();
        let secret = temp.path().join(".secret");
        fs::create_dir(&secret).unwrap();
        fs::write(secret.join(RUN_ID_FILE), "../not-a-run").unwrap();
        let error = build_in_runner(temp.path(), &[], false, Arc::new(AtomicBool::new(false)))
            .expect_err("invalid run pointer must fail")
            .to_string();
        assert!(error.contains("run id is invalid"), "{error}");

        fs::write(secret.join(RUN_ID_FILE), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(
            build_in_runner(temp.path(), &[], false, Arc::new(AtomicBool::new(false)),)
                .unwrap()
                .is_empty(),
            "a pointer without its active lease must not opt plain dev in"
        );
    }

    #[test]
    fn source_signature_excludes_build_output_and_dependencies() {
        let temp = tempfile::tempdir().unwrap();
        let client = temp.path().join("client");
        let output = client.join("dist");
        fs::create_dir_all(client.join("src")).unwrap();
        fs::create_dir_all(&output).unwrap();
        fs::create_dir_all(client.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(client.join(".cache")).unwrap();
        fs::write(client.join("src/index.ts"), "export const value = 1;\n").unwrap();
        fs::write(output.join("index.js"), "built one\n").unwrap();
        fs::write(client.join("node_modules/pkg/index.js"), "dependency one\n").unwrap();
        fs::write(client.join(".cache/bundle.json"), "cache one\n").unwrap();
        fs::write(client.join("tsconfig.tsbuildinfo"), "state one\n").unwrap();
        let initial = source_signature(&client, &output);

        fs::write(output.join("index.js"), "built output changed\n").unwrap();
        fs::write(
            client.join("node_modules/pkg/index.js"),
            "dependency output changed\n",
        )
        .unwrap();
        fs::write(client.join(".cache/bundle.json"), "cache changed\n").unwrap();
        fs::write(client.join("tsconfig.tsbuildinfo"), "state changed\n").unwrap();
        assert_eq!(source_signature(&client, &output), initial);

        // Same-length edits must be detected, including an edit that lands
        // after a watcher captured its pre-build signature.
        let captured_before_build = source_signature(&client, &output);
        fs::write(client.join("src/index.ts"), "export const value = 2;\n").unwrap();
        assert_ne!(
            source_signature(&client, &output),
            captured_before_build,
            "an edit during npm build must schedule a follow-up build"
        );
        assert_ne!(source_signature(&client, &output), initial);
    }

    #[cfg(unix)]
    #[test]
    fn package_target_rejects_output_that_resolves_outside_client() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let client = temp.path().join("client");
        let external = temp.path().join("external-dist");
        fs::create_dir(&client).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(external.join("index.js"), "export default () => ({})\n").unwrap();
        fs::write(
            external.join("index.d.ts"),
            "export default function plugin(): object;\n",
        )
        .unwrap();
        symlink(&external, client.join("dist")).unwrap();
        let target = ClientTarget {
            client_dir: client.clone(),
            output_dir: client.join("dist"),
            ..test_target(temp.path())
        };

        let error = package_target(&target)
            .expect_err("output symlink must not escape the client directory")
            .to_string();

        assert!(error.contains("outside its client directory"), "{error}");
    }

    #[test]
    fn publish_retry_adopts_credentials_rotated_by_another_worker() {
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = tempfile::tempdir().unwrap();
        let _restore = credentials::redirect_config_dir(config.path());
        let mut stale = Credentials {
            access_token: "AT_stale".into(),
            refresh_token: "RT_spent".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3_600),
        };
        credentials::save(&Credentials {
            access_token: "AT_live".into(),
            refresh_token: "RT_rotated".into(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3_600),
        })
        .unwrap();
        let mut attempted = Vec::new();

        retry_with_rotated_credentials(&mut stale, |current| {
            attempted.push(current.access_token.clone());
            if current.access_token == "AT_live" {
                Ok(())
            } else {
                Err(ApiError::Unauthenticated)
            }
        })
        .unwrap();

        assert_eq!(attempted, ["AT_stale", "AT_live"]);
        assert_eq!(stale.refresh_token, "RT_rotated");
    }

    #[test]
    fn publish_failures_back_off_with_jitter_and_a_cap() {
        let mut previous = Duration::ZERO;
        for failures in 1..=6 {
            let delay = publish_retry_delay(failures);
            assert!(delay > previous, "failure {failures}: {delay:?}");
            assert!(delay <= PUBLISH_RETRY_CAP, "failure {failures}: {delay:?}");
            previous = delay;
        }
        for failures in 7..=32 {
            assert!(publish_retry_delay(failures) <= PUBLISH_RETRY_CAP);
        }
    }

    #[test]
    fn active_client_leases_are_renewed_twice_per_day() {
        assert_eq!(PUBLISH_RENEW_INTERVAL, Duration::from_secs(12 * 60 * 60));
        assert!(PUBLISH_RENEW_INTERVAL * 4 <= Duration::from_secs(2 * 24 * 60 * 60));

        let now = Instant::now();
        assert!(!publication_due(
            "current",
            "current",
            2,
            2,
            now + PUBLISH_RENEW_INTERVAL,
            now,
        ));
        assert!(publication_due("current", "current", 2, 2, now, now,));
        assert!(publication_due(
            "old-hash",
            "new-hash",
            2,
            2,
            now + PUBLISH_RENEW_INTERVAL,
            now,
        ));
        assert!(publication_due(
            "current",
            "current",
            1,
            2,
            now + PUBLISH_RENEW_INTERVAL,
            now,
        ));
    }

    #[test]
    fn upload_failure_never_exposes_the_presigned_url_or_echoed_secret() {
        let mut server = Server::new();
        let _upload = server
            .mock("PUT", "/upload")
            .match_header("content-type", "application/octet-stream")
            .match_query(mockito::Matcher::UrlEncoded(
                "X-Amz-Signature".into(),
                "top-secret".into(),
            ))
            .with_status(500)
            .with_body("failed /upload?X-Amz-Signature=top-secret")
            .create();
        let client = http::client(Duration::from_secs(2)).unwrap();
        let url = format!("{}/upload?X-Amz-Signature=top-secret", server.url());
        let headers = BTreeMap::from([(
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        )]);

        let error = put_artifact(&client, &url, &headers, b"artifact")
            .expect_err("storage failure must surface")
            .to_string();

        assert!(error.contains("module client upload failed"), "{error}");
        assert!(!error.contains("top-secret"), "{error}");
        assert!(!error.contains(&url), "{error}");
    }

    #[test]
    fn upload_transport_error_removes_the_presigned_url() {
        let url = {
            let server = Server::new();
            format!("{}/gone?X-Amz-Signature=top-secret", server.url())
        };
        let client = http::client(Duration::from_secs(2)).unwrap();

        let error = put_artifact(&client, &url, &BTreeMap::new(), b"artifact")
            .expect_err("closed storage endpoint must fail")
            .to_string();

        assert!(!error.contains("top-secret"), "{error}");
        assert!(!error.contains(&url), "{error}");
    }
}
