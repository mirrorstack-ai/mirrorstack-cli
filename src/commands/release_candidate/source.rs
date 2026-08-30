//! Immutable, bounded release-source staging.
//!
//! Git's tracked plus unignored working set is the release input. That keeps
//! dirty-but-intentional source edits while excluding generated/ignored
//! `node_modules`, `dist`, `.tmp`, secrets, and Git metadata. Every accepted
//! regular file is copied into a fresh stage and hashed with its relative path
//! and exact bytes. Builds only run from that stage.
//!
//! This proves provenance for a trusted local publisher; it is not a sandbox
//! against a malicious same-UID process. No-follow opens, single-link checks,
//! identity/size/change-time stability, and final live-tree rehashes reject
//! ordinary path and source drift. A coordinated process with the publisher's
//! own filesystem authority can still mutate and restore input between checks.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};

use super::process::{ProcessRunner, ProcessSpec, SystemRunner};

/// A source tree large enough to hit this ceiling is not a module release
/// candidate. The cap bounds both local disk use and the amount of data one
/// command will hash/copy before it can fail.
const MAX_SOURCE_BYTES: u64 = 512 * 1024 * 1024;
/// Bound pathological repositories independently of their byte size.
const MAX_SOURCE_FILES: usize = 50_000;
/// One accidentally tracked database/archive should fail by itself rather
/// than consuming the full workspace allowance.
const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// `git ls-files -z` output is also attacker-controlled input.
const MAX_GIT_FILE_LIST_BYTES: usize = 8 * 1024 * 1024;

const SOURCE_PROTOCOL: &[u8] = b"mirrorstack.release-source/v1\0";

/// Directory components that are build products, dependency caches, control
/// data, or credentials rather than canonical release source. Git normally
/// excludes these already; the explicit guard keeps a mistakenly tracked
/// output from entering an immutable candidate.
const EXCLUDED_COMPONENTS: [&str; 7] = [
    ".git",
    ".secret",
    ".tmp",
    "dist",
    "node_modules",
    "target",
    ".mirrorstack-linux",
];

/// Frozen source bytes plus enough provenance to verify the live worktree did
/// not change while the (potentially slow) release builds ran.
pub(crate) struct SourceSnapshot {
    _baseline: TempDir,
    source_root: PathBuf,
    baseline_root: PathBuf,
    module_relative: PathBuf,
    entries: Vec<SourceEntry>,
    source_sha256: String,
}

/// A disposable build view copied from the untouched baseline. Each release
/// phase gets its own view, so lifecycle scripts or Go tooling cannot feed a
/// mutation from manifest generation into web or artifact construction.
pub(crate) struct BuildView {
    _view: TempDir,
    root: PathBuf,
    module_relative: PathBuf,
    entries: Vec<SourceEntry>,
    source_sha256: String,
    allowed_generated_output: Option<PathBuf>,
}

impl SourceSnapshot {
    /// Copy the Git working set containing `module_dir` into a fresh stage.
    /// The initial post-copy verification catches additions, removals, or
    /// edits that raced the copy itself.
    pub(crate) fn create(module_dir: &Path) -> Result<Self> {
        let requested = fs::symlink_metadata(module_dir).with_context(|| {
            format!(
                "release candidate: inspect module path {}",
                module_dir.display()
            )
        })?;
        if requested.file_type().is_symlink() {
            return Err(anyhow!(
                "release candidate: --dir must not be a symlink: {}",
                module_dir.display()
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            if requested.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(anyhow!(
                    "release candidate: --dir must not be a Windows reparse point: {}",
                    module_dir.display()
                ));
            }
        }
        if !requested.is_dir() {
            return Err(anyhow!(
                "release candidate: --dir is not a directory: {}",
                module_dir.display()
            ));
        }
        let source_root = git_root(module_dir)?;
        let module_dir = fs::canonicalize(module_dir)
            .with_context(|| format!("release candidate: resolve {}", module_dir.display()))?;
        let module_relative = module_dir
            .strip_prefix(&source_root)
            .map_err(|_| {
                anyhow!(
                    "release candidate: module {} is outside Git worktree {}",
                    module_dir.display(),
                    source_root.display()
                )
            })?
            .to_path_buf();
        if module_relative.as_os_str().is_empty() {
            return Err(anyhow!(
                "release candidate: --dir must name a module directory inside the Git worktree, not the worktree root"
            ));
        }

        let baseline = Builder::new()
            .prefix("mirrorstack-release-source-")
            .tempdir()
            .context("release candidate: create source stage")?;
        let baseline_root = baseline.path().to_path_buf();
        let scanned = scan_worktree(&source_root, Some(&baseline_root))?;

        let snapshot = Self {
            _baseline: baseline,
            source_root,
            baseline_root,
            module_relative,
            entries: scanned.entries,
            source_sha256: scanned.sha256,
        };
        snapshot.verify_unchanged().context(
            "release candidate: source changed while the immutable stage was being created",
        )?;
        if !snapshot.module_dir().join("go.mod").is_file() {
            return Err(anyhow!(
                "release candidate: staged module {} has no go.mod",
                snapshot.module_dir().display()
            ));
        }
        Ok(snapshot)
    }

    pub(crate) fn module_dir(&self) -> PathBuf {
        self.baseline_root.join(&self.module_relative)
    }

    pub(crate) fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// Recompute the exact Git working-set digest. Release preparation calls
    /// this again after all builds, so an edit during a long compile fails the
    /// command even though every build itself used the coherent frozen stage.
    pub(crate) fn verify_unchanged(&self) -> Result<()> {
        let current = scan_worktree(&self.source_root, None)?;
        if current.sha256 != self.source_sha256 {
            return Err(anyhow!(
                "release candidate: source drift detected in {} (staged {}, current {}); discard this candidate and rebuild",
                self.source_root.display(),
                self.source_sha256,
                current.sha256
            ));
        }
        Ok(())
    }

    /// Produce a fresh phase-local build view from the pristine baseline.
    /// Baseline verification on both sides makes a mutation during the copy
    /// fail rather than silently becoming a new candidate input.
    pub(crate) fn fresh_view(&self, phase: &str) -> Result<BuildView> {
        self.fresh_view_with_output(phase, None)
    }

    pub(crate) fn fresh_web_view(&self) -> Result<BuildView> {
        self.fresh_view_with_output(
            "web",
            Some(self.module_relative.join("web/src/__generated__/styles.ts")),
        )
    }

    fn fresh_view_with_output(
        &self,
        phase: &str,
        allowed_generated_output: Option<PathBuf>,
    ) -> Result<BuildView> {
        self.verify_baseline()?;
        let view = Builder::new()
            .prefix(&format!("mirrorstack-release-{phase}-"))
            .tempdir()
            .with_context(|| format!("release candidate: create {phase} build view"))?;
        let root = view.path().to_path_buf();
        copy_entries(&self.baseline_root, &root, &self.entries)?;
        self.verify_baseline()?;
        let build = BuildView {
            _view: view,
            root,
            module_relative: self.module_relative.clone(),
            entries: self.entries.clone(),
            source_sha256: self.source_sha256.clone(),
            allowed_generated_output,
        };
        build.verify_inputs()?;
        Ok(build)
    }

    fn verify_baseline(&self) -> Result<()> {
        let current = scan_entries(&self.baseline_root, &self.entries)?;
        if current != self.source_sha256 {
            return Err(anyhow!(
                "release candidate: pristine source baseline changed (expected {}, current {current})",
                self.source_sha256
            ));
        }
        reject_unexpected_inputs(&self.baseline_root, &self.entries, None)?;
        Ok(())
    }
}

impl BuildView {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn module_dir(&self) -> PathBuf {
        self.root.join(&self.module_relative)
    }

    /// Prove that a phase neither changed canonical source nor added a new
    /// build input. Known output/cache directories are ignored deliberately.
    pub(crate) fn verify_inputs(&self) -> Result<()> {
        let current = scan_entries(&self.root, &self.entries)?;
        if current != self.source_sha256 {
            return Err(anyhow!(
                "release candidate: phase build view changed canonical source (expected {}, current {current})",
                self.source_sha256
            ));
        }
        reject_unexpected_inputs(
            &self.root,
            &self.entries,
            self.allowed_generated_output.as_deref(),
        )
    }
}

struct ScanResult {
    sha256: String,
    entries: Vec<SourceEntry>,
}

fn git_root(module_dir: &Path) -> Result<PathBuf> {
    let spec = git_spec(module_dir)
        .args(["rev-parse", "--show-toplevel"])
        .timeout(Duration::from_secs(30))
        .limits(4096, 16 * 1024);
    let output = SystemRunner
        .run(&spec)
        .context("release candidate: Git is required to define the canonical source working set")?;
    if !output.success {
        return Err(anyhow!(
            "release candidate: {} is not inside a Git worktree: {}",
            module_dir.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let raw = std::str::from_utf8(&output.stdout)
        .context("release candidate: Git worktree path is not UTF-8")?;
    let path = raw
        .strip_suffix('\n')
        .ok_or_else(|| anyhow!("release candidate: malformed git rev-parse output"))?;
    if path.is_empty() || path.contains('\n') || path.ends_with('\r') {
        return Err(anyhow!("release candidate: malformed git rev-parse output"));
    }
    fs::canonicalize(path)
        .with_context(|| format!("release candidate: resolve Git worktree {path}"))
}

fn scan_worktree(source_root: &Path, copy_to: Option<&Path>) -> Result<ScanResult> {
    let paths = git_source_paths(source_root)?;
    if paths.len() > MAX_SOURCE_FILES {
        return Err(anyhow!(
            "release candidate: source has {} files (cap: {MAX_SOURCE_FILES})",
            paths.len()
        ));
    }

    let mut present = Vec::with_capacity(paths.len());
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_PROTOCOL);
    let mut total_bytes = 0u64;
    for entry in paths {
        let source = source_root.join(&entry.path);
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A tracked deletion is part of the working state by its
                // absence. `git ls-files --cached` still names it.
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("release candidate: inspect {}", source.display()));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "release candidate: symlink source input is not allowed: {}",
                source.display()
            ));
        }
        if !metadata.is_file() {
            return Err(anyhow!(
                "release candidate: source input is not a regular file: {}",
                source.display()
            ));
        }
        reject_symlink_parents(source_root, &entry.path)?;
        if metadata.len() > MAX_SOURCE_FILE_BYTES {
            return Err(anyhow!(
                "release candidate: source file {} is {} bytes (per-file cap: {MAX_SOURCE_FILE_BYTES})",
                entry.path.display(),
                metadata.len()
            ));
        }
        let bytes = read_regular_bounded(
            source_root,
            &entry.path,
            MAX_SOURCE_FILE_BYTES,
            "source file",
        )?;
        // Charge the bytes proved through the no-follow handle, not the
        // earlier path metadata. A file may grow between lstat and open while
        // remaining below the per-file cap; the aggregate limit must still
        // account for every byte copied into the immutable stage.
        total_bytes = checked_total_bytes(total_bytes, bytes.len() as u64, MAX_SOURCE_BYTES)?;
        hasher.update((entry.normalized.len() as u64).to_be_bytes());
        hasher.update(entry.normalized.as_bytes());
        hasher.update([u8::from(entry.executable)]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
        if let Some(stage_root) = copy_to {
            let destination = stage_root.join(&entry.path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "release candidate: create staged directory {}",
                        parent.display()
                    )
                })?;
            }
            write_new_file(&destination, &bytes, "staged file")?;
            set_canonical_permissions(&destination, entry.executable)?;
        }
        present.push(entry);
    }

    Ok(ScanResult {
        sha256: format!("{:x}", hasher.finalize()),
        entries: present,
    })
}

fn scan_entries(root: &Path, entries: &[SourceEntry]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_PROTOCOL);
    let mut total_bytes = 0u64;
    for entry in entries {
        let bytes = read_canonical_entry(
            root,
            &entry.path,
            MAX_SOURCE_FILE_BYTES,
            "canonical source file",
            entry.executable,
        )?;
        total_bytes = checked_total_bytes(total_bytes, bytes.len() as u64, MAX_SOURCE_BYTES)?;
        hasher.update((entry.normalized.len() as u64).to_be_bytes());
        hasher.update(entry.normalized.as_bytes());
        hasher.update([u8::from(entry.executable)]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_entries(from: &Path, to: &Path, entries: &[SourceEntry]) -> Result<()> {
    for entry in entries {
        let bytes = read_canonical_entry(
            from,
            &entry.path,
            MAX_SOURCE_FILE_BYTES,
            "baseline source file",
            entry.executable,
        )?;
        let destination = to.join(&entry.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "release candidate: create phase directory {}",
                    parent.display()
                )
            })?;
        }
        write_new_file(&destination, &bytes, "phase source")?;
        set_canonical_permissions(&destination, entry.executable)?;
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    use std::io::Write;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "release candidate: create {label} {} (source paths must map injectively)",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("release candidate: write {label} {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("release candidate: sync {label} {}", path.display()))?;
    Ok(())
}

fn reject_unexpected_inputs(
    root: &Path,
    entries: &[SourceEntry],
    allowed_generated_output: Option<&Path>,
) -> Result<()> {
    let expected = entries
        .iter()
        .map(|entry| entry.normalized.as_str())
        .collect::<HashSet<_>>();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative_dir) = pending.pop() {
        let directory = root.join(&relative_dir);
        for item in fs::read_dir(&directory).with_context(|| {
            format!(
                "release candidate: inspect phase directory {}",
                directory.display()
            )
        })? {
            let item = item.with_context(|| {
                format!(
                    "release candidate: enumerate phase directory {}",
                    directory.display()
                )
            })?;
            let relative = relative_dir.join(item.file_name());
            if excluded(&relative) {
                continue;
            }
            let metadata = fs::symlink_metadata(item.path()).with_context(|| {
                format!(
                    "release candidate: inspect phase path {}",
                    item.path().display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(anyhow!(
                    "release candidate: phase created a symlink outside allowed output directories: {}",
                    relative.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(relative);
                continue;
            }
            if !metadata.is_file() {
                return Err(anyhow!(
                    "release candidate: phase created a non-regular input: {}",
                    relative.display()
                ));
            }
            let normalized = normalized_relative(&relative)?;
            let allowed_generated =
                allowed_generated_output.is_some_and(|allowed| relative.as_path() == allowed);
            if !expected.contains(normalized.as_str()) && !allowed_generated {
                return Err(anyhow!(
                    "release candidate: phase created unexpected build input {normalized}"
                ));
            }
        }
    }
    Ok(())
}

fn normalized_relative(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(anyhow!(
                "release candidate: invalid phase path {}",
                path.display()
            ));
        };
        let value = value.to_str().ok_or_else(|| {
            anyhow!(
                "release candidate: phase path is not UTF-8: {}",
                path.display()
            )
        })?;
        parts.push(value);
    }
    Ok(parts.join("/"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceEntry {
    path: PathBuf,
    normalized: String,
    executable: bool,
}

fn git_source_paths(root: &Path) -> Result<Vec<SourceEntry>> {
    let tracked = git_ls_files(root, &["--stage", "-z", "--full-name"])?;
    let untracked = git_ls_files(
        root,
        &["--others", "--exclude-standard", "-z", "--full-name"],
    )?;
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for raw in tracked.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let tab = raw
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| anyhow!("release candidate: malformed Git index record"))?;
        let header = std::str::from_utf8(&raw[..tab])
            .context("release candidate: Git index header is not UTF-8")?;
        let mode = header
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| anyhow!("release candidate: Git index mode is missing"))?;
        let executable = match mode {
            "100644" => false,
            "100755" => true,
            "120000" => {
                let path = String::from_utf8_lossy(&raw[tab + 1..]);
                return Err(anyhow!(
                    "release candidate: symlink source input is not allowed: {}",
                    root.join(path.as_ref()).display()
                ));
            }
            other => {
                let path = String::from_utf8_lossy(&raw[tab + 1..]);
                return Err(anyhow!(
                    "release candidate: unsupported Git entry mode {other} for {path}"
                ));
            }
        };
        push_source_entry(&mut paths, &mut seen, &raw[tab + 1..], executable)?;
    }
    for raw in untracked.split(|byte| *byte == 0) {
        if !raw.is_empty() {
            // Untracked files have no cross-platform Git executable mode.
            // Canonicalize them to data files in the stage.
            push_source_entry(&mut paths, &mut seen, raw, false)?;
        }
    }
    paths.sort_by(|left, right| left.normalized.cmp(&right.normalized));
    Ok(paths)
}

fn git_ls_files(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let spec = git_spec(root)
        .arg("ls-files")
        .args(args.iter().copied())
        .timeout(Duration::from_secs(60))
        .limits(MAX_GIT_FILE_LIST_BYTES, 256 * 1024);
    let output = SystemRunner
        .run(&spec)
        .context("release candidate: list Git source files")?;
    if !output.success {
        return Err(anyhow!(
            "release candidate: git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn git_spec(cwd: &Path) -> ProcessSpec {
    [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        // These two are the supported command-line config injection paths.
        // Removing COUNT disables every GIT_CONFIG_KEY_n/VALUE_n pair, even
        // though their unbounded suffixes cannot be enumerated here.
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
    ]
    .into_iter()
    .fold(ProcessSpec::new("git", cwd), ProcessSpec::env_remove)
    // Repository .gitignore and .git/info/exclude remain authoritative, but
    // machine-global/system config and core.excludesFile must not silently
    // remove source from an attested snapshot.
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_SYSTEM", null_git_config())
    .env("GIT_CONFIG_GLOBAL", null_git_config())
    .env("GIT_OPTIONAL_LOCKS", "0")
    .args(["-c", "core.excludesFile="])
}

#[cfg(windows)]
fn null_git_config() -> &'static str {
    "NUL"
}

#[cfg(not(windows))]
fn null_git_config() -> &'static str {
    "/dev/null"
}

fn push_source_entry(
    paths: &mut Vec<SourceEntry>,
    seen: &mut HashSet<String>,
    raw: &[u8],
    executable: bool,
) -> Result<()> {
    let text =
        std::str::from_utf8(raw).context("release candidate: Git source path is not UTF-8")?;
    let path = validate_relative_path(text)?;
    if excluded(&path) {
        return Ok(());
    }
    let normalized = text.replace('\\', "/");
    let alias_key = stage_alias_key(&normalized);
    if !seen.insert(alias_key) {
        return Err(anyhow!(
            "release candidate: Git source paths alias in the release stage: {normalized}"
        ));
    }
    paths.push(SourceEntry {
        path,
        normalized,
        executable,
    });
    Ok(())
}

fn validate_relative_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        return Err(anyhow!(
            "release candidate: Git listed an empty source path"
        ));
    }
    let path = PathBuf::from(raw);
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                #[cfg(windows)]
                validate_windows_component(value, raw)?;
                #[cfg(not(windows))]
                let _ = value;
            }
            _ => {
                return Err(anyhow!(
                    "release candidate: Git source path escapes the worktree: {raw}"
                ));
            }
        }
    }
    Ok(path)
}

fn stage_alias_key(normalized: &str) -> String {
    #[cfg(any(windows, target_os = "macos"))]
    {
        normalized.to_lowercase()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        normalized.to_string()
    }
}

#[cfg(windows)]
fn validate_windows_component(value: &std::ffi::OsStr, full_path: &str) -> Result<()> {
    let value = value.to_str().ok_or_else(|| {
        anyhow!("release candidate: Windows source path is not Unicode: {full_path}")
    })?;
    if value.contains(':') || value.ends_with(['.', ' ']) {
        return Err(anyhow!(
            "release candidate: Windows source path has an alternate-stream or normalized alias: {full_path}"
        ));
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    if reserved {
        return Err(anyhow!(
            "release candidate: Windows reserved source path is not allowed: {full_path}"
        ));
    }
    Ok(())
}

fn excluded(path: &Path) -> bool {
    path.components().any(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        EXCLUDED_COMPONENTS
            .iter()
            .any(|excluded| name == std::ffi::OsStr::new(excluded))
    })
}

fn reject_symlink_parents(root: &Path, relative: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(anyhow!(
                "release candidate: invalid source path {}",
                relative.display()
            ));
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "release candidate: inspect source directory {}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "release candidate: symlink source directory is not allowed: {}",
                current.display()
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(anyhow!(
                    "release candidate: reparse-point source directory is not allowed: {}",
                    current.display()
                ));
            }
        }
        if !metadata.is_dir() {
            return Err(anyhow!(
                "release candidate: source parent is not a directory: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn read_regular_bounded(
    root: &Path,
    relative: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    read_regular_bounded_inner(root, relative, max_bytes, label, None)
}

fn read_canonical_entry(
    root: &Path,
    relative: &Path,
    max_bytes: u64,
    label: &str,
    executable: bool,
) -> Result<Vec<u8>> {
    read_regular_bounded_inner(root, relative, max_bytes, label, Some(executable))
}

fn read_regular_bounded_inner(
    root: &Path,
    relative: &Path,
    max_bytes: u64,
    label: &str,
    expected_executable: Option<bool>,
) -> Result<Vec<u8>> {
    let path = root.join(relative);
    let mut file = open_no_follow_beneath(root, relative)?;
    let before = file
        .metadata()
        .with_context(|| format!("release candidate: inspect open file {}", path.display()))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(anyhow!(
            "release candidate: source input is not a no-follow regular file: {}",
            path.display()
        ));
    }
    verify_handle_beneath(&file, root)?;
    verify_canonical_mode(&before, expected_executable, &path)?;
    verify_single_link(&file, &before, &path)?;
    if before.len() > max_bytes {
        return Err(anyhow!(
            "release candidate: {label} {} is {} bytes (cap: {max_bytes})",
            path.display(),
            before.len()
        ));
    }
    let identity = file_identity(&file, &before)?;
    let stability = file_stability(&before);
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("release candidate: read {label} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(anyhow!(
            "release candidate: {label} {} grew beyond the {max_bytes}-byte cap while being read",
            path.display()
        ));
    }
    let after = file
        .metadata()
        .with_context(|| format!("release candidate: re-inspect open file {}", path.display()))?;
    if file_identity(&file, &after)? != identity
        || file_stability(&after) != stability
        || after.len() != before.len()
        || after.len() != bytes.len() as u64
    {
        return Err(anyhow!(
            "release candidate: source file changed while being read: {}",
            path.display()
        ));
    }
    verify_canonical_mode(&after, expected_executable, &path)?;
    verify_single_link(&file, &after, &path)?;

    // Re-open by name without following a final symlink and prove the path
    // still names the same object. This closes the lstat→open swap that would
    // otherwise let a raced symlink pull bytes from outside the worktree.
    let current = open_no_follow_beneath(root, relative)?;
    let current_metadata = current.metadata().with_context(|| {
        format!(
            "release candidate: inspect re-opened file {}",
            path.display()
        )
    })?;
    if !current_metadata.is_file()
        || current_metadata.file_type().is_symlink()
        || file_identity(&current, &current_metadata)? != identity
        || file_stability(&current_metadata) != stability
        || current_metadata.len() != bytes.len() as u64
    {
        return Err(anyhow!(
            "release candidate: source path changed while being read: {}",
            path.display()
        ));
    }
    verify_canonical_mode(&current_metadata, expected_executable, &path)?;
    verify_single_link(&current, &current_metadata, &path)?;
    verify_handle_beneath(&current, root)?;
    Ok(bytes)
}

#[cfg(unix)]
fn verify_canonical_mode(
    metadata: &fs::Metadata,
    expected_executable: Option<bool>,
    path: &Path,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Some(executable) = expected_executable else {
        return Ok(());
    };
    let expected = if executable { 0o755 } else { 0o644 };
    let actual = metadata.permissions().mode() & 0o777;
    if actual != expected {
        return Err(anyhow!(
            "release candidate: canonical input mode changed for {} (expected {expected:o}, current {actual:o})",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_canonical_mode(
    _metadata: &fs::Metadata,
    _expected_executable: Option<bool>,
    _path: &Path,
) -> Result<()> {
    Ok(())
}

fn checked_total_bytes(current: u64, next: u64, max_bytes: u64) -> Result<u64> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| anyhow!("release candidate: source size overflow"))?;
    if total > max_bytes {
        return Err(anyhow!(
            "release candidate: source is {total} bytes (cap: {max_bytes})"
        ));
    }
    Ok(total)
}

#[cfg(unix)]
fn open_no_follow_beneath(root: &Path, relative: &Path) -> Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => CString::new(value.as_bytes()).map_err(|_| {
                anyhow!(
                    "release candidate: path contains NUL: {}",
                    relative.display()
                )
            }),
            _ => Err(anyhow!(
                "release candidate: path escapes trusted root: {}",
                relative.display()
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() {
        return Err(anyhow!(
            "release candidate: cannot open an empty relative path"
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut directory = options.open(root).with_context(|| {
        format!(
            "release candidate: no-follow open trusted root {}",
            root.display()
        )
    })?;
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: directory is a live fd and component is a NUL-terminated
        // single path component. Each parent is opened without following
        // links, so a raced parent swap cannot redirect later lookups.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "release candidate: no-follow open {} beneath {}",
                    relative.display(),
                    root.display()
                )
            });
        }
        // SAFETY: openat returned a new owned descriptor.
        let opened = unsafe { File::from_raw_fd(fd) };
        if last {
            return Ok(opened);
        }
        let metadata = opened.metadata().with_context(|| {
            format!(
                "release candidate: inspect parent of {}",
                relative.display()
            )
        })?;
        if !metadata.is_dir() {
            return Err(anyhow!(
                "release candidate: source parent is not a directory: {}",
                relative.display()
            ));
        }
        directory = opened;
    }
    unreachable!("nonempty component list returns from its last component")
}

#[cfg(windows)]
fn open_no_follow_beneath(root: &Path, relative: &Path) -> Result<File> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    validate_relative_components(relative)?;
    // Hold every ancestor open without FILE_SHARE_DELETE while opening the
    // final file. A junction/reparse swap therefore cannot redirect the
    // full-path CreateFile call between validation and open.
    let mut parents = Vec::new();
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let Component::Normal(name) = component else {
                return Err(anyhow!(
                    "release candidate: path escapes trusted root: {}",
                    relative.display()
                ));
            };
            current.push(name);
            let mut options = OpenOptions::new();
            options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            let directory = options.open(&current).with_context(|| {
                format!(
                    "release candidate: no-follow open Windows source parent {}",
                    current.display()
                )
            })?;
            let metadata = directory.metadata().with_context(|| {
                format!(
                    "release candidate: inspect Windows source parent {}",
                    current.display()
                )
            })?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(anyhow!(
                    "release candidate: Windows source parent is not a no-follow directory: {}",
                    current.display()
                ));
            }
            verify_handle_beneath(&directory, root)?;
            parents.push(directory);
        }
    }

    let path = root.join(relative);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(&path)
        .with_context(|| format!("release candidate: no-follow open {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("release candidate: inspect open file {}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(anyhow!(
            "release candidate: Windows source input is a reparse point: {}",
            path.display()
        ));
    }
    drop(parents);
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow_beneath(root: &Path, relative: &Path) -> Result<File> {
    validate_relative_components(relative)?;
    let path = root.join(relative);
    OpenOptions::new()
        .read(true)
        .open(&path)
        .with_context(|| format!("release candidate: open {}", path.display()))
}

#[cfg(not(unix))]
fn validate_relative_components(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!(
            "release candidate: path escapes trusted root: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_handle_beneath(_file: &File, _root: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn verify_handle_beneath(file: &File, root: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, GetFinalPathNameByHandleW,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let root_handle = options.open(root).with_context(|| {
        format!(
            "release candidate: open trusted Windows root {}",
            root.display()
        )
    })?;
    let mut opened = final_path(file.as_raw_handle() as HANDLE)?;
    let mut root_path = final_path(root_handle.as_raw_handle() as HANDLE)?;
    while opened.last() == Some(&(b'\\' as u16)) {
        opened.pop();
    }
    while root_path.last() == Some(&(b'\\' as u16)) {
        root_path.pop();
    }
    if opened.len() < root_path.len() {
        return Err(anyhow!(
            "release candidate: opened Windows path escaped trusted root {}",
            root.display()
        ));
    }
    let has_boundary =
        opened.len() == root_path.len() || opened.get(root_path.len()) == Some(&(b'\\' as u16));
    let equal_prefix = root_path.len() <= i32::MAX as usize
        && unsafe {
            CompareStringOrdinal(
                opened.as_ptr(),
                root_path.len() as i32,
                root_path.as_ptr(),
                root_path.len() as i32,
                1,
            )
        } == CSTR_EQUAL;
    if !has_boundary || !equal_prefix {
        return Err(anyhow!(
            "release candidate: opened Windows path escaped trusted root {}",
            root.display()
        ));
    }
    let result = Ok(());

    fn final_path(handle: HANDLE) -> Result<Vec<u16>> {
        // SAFETY: a zero-length probe with a null output buffer is supported.
        let needed = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0) };
        if needed == 0 || needed > 32_768 {
            return Err(std::io::Error::last_os_error())
                .context("release candidate: resolve opened Windows file path");
        }
        let mut buffer = vec![0u16; needed as usize + 1];
        // SAFETY: buffer is writable for its declared size and handle is live.
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        };
        if written == 0 || written as usize >= buffer.len() {
            return Err(std::io::Error::last_os_error())
                .context("release candidate: read opened Windows file path");
        }
        buffer.truncate(written as usize);
        Ok(buffer)
    }
    result
}

#[cfg(unix)]
fn file_identity(_file: &File, metadata: &fs::Metadata) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn file_stability(metadata: &fs::Metadata) -> (u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(unix)]
fn verify_single_link(_file: &File, metadata: &fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        return Err(anyhow!(
            "release candidate: source input has multiple hard links and is not immutable by path: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn file_identity(file: &File, _metadata: &fs::Metadata) -> Result<(u32, u64)> {
    let information = windows_file_information(file)?;
    let index = ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64;
    Ok((information.dwVolumeSerialNumber, index))
}

#[cfg(windows)]
fn windows_file_information(
    file: &File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `file` owns a valid handle for the duration of this call and the
    // output pointer addresses a correctly sized writable structure.
    let ok = unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .context("release candidate: read Windows file identity");
    }
    // SAFETY: a nonzero return initialized the complete structure.
    Ok(unsafe { information.assume_init() })
}

#[cfg(windows)]
fn file_stability(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::windows::fs::MetadataExt;
    (metadata.file_size(), metadata.last_write_time())
}

#[cfg(windows)]
fn verify_single_link(file: &File, _metadata: &fs::Metadata, path: &Path) -> Result<()> {
    if windows_file_information(file)?.nNumberOfLinks != 1 {
        return Err(anyhow!(
            "release candidate: source input has multiple hard links and is not immutable by path: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File, metadata: &fs::Metadata) -> Result<(u64,)> {
    Ok((metadata.len(),))
}

#[cfg(not(any(unix, windows)))]
fn file_stability(metadata: &fs::Metadata) -> (u64,) {
    (metadata.len(),)
}

#[cfg(not(any(unix, windows)))]
fn verify_single_link(_file: &File, _metadata: &fs::Metadata, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_canonical_permissions(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| {
        format!(
            "release candidate: set canonical permissions on {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn set_canonical_permissions(path: &Path, _executable: bool) -> Result<()> {
    let mut permissions = fs::metadata(path)
        .with_context(|| format!("release candidate: inspect staged file {}", path.display()))?
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).with_context(|| {
        format!(
            "release candidate: set canonical permissions on {}",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?}");
    }

    fn repo() -> TempDir {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-q"]);
        fs::create_dir_all(root.path().join("module")).unwrap();
        fs::write(
            root.path().join("module/go.mod"),
            "module example.com/module\n\ngo 1.23\n",
        )
        .unwrap();
        fs::write(root.path().join("module/main.go"), "package main\n").unwrap();
        fs::write(
            root.path().join(".gitignore"),
            ".secret/\nnode_modules/\ndist/\n.tmp/\n",
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        root
    }

    #[test]
    fn snapshot_copies_tracked_and_unignored_source_with_stable_hash() {
        let root = repo();
        fs::write(root.path().join("module/untracked.go"), "package main\n").unwrap();
        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        assert!(snapshot.module_dir().join("main.go").is_file());
        assert!(snapshot.module_dir().join("untracked.go").is_file());
        assert_eq!(snapshot.source_sha256().len(), 64);
        snapshot.verify_unchanged().unwrap();
    }

    #[test]
    fn ignored_generated_outputs_never_enter_or_change_the_snapshot() {
        let root = repo();
        for relative in [
            "module/web/.tmp/tailwind-input.css",
            "module/web/.tmp/tailwind.css",
            "module/web/dist/index.js",
            "module/web/node_modules/pkg/index.js",
            ".secret/ms-release-session-module.json",
        ] {
            let path = root.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, relative).unwrap();
        }

        let first = SourceSnapshot::create(&root.path().join("module")).unwrap();
        assert!(!first.module_dir().join("web/.tmp").exists());
        assert!(!first.module_dir().join("web/dist").exists());
        assert!(!first.module_dir().join("web/node_modules").exists());
        let hash = first.source_sha256().to_string();

        fs::write(
            root.path().join("module/web/.tmp/tailwind.css"),
            "changed generated output",
        )
        .unwrap();
        first.verify_unchanged().unwrap();
        let second = SourceSnapshot::create(&root.path().join("module")).unwrap();
        assert_eq!(second.source_sha256(), hash);
    }

    #[test]
    fn tracked_source_drift_is_rejected() {
        let root = repo();
        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        fs::write(
            root.path().join("module/main.go"),
            "package main\n// edit\n",
        )
        .unwrap();
        let error = snapshot.verify_unchanged().unwrap_err();
        assert!(error.to_string().contains("source drift"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_source_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = repo();
        fs::write(root.path().join("outside.go"), "package main\n").unwrap();
        symlink("../outside.go", root.path().join("module/link.go")).unwrap();
        let error = SourceSnapshot::create(&root.path().join("module"))
            .err()
            .expect("symlink rejected");
        assert!(error.to_string().contains("symlink"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_source_is_rejected() {
        let root = repo();
        fs::hard_link(
            root.path().join("module/main.go"),
            root.path().join("main-alias.go"),
        )
        .unwrap();
        let error = SourceSnapshot::create(&root.path().join("module"))
            .err()
            .expect("hard-linked source rejected");
        assert!(
            error.to_string().contains("multiple hard links"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn same_size_rewrite_changes_the_stability_stamp() {
        let root = repo();
        let path = root.path().join("module/main.go");
        let before = file_stability(&fs::metadata(&path).unwrap());
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&path, "package nope\n").unwrap();
        let after = file_stability(&fs::metadata(&path).unwrap());
        assert_eq!(before.0, after.0, "fixture must keep the same size");
        assert_ne!(before, after, "same-size rewrite must change ctime/mtime");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_module_dir_is_rejected_before_canonicalization() {
        use std::os::unix::fs::symlink;

        let root = repo();
        symlink(root.path().join("module"), root.path().join("module-link")).unwrap();
        let error = SourceSnapshot::create(&root.path().join("module-link"))
            .err()
            .expect("symlinked --dir rejected");
        assert!(error.to_string().contains("--dir"), "{error:#}");
        assert!(error.to_string().contains("symlink"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn stage_mode_and_digest_use_canonical_git_executable_bit() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = repo();
        let main = root.path().join("module/main.go");
        fs::set_permissions(&main, fs::Permissions::from_mode(0o777)).unwrap();

        // An unstaged filesystem chmod is canonicalized back to the Git index
        // mode, so ambient umasks/checkout semantics cannot change the stage.
        let data = SourceSnapshot::create(&root.path().join("module")).unwrap();
        assert_eq!(
            fs::metadata(data.module_dir().join("main.go"))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
        let data_hash = data.source_sha256().to_string();

        git(
            root.path(),
            &["update-index", "--chmod=+x", "module/main.go"],
        );
        let executable = SourceSnapshot::create(&root.path().join("module")).unwrap();
        assert_eq!(
            fs::metadata(executable.module_dir().join("main.go"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert_ne!(executable.source_sha256(), data_hash);
    }

    #[test]
    fn aggregate_limit_charges_post_open_bytes() {
        // This models a path whose pre-open metadata reported four bytes but
        // whose no-follow handle proved six after a concurrent growth. The
        // caller charges the latter and therefore rejects the aggregate.
        let pre_open_metadata_len = 4;
        let bytes_read_from_handle = 6;
        assert!(pre_open_metadata_len + 5 <= 10);
        let error = checked_total_bytes(5, bytes_read_from_handle, 10).unwrap_err();
        assert!(
            error.to_string().contains("source is 11 bytes"),
            "{error:#}"
        );
    }

    #[test]
    fn every_phase_gets_a_pristine_independent_view() {
        let root = repo();
        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        let first = snapshot.fresh_view("first").unwrap();
        let second = snapshot.fresh_view("second").unwrap();

        fs::write(
            first.module_dir().join("main.go"),
            "package main\n// phase mutation\n",
        )
        .unwrap();
        let error = first.verify_inputs().unwrap_err();
        assert!(error.to_string().contains("canonical source"), "{error:#}");

        second.verify_inputs().unwrap();
        assert_eq!(
            fs::read_to_string(second.module_dir().join("main.go")).unwrap(),
            "package main\n"
        );
        let third = snapshot.fresh_view("third").unwrap();
        third.verify_inputs().unwrap();
    }

    #[test]
    fn phase_additions_are_rejected_but_declared_output_dirs_are_not_inputs() {
        let root = repo();
        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        let view = snapshot.fresh_view("outputs").unwrap();
        fs::write(view.module_dir().join("injected.go"), "package main\n").unwrap();
        let error = view.verify_inputs().unwrap_err();
        assert!(
            error.to_string().contains("unexpected build input"),
            "{error:#}"
        );

        fs::remove_file(view.module_dir().join("injected.go")).unwrap();
        fs::create_dir_all(view.module_dir().join("web/dist")).unwrap();
        fs::write(
            view.module_dir().join("web/dist/index.js"),
            "export default {}",
        )
        .unwrap();
        view.verify_inputs().unwrap();
    }

    #[test]
    fn web_phase_allows_compiler_generated_styles_only_in_its_output_path() {
        let root = repo();
        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        let view = snapshot.fresh_web_view().unwrap();
        let generated = view.module_dir().join("web/src/__generated__/styles.ts");
        fs::create_dir_all(generated.parent().unwrap()).unwrap();
        fs::write(&generated, "export const styles = 'release';\n").unwrap();
        view.verify_inputs().unwrap();

        let unrelated = snapshot.fresh_web_view().unwrap();
        let generated = unrelated
            .root()
            .join("another-module/web/src/__generated__/styles.ts");
        fs::create_dir_all(generated.parent().unwrap()).unwrap();
        fs::write(&generated, "export const styles = 'unrelated';\n").unwrap();
        let error = unrelated.verify_inputs().unwrap_err();
        assert!(
            error.to_string().contains("unexpected build input"),
            "{error:#}"
        );

        let extra = snapshot.fresh_web_view().unwrap();
        let source_map = extra
            .module_dir()
            .join("web/src/__generated__/styles.ts.map");
        fs::create_dir_all(source_map.parent().unwrap()).unwrap();
        fs::write(source_map, "{}").unwrap();
        let error = extra.verify_inputs().unwrap_err();
        assert!(
            error.to_string().contains("unexpected build input"),
            "{error:#}"
        );

        let ordinary = snapshot.fresh_view("ordinary").unwrap();
        let generated = ordinary
            .module_dir()
            .join("web/src/__generated__/styles.ts");
        fs::create_dir_all(generated.parent().unwrap()).unwrap();
        fs::write(&generated, "export const styles = 'release';\n").unwrap();
        let error = ordinary.verify_inputs().unwrap_err();
        assert!(
            error.to_string().contains("unexpected build input"),
            "{error:#}"
        );
    }

    #[test]
    fn tracked_web_generated_source_remains_a_verified_input() {
        let root = repo();
        let generated = root.path().join("module/web/src/__generated__/styles.ts");
        fs::create_dir_all(generated.parent().unwrap()).unwrap();
        fs::write(&generated, "export const styles = 'tracked';\n").unwrap();
        git(root.path(), &["add", "."]);

        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        let view = snapshot.fresh_web_view().unwrap();
        fs::write(
            view.module_dir().join("web/src/__generated__/styles.ts"),
            "export const styles = 'mutated';\n",
        )
        .unwrap();
        let error = view.verify_inputs().unwrap_err();
        assert!(error.to_string().contains("canonical source"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn phase_chmod_is_build_relevant_and_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let root = repo();
        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        let view = snapshot.fresh_view("chmod").unwrap();
        fs::set_permissions(
            view.module_dir().join("main.go"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let error = view.verify_inputs().unwrap_err();
        assert!(error.to_string().contains("mode changed"), "{error:#}");
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn case_folded_stage_aliases_are_rejected() {
        assert_eq!(
            stage_alias_key("module/Foo.go"),
            stage_alias_key("module/foo.go")
        );
    }

    #[test]
    fn git_commands_ignore_ambient_repository_selectors() {
        let spec = git_spec(Path::new("."));
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
        ] {
            assert!(
                spec.env_remove.contains(std::ffi::OsStr::new(name)),
                "{name}"
            );
        }
        assert_eq!(
            spec.env.get(std::ffi::OsStr::new("GIT_CONFIG_NOSYSTEM")),
            Some(&std::ffi::OsString::from("1"))
        );
        assert_eq!(
            spec.args,
            ["-c", "core.excludesFile="]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn snapshot_ignores_configured_global_excludes_but_honors_repository_rules() {
        let root = repo();
        let external_excludes = root.path().join("external-excludes");
        fs::write(&external_excludes, "ambient.go\n").unwrap();
        git(
            root.path(),
            &[
                "config",
                "core.excludesFile",
                external_excludes.to_str().unwrap(),
            ],
        );
        fs::write(root.path().join("module/ambient.go"), "package main\n").unwrap();
        fs::write(root.path().join("module/repository.go"), "package main\n").unwrap();
        fs::write(
            root.path().join(".git/info/exclude"),
            "module/repository.go\n",
        )
        .unwrap();

        let snapshot = SourceSnapshot::create(&root.path().join("module")).unwrap();
        assert!(snapshot.module_dir().join("ambient.go").is_file());
        assert!(!snapshot.module_dir().join("repository.go").exists());
    }
}
