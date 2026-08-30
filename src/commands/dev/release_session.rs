//! Durable, current-tunnel-session release evidence.
//!
//! A separate `module deploy` process cannot safely consume the outer dev
//! process's in-memory session tracker. This store publishes one small atomic
//! receipt per module under the exact workspace. Reconnect replaces the
//! session and clears web evidence; teardown removes only receipts owned by
//! this dev run. The share flow may attach a confirmed `{session, sha, size}`
//! tuple only while that same session is still current.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fs2::FileExt;
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::commands::release_candidate::source;

const SESSION_PROTOCOL: &str = "mirrorstack.release-session/v1";
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const MAX_WEB_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfirmedWeb {
    pub session_id: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseSessionReceipt {
    pub protocol: String,
    pub run_id: String,
    pub workspace_root: String,
    pub module_relative: String,
    pub slug: String,
    pub module_id: String,
    pub session_id: String,
    pub local_url: String,
    pub watch: bool,
    pub share: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<ConfirmedWeb>,
}

#[derive(Clone)]
pub(crate) struct SessionOpen<'a> {
    pub slug: &'a str,
    pub module_id: &'a str,
    pub session_id: &'a str,
    pub local_url: &'a str,
    pub module_dir: &'a Path,
    pub watch: bool,
    pub share: bool,
}

/// Exact credential files published with the initial tunnel receipt. All
/// three files are one workspace-locked ownership unit: a deploy may observe
/// the receipt only after both credentials are durable, and an old dev run
/// may remove them only while its own run id is still on disk.
#[derive(Clone, Copy)]
pub(crate) struct SessionCredentials<'a> {
    pub token_file: &'a Path,
    pub platform_token: &'a str,
    pub internal_secret_file: &'a Path,
    pub internal_secret: &'a str,
}

struct StoreState {
    closed: bool,
    receipts: HashMap<String, ReleaseSessionReceipt>,
}

/// One outer `dev --tunnel` run. All mutations serialize through `state`, so
/// a reconnect and a share confirmation cannot publish mixed session facts.
pub(crate) struct ReleaseSessionStore {
    workspace_root: PathBuf,
    workspace_text: String,
    run_id: String,
    state: Mutex<StoreState>,
}

impl ReleaseSessionStore {
    pub(crate) fn new(workspace_root: &Path) -> Result<Self> {
        let mut random = [0u8; 24];
        OsRng
            .try_fill_bytes(&mut random)
            .context("dev: mint release-session run id")?;
        Self::new_with_run_id(workspace_root, URL_SAFE_NO_PAD.encode(random))
    }

    fn new_with_run_id(workspace_root: &Path, run_id: String) -> Result<Self> {
        let workspace_root = fs::canonicalize(workspace_root).with_context(|| {
            format!(
                "dev: resolve release-session workspace {}",
                workspace_root.display()
            )
        })?;
        let workspace_text = path_text(&workspace_root, "workspace root")?;
        validate_token(&run_id, "run id", 128)?;
        Ok(Self {
            workspace_root,
            workspace_text,
            run_id,
            state: Mutex::new(StoreState {
                closed: false,
                receipts: HashMap::new(),
            }),
        })
    }

    fn receipt_for_open(&self, open: SessionOpen<'_>) -> Result<ReleaseSessionReceipt> {
        validate_slug(open.slug)?;
        validate_token(open.module_id, "module id", 128)?;
        validate_token(open.session_id, "session id", 256)?;
        validate_token(open.local_url, "local URL", 2048)?;
        let module_dir = fs::canonicalize(open.module_dir).with_context(|| {
            format!(
                "dev: resolve release-session module {}",
                open.module_dir.display()
            )
        })?;
        let module_relative = module_dir.strip_prefix(&self.workspace_root).map_err(|_| {
            anyhow!(
                "dev: module {} is outside release-session workspace {}",
                module_dir.display(),
                self.workspace_root.display()
            )
        })?;
        validate_relative(module_relative)?;
        let module_relative = normalized_path(module_relative)?;

        Ok(ReleaseSessionReceipt {
            protocol: SESSION_PROTOCOL.to_string(),
            run_id: self.run_id.clone(),
            workspace_root: self.workspace_text.clone(),
            module_relative,
            slug: open.slug.to_string(),
            module_id: open.module_id.to_string(),
            session_id: open.session_id.to_string(),
            local_url: open.local_url.to_string(),
            watch: open.watch,
            share: open.share,
            web: None,
        })
    }

    /// Publish the initial platform token, internal secret, and release
    /// receipt as one cross-process ownership transition.
    pub(crate) fn install_with_token(
        &self,
        open: SessionOpen<'_>,
        credentials: SessionCredentials<'_>,
    ) -> Result<()> {
        self.install_with_token_writer(open, credentials, write_atomic_locked, || {})
    }

    fn install_with_token_writer(
        &self,
        open: SessionOpen<'_>,
        credentials: SessionCredentials<'_>,
        write_receipt: impl FnOnce(&Path, &ReleaseSessionReceipt) -> Result<()>,
        after_credentials: impl FnOnce(),
    ) -> Result<()> {
        validate_token(credentials.platform_token, "platform token", 16 * 1024)?;
        validate_token(credentials.internal_secret, "internal secret", 16 * 1024)?;
        let receipt = self.receipt_for_open(open)?;
        let mut state = self.lock_state();
        ensure_open(&state)?;
        let _workspace_lock = workspace_lock(&self.workspace_root)?;
        validate_credential_path(
            &self.workspace_root,
            &receipt.slug,
            credentials.token_file,
            "ms-platform-token-",
            "platform token",
        )?;
        validate_credential_path(
            &self.workspace_root,
            &receipt.slug,
            credentials.internal_secret_file,
            "ms-internal-secret-",
            "internal secret",
        )?;

        if let Err(error) = write_atomic_credential(
            credentials.token_file,
            credentials.platform_token,
            &receipt.slug,
            "platform token",
        ) {
            let cleanup = remove_owned_publication_locked(&self.workspace_root, &receipt.slug);
            state.receipts.remove(&receipt.slug);
            return Err(with_cleanup_error(error, cleanup));
        }
        if let Err(error) = write_atomic_credential(
            credentials.internal_secret_file,
            credentials.internal_secret,
            &receipt.slug,
            "internal secret",
        ) {
            let cleanup = remove_owned_publication_locked(&self.workspace_root, &receipt.slug);
            state.receipts.remove(&receipt.slug);
            return Err(with_cleanup_error(error, cleanup));
        }
        after_credentials();
        if let Err(error) = write_receipt(&self.workspace_root, &receipt) {
            let cleanup = remove_owned_publication_locked(&self.workspace_root, &receipt.slug);
            state.receipts.remove(&receipt.slug);
            return Err(with_cleanup_error(error, cleanup));
        }
        state.receipts.insert(receipt.slug.clone(), receipt);
        Ok(())
    }

    /// Receipt-only installation exists only for focused store/candidate tests.
    /// Production tunnel publication must use [`Self::install_with_token`].
    #[cfg(test)]
    pub(crate) fn install(&self, open: SessionOpen<'_>) -> Result<()> {
        let receipt = self.receipt_for_open(open)?;
        let mut state = self.lock_state();
        ensure_open(&state)?;
        let _workspace_lock = workspace_lock(&self.workspace_root)?;
        write_atomic_locked(&self.workspace_root, &receipt)?;
        state.receipts.insert(receipt.slug.clone(), receipt);
        Ok(())
    }

    /// Install a reconnect only if this run already owns the module receipt.
    /// Any confirmed web tuple belongs to the dead predecessor session and is
    /// deliberately cleared before the new session becomes consumable.
    #[cfg(test)]
    pub(crate) fn replace_session(&self, slug: &str, session_id: &str) -> Result<()> {
        validate_token(session_id, "session id", 256)?;
        let mut state = self.lock_state();
        ensure_open(&state)?;
        let _workspace_lock = workspace_lock(&self.workspace_root)?;
        let receipt = state
            .receipts
            .get(slug)
            .ok_or_else(|| anyhow!("dev: no release-session receipt for {slug}"))?;
        ensure_disk_owner(&self.workspace_root, receipt, &self.run_id)?;
        let mut next = receipt.clone();
        next.session_id = session_id.to_string();
        next.web = None;
        write_atomic_locked(&self.workspace_root, &next)?;
        state.receipts.insert(slug.to_string(), next);
        Ok(())
    }

    /// Publish a reconnect's module token and receipt as one ownership-locked
    /// transition. The token must change before the receipt becomes
    /// consumable, because dispatch starts using the reconnect's token as soon
    /// as registration succeeds. If either durable write fails, both local
    /// files are removed while the workspace lock is still held; the caller
    /// then closes both tunnel handles.
    pub(crate) fn replace_session_with_token(
        &self,
        slug: &str,
        session_id: &str,
        token_file: &Path,
        platform_token: &str,
    ) -> Result<()> {
        self.replace_session_with_token_writer(
            slug,
            session_id,
            token_file,
            platform_token,
            write_atomic_locked,
        )
    }

    fn replace_session_with_token_writer(
        &self,
        slug: &str,
        session_id: &str,
        token_file: &Path,
        platform_token: &str,
        write_receipt: impl FnOnce(&Path, &ReleaseSessionReceipt) -> Result<()>,
    ) -> Result<()> {
        validate_slug(slug)?;
        validate_token(session_id, "session id", 256)?;
        validate_token(platform_token, "platform token", 16 * 1024)?;

        let mut state = self.lock_state();
        ensure_open(&state)?;
        let _workspace_lock = workspace_lock(&self.workspace_root)?;
        validate_credential_path(
            &self.workspace_root,
            slug,
            token_file,
            "ms-platform-token-",
            "platform token",
        )?;
        let receipt = state
            .receipts
            .get(slug)
            .ok_or_else(|| anyhow!("dev: no release-session receipt for {slug}"))?;
        // This check happens before touching the shared token path. A stale
        // process that lost ownership must not remove or overwrite its
        // successor's token/receipt pair.
        ensure_disk_owner(&self.workspace_root, receipt, &self.run_id)?;

        let mut next = receipt.clone();
        next.session_id = session_id.to_string();
        next.web = None;
        if let Err(error) =
            write_atomic_credential(token_file, platform_token, slug, "platform token")
        {
            let cleanup = remove_owned_publication_locked(&self.workspace_root, slug);
            state.receipts.remove(slug);
            return Err(with_cleanup_error(error, cleanup));
        }
        if let Err(error) = write_receipt(&self.workspace_root, &next) {
            let cleanup = remove_owned_publication_locked(&self.workspace_root, slug);
            state.receipts.remove(slug);
            return Err(with_cleanup_error(error, cleanup));
        }
        state.receipts.insert(slug.to_string(), next);
        Ok(())
    }

    /// Attach exact web bytes to one still-current session. A reconnect that
    /// won while upload/confirm was in flight makes this fail closed.
    pub(crate) fn confirm_web(
        &self,
        slug: &str,
        expected_session_id: &str,
        sha256: &str,
        size_bytes: u64,
    ) -> Result<()> {
        validate_sha256(sha256)?;
        if size_bytes == 0 || size_bytes > MAX_WEB_BYTES {
            return Err(anyhow!(
                "dev: confirmed web bundle size {size_bytes} is outside 1..={MAX_WEB_BYTES}"
            ));
        }
        let mut state = self.lock_state();
        ensure_open(&state)?;
        let _workspace_lock = workspace_lock(&self.workspace_root)?;
        let receipt = state
            .receipts
            .get(slug)
            .ok_or_else(|| anyhow!("dev: no release-session receipt for {slug}"))?;
        ensure_disk_owner(&self.workspace_root, receipt, &self.run_id)?;
        if receipt.session_id != expected_session_id {
            return Err(anyhow!(
                "dev: tunnel session changed while confirming {slug} web bundle (expected {expected_session_id}, current {})",
                receipt.session_id
            ));
        }
        let mut next = receipt.clone();
        next.web = Some(ConfirmedWeb {
            session_id: expected_session_id.to_string(),
            sha256: sha256.to_string(),
            size_bytes,
        });
        write_atomic_locked(&self.workspace_root, &next)?;
        state.receipts.insert(slug.to_string(), next);
        Ok(())
    }

    /// Mark the run closed and remove only files that still carry this run's
    /// id. A stale process can therefore never delete a successor's receipt.
    pub(crate) fn close_all(&self) {
        self.close_all_with_hook(|| {});
    }

    fn close_all_with_hook(&self, mut after_owner_read: impl FnMut()) {
        let slugs = {
            let mut state = self.lock_state();
            state.closed = true;
            state.receipts.keys().cloned().collect::<Vec<_>>()
        };
        let Ok(_workspace_lock) = workspace_lock(&self.workspace_root) else {
            return;
        };
        for slug in slugs {
            let path = receipt_path(&self.workspace_root, &slug);
            let Ok(current) = read_receipt_path(&path) else {
                continue;
            };
            if current.run_id == self.run_id {
                after_owner_read();
                let _ = remove_owned_publication_locked(&self.workspace_root, &slug);
            }
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, StoreState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for ReleaseSessionStore {
    fn drop(&mut self) {
        self.close_all();
    }
}

/// Find the receipt in the exact workspace ancestor that owns `module_dir`.
/// A sibling Git worktree has a different ancestor path and cannot consume it.
pub(crate) fn load_for_module(module_dir: &Path, slug: &str) -> Result<ReleaseSessionReceipt> {
    validate_slug(slug)?;
    let module_dir = fs::canonicalize(module_dir).with_context(|| {
        format!(
            "release candidate: resolve module directory {}",
            module_dir.display()
        )
    })?;
    let mut current = Some(module_dir.as_path());
    while let Some(root) = current {
        let path = receipt_path(root, slug);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let _workspace_lock = workspace_lock(root)?;
                let receipt = read_receipt_path(&path)?;
                validate_receipt(&receipt)?;
                if receipt.slug != slug {
                    return Err(anyhow!(
                        "release candidate: tunnel receipt path for {slug} contains slug {}",
                        receipt.slug
                    ));
                }
                let root_text = path_text(root, "workspace root")?;
                if receipt.workspace_root != root_text {
                    return Err(anyhow!(
                        "release candidate: tunnel receipt belongs to a different workspace ({})",
                        receipt.workspace_root
                    ));
                }
                let expected = module_dir.strip_prefix(root).map_err(|_| {
                    anyhow!("release candidate: module is outside its tunnel workspace")
                })?;
                if receipt.module_relative != normalized_path(expected)? {
                    return Err(anyhow!(
                        "release candidate: tunnel receipt for {slug} belongs to module {}, not {}",
                        receipt.module_relative,
                        expected.display()
                    ));
                }
                return Ok(receipt);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "release candidate: inspect tunnel receipt {}",
                        path.display()
                    )
                });
            }
        }
        current = root.parent();
    }
    Err(anyhow!(
        "release candidate: no current tunnel receipt for {slug}; run `mirrorstack dev --tunnel --share --watch=false` from this workspace"
    ))
}

fn receipt_path(root: &Path, slug: &str) -> PathBuf {
    root.join(".secret")
        .join(format!("ms-release-session-{slug}.json"))
}

struct WorkspaceLock {
    _file: fs::File,
}

fn workspace_lock(root: &Path) -> Result<WorkspaceLock> {
    let secret = ensure_secret_dir(root)?;
    let path = secret.join("ms-release-session.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("dev: open release-session lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("dev: inspect release-session lock {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "dev: release-session lock is not a regular no-follow file: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!(
                "dev: release-session lock must not be a reparse point: {}",
                path.display()
            ));
        }
    }
    file.lock_exclusive()
        .with_context(|| format!("dev: lock release-session workspace {}", root.display()))?;
    Ok(WorkspaceLock { _file: file })
}

fn ensure_secret_dir(root: &Path) -> Result<PathBuf> {
    let secret = root.join(".secret");
    match fs::create_dir(&secret) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("dev: create release-session directory {}", secret.display())
            });
        }
    }
    let metadata = fs::symlink_metadata(&secret).with_context(|| {
        format!(
            "dev: inspect release-session directory {}",
            secret.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(anyhow!(
            "dev: release-session directory is not a no-follow directory: {}",
            secret.display()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(anyhow!(
                "dev: release-session directory must not be a reparse point: {}",
                secret.display()
            ));
        }
    }
    Ok(secret)
}

fn ensure_disk_owner(root: &Path, expected: &ReleaseSessionReceipt, run_id: &str) -> Result<()> {
    let current = read_receipt_path(&receipt_path(root, &expected.slug)).with_context(|| {
        format!(
            "dev: release-session ownership for {} is no longer readable",
            expected.slug
        )
    })?;
    if current.run_id != run_id {
        return Err(anyhow!(
            "dev: release-session ownership for {} was replaced by another run",
            expected.slug
        ));
    }
    if current != *expected {
        return Err(anyhow!(
            "dev: release-session state for {} changed outside this run",
            expected.slug
        ));
    }
    Ok(())
}

fn validate_credential_path(
    root: &Path,
    slug: &str,
    path: &Path,
    prefix: &str,
    label: &str,
) -> Result<()> {
    let expected_name = format!("{prefix}{slug}");
    let expected_parent = fs::canonicalize(root.join(".secret"))
        .context("dev: resolve release-session credential directory")?;
    let actual_parent = path
        .parent()
        .ok_or_else(|| anyhow!("dev: {label} path for {slug} has no parent"))?;
    let actual_parent = fs::canonicalize(actual_parent)
        .with_context(|| format!("dev: resolve {label} directory for {slug}"))?;
    if path.file_name() != Some(std::ffi::OsStr::new(&expected_name))
        || actual_parent != expected_parent
    {
        return Err(anyhow!(
            "dev: {label} path for {slug} is outside its release-session workspace"
        ));
    }
    Ok(())
}

fn write_atomic_credential(path: &Path, value: &str, slug: &str, label: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("dev: {label} path for {slug} has no parent"))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("dev: create {label} file for {slug}"))?;
    temporary
        .write_all(value.as_bytes())
        .with_context(|| format!("dev: write {label} file for {slug}"))?;
    temporary
        .as_file_mut()
        .sync_all()
        .with_context(|| format!("dev: sync {label} file for {slug}"))?;
    set_private_permissions(temporary.path())?;
    temporary
        .persist(path)
        .map_err(|error| anyhow!("dev: publish {label} file for {slug}: {}", error.error))?;
    sync_directory(parent)?;
    Ok(())
}

fn remove_owned_publication_locked(root: &Path, slug: &str) -> Result<()> {
    let receipt = receipt_path(root, slug);
    let token = super::platform_token_file(root, slug);
    let internal_secret = super::internal_secret_file(root, slug);
    let mut first_error = None;
    for (path, label) in [
        (receipt.as_path(), "release-session receipt"),
        (token.as_path(), "platform token"),
        (internal_secret.as_path(), "internal secret"),
    ] {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
            && first_error.is_none()
        {
            first_error = Some(anyhow!(
                "dev: remove invalid {label} {}: {error}",
                path.display()
            ));
        }
    }
    if let Err(error) = sync_directory(&root.join(".secret"))
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn with_cleanup_error(error: anyhow::Error, cleanup: Result<()>) -> anyhow::Error {
    match cleanup {
        Ok(()) => error,
        Err(cleanup) => {
            anyhow!("{error:#}; local tunnel publication cleanup also failed: {cleanup:#}")
        }
    }
}

fn write_atomic_locked(root: &Path, receipt: &ReleaseSessionReceipt) -> Result<()> {
    validate_receipt(receipt)?;
    let mut bytes = serde_json::to_vec(receipt).context("dev: encode release-session receipt")?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(anyhow!(
            "dev: release-session receipt exceeds {MAX_RECEIPT_BYTES} bytes"
        ));
    }
    let secret = ensure_secret_dir(root)?;
    let mut temporary =
        NamedTempFile::new_in(&secret).context("dev: create atomic release-session receipt")?;
    temporary
        .write_all(&bytes)
        .context("dev: write release-session receipt")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("dev: sync release-session receipt")?;
    set_private_permissions(temporary.path())?;
    let destination = receipt_path(root, &receipt.slug);
    temporary.persist(&destination).map_err(|error| {
        anyhow!(
            "dev: publish release-session receipt {}: {}",
            destination.display(),
            error.error
        )
    })?;
    sync_directory(&secret)?;
    Ok(())
}

fn read_receipt_path(path: &Path) -> Result<ReleaseSessionReceipt> {
    let secret = path
        .parent()
        .ok_or_else(|| anyhow!("release candidate: tunnel receipt has no parent"))?;
    let root = secret
        .parent()
        .ok_or_else(|| anyhow!("release candidate: tunnel receipt has no workspace root"))?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("release candidate: tunnel receipt escaped its workspace root"))?;
    let bytes =
        source::read_regular_bounded(root, relative, MAX_RECEIPT_BYTES as u64, "tunnel receipt")?;
    serde_json::from_slice(&bytes).context("release candidate: parse tunnel receipt")
}

fn validate_receipt(receipt: &ReleaseSessionReceipt) -> Result<()> {
    if receipt.protocol != SESSION_PROTOCOL {
        return Err(anyhow!(
            "release candidate: unsupported tunnel receipt protocol {}",
            receipt.protocol
        ));
    }
    validate_token(&receipt.run_id, "run id", 128)?;
    validate_token(&receipt.workspace_root, "workspace root", 4096)?;
    validate_token(&receipt.module_relative, "module path", 4096)?;
    validate_slug(&receipt.slug)?;
    validate_token(&receipt.module_id, "module id", 128)?;
    validate_token(&receipt.session_id, "session id", 256)?;
    validate_token(&receipt.local_url, "local URL", 2048)?;
    if let Some(web) = &receipt.web {
        if web.session_id != receipt.session_id {
            return Err(anyhow!(
                "release candidate: tunnel receipt mixes session {} with web session {}",
                receipt.session_id,
                web.session_id
            ));
        }
        validate_sha256(&web.sha256)?;
        if web.size_bytes == 0 || web.size_bytes > MAX_WEB_BYTES {
            return Err(anyhow!(
                "release candidate: tunnel receipt web size is outside 1..={MAX_WEB_BYTES}"
            ));
        }
    }
    Ok(())
}

fn validate_slug(slug: &str) -> Result<()> {
    if slug.is_empty()
        || slug.len() > 64
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(anyhow!("release session: invalid module slug `{slug}`"));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(anyhow!(
            "release session: sha256 must be exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_token(value: &str, label: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(anyhow!("release session: invalid {label}"));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(anyhow!(
            "release session: module path must stay inside the workspace"
        ));
    }
    Ok(())
}

fn normalized_path(path: &Path) -> Result<String> {
    validate_relative(path)?;
    Ok(path
        .to_str()
        .ok_or_else(|| anyhow!("release session: module path is not UTF-8"))?
        .replace('\\', "/"))
}

fn path_text(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("release session: {label} is not UTF-8"))
}

fn ensure_open(state: &StoreState) -> Result<()> {
    if state.closed {
        Err(anyhow!("dev: release-session store is closed"))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("dev: protect release-session receipt")
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("dev: sync release-session directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn module(root: &Path) -> PathBuf {
        let module = root.join("module");
        fs::create_dir_all(&module).unwrap();
        module
    }

    fn open<'a>(module: &'a Path, session: &'a str, watch: bool) -> SessionOpen<'a> {
        SessionOpen {
            slug: "user-core",
            module_id: "m11111111111111111111111111111111",
            session_id: session,
            local_url: "http://localhost:9080/_m/user-core",
            module_dir: module,
            watch,
            share: true,
        }
    }

    fn credential_paths(root: &Path) -> (PathBuf, PathBuf) {
        (
            super::super::platform_token_file(root, "user-core"),
            super::super::internal_secret_file(root, "user-core"),
        )
    }

    fn credentials<'a>(
        token_file: &'a Path,
        token: &'a str,
        secret_file: &'a Path,
        secret: &'a str,
    ) -> SessionCredentials<'a> {
        SessionCredentials {
            token_file,
            platform_token: token,
            internal_secret_file: secret_file,
            internal_secret: secret,
        }
    }

    #[test]
    fn lifecycle_is_atomic_session_owned_and_teardown_removes_it() {
        let root = tempfile::tempdir().unwrap();
        let module_dir = module(root.path());
        let store = ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap();
        store
            .install(open(&module_dir, "session-one", false))
            .unwrap();
        store
            .confirm_web("user-core", "session-one", SHA_A, 42)
            .unwrap();
        let confirmed = load_for_module(&module_dir, "user-core").unwrap();
        assert_eq!(confirmed.web.unwrap().size_bytes, 42);

        store.replace_session("user-core", "session-two").unwrap();
        let replaced = load_for_module(&module_dir, "user-core").unwrap();
        assert_eq!(replaced.session_id, "session-two");
        assert!(replaced.web.is_none());
        assert!(
            store
                .confirm_web("user-core", "session-one", SHA_A, 42)
                .unwrap_err()
                .to_string()
                .contains("session changed")
        );

        store.close_all();
        assert!(!receipt_path(root.path(), "user-core").exists());
    }

    #[test]
    fn stale_teardown_cannot_remove_successor_receipt() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let (token, secret) = credential_paths(root.path());
        let old = ReleaseSessionStore::new_with_run_id(root.path(), "old-run".into()).unwrap();
        old.install_with_token(
            open(&module, "old-session", false),
            credentials(&token, "old-token", &secret, "old-secret"),
        )
        .unwrap();
        let new = ReleaseSessionStore::new_with_run_id(root.path(), "new-run".into()).unwrap();
        new.install_with_token(
            open(&module, "new-session", false),
            credentials(&token, "new-token", &secret, "new-secret"),
        )
        .unwrap();

        old.close_all();
        let current = load_for_module(&module, "user-core").unwrap();
        assert_eq!(current.run_id, "new-run");
        assert_eq!(fs::read_to_string(&token).unwrap(), "new-token");
        assert_eq!(fs::read_to_string(&secret).unwrap(), "new-secret");
        new.close_all();
        assert!(!receipt_path(root.path(), "user-core").exists());
        assert!(!token.exists());
        assert!(!secret.exists());
    }

    #[test]
    fn initial_publication_failure_removes_token_secret_and_receipt() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let (token, secret) = credential_paths(root.path());
        let store = ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap();

        let error = store
            .install_with_token_writer(
                open(&module, "session-one", false),
                credentials(&token, "platform-one", &secret, "internal-one"),
                |_, _| Err(anyhow!("injected initial receipt persistence failure")),
                || {
                    assert_eq!(fs::read_to_string(&token).unwrap(), "platform-one");
                    assert_eq!(fs::read_to_string(&secret).unwrap(), "internal-one");
                    assert!(!receipt_path(root.path(), "user-core").exists());
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("injected initial"), "{error:#}");
        assert!(!receipt_path(root.path(), "user-core").exists());
        assert!(!token.exists());
        assert!(!secret.exists());
    }

    #[test]
    fn concurrent_initial_publications_never_mix_two_runs() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let (token, secret) = credential_paths(root.path());
        let first =
            Arc::new(ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap());
        let second =
            Arc::new(ReleaseSessionStore::new_with_run_id(root.path(), "run-two".into()).unwrap());
        let credentials_written = Arc::new(Barrier::new(2));
        let allow_receipt = Arc::new(Barrier::new(2));

        let first_publish = {
            let first = first.clone();
            let module = module.clone();
            let token = token.clone();
            let secret = secret.clone();
            let credentials_written = credentials_written.clone();
            let allow_receipt = allow_receipt.clone();
            std::thread::spawn(move || {
                first
                    .install_with_token_writer(
                        open(&module, "session-one", false),
                        credentials(&token, "token-one", &secret, "secret-one"),
                        write_atomic_locked,
                        || {
                            credentials_written.wait();
                            allow_receipt.wait();
                        },
                    )
                    .unwrap();
            })
        };
        credentials_written.wait();
        assert_eq!(fs::read_to_string(&token).unwrap(), "token-one");
        assert_eq!(fs::read_to_string(&secret).unwrap(), "secret-one");
        assert!(!receipt_path(root.path(), "user-core").exists());

        let (published, received) = mpsc::channel();
        let second_publish = {
            let second = second.clone();
            let module = module.clone();
            let token = token.clone();
            let secret = secret.clone();
            std::thread::spawn(move || {
                second
                    .install_with_token(
                        open(&module, "session-two", false),
                        credentials(&token, "token-two", &secret, "secret-two"),
                    )
                    .unwrap();
                published.send(()).unwrap();
            })
        };
        assert!(
            received.recv_timeout(Duration::from_millis(100)).is_err(),
            "second store published through the first store's locked transition"
        );
        allow_receipt.wait();
        first_publish.join().unwrap();
        second_publish.join().unwrap();
        received.recv_timeout(Duration::from_secs(1)).unwrap();

        let current = load_for_module(&module, "user-core").unwrap();
        assert_eq!(current.run_id, "run-two");
        assert_eq!(current.session_id, "session-two");
        assert_eq!(fs::read_to_string(&token).unwrap(), "token-two");
        assert_eq!(fs::read_to_string(&secret).unwrap(), "secret-two");
    }

    #[test]
    fn successor_ownership_blocks_old_reconnect_and_share_writes() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let old = ReleaseSessionStore::new_with_run_id(root.path(), "old-run".into()).unwrap();
        old.install(open(&module, "old-session", false)).unwrap();
        let new = ReleaseSessionStore::new_with_run_id(root.path(), "new-run".into()).unwrap();
        new.install(open(&module, "new-session", false)).unwrap();

        let reconnect = old
            .replace_session("user-core", "stale-reconnect")
            .unwrap_err();
        assert!(
            reconnect.to_string().contains("another run"),
            "{reconnect:#}"
        );
        let share = old
            .confirm_web("user-core", "old-session", SHA_A, 42)
            .unwrap_err();
        assert!(share.to_string().contains("another run"), "{share:#}");

        let current = load_for_module(&module, "user-core").unwrap();
        assert_eq!(current.run_id, "new-run");
        assert_eq!(current.session_id, "new-session");
        assert!(current.web.is_none());
    }

    #[test]
    fn receipt_write_failure_after_token_publish_removes_both_local_halves() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let store = ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap();
        store.install(open(&module, "session-one", false)).unwrap();
        let token = root.path().join(".secret/ms-platform-token-user-core");
        fs::write(&token, "token-one").unwrap();

        let error = store
            .replace_session_with_token_writer(
                "user-core",
                "session-two",
                &token,
                "token-two",
                |_, _| {
                    assert_eq!(fs::read_to_string(&token).unwrap(), "token-two");
                    Err(anyhow!("injected receipt persistence failure"))
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("injected"), "{error:#}");
        assert!(!token.exists(), "new token must not survive alone");
        assert!(
            !receipt_path(root.path(), "user-core").exists(),
            "old or partially replaced receipt must not survive alone"
        );
        assert!(
            store
                .confirm_web("user-core", "session-two", SHA_A, 42)
                .unwrap_err()
                .to_string()
                .contains("no release-session receipt")
        );
    }

    #[test]
    fn stale_reconnect_never_touches_successor_token_file() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let old = ReleaseSessionStore::new_with_run_id(root.path(), "old-run".into()).unwrap();
        old.install(open(&module, "old-session", false)).unwrap();
        let new = ReleaseSessionStore::new_with_run_id(root.path(), "new-run".into()).unwrap();
        new.install(open(&module, "new-session", false)).unwrap();
        let token = root.path().join(".secret/ms-platform-token-user-core");
        fs::write(&token, "successor-token").unwrap();

        let error = old
            .replace_session_with_token("user-core", "stale-session", &token, "stale-token")
            .unwrap_err();
        assert!(error.to_string().contains("another run"), "{error:#}");
        assert_eq!(fs::read_to_string(&token).unwrap(), "successor-token");
        assert_eq!(
            load_for_module(&module, "user-core").unwrap().run_id,
            "new-run"
        );
    }

    #[test]
    fn teardown_compare_delete_holds_the_workspace_lock_against_successor_install() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let old =
            Arc::new(ReleaseSessionStore::new_with_run_id(root.path(), "old-run".into()).unwrap());
        old.install(open(&module, "old-session", false)).unwrap();
        let new =
            Arc::new(ReleaseSessionStore::new_with_run_id(root.path(), "new-run".into()).unwrap());
        let owner_read = Arc::new(Barrier::new(2));
        let allow_delete = Arc::new(Barrier::new(2));

        let teardown = {
            let old = old.clone();
            let owner_read = owner_read.clone();
            let allow_delete = allow_delete.clone();
            std::thread::spawn(move || {
                old.close_all_with_hook(|| {
                    owner_read.wait();
                    allow_delete.wait();
                });
            })
        };
        owner_read.wait();

        let (installed, received) = mpsc::channel();
        let successor = {
            let new = new.clone();
            let module = module.clone();
            std::thread::spawn(move || {
                new.install(open(&module, "new-session", false)).unwrap();
                installed.send(()).unwrap();
            })
        };
        assert!(
            received.recv_timeout(Duration::from_millis(100)).is_err(),
            "successor install passed the old run's locked compare-delete window"
        );
        allow_delete.wait();
        teardown.join().unwrap();
        successor.join().unwrap();
        received.recv_timeout(Duration::from_secs(1)).unwrap();

        let current = load_for_module(&module, "user-core").unwrap();
        assert_eq!(current.run_id, "new-run");
        assert_eq!(current.session_id, "new-session");
    }

    #[test]
    fn copied_receipt_cannot_be_consumed_from_another_worktree() {
        let first = tempfile::tempdir().unwrap();
        let first_module = module(first.path());
        let store = ReleaseSessionStore::new_with_run_id(first.path(), "run-one".into()).unwrap();
        store
            .install(open(&first_module, "session-one", false))
            .unwrap();

        let second = tempfile::tempdir().unwrap();
        let second_module = module(second.path());
        fs::create_dir_all(second.path().join(".secret")).unwrap();
        fs::copy(
            receipt_path(first.path(), "user-core"),
            receipt_path(second.path(), "user-core"),
        )
        .unwrap();
        let error = load_for_module(&second_module, "user-core").unwrap_err();
        assert!(
            error.to_string().contains("different workspace"),
            "{error:#}"
        );
    }

    #[test]
    fn receipt_slug_must_match_the_requested_path_slug() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let store = ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap();
        store.install(open(&module, "session-one", false)).unwrap();
        let path = receipt_path(root.path(), "user-core");
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        receipt["slug"] = serde_json::Value::String("other-core".into());
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();

        let error = load_for_module(&module, "user-core").unwrap_err();
        assert!(
            error.to_string().contains("contains slug other-core"),
            "{error:#}"
        );
    }

    #[test]
    fn watch_mode_is_explicit_in_receipt() {
        let root = tempfile::tempdir().unwrap();
        let module = module(root.path());
        let store = ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap();
        store.install(open(&module, "session-one", true)).unwrap();
        assert!(load_for_module(&module, "user-core").unwrap().watch);
    }

    #[cfg(unix)]
    #[test]
    fn receipt_and_secret_symlinks_are_rejected_without_following() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let first_module = module(root.path());
        let store = ReleaseSessionStore::new_with_run_id(root.path(), "run-one".into()).unwrap();
        store
            .install(open(&first_module, "session-one", false))
            .unwrap();
        let receipt = receipt_path(root.path(), "user-core");
        let outside = root.path().join("outside.json");
        fs::write(&outside, b"{}").unwrap();
        fs::remove_file(&receipt).unwrap();
        symlink(&outside, &receipt).unwrap();
        let error = load_for_module(&first_module, "user-core").unwrap_err();
        assert!(error.to_string().contains("no-follow"), "{error:#}");

        let other = tempfile::tempdir().unwrap();
        let other_module = module(other.path());
        let external_secret = other.path().join("external-secret");
        fs::create_dir(&external_secret).unwrap();
        symlink(&external_secret, other.path().join(".secret")).unwrap();
        let other_store =
            ReleaseSessionStore::new_with_run_id(other.path(), "run-two".into()).unwrap();
        let error = other_store
            .install(open(&other_module, "session-two", false))
            .unwrap_err();
        assert!(
            error.to_string().contains("no-follow directory"),
            "{error:#}"
        );
    }
}
