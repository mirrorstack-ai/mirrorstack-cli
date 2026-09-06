//! Install the clients of the modules installed on an app.
//!
//! The producer side of this is `mirrorstack dev --tunnel`, which builds each
//! declared module client and publishes it bound to its tunnel session. This
//! is the consumer: it asks the platform what is installable for one app and
//! lays each client into `node_modules` under the platform-owned import name.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use console::style;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::api::{self, ApiError, AppModuleClient};
use crate::commands::{
    DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base, session_expired, warn_prefix,
};
use crate::{credentials, http};

/// The npm scope every module client is installed under. The platform owns
/// package identity; a module repository never names its own package.
const PLATFORM_SCOPE: &str = "@mirrorstack-ai";

/// Downloads get their own client: a presigned URL carries its own auth, so it
/// must not receive the bearer token, and an artifact is larger than a JSON
/// call.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Caps applied to bytes we did not produce. The producer bounds what it packs;
/// these bound what we unpack, which is the side that faces a hostile archive.
const MAX_COMPRESSED_BYTES: u64 = 10 << 20;
const MAX_EXPANDED_BYTES: u64 = 32 << 20;
const MAX_ENTRIES: usize = 1_024;
const MAX_PATH_BYTES: usize = 240;
const ALLOWED_SUFFIXES: [&str; 9] = [
    ".js", ".mjs", ".cjs", ".d.ts", ".d.mts", ".d.cts", ".json", ".map", ".css",
];

const MIN_WATCH_INTERVAL_SECS: u64 = 2;

#[derive(Args)]
pub struct InstallArgs {
    /// App ID or slug whose installed modules' clients to install.
    #[arg(long)]
    app: String,
    /// Project directory holding `node_modules`. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Keep running: reinstall a dev-mode module's client whenever its tunnel
    /// publishes a new revision. Ctrl-C to stop.
    #[arg(long)]
    dev: bool,
    /// Seconds between checks while watching with --dev.
    #[arg(long, default_value_t = 5)]
    interval: u64,
}

pub(super) fn run(args: InstallArgs) -> Result<()> {
    let root = match &args.dir {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().context("resolve the current directory")?,
    };
    if !root.is_dir() {
        return Err(anyhow!("{} is not a directory", root.display()));
    }
    let interval = Duration::from_secs(args.interval.max(MIN_WATCH_INTERVAL_SECS));

    let mut creds = credentials::load_or_login_hint()?;
    let client = http::client(Duration::from_secs(15))?;
    let download_client = http::client(DOWNLOAD_TIMEOUT)?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);

    // `module-clients` resolves the per-app tenant schema from the id, so it
    // needs the UUID — the id-or-slug `--app` is resolved first.
    let app = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::get_app(&client, &apps_base, tok, &args.app)
    }) {
        Ok(Some(app)) => app,
        Ok(None) => {
            return Err(anyhow!(
                "app '{}' not found (or you are not a member)",
                args.app
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    // Revision per module id, so a watch pass reinstalls only what changed.
    let mut installed: BTreeMap<String, String> = BTreeMap::new();

    let outcome = install_pass(
        &client,
        &download_client,
        &apps_base,
        &mut creds,
        &app.id,
        &root,
        &mut installed,
        true,
    )?;
    if !args.dev {
        if outcome.installed == 0 {
            eprintln!(
                "{} no module client was installable. Start a tunnel for the module you need with `mirrorstack dev --tunnel`.",
                warn_prefix()
            );
        }
        return Ok(());
    }

    eprintln!(
        "{} watching {} for new client revisions every {}s — ctrl-c to stop",
        ok_mark(),
        style(&app.slug).cyan(),
        interval.as_secs()
    );
    loop {
        std::thread::sleep(interval);
        match install_pass(
            &client,
            &download_client,
            &apps_base,
            &mut creds,
            &app.id,
            &root,
            &mut installed,
            false,
        ) {
            Ok(_) => {}
            // A watch must survive a transient platform or network failure;
            // only an unrecoverable session ends it.
            Err(error) if is_fatal_watch_error(&error) => return Err(error),
            Err(error) => {
                eprintln!(
                    "{} {error}; retrying in {}s",
                    warn_prefix(),
                    interval.as_secs()
                );
            }
        }
    }
}

fn is_fatal_watch_error(error: &anyhow::Error) -> bool {
    error.to_string().contains("session expired")
}

struct PassOutcome {
    installed: usize,
}

#[allow(clippy::too_many_arguments)]
fn install_pass(
    client: &reqwest::blocking::Client,
    download_client: &reqwest::blocking::Client,
    apps_base: &str,
    creds: &mut credentials::Credentials,
    app_id: &str,
    root: &Path,
    installed: &mut BTreeMap<String, String>,
    report_skips: bool,
) -> Result<PassOutcome> {
    let clients = match credentials::with_refresh_retry(creds, |tok| {
        api::list_app_module_clients(client, apps_base, tok, app_id)
    }) {
        Ok(clients) => clients,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(ApiError::Server { code, message, .. }) => return Err(anyhow!("{code}: {message}")),
        // The app resolved a moment ago, so a bare 404 here is not a missing
        // app — it is a platform that does not mount this route yet. Say that
        // rather than leaving the reader to guess which of the two it is.
        Err(ApiError::Unexpected { status: 404, .. }) => {
            return Err(anyhow!(
                "this platform does not serve module clients yet (mirrorstack-ai/mirrorstack-core-v2#742). Upgrade the platform, or link a module's client directory by hand until it ships."
            ));
        }
        Err(e) => return Err(e.into()),
    };

    let mut count = 0usize;
    let mut owners: BTreeSet<String> = BTreeSet::new();
    for module in &clients {
        let Some(descriptor) = &module.client else {
            if report_skips {
                report_skip(module);
            }
            // A module that stops being installable keeps whatever is already
            // on disk: a tunnel restarting must not break a running build.
            continue;
        };
        if module.owner_username.is_empty() {
            eprintln!(
                "{} [{}] has no owner on the platform, so it has no import name; skipped",
                warn_prefix(),
                style(&module.slug).cyan()
            );
            continue;
        }
        if installed.get(&module.module_id) == Some(&descriptor.revision) {
            owners.insert(module.owner_username.clone());
            continue;
        }

        let download = match credentials::with_refresh_retry(creds, |tok| {
            api::request_module_client_download(client, apps_base, tok, app_id, &module.module_id)
        }) {
            Ok(download) => download,
            Err(ApiError::Unauthenticated) => return Err(session_expired()),
            Err(ApiError::Server { code, message, .. }) => {
                eprintln!(
                    "{} [{}] {code}: {message}",
                    warn_prefix(),
                    style(&module.slug).cyan()
                );
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        // The list decided what to install; the download mints a URL a moment
        // later. If the artifact moved in between, install nothing this pass
        // rather than a revision nobody asked for — the next pass sees it.
        if download.revision != descriptor.revision
            || download.sha256 != descriptor.sha256
            || download.size_bytes != descriptor.size_bytes
        {
            eprintln!(
                "{} [{}] published a new revision mid-install; picking it up next pass",
                warn_prefix(),
                style(&module.slug).cyan()
            );
            continue;
        }

        let bytes = fetch(download_client, &download.url, download.size_bytes)
            .with_context(|| format!("download the client of [{}]", module.slug))?;
        verify(&bytes, &download.sha256, download.size_bytes)
            .with_context(|| format!("verify the client of [{}]", module.slug))?;

        let package_dir = root
            .join("node_modules")
            .join(PLATFORM_SCOPE)
            .join(&module.owner_username)
            .join(&module.slug);
        install_archive(&bytes, &package_dir)
            .with_context(|| format!("install the client of [{}]", module.slug))?;

        installed.insert(module.module_id.clone(), descriptor.revision.clone());
        owners.insert(module.owner_username.clone());
        count += 1;
        eprintln!(
            "{} {}/{}/{} · {}",
            ok_mark(),
            style(PLATFORM_SCOPE).dim(),
            style(&module.owner_username).dim(),
            style(&module.slug).cyan(),
            style(short_revision(&descriptor.revision)).dim()
        );
    }

    for owner in &owners {
        let owner_dir = root.join("node_modules").join(PLATFORM_SCOPE).join(owner);
        write_owner_manifest(&owner_dir, owner)
            .with_context(|| format!("write the {PLATFORM_SCOPE}/{owner} package manifest"))?;
    }

    Ok(PassOutcome { installed: count })
}

fn report_skip(module: &AppModuleClient) {
    let reason = module.reason.as_deref().unwrap_or("unavailable");
    let pinned = format!(
        "installed from published version {}, which carries no client yet",
        module.installed_version
    );
    let explanation = match reason {
        "not_dev_mode" => pinned.as_str(),
        "no_client_published" => "its tunnel has published no client (the module may declare none)",
        "tunnel_offline" => "no tunnel is serving it — run `mirrorstack dev --tunnel` for it",
        "tunnel_session_expired" => "its published client expired with its tunnel session",
        _ => "no installable client right now",
    };
    eprintln!(
        "{} [{}] {explanation}",
        warn_prefix(),
        style(&module.slug).cyan()
    );
}

fn short_revision(revision: &str) -> String {
    let hex = revision.strip_prefix("sha256:").unwrap_or(revision);
    hex.chars().take(12).collect()
}

/// Read at most one artifact's worth of bytes from a presigned URL. The
/// declared size bounds the read so a redirected or swapped object cannot
/// stream without limit.
fn fetch(client: &reqwest::blocking::Client, url: &str, size_bytes: u64) -> Result<Vec<u8>> {
    if size_bytes == 0 || size_bytes > MAX_COMPRESSED_BYTES {
        return Err(anyhow!(
            "declared size {size_bytes} is outside the allowed range"
        ));
    }
    // The presigned URL is a credential: keep it out of any error text.
    let resp = client
        .get(url)
        .send()
        .map_err(|e| anyhow!("request failed: {}", e.without_url()))?;
    if !resp.status().is_success() {
        return Err(anyhow!("download failed with status {}", resp.status()));
    }
    let mut bytes = Vec::with_capacity(size_bytes as usize);
    resp.take(size_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow!("read body: {e}"))?;
    Ok(bytes)
}

/// Verify received bytes against the platform's declaration before anything
/// touches the filesystem. Without this the download is unauthenticated data.
fn verify(bytes: &[u8], sha256hex: &str, size_bytes: u64) -> Result<()> {
    if bytes.len() as u64 != size_bytes {
        return Err(anyhow!(
            "size mismatch: got {} bytes, expected {size_bytes}",
            bytes.len()
        ));
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != sha256hex {
        return Err(anyhow!(
            "sha256 mismatch: got {actual}, expected {sha256hex}"
        ));
    }
    Ok(())
}

/// Unpack a verified artifact into its package directory, replacing whatever
/// was there. Every rule the packer enforces on its own inputs is re-applied
/// here, because this side unpacks bytes it did not produce.
fn install_archive(bytes: &[u8], package_dir: &Path) -> Result<()> {
    let files = read_archive(bytes)?;
    for required in ["dist/index.js", "dist/index.d.ts"] {
        match files.get(required) {
            None => return Err(anyhow!("archive is missing {required}")),
            Some(content) if content.is_empty() => {
                return Err(anyhow!("archive entry {required} is empty"));
            }
            Some(_) => {}
        }
    }

    // Stage beside the destination and swap, so an interrupted install never
    // leaves a half-written package a bundler could read.
    let parent = package_dir
        .parent()
        .ok_or_else(|| anyhow!("package directory has no parent"))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let staging = parent.join(format!(
        ".{}.tmp-{}",
        package_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("client"),
        std::process::id()
    ));
    if staging.exists() {
        fs::remove_dir_all(&staging).ok();
    }
    let result = (|| -> Result<()> {
        for (relative, content) in &files {
            let target = staging.join(relative);
            if let Some(dir) = target.parent() {
                fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
            }
            write_regular(&target, content)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        fs::remove_dir_all(&staging).ok();
        return Err(error);
    }
    if package_dir.exists() {
        fs::remove_dir_all(package_dir)
            .with_context(|| format!("replace {}", package_dir.display()))?;
    }
    fs::rename(&staging, package_dir)
        .with_context(|| format!("move the staged client into {}", package_dir.display()))?;
    Ok(())
}

fn write_regular(path: &Path, content: &[u8]) -> Result<()> {
    // Modes, owners and times in the archive are ignored: a downloaded file is
    // data, never a permission grant.
    fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o644);
    }
    #[cfg(not(unix))]
    {
        perms.set_readonly(false);
    }
    fs::set_permissions(path, perms)
        .with_context(|| format!("set permissions on {}", path.display()))?;
    Ok(())
}

/// Decode the canonical v1 artifact into `relative path -> bytes`, rejecting
/// anything the packer could not have produced.
fn read_archive(bytes: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    if bytes.len() as u64 > MAX_COMPRESSED_BYTES {
        return Err(anyhow!("archive is larger than the allowed size"));
    }
    // Bound the DECOMPRESSED stream: the compressed cap alone cannot stop a
    // small archive from expanding without limit.
    let decoder = GzDecoder::new(bytes).take(MAX_EXPANDED_BYTES + 1);
    let mut archive = Archive::new(decoder);
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut expanded: u64 = 0;

    for entry in archive
        .entries()
        .context("read the module client archive")?
    {
        let mut entry = entry.context("read a module client archive entry")?;
        // tar can carry symlinks, hardlinks, devices and directory entries.
        // Only regular files are ever written.
        if entry.header().entry_type() != tar::EntryType::Regular {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            return Err(anyhow!("archive contains a non-regular entry"));
        }
        let path = entry.path().context("read an archive entry path")?;
        let archive_path = portable_archive_path(&path)?;
        if archive_path.len() > MAX_PATH_BYTES {
            return Err(anyhow!("archive entry path is too long"));
        }
        let Some(relative) = archive_path.strip_prefix("package/") else {
            return Err(anyhow!(
                "archive entry {archive_path} is outside the package root"
            ));
        };
        if relative == "package.json" {
            // The packer's manifest carries no name or version; ours is
            // written from the platform's own identity instead.
            continue;
        }
        let Some(dist_relative) = relative.strip_prefix("dist/") else {
            return Err(anyhow!("archive entry {relative} is outside dist/"));
        };
        if dist_relative.is_empty() {
            return Err(anyhow!("archive entry has an empty path"));
        }
        if !ALLOWED_SUFFIXES
            .iter()
            .any(|suffix| dist_relative.ends_with(suffix))
        {
            return Err(anyhow!("archive entry {relative} has a disallowed type"));
        }
        if files.len() + 1 > MAX_ENTRIES {
            return Err(anyhow!("archive has too many entries"));
        }
        let declared = entry.header().size().unwrap_or(0);
        expanded = expanded
            .checked_add(declared)
            .ok_or_else(|| anyhow!("archive expanded size overflow"))?;
        if expanded > MAX_EXPANDED_BYTES {
            return Err(anyhow!("archive expands beyond the allowed size"));
        }
        let mut content = Vec::with_capacity(declared as usize);
        entry
            .read_to_end(&mut content)
            .context("read an archive entry body")?;
        files.insert(relative.to_string(), content);
    }
    if files.is_empty() {
        return Err(anyhow!("archive contains no client files"));
    }
    Ok(files)
}

/// Accept only plain, relative, forward-slashed paths — the exact shape the
/// packer emits. Anything else (absolute, `..`, a Windows separator, a
/// non-UTF-8 name) is refused rather than normalized.
fn portable_archive_path(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let text = part
                    .to_str()
                    .ok_or_else(|| anyhow!("archive entry path is not valid UTF-8"))?;
                if text.is_empty() || text == "." || text == ".." || text.contains('\\') {
                    return Err(anyhow!("archive entry path is not relative"));
                }
                parts.push(text);
            }
            _ => return Err(anyhow!("archive entry path is not relative")),
        }
    }
    if parts.is_empty() {
        return Err(anyhow!("archive entry path is empty"));
    }
    Ok(parts.join("/"))
}

/// Write the owner package that makes `@mirrorstack-ai/<owner>/<module>`
/// resolve.
///
/// Node reads that specifier as package `@mirrorstack-ai/<owner>` plus subpath
/// `./<module>`, so the payload directories alone are not importable — the
/// owner package must exist and map each subpath explicitly. It is regenerated
/// from what is on disk so removing a module's directory removes its export.
fn write_owner_manifest(owner_dir: &Path, owner: &str) -> Result<()> {
    let mut exports = BTreeMap::new();
    let entries =
        fs::read_dir(owner_dir).with_context(|| format!("read {}", owner_dir.display()))?;
    for entry in entries {
        let entry = entry.context("read a directory entry")?;
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if !owner_dir.join(&name).join("dist/index.js").is_file() {
            continue;
        }
        exports.insert(
            format!("./{name}"),
            serde_json::json!({
                "types": format!("./{name}/dist/index.d.ts"),
                "import": format!("./{name}/dist/index.js"),
                "default": format!("./{name}/dist/index.js"),
            }),
        );
    }
    let manifest = serde_json::json!({
        "name": format!("{PLATFORM_SCOPE}/{owner}"),
        // Dev clients are session-bound, not released. A fixed placeholder
        // keeps the package valid without implying a published version.
        "version": "0.0.0-dev",
        "private": true,
        "type": "module",
        "exports": exports,
    });
    let path = owner_dir.join("package.json");
    let mut text = serde_json::to_string_pretty(&manifest).context("render the manifest")?;
    text.push('\n');
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, Header};
    use tempfile::TempDir;

    fn entry(archive: &mut Builder<GzEncoder<Vec<u8>>>, path: &str, bytes: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, path, bytes).unwrap();
    }

    fn archive_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut archive = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, bytes) in files {
            entry(&mut archive, path, bytes);
        }
        archive.into_inner().unwrap().finish().unwrap()
    }

    fn valid_archive() -> Vec<u8> {
        archive_of(&[
            ("package/package.json", b"{\"type\":\"module\"}"),
            ("package/dist/index.js", b"export const a = 1;\n"),
            (
                "package/dist/index.d.ts",
                b"export declare const a: number;\n",
            ),
            ("package/dist/chunks/helper.js", b"export const b = 2;\n"),
        ])
    }

    #[test]
    fn install_lays_dist_under_the_package_directory() {
        let dir = TempDir::new().unwrap();
        let package_dir = dir
            .path()
            .join("node_modules/@mirrorstack-ai/acme/user-core");

        install_archive(&valid_archive(), &package_dir).expect("install");

        assert_eq!(
            fs::read_to_string(package_dir.join("dist/index.js")).unwrap(),
            "export const a = 1;\n"
        );
        assert!(package_dir.join("dist/index.d.ts").is_file());
        assert!(package_dir.join("dist/chunks/helper.js").is_file());
        // The packer's identity-free manifest is never laid down; the owner
        // package carries identity instead.
        assert!(!package_dir.join("package.json").exists());
    }

    #[test]
    fn install_replaces_a_previous_revision_without_leaving_stale_files() {
        let dir = TempDir::new().unwrap();
        let package_dir = dir
            .path()
            .join("node_modules/@mirrorstack-ai/acme/user-core");
        install_archive(&valid_archive(), &package_dir).expect("first install");
        assert!(package_dir.join("dist/chunks/helper.js").is_file());

        let leaner = archive_of(&[
            ("package/dist/index.js", b"export const a = 2;\n"),
            (
                "package/dist/index.d.ts",
                b"export declare const a: number;\n",
            ),
        ]);
        install_archive(&leaner, &package_dir).expect("second install");

        assert_eq!(
            fs::read_to_string(package_dir.join("dist/index.js")).unwrap(),
            "export const a = 2;\n"
        );
        assert!(
            !package_dir.join("dist/chunks/helper.js").exists(),
            "a file dropped by the new revision must not survive"
        );
    }

    #[test]
    fn install_rejects_archives_a_packer_could_not_have_produced() {
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "an entry outside package/",
                archive_of(&[("other/dist/index.js", b"x")]),
                "outside the package root",
            ),
            (
                "an entry outside dist/",
                archive_of(&[("package/scripts/postinstall.js", b"x")]),
                "outside dist/",
            ),
            (
                "a disallowed file type",
                archive_of(&[("package/dist/postinstall.sh", b"x")]),
                "disallowed type",
            ),
            (
                "no client files at all",
                archive_of(&[("package/package.json", b"{}")]),
                "no client files",
            ),
        ];
        for (name, bytes, expected) in cases {
            let dir = TempDir::new().unwrap();
            let error = install_archive(&bytes, &dir.path().join("pkg"))
                .expect_err(name)
                .to_string();
            assert!(error.contains(expected), "{name}: {error}");
            assert!(
                !dir.path().join("pkg").exists(),
                "{name}: nothing may be written for a rejected archive"
            );
        }
    }

    #[test]
    fn archive_paths_that_escape_or_are_not_portable_are_refused() {
        // These cannot be built with tar::Builder — it refuses to write them —
        // but a hostile archive is not built with tar::Builder. The guard is
        // exercised directly, on the shapes a crafted archive carries.
        for hostile in [
            "package/../../evil.js",
            "../evil.js",
            "/etc/passwd",
            "package/dist/..",
            "package\\dist\\index.js",
        ] {
            let error = portable_archive_path(Path::new(hostile))
                .expect_err(hostile)
                .to_string();
            assert!(
                error.contains("not relative") || error.contains("empty"),
                "{hostile}: {error}"
            );
        }

        assert_eq!(
            portable_archive_path(Path::new("package/dist/chunks/helper.js")).unwrap(),
            "package/dist/chunks/helper.js"
        );
    }

    #[test]
    fn install_requires_a_non_empty_entrypoint_and_types() {
        let missing = archive_of(&[("package/dist/index.d.ts", b"declare const a: number;\n")]);
        let dir = TempDir::new().unwrap();
        let error = install_archive(&missing, &dir.path().join("pkg"))
            .expect_err("missing entrypoint")
            .to_string();
        assert!(error.contains("missing dist/index.js"), "{error}");

        let empty = archive_of(&[
            ("package/dist/index.js", b""),
            ("package/dist/index.d.ts", b"declare const a: number;\n"),
        ]);
        let dir = TempDir::new().unwrap();
        let error = install_archive(&empty, &dir.path().join("pkg"))
            .expect_err("empty entrypoint")
            .to_string();
        assert!(error.contains("is empty"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_a_symlink_entry() {
        let mut archive = Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        entry(
            &mut archive,
            "package/dist/index.js",
            b"export const a = 1;\n",
        );
        entry(
            &mut archive,
            "package/dist/index.d.ts",
            b"export declare const a: number;\n",
        );
        let mut header = Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_link_name("/etc/passwd").unwrap();
        header.set_cksum();
        archive
            .append_data(&mut header, "package/dist/link.js", &b""[..])
            .unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();

        let dir = TempDir::new().unwrap();
        let error = install_archive(&bytes, &dir.path().join("pkg"))
            .expect_err("symlink")
            .to_string();
        assert!(error.contains("non-regular entry"), "{error}");
    }

    #[test]
    fn install_rejects_an_archive_that_expands_past_the_cap() {
        // Highly compressible: small on the wire, far too large unpacked.
        let big = vec![b'a'; (MAX_EXPANDED_BYTES + 1) as usize];
        let bytes = archive_of(&[
            ("package/dist/index.js", b"export const a = 1;\n"),
            ("package/dist/index.d.ts", b"declare const a: number;\n"),
            ("package/dist/big.js", &big),
        ]);
        assert!(
            bytes.len() as u64 <= MAX_COMPRESSED_BYTES,
            "the fixture must pass the compressed cap to exercise the expanded one"
        );

        let dir = TempDir::new().unwrap();
        let error = install_archive(&bytes, &dir.path().join("pkg"))
            .expect_err("gzip bomb")
            .to_string();
        assert!(error.contains("expands beyond"), "{error}");
    }

    #[test]
    fn verify_rejects_bytes_that_are_not_what_the_platform_declared() {
        let bytes = b"client bytes";
        let sha = format!("{:x}", Sha256::digest(bytes));

        verify(bytes, &sha, bytes.len() as u64).expect("matching bytes verify");

        let wrong_hash = verify(bytes, &"0".repeat(64), bytes.len() as u64)
            .expect_err("hash mismatch")
            .to_string();
        assert!(wrong_hash.contains("sha256 mismatch"), "{wrong_hash}");

        let wrong_size = verify(bytes, &sha, 999)
            .expect_err("size mismatch")
            .to_string();
        assert!(wrong_size.contains("size mismatch"), "{wrong_size}");
    }

    #[test]
    fn owner_manifest_maps_each_installed_module_as_a_subpath() {
        let dir = TempDir::new().unwrap();
        let owner_dir = dir.path().join("node_modules/@mirrorstack-ai/acme");
        install_archive(&valid_archive(), &owner_dir.join("user-core")).unwrap();
        install_archive(&valid_archive(), &owner_dir.join("credit")).unwrap();
        // A directory with no built entrypoint must not be exported.
        fs::create_dir_all(owner_dir.join("half-installed")).unwrap();

        write_owner_manifest(&owner_dir, "acme").expect("write manifest");

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(owner_dir.join("package.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["name"], "@mirrorstack-ai/acme");
        // Node reads `@mirrorstack-ai/acme/user-core` as this package plus the
        // subpath, so the mapping is what makes the import resolve at all.
        assert_eq!(
            manifest["exports"]["./user-core"]["import"],
            "./user-core/dist/index.js"
        );
        assert_eq!(
            manifest["exports"]["./user-core"]["types"],
            "./user-core/dist/index.d.ts"
        );
        assert_eq!(
            manifest["exports"]["./credit"]["import"],
            "./credit/dist/index.js"
        );
        assert!(
            manifest["exports"].get("./half-installed").is_none(),
            "a directory with no entrypoint must not be exported"
        );
    }

    #[test]
    fn owner_manifest_drops_a_module_removed_from_disk() {
        let dir = TempDir::new().unwrap();
        let owner_dir = dir.path().join("node_modules/@mirrorstack-ai/acme");
        install_archive(&valid_archive(), &owner_dir.join("user-core")).unwrap();
        install_archive(&valid_archive(), &owner_dir.join("credit")).unwrap();
        write_owner_manifest(&owner_dir, "acme").unwrap();

        fs::remove_dir_all(owner_dir.join("credit")).unwrap();
        write_owner_manifest(&owner_dir, "acme").unwrap();

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(owner_dir.join("package.json")).unwrap())
                .unwrap();
        assert!(manifest["exports"].get("./user-core").is_some());
        assert!(
            manifest["exports"].get("./credit").is_none(),
            "the manifest is regenerated from disk, not appended to"
        );
    }
}
