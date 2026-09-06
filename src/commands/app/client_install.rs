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
    /// Install exactly what `mirrorstack.modules.json` records, and fail if the
    /// platform's installable set or any revision differs. For CI.
    #[arg(long, conflicts_with = "dev")]
    frozen: bool,
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

    let expected = if args.frozen {
        Some(read_manifest(&root)?)
    } else {
        None
    };
    let outcome = install_pass(
        &client,
        &download_client,
        &apps_base,
        &mut creds,
        &app.id,
        &app.slug,
        &root,
        &mut installed,
        true,
        expected.as_ref(),
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
            &app.slug,
            &root,
            &mut installed,
            false,
            None,
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
    app_slug: &str,
    root: &Path,
    installed: &mut BTreeMap<String, String>,
    report_skips: bool,
    frozen: Option<&Manifest>,
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

    if let Some(expected) = frozen {
        let drift = manifest_drift(expected, app_slug, &clients);
        if !drift.is_empty() {
            return Err(anyhow!(
                "mirrorstack.modules.json does not match the platform (--frozen):\n  {}\nRe-run without --frozen to update it, and commit the result.",
                drift.join("\n  ")
            ));
        }
    }

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

    // What is on disk now, as the app's committed record of its module
    // clients — and as the generated package that composes them, so the app
    // never re-declares by hand what this command already knows it installed.
    let manifest = Manifest::from_installed(app_slug, &clients, installed);
    if frozen.is_none() {
        write_manifest(root, &manifest)?;
    }
    write_generated_client(root, &manifest)?;

    Ok(PassOutcome { installed: count })
}

/// The project's record of installed module clients: `mirrorstack.modules.json`.
/// Committed like a lockfile; `--frozen` installs exactly this and fails on
/// drift, which is what lets CI reproduce a developer's tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Manifest {
    pub app: String,
    pub clients: Vec<ManifestClient>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ManifestClient {
    pub owner: String,
    pub module: String,
    pub revision: String,
}

const MANIFEST_FILE: &str = "mirrorstack.modules.json";
/// The generated package that composes every installed client. A reserved
/// name under the platform scope: no owner can be called `modules`.
const GENERATED_PACKAGE: &str = "modules";

impl Manifest {
    fn from_installed(
        app_slug: &str,
        clients: &[AppModuleClient],
        installed: &BTreeMap<String, String>,
    ) -> Self {
        let mut entries: Vec<ManifestClient> = clients
            .iter()
            .filter(|m| !m.owner_username.is_empty())
            .filter_map(|m| {
                let revision = installed.get(&m.module_id)?;
                Some(ManifestClient {
                    owner: m.owner_username.clone(),
                    module: m.slug.clone(),
                    revision: revision.clone(),
                })
            })
            .collect();
        entries.sort_by(|a, b| (&a.owner, &a.module).cmp(&(&b.owner, &b.module)));
        Manifest {
            app: app_slug.to_string(),
            clients: entries,
        }
    }
}

fn read_manifest(root: &Path) -> Result<Manifest> {
    let path = root.join(MANIFEST_FILE);
    let text = fs::read_to_string(&path).with_context(|| {
        format!(
            "--frozen needs {} — run once without it to create the file",
            path.display()
        )
    })?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn write_manifest(root: &Path, manifest: &Manifest) -> Result<()> {
    let path = root.join(MANIFEST_FILE);
    let mut text = serde_json::to_string_pretty(manifest).context("render the manifest")?;
    text.push('\n');
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

/// Every way the platform's installable set differs from the manifest, one
/// line each, empty when they agree. Pure, so it is testable without a network.
fn manifest_drift(expected: &Manifest, app_slug: &str, clients: &[AppModuleClient]) -> Vec<String> {
    let mut drift = Vec::new();
    if expected.app != app_slug {
        drift.push(format!(
            "manifest is for app '{}', this is '{app_slug}'",
            expected.app
        ));
    }
    let mut installable: BTreeMap<(String, String), String> = BTreeMap::new();
    for m in clients {
        if let (Some(d), false) = (&m.client, m.owner_username.is_empty()) {
            installable.insert(
                (m.owner_username.clone(), m.slug.clone()),
                d.revision.clone(),
            );
        }
    }
    for e in &expected.clients {
        match installable.remove(&(e.owner.clone(), e.module.clone())) {
            None => drift.push(format!(
                "{}/{} is in the manifest but not installable now",
                e.owner, e.module
            )),
            Some(rev) if rev != e.revision => drift.push(format!(
                "{}/{} is at {} on the platform, manifest has {}",
                e.owner,
                e.module,
                short_revision(&rev),
                short_revision(&e.revision)
            )),
            Some(_) => {}
        }
    }
    for ((owner, module), _) in installable {
        drift.push(format!(
            "{owner}/{module} is installable but not in the manifest"
        ));
    }
    drift
}

/// `user-core` → `userCore`: the key the generated client registers a module
/// under, and the factory name a module's client package exports by
/// convention (User Core's exports `userCore`).
fn camel_case(slug: &str) -> String {
    let mut out = String::with_capacity(slug.len());
    let mut upper = false;
    for ch in slug.chars() {
        if ch == '-' || ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The generated `@mirrorstack-ai/modules` package: static imports of every
/// installed client (bundlers can follow them; nothing scans node_modules at
/// runtime) and one `createClient` that registers them all.
fn generated_client_sources(manifest: &Manifest) -> (String, String) {
    let mut js = String::from(
        "// Generated by `mirrorstack apps client install` from mirrorstack.modules.json. Do not edit.\n\
         import { createAppClient, platformBaseUrl } from \"@mirrorstack-ai/app-module-client\";\n",
    );
    let mut dts = String::from(
        "// Generated by `mirrorstack apps client install` from mirrorstack.modules.json. Do not edit.\n\
         import type { AppClient, CreateAppClientOptions } from \"@mirrorstack-ai/app-module-client\";\n",
    );
    let mut plugins = String::new();
    let mut plugin_types = String::new();
    for c in &manifest.clients {
        let key = camel_case(&c.module);
        let spec = format!("{PLATFORM_SCOPE}/{}/{}", c.owner, c.module);
        js.push_str(&format!("import {{ {key} }} from \"{spec}\";\n"));
        dts.push_str(&format!("import {{ {key} }} from \"{spec}\";\n"));
        plugins.push_str(&format!("  {key}: {key}(),\n"));
        plugin_types.push_str(&format!("  readonly {key}: ReturnType<typeof {key}>;\n"));
    }
    js.push_str(&format!(
        "\nexport const plugins = {{\n{plugins}}};\n\n\
         export function createClient(options) {{\n\
         \x20 const {{ apiUrl, appSlug, credential, headers, ...rest }} = options;\n\
         \x20 return createAppClient({{\n\
         \x20   baseUrl: platformBaseUrl({{ apiUrl, appSlug }}),\n\
         \x20   headers: credential ? {{ ...(headers ?? {{}}), Authorization: `Bearer ${{credential}}` }} : headers,\n\
         \x20   modules: plugins,\n\
         \x20   ...rest,\n\
         \x20 }});\n\
         }}\n"
    ));
    dts.push_str(&format!(
        "\nexport declare const plugins: {{\n{plugin_types}}};\n\n\
         export interface CreateClientOptions extends Omit<CreateAppClientOptions<typeof plugins>, \"baseUrl\" | \"modules\" | \"headers\"> {{\n\
         \x20 /** Absolute HTTP(S) platform API URL, typically MIRRORSTACK_API_URL. */\n\
         \x20 readonly apiUrl: string;\n\
         \x20 /** The app slug shown in the console URL. */\n\
         \x20 readonly appSlug: string;\n\
         \x20 /** A member session credential to present as a bearer. Server-side only. */\n\
         \x20 readonly credential?: string;\n\
         \x20 readonly headers?: Record<string, string>;\n\
         }}\n\n\
         export declare function createClient(options: CreateClientOptions): AppClient<typeof plugins>;\n"
    ));
    (js, dts)
}

fn write_generated_client(root: &Path, manifest: &Manifest) -> Result<()> {
    let dir = root
        .join("node_modules")
        .join(PLATFORM_SCOPE)
        .join(GENERATED_PACKAGE);
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let (js, dts) = generated_client_sources(manifest);
    let package = serde_json::json!({
        "name": format!("{PLATFORM_SCOPE}/{GENERATED_PACKAGE}"),
        "version": "0.0.0-dev",
        "private": true,
        "type": "module",
        "exports": { ".": { "types": "./index.d.ts", "import": "./index.js", "default": "./index.js" } },
    });
    let mut package_text =
        serde_json::to_string_pretty(&package).context("render the generated package manifest")?;
    package_text.push('\n');
    fs::write(dir.join("package.json"), package_text)
        .with_context(|| format!("write {}", dir.join("package.json").display()))?;
    fs::write(dir.join("index.js"), js)
        .with_context(|| format!("write {}", dir.join("index.js").display()))?;
    fs::write(dir.join("index.d.ts"), dts)
        .with_context(|| format!("write {}", dir.join("index.d.ts").display()))?;
    Ok(())
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

    fn module(owner: &str, slug: &str, id: &str, revision: Option<&str>) -> AppModuleClient {
        AppModuleClient {
            module_id: id.to_string(),
            slug: slug.to_string(),
            owner_username: owner.to_string(),
            installed_version: String::new(),
            client: revision.map(|r| crate::api::ModuleClientDescriptor {
                source: "dev-tunnel".to_string(),
                revision: r.to_string(),
                sha256: "0".repeat(64),
                size_bytes: 1,
                format_version: 1,
                confirmed_at: String::new(),
                session_id: String::new(),
            }),
            reason: None,
        }
    }

    #[test]
    fn camel_case_follows_the_client_export_convention() {
        assert_eq!(camel_case("user-core"), "userCore");
        assert_eq!(camel_case("users-profile"), "usersProfile");
        assert_eq!(camel_case("credit"), "credit");
        assert_eq!(camel_case("video-core-v2"), "videoCoreV2");
    }

    #[test]
    fn manifest_records_only_what_was_installed_sorted_by_owner_and_module() {
        let clients = vec![
            module("mirrorstack", "users-roles", "m2", Some("sha256:bb")),
            module("mirrorstack", "user-core", "m1", Some("sha256:aa")),
            module("mirrorstack", "credit", "m3", None),
            module("", "orphan", "m4", Some("sha256:cc")),
        ];
        let mut installed = BTreeMap::new();
        installed.insert("m1".to_string(), "sha256:aa".to_string());
        installed.insert("m2".to_string(), "sha256:bb".to_string());
        installed.insert("m4".to_string(), "sha256:cc".to_string());
        let manifest = Manifest::from_installed("twkpa-edu", &clients, &installed);
        assert_eq!(manifest.app, "twkpa-edu");
        let names: Vec<String> = manifest.clients.iter().map(|c| c.module.clone()).collect();
        assert_eq!(names, vec!["user-core", "users-roles"]);
    }

    #[test]
    fn frozen_drift_names_every_difference_and_is_empty_on_agreement() {
        let expected = Manifest {
            app: "twkpa-edu".into(),
            clients: vec![
                ManifestClient {
                    owner: "mirrorstack".into(),
                    module: "user-core".into(),
                    revision: "sha256:aa".into(),
                },
                ManifestClient {
                    owner: "mirrorstack".into(),
                    module: "gone".into(),
                    revision: "sha256:cc".into(),
                },
            ],
        };
        let clients = vec![
            module("mirrorstack", "user-core", "m1", Some("sha256:ab")),
            module("mirrorstack", "extra", "m9", Some("sha256:ee")),
            module("mirrorstack", "silent", "m5", None),
        ];
        let drift = manifest_drift(&expected, "other-app", &clients);
        assert_eq!(drift.len(), 4, "{drift:?}");
        assert!(drift[0].contains("manifest is for app 'twkpa-edu'"));
        assert!(drift.iter().any(|d| d.contains("user-core is at")));
        assert!(
            drift
                .iter()
                .any(|d| d.contains("gone is in the manifest but not installable"))
        );
        assert!(
            drift
                .iter()
                .any(|d| d.contains("extra is installable but not in the manifest"))
        );

        let agreeing = Manifest {
            app: "twkpa-edu".into(),
            clients: vec![ManifestClient {
                owner: "mirrorstack".into(),
                module: "user-core".into(),
                revision: "sha256:ab".into(),
            }],
        };
        let clients = vec![
            module("mirrorstack", "user-core", "m1", Some("sha256:ab")),
            module("mirrorstack", "silent", "m5", None),
        ];
        assert!(manifest_drift(&agreeing, "twkpa-edu", &clients).is_empty());
    }

    #[test]
    fn generated_client_imports_each_client_statically_and_registers_it_under_its_camel_key() {
        let manifest = Manifest {
            app: "twkpa-edu".into(),
            clients: vec![
                ManifestClient {
                    owner: "mirrorstack".into(),
                    module: "user-core".into(),
                    revision: "sha256:aa".into(),
                },
                ManifestClient {
                    owner: "acme".into(),
                    module: "asset-library".into(),
                    revision: "sha256:bb".into(),
                },
            ],
        };
        let (js, dts) = generated_client_sources(&manifest);
        assert!(js.contains("import { userCore } from \"@mirrorstack-ai/mirrorstack/user-core\";"));
        assert!(
            js.contains("import { assetLibrary } from \"@mirrorstack-ai/acme/asset-library\";")
        );
        assert!(js.contains("userCore: userCore(),"));
        assert!(js.contains("assetLibrary: assetLibrary(),"));
        assert!(js.contains("platformBaseUrl({ apiUrl, appSlug })"));
        assert!(js.contains("Authorization: `Bearer ${credential}`"));
        assert!(dts.contains("readonly userCore: ReturnType<typeof userCore>;"));
        assert!(dts.contains("export declare function createClient(options: CreateClientOptions): AppClient<typeof plugins>;"));
        // Nothing dynamic: no require, no import(), no directory scan.
        assert!(!js.contains("import(") && !js.contains("require(") && !js.contains("readdir"));
    }

    #[test]
    fn generated_package_and_manifest_land_on_disk() {
        let root = TempDir::new().unwrap();
        let manifest = Manifest {
            app: "twkpa-edu".into(),
            clients: vec![ManifestClient {
                owner: "mirrorstack".into(),
                module: "user-core".into(),
                revision: "sha256:aa".into(),
            }],
        };
        write_manifest(root.path(), &manifest).unwrap();
        write_generated_client(root.path(), &manifest).unwrap();
        assert_eq!(read_manifest(root.path()).unwrap(), manifest);
        let dir = root.path().join("node_modules/@mirrorstack-ai/modules");
        let package: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join("package.json")).unwrap()).unwrap();
        assert_eq!(package["name"], "@mirrorstack-ai/modules");
        assert_eq!(package["exports"]["."]["types"], "./index.d.ts");
        assert!(dir.join("index.js").is_file() && dir.join("index.d.ts").is_file());
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
