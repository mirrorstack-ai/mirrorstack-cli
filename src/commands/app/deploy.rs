//! `mirrorstack app web deploy` — ship a build directory to the platform's
//! app hosting, served on `https://<slug>.mirrorstack.app`.
//!
//! Two runtimes.
//!
//! `static` (default): walk the build dir into a manifest (path + size +
//! sha256), POST it for presigned S3 PUTs, upload every file (bounded
//! fan-out), finalize (the platform spot-checks the objects), then
//! activate the deploy on the stage unless `--no-activate`.
//!
//! `ssr`: package `--dir`'s `.next/standalone` + `.next/static` into a
//! single Lambda-ready zip (see [`super::ssr`]), check it against the same
//! 250 MB ceiling the platform enforces server-side, upload it as the
//! deploy's one file, then finalize/activate exactly as above.
//! Auto-detected from a `.next/standalone` subdirectory under `--dir`, or
//! forced either way via `--runtime`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, ValueEnum};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};

use crate::api::{self, CreateAppDeployInput, DeployFile};
use crate::commands::{DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base};
use crate::credentials::load_or_login_hint;
use crate::http;

use super::deploy_auth::{self, DeployAuth, SelectedDeployAuth};
use super::ssr;
use super::with_spinner;

/// Platform caps on one deploy, mirrored client-side so the failure is a
/// local error before any bytes move (the server re-validates). Applies to
/// the static-file manifest; an SSR bundle is a single zip and isn't
/// subject to the file-count cap.
const MAX_TOTAL_BYTES: u64 = 26_214_400; // 25 MB
const MAX_FILES: usize = 500;

/// Cap on the packaged SSR bundle zip, mirrored client-side for the same
/// reason as `MAX_TOTAL_BYTES` above but for a different artifact shape:
/// this is AWS Lambda's real ceiling for an S3-sourced deployment package,
/// and the ceiling api-platform enforces server-side for `runtime: "ssr"`
/// deploys. Distinct from `MAX_TOTAL_BYTES` (the static-file-manifest
/// cap) — do not conflate the two.
const MAX_SSR_BUNDLE_BYTES: u64 = 250 * 1024 * 1024; // 250 MB

/// Bounded fan-out for the presigned PUTs. S3 happily takes more, but 8
/// keeps memory (one file body per in-flight PUT) and socket use small.
const UPLOAD_CONCURRENCY: usize = 8;

/// Generous per-PUT timeout: the largest legal deploy is 25 MB, which on
/// a slow uplink can far exceed the 15s used for the JSON API calls.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// `--runtime` override for the auto-detected build kind.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum RuntimeArg {
    Static,
    Ssr,
}

#[derive(Args)]
pub struct DeployArgs {
    /// App ID or slug the deploy belongs to.
    #[arg(long)]
    app: String,
    /// Target stage environment.
    #[arg(long, default_value = "prod")]
    env: String,
    /// Build directory to ship. Defaults to cwd. Dotfiles and
    /// node_modules never upload.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Free-form note shown in the deploy list (e.g. a commit subject).
    #[arg(long)]
    note: Option<String>,
    /// Upload + finalize only; leave the stage on its current deploy.
    #[arg(long)]
    no_activate: bool,
    /// Runtime to ship: `static` (a plain build/export directory) or `ssr`
    /// (a Next.js standalone build). Auto-detected from `--dir` (SSR means
    /// a `.next/standalone` subdirectory is present) when omitted; pass
    /// this to override the detection.
    #[arg(long, value_enum)]
    runtime: Option<RuntimeArg>,
    /// Authenticate with the GitHub Actions OIDC identity for this job.
    #[arg(long)]
    oidc: bool,
}

pub fn run(args: DeployArgs) -> Result<()> {
    let dir = match args.dir.clone() {
        Some(dir) => dir,
        // Not unreachable in CI: a job whose workspace is removed mid-run
        // leaves the process with no cwd. Panicking there exits 101 with a
        // backtrace instead of saying what to pass.
        None => std::env::current_dir()
            .context("could not read the current directory — pass --dir explicitly")?,
    };
    if !dir.is_dir() {
        return Err(anyhow!("{} is not a directory", dir.display()));
    }

    let is_ssr = match args.runtime {
        Some(RuntimeArg::Ssr) => true,
        Some(RuntimeArg::Static) => false,
        None => ssr::looks_like_standalone(&dir),
    };

    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let oidc_audience = deploy_auth::resolve_oidc_audience(|name| std::env::var(name).ok())?;
    let client = http::client(Duration::from_secs(15))?;

    let selected = deploy_auth::select_deploy_auth(
        args.oidc,
        |name| std::env::var(name).ok(),
        load_or_login_hint,
    )?;
    let (target, mut auth) = match selected {
        SelectedDeployAuth::Oidc {
            request_url,
            request_token,
        } => {
            let exchanged = deploy_auth::exchange_oidc(
                &client,
                &apps_base,
                &request_url,
                &request_token,
                &oidc_audience,
                &args.app,
                &args.env,
            )?;
            oidc_target(exchanged, &args.env)?
        }
        SelectedDeployAuth::Ready(DeployAuth::Token(token)) => (
            DeployTarget {
                id: args.app.clone(),
                slug: None,
            },
            DeployAuth::Token(token),
        ),
        SelectedDeployAuth::Ready(mut user @ DeployAuth::User(_)) => {
            // Only a user principal may resolve a slug/UUID through the
            // management endpoint. Deploy principals are endpoint-limited.
            let app = match user.with_retry(|tok| api::get_app(&client, &apps_base, tok, &args.app))
            {
                Ok(Some(app)) => app,
                Ok(None) => {
                    return Err(anyhow!(
                        "app '{}' not found (pass an app ID or slug you're a member of)",
                        args.app
                    ));
                }
                Err(error) => return Err(user.deploy_error(error)),
            };
            (
                DeployTarget {
                    id: app.id,
                    slug: Some(app.slug),
                },
                user,
            )
        }
        SelectedDeployAuth::Ready(DeployAuth::Grant(_)) => {
            unreachable!("grants are created only by the OIDC exchange")
        }
    };

    if is_ssr {
        deploy_ssr(&args, &dir, &target, &mut auth, &apps_base, &client)
    } else {
        deploy_static(&args, &dir, &target, &mut auth, &apps_base, &client)
    }
}

#[derive(Debug)]
struct DeployTarget {
    id: String,
    slug: Option<String>,
}

impl DeployTarget {
    fn label<'a>(&'a self, app_ref: &'a str) -> &'a str {
        self.slug.as_deref().unwrap_or(app_ref)
    }
}

fn oidc_target(grant: api::DeployGrant, requested_env: &str) -> Result<(DeployTarget, DeployAuth)> {
    if grant.env != requested_env {
        return Err(anyhow!(
            "OIDC deploy grant was bound to environment '{}' but --env requested '{}'; refusing to deploy",
            grant.env,
            requested_env
        ));
    }
    Ok((
        DeployTarget {
            id: grant.app_id,
            slug: None,
        },
        DeployAuth::Grant(grant.grant),
    ))
}

/// Today's flow, byte-for-byte unchanged: walk `dir` into a static-file
/// manifest, create the deploy, upload every file, finalize, activate.
fn deploy_static(
    args: &DeployArgs,
    dir: &Path,
    app: &DeployTarget,
    creds: &mut DeployAuth,
    apps_base: &str,
    client: &Client,
) -> Result<()> {
    let files = with_spinner("Scanning files…", || build_manifest(dir))?;
    let bytes_total: u64 = files.iter().map(|f| f.size).sum();

    eprintln!(
        "  {} {} → {} ({} files, {})",
        style("Deploying:").dim(),
        style(dir.display()).bold(),
        style(format!("{}@{}", app.label(&args.app), args.env))
            .cyan()
            .bold(),
        files.len(),
        human_bytes(bytes_total)
    );

    let file_inputs: Vec<DeployFile> = files
        .iter()
        .map(|f| DeployFile {
            path: &f.rel_path,
            size: f.size,
            sha256: &f.sha256,
        })
        .collect();
    let created = with_spinner("Creating deploy…", || {
        creds.with_retry(|tok| {
            api::create_app_deploy(
                client,
                apps_base,
                tok,
                &app.id,
                &CreateAppDeployInput {
                    env: &args.env,
                    note: args.note.as_deref(),
                    runtime: None,
                    files: &file_inputs,
                },
            )
        })
    })
    .map_err(|error| creds.deploy_error(error))?;

    // Presigned URLs carry their own auth — a dedicated client without the
    // bearer token and with an upload-sized timeout.
    let upload_client = http::client(UPLOAD_TIMEOUT)?;
    upload_all(&upload_client, &created.uploads, &files)?;

    finish_deploy(args, app, creds, apps_base, client, &created.deploy_id)
}

/// SSR flow: package `dir`'s standalone build into one zip, ship it as the
/// deploy's single file, then finalize/activate exactly like the static
/// path (via the shared [`finish_deploy`] tail).
///
/// Thin wrapper over [`deploy_ssr_with_cap`] passing the real production
/// ceiling — the split exists so tests can exercise the exact same
/// packaging/upload/finalize logic against a tiny cap instead of needing a
/// genuine 250 MB fixture on disk to prove the guard rejects.
fn deploy_ssr(
    args: &DeployArgs,
    dir: &Path,
    app: &DeployTarget,
    creds: &mut DeployAuth,
    apps_base: &str,
    client: &Client,
) -> Result<()> {
    deploy_ssr_with_cap(
        args,
        dir,
        app,
        creds,
        apps_base,
        client,
        MAX_SSR_BUNDLE_BYTES,
    )
}

fn deploy_ssr_with_cap(
    args: &DeployArgs,
    dir: &Path,
    app: &DeployTarget,
    creds: &mut DeployAuth,
    apps_base: &str,
    client: &Client,
    max_bundle_bytes: u64,
) -> Result<()> {
    let (_bundle_dir, zip_path) =
        with_spinner("Packaging SSR bundle…", || ssr::package_bundle(dir))?;
    let (size, sha256) = hash_file(&zip_path)?;

    eprintln!(
        "  {} {} → {} (ssr bundle, {})",
        style("Deploying:").dim(),
        style(dir.display()).bold(),
        style(format!("{}@{}", app.label(&args.app), args.env))
            .cyan()
            .bold(),
        human_bytes(size)
    );

    // Check the packaged zip against the same ceiling api-platform enforces
    // server-side *before* touching the network — a build that's too large
    // fails locally and instantly instead of after a full upload attempt.
    if size > max_bundle_bytes {
        return Err(anyhow!(
            "SSR bundle too large: {} (capped at {}, the same ceiling the platform enforces for Lambda-packaged deploys) — trim the standalone build or exclude unused dependencies",
            human_bytes(size),
            human_bytes(max_bundle_bytes)
        ));
    }

    let file_inputs = [DeployFile {
        path: "ssr-bundle.zip",
        size,
        sha256: &sha256,
    }];
    // `runtime: "ssr"` tells the platform this deploy's one file is a
    // Lambda bundle, not a static-file manifest entry — see the PR
    // description for the request-shape assumption this rests on.
    let created = with_spinner("Creating deploy…", || {
        creds.with_retry(|tok| {
            api::create_app_deploy(
                client,
                apps_base,
                tok,
                &app.id,
                &CreateAppDeployInput {
                    env: &args.env,
                    note: args.note.as_deref(),
                    runtime: Some("ssr"),
                    files: &file_inputs,
                },
            )
        })
    })
    .map_err(|error| creds.deploy_error(error))?;

    let bundle_file = ManifestFile {
        rel_path: "ssr-bundle.zip".to_string(),
        abs_path: zip_path,
        size,
        sha256,
    };
    let upload_client = http::client(UPLOAD_TIMEOUT)?;
    upload_all(
        &upload_client,
        &created.uploads,
        std::slice::from_ref(&bundle_file),
    )?;
    // `_bundle_dir` (the temp dir backing `bundle_file.abs_path`) stays
    // alive through the upload above by still being in scope here.

    finish_deploy(args, app, creds, apps_base, client, &created.deploy_id)
}

/// Shared tail for both runtimes: finalize the already-uploaded deploy,
/// then activate it (unless `--no-activate`), printing the same status
/// lines either way.
fn finish_deploy(
    args: &DeployArgs,
    app: &DeployTarget,
    creds: &mut DeployAuth,
    apps_base: &str,
    client: &Client,
    deploy_id: &str,
) -> Result<()> {
    with_spinner("Finalizing…", || {
        creds.with_retry(|tok| api::finalize_app_deploy(client, apps_base, tok, &app.id, deploy_id))
    })
    .map_err(|error| creds.deploy_error(error))?;

    if args.no_activate {
        eprintln!(
            "{} deployed {} (not activated)",
            ok_mark(),
            style(format!("{}@{}", app.label(&args.app), args.env))
                .cyan()
                .bold()
        );
        eprintln!("  {} {}", style("deploy:").dim(), deploy_id);
        eprintln!(
            "  {} activate it from the app's deployment settings, or re-run without --no-activate",
            style("next:").dim()
        );
        return Ok(());
    }

    with_spinner("Activating…", || {
        creds.with_retry(|tok| {
            api::activate_app_stage(client, apps_base, tok, &app.id, &args.env, deploy_id)
        })
    })
    .map_err(|error| creds.deploy_error(error))?;

    eprintln!(
        "{} deployed {}",
        ok_mark(),
        style(format!("{}@{}", app.label(&args.app), args.env))
            .cyan()
            .bold()
    );
    eprintln!("  {} {}", style("deploy:").dim(), deploy_id);
    if let Some(slug) = &app.slug {
        eprintln!(
            "  {} {}",
            style("url:").dim(),
            style(format!("https://{slug}.mirrorstack.app"))
                .cyan()
                .bold()
        );
    }
    Ok(())
}

/// One file under the deploy root: its manifest entry plus where to read
/// the bytes back at upload time. Also doubles as the single-entry
/// manifest for an SSR bundle upload.
#[derive(Debug)]
struct ManifestFile {
    /// Forward-slash path relative to the deploy root — the S3 key tail.
    rel_path: String,
    abs_path: PathBuf,
    size: u64,
    /// Lowercase hex SHA-256 of the contents.
    sha256: String,
}

/// Walk `root` into a sorted, validated deploy manifest. Dotfiles and
/// dot-directories (`.git`, `.env`, `.DS_Store`), `node_modules`, and
/// symlinks (which could point outside the deploy dir) are skipped — a
/// deploy is a built static site, not the working tree.
fn build_manifest(root: &Path) -> Result<Vec<ManifestFile>> {
    let mut files = Vec::new();
    walk(root, "", &mut files)?;
    if files.is_empty() {
        return Err(anyhow!(
            "no deployable files under {} (dotfiles and node_modules are skipped)",
            root.display()
        ));
    }
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    validate_manifest(&files)?;
    Ok(files)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<ManifestFile>) -> Result<()> {
    let entries =
        std::fs::read_dir(dir).with_context(|| format!("read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read directory {}", dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(anyhow!(
                "non-UTF-8 file name under {} — rename it to deploy",
                dir.display()
            ));
        };
        if skip_name(name) {
            continue;
        }
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        // symlink_metadata (not metadata) so links are detected, not followed.
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk(&entry.path(), &rel, out)?;
        } else if file_type.is_file() {
            if !path_valid(&rel) {
                return Err(anyhow!(
                    "file path {rel:?} contains a backslash or control character — rename it to deploy"
                ));
            }
            let (size, sha256) = hash_file(&entry.path())?;
            out.push(ManifestFile {
                rel_path: rel,
                abs_path: entry.path(),
                size,
                sha256,
            });
        }
    }
    Ok(())
}

/// Names that never ship: dotfiles/dot-dirs and node_modules (any depth).
fn skip_name(name: &str) -> bool {
    name.starts_with('.') || name == "node_modules"
}

/// The platform's path rules, minus the ones the walk makes impossible by
/// construction (relative, no `..` segments, no leading `/`).
fn path_valid(rel: &str) -> bool {
    !rel.contains('\\') && rel.chars().all(|c| !c.is_control())
}

/// Client-side mirror of the platform's deploy caps.
fn validate_manifest(files: &[ManifestFile]) -> Result<()> {
    if files.len() > MAX_FILES {
        return Err(anyhow!(
            "too many files: {} (a deploy is capped at {MAX_FILES})",
            files.len()
        ));
    }
    let total: u64 = files.iter().map(|f| f.size).sum();
    if total > MAX_TOTAL_BYTES {
        return Err(anyhow!(
            "deploy too large: {} (capped at {})",
            human_bytes(total),
            human_bytes(MAX_TOTAL_BYTES)
        ));
    }
    Ok(())
}

/// Stream a file through SHA-256 without holding it in memory; returns
/// (size, lowercase hex digest).
fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let size =
        io::copy(&mut file, &mut hasher).with_context(|| format!("read {}", path.display()))?;
    Ok((size, format!("{:x}", hasher.finalize())))
}

/// PUT every presigned upload with a bounded worker pool. The first
/// failure wins: remaining workers drain out without starting new PUTs,
/// and its error (tagged with the file path) is returned.
fn upload_all(
    client: &Client,
    uploads: &[api::UploadTarget],
    files: &[ManifestFile],
) -> Result<()> {
    let by_path: HashMap<&str, &ManifestFile> =
        files.iter().map(|f| (f.rel_path.as_str(), f)).collect();
    // Every server-issued upload must map back to a manifest file we sent —
    // anything else means the create response is broken; fail before PUTs.
    for u in uploads {
        if !by_path.contains_key(u.path.as_str()) {
            return Err(anyhow!(
                "server requested an upload for unknown path {:?}",
                u.path
            ));
        }
    }

    let pb = upload_progress(uploads.len() as u64);
    let next = AtomicUsize::new(0);
    let first_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..UPLOAD_CONCURRENCY.min(uploads.len()) {
            s.spawn(|| {
                loop {
                    if first_err.lock().expect("uploads mutex").is_some() {
                        return;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(target) = uploads.get(i) else { return };
                    let file = by_path[target.path.as_str()];
                    match upload_one(client, target, &file.abs_path) {
                        Ok(()) => pb.inc(1),
                        Err(e) => {
                            let mut slot = first_err.lock().expect("uploads mutex");
                            if slot.is_none() {
                                *slot = Some(e.context(format!("upload {}", target.path)));
                            }
                            return;
                        }
                    }
                }
            });
        }
    });
    pb.finish_and_clear();

    match first_err.into_inner().expect("uploads mutex") {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// One presigned S3 PUT: the body is the file verbatim and the headers
/// are exactly what the URL was signed with — nothing added (no bearer
/// token; the signature IS the auth).
fn upload_one(client: &Client, target: &api::UploadTarget, path: &Path) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut req = client.put(&target.url).body(bytes);
    for (k, v) in &target.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    // `reqwest::Error` renders the URL it failed on, and this one carries a
    // live signature. In a CI log that is a usable write credential until it
    // expires, so strip the URL before the error can reach stderr.
    let resp = req
        .send()
        .map_err(|e| anyhow!("presigned PUT failed: {}", e.without_url()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = http::read_capped(resp).unwrap_or_default();
        return Err(anyhow!(
            "presigned PUT failed: HTTP {} {}",
            status.as_u16(),
            String::from_utf8_lossy(&body).trim()
        ));
    }
    Ok(())
}

/// Counter-style progress for the upload pool. Hidden when stderr isn't
/// a TTY (same rationale as `with_spinner`: keep CI logs clean).
fn upload_progress(len: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} uploading {pos}/{len}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// `1023 B` / `4.2 KB` / `25.0 MB` — one decimal above bytes. Shared by
/// both size lines: the static-manifest cap (25 MB) and the SSR bundle
/// cap (250 MB).
fn human_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let n = n as f64;
    if n < KB {
        format!("{n:.0} B")
    } else if n < KB * KB {
        format!("{:.1} KB", n / KB)
    } else {
        format!("{:.1} MB", n / (KB * KB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    /// SHA-256 of the 5-byte string "hello".
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    #[test]
    fn build_manifest_walks_hashes_and_sorts() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "index.html", "hello");
        write(dir.path(), "assets/app.js", "console.log(1)");
        write(dir.path(), "assets/img/logo.svg", "<svg/>");

        let files = build_manifest(dir.path()).expect("ok");
        let paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["assets/app.js", "assets/img/logo.svg", "index.html"]
        );

        let index = files.iter().find(|f| f.rel_path == "index.html").unwrap();
        assert_eq!(index.size, 5);
        assert_eq!(index.sha256, HELLO_SHA256);
        assert!(index.abs_path.is_file());
    }

    #[test]
    fn build_manifest_skips_dotfiles_and_node_modules() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "index.html", "hello");
        write(dir.path(), ".env", "SECRET=1");
        write(dir.path(), ".git/config", "[core]");
        write(dir.path(), "node_modules/pkg/index.js", "x");
        write(dir.path(), "nested/node_modules/pkg/y.js", "y");
        write(dir.path(), "nested/.DS_Store", "junk");
        write(dir.path(), "nested/page.html", "hi");

        let files = build_manifest(dir.path()).expect("ok");
        let paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(paths, vec!["index.html", "nested/page.html"]);
    }

    #[cfg(unix)]
    #[test]
    fn build_manifest_skips_symlinks() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "index.html", "hello");
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join("hosts")).unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("etc-dir")).unwrap();

        let files = build_manifest(dir.path()).expect("ok");
        let paths: Vec<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(paths, vec!["index.html"]);
    }

    #[test]
    fn build_manifest_empty_dir_errors() {
        let dir = TempDir::new().unwrap();
        let err = build_manifest(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no deployable files"), "{err}");
    }

    #[test]
    fn build_manifest_only_skipped_files_errors() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".env", "SECRET=1");
        write(dir.path(), "node_modules/x.js", "x");
        let err = build_manifest(dir.path()).unwrap_err();
        assert!(err.to_string().contains("no deployable files"), "{err}");
    }

    fn stub_file(rel_path: &str, size: u64) -> ManifestFile {
        ManifestFile {
            rel_path: rel_path.to_string(),
            abs_path: PathBuf::from(rel_path),
            size,
            sha256: HELLO_SHA256.to_string(),
        }
    }

    #[test]
    fn validate_manifest_rejects_too_many_files() {
        let files: Vec<ManifestFile> = (0..=MAX_FILES)
            .map(|i| stub_file(&format!("f{i}.txt"), 1))
            .collect();
        let err = validate_manifest(&files).unwrap_err();
        assert!(err.to_string().contains("too many files"), "{err}");
    }

    #[test]
    fn validate_manifest_rejects_oversized_total() {
        let files = vec![stub_file("a.bin", MAX_TOTAL_BYTES), stub_file("b.bin", 1)];
        let err = validate_manifest(&files).unwrap_err();
        assert!(err.to_string().contains("deploy too large"), "{err}");
    }

    #[test]
    fn validate_manifest_accepts_exact_caps() {
        let files = vec![stub_file("a.bin", MAX_TOTAL_BYTES)];
        assert!(validate_manifest(&files).is_ok());
        let many: Vec<ManifestFile> = (0..MAX_FILES)
            .map(|i| stub_file(&format!("f{i}.txt"), 1))
            .collect();
        assert!(validate_manifest(&many).is_ok());
    }

    #[test]
    fn skip_name_cases() {
        assert!(skip_name(".env"));
        assert!(skip_name(".git"));
        assert!(skip_name("node_modules"));
        assert!(!skip_name("index.html"));
        assert!(!skip_name("my.node_modules.txt"));
    }

    #[test]
    fn path_valid_rejects_backslash_and_control_chars() {
        assert!(path_valid("assets/app.js"));
        assert!(path_valid("中文/页面.html"));
        assert!(!path_valid("assets\\app.js"));
        assert!(!path_valid("bad\u{7}name.txt"));
        assert!(!path_valid("bad\nname.txt"));
    }

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4302), "4.2 KB");
        assert_eq!(human_bytes(MAX_TOTAL_BYTES), "25.0 MB");
    }

    #[test]
    fn hash_file_matches_ssr_module_shape() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "ssr-bundle.zip", "hello");
        let (size, sha256) = hash_file(&dir.path().join("ssr-bundle.zip")).unwrap();
        assert_eq!(size, 5);
        assert_eq!(sha256, HELLO_SHA256);
    }

    // ---- deploy_ssr() end-to-end -----------------------------------------
    //
    // The tests below drive `deploy_ssr`/`deploy_ssr_with_cap` themselves
    // (not just the `ssr` module's packaging helpers, which have their own
    // coverage in `super::ssr::tests`), through the same mockito convention
    // `api.rs` uses for the JSON API calls. The presigned "S3 PUT" target is
    // a raw `TcpListener` capture stub — mockito's `Matcher` can match a
    // request body but can't hand the raw bytes back for inspection, and we
    // need the actual uploaded zip to assert its internal structure. This
    // mirrors the raw-TCP fake-backend pattern `commands::dev::proxy`'s own
    // tests already use.

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    use mockito::Server;
    use serde_json::json;

    use crate::credentials;

    fn ssr_fixture(dir: &Path) {
        write(dir, ".next/standalone/server.js", "server");
        write(dir, ".next/standalone/node_modules/pkg/index.js", "pkg");
        write(dir, ".next/static/chunks/app.js", "chunk");
    }

    fn test_args() -> DeployArgs {
        DeployArgs {
            app: "a-1".to_string(),
            env: "prod".to_string(),
            dir: None,
            note: None,
            no_activate: false,
            runtime: None,
            oidc: false,
        }
    }

    fn test_app() -> DeployTarget {
        DeployTarget {
            id: "a-1".to_string(),
            slug: Some("test-app".to_string()),
        }
    }

    fn test_creds() -> DeployAuth {
        DeployAuth::User(credentials::Credentials {
            access_token: "AT".to_string(),
            refresh_token: "RT".to_string(),
            expires_at: std::time::SystemTime::now() + Duration::from_secs(3600),
        })
    }

    /// Accepts exactly one connection, reads a full HTTP request (headers +
    /// a `Content-Length` body), stashes the raw body in the returned
    /// `Arc<Mutex<Vec<u8>>>`, and replies `200`. Standing in for a presigned
    /// S3 PUT target: the returned URL is what a `create_app_deploy` mock
    /// response can point `uploads[0].url` at.
    fn spawn_upload_capture() -> (String, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind capture listener");
        let port = listener.local_addr().expect("local_addr").port();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_writer = Arc::clone(&captured);

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept upload connection");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let header_end = loop {
                let n = stream.read(&mut chunk).expect("read upload request");
                assert!(n > 0, "connection closed before headers completed");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
            let content_length: usize = headers
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())
                        .flatten()
                })
                .unwrap_or(0);

            let mut body = buf[header_end..].to_vec();
            while body.len() < content_length {
                let n = stream.read(&mut chunk).expect("read upload body");
                assert!(n > 0, "connection closed before full body received");
                body.extend_from_slice(&chunk[..n]);
            }
            *captured_writer.lock().expect("captured mutex") = body;

            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("write upload response");
        });

        (format!("http://127.0.0.1:{port}/upload"), captured)
    }

    #[test]
    fn deploy_ssr_end_to_end_packages_uploads_finalizes_and_activates() {
        let dir = TempDir::new().unwrap();
        ssr_fixture(dir.path());

        let (upload_url, captured) = spawn_upload_capture();

        let mut server = Server::new();
        let _create = server
            .mock("POST", "/v1/apps/a-1/deploys")
            .match_header("authorization", "Bearer AT")
            .with_status(201)
            .with_body(
                json!({
                    "deploy_id": "d-1",
                    "uploads": [{
                        "path": "ssr-bundle.zip",
                        "url": upload_url,
                        "headers": {}
                    }]
                })
                .to_string(),
            )
            .create();
        let _finalize = server
            .mock("POST", "/v1/apps/a-1/deploys/d-1/finalize")
            .with_status(200)
            .with_body(json!({"status": "ready"}).to_string())
            .create();
        let _activate = server
            .mock("POST", "/v1/apps/a-1/stages/prod/activate")
            .with_status(200)
            .with_body(json!({"active_deploy_id": "d-1"}).to_string())
            .create();

        let args = test_args();
        let app = test_app();
        let mut creds = test_creds();
        let client = http::client(Duration::from_secs(15)).unwrap();

        deploy_ssr(&args, dir.path(), &app, &mut creds, &server.url(), &client)
            .expect("deploy_ssr ok");

        let bytes = captured.lock().expect("captured mutex").clone();
        assert!(!bytes.is_empty(), "no bytes reached the upload stub");

        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("uploaded bytes are a zip");
        let mut names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        names.sort();
        assert!(names.contains(&"run.sh".to_string()), "{names:?}");
        assert!(names.contains(&"server.js".to_string()), "{names:?}");
        assert!(
            names.contains(&".next/static/chunks/app.js".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"node_modules/pkg/index.js".to_string()),
            "{names:?}"
        );

        let mut run_sh = archive.by_name("run.sh").unwrap();
        let mut contents = String::new();
        run_sh.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "#!/bin/bash\nexec node server.js\n");
        drop(run_sh);

        const S_IFLNK: u32 = 0xA000;
        for i in 0..archive.len() {
            let entry = archive.by_index(i).unwrap();
            if let Some(mode) = entry.unix_mode() {
                assert_ne!(mode & 0xF000, S_IFLNK, "{:?} is a symlink", entry.name());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn deploy_ssr_propagates_symlink_rejection_from_real_packaging() {
        // Proves `deploy_ssr` runs the real `ssr::package_bundle` symlink
        // guard itself (not a stub) — the failure must surface before any
        // network call, so an unroutable-looking `apps_base` never gets
        // dialed.
        let dir = TempDir::new().unwrap();
        ssr_fixture(dir.path());
        std::os::unix::fs::symlink("/etc/hosts", dir.path().join(".next/standalone/leaky-link"))
            .unwrap();

        let args = test_args();
        let app = test_app();
        let mut creds = test_creds();
        let client = http::client(Duration::from_secs(15)).unwrap();

        let err = deploy_ssr(
            &args,
            dir.path(),
            &app,
            &mut creds,
            "http://127.0.0.1:1",
            &client,
        )
        .unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn deploy_ssr_with_cap_rejects_oversized_bundle_before_any_upload() {
        // Real packaging + real zip, checked against a tiny cap standing in
        // for `MAX_SSR_BUNDLE_BYTES` — proves the GAP-1 size guard runs on
        // the actual packaged artifact and rejects before any network call
        // (no mock is registered on `server`, so a network attempt would
        // surface as a very different, non-"too large" error).
        let dir = TempDir::new().unwrap();
        ssr_fixture(dir.path());

        let server = Server::new();
        let args = test_args();
        let app = test_app();
        let mut creds = test_creds();
        let client = http::client(Duration::from_secs(15)).unwrap();

        let err = deploy_ssr_with_cap(
            &args,
            dir.path(),
            &app,
            &mut creds,
            &server.url(),
            &client,
            1, // 1 byte: any real zip trips this
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too large"), "{msg}");
        assert!(msg.contains("1 B"), "{msg}");
    }

    #[test]
    fn deploy_token_path_needs_no_stored_credentials_or_app_lookup() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "index.html", "hello");

        let loader_called = std::cell::Cell::new(false);
        let selected = deploy_auth::select_deploy_auth(
            false,
            |name| (name == deploy_auth::ENV_DEPLOY_TOKEN).then(|| "token-secret".to_string()),
            || {
                loader_called.set(true);
                Err(anyhow!("no credentials file"))
            },
        )
        .expect("deploy token selected");
        assert!(!loader_called.get(), "stored credentials were loaded");
        let SelectedDeployAuth::Ready(mut auth @ DeployAuth::Token(_)) = selected else {
            panic!("expected deploy token");
        };

        let mut server = Server::new();
        let no_lookup = server.mock("GET", "/v1/apps/company").expect(0).create();
        let create = server
            .mock("POST", "/v1/apps/company/deploys")
            .match_header("authorization", "Bearer token-secret")
            .with_status(201)
            .with_body(json!({"deploy_id": "d-1", "uploads": []}).to_string())
            .create();
        let finalize = server
            .mock("POST", "/v1/apps/company/deploys/d-1/finalize")
            .match_header("authorization", "Bearer token-secret")
            .with_status(200)
            .with_body(json!({"status": "ready"}).to_string())
            .create();
        let activate = server
            .mock("POST", "/v1/apps/company/stages/prod/activate")
            .match_header("authorization", "Bearer token-secret")
            .with_status(200)
            .with_body(json!({"active_deploy_id": "d-1"}).to_string())
            .create();
        let target = DeployTarget {
            id: "company".into(),
            slug: None,
        };
        let args = test_args();
        let client = http::client(Duration::from_secs(15)).unwrap();

        deploy_static(
            &args,
            dir.path(),
            &target,
            &mut auth,
            &server.url(),
            &client,
        )
        .expect("deploy token works");
        no_lookup.assert();
        create.assert();
        finalize.assert();
        activate.assert();
    }

    #[test]
    fn oidc_target_rejects_an_environment_substitution() {
        let error = oidc_target(
            api::DeployGrant {
                grant: "grant-secret".into(),
                expires_at: "2026-07-27T05:30:00Z".into(),
                app_id: "app-1".into(),
                env: "staging".into(),
            },
            "prod",
        )
        .expect_err("environment mismatch");
        let message = error.to_string();
        assert!(message.contains("staging"), "{message}");
        assert!(message.contains("prod"), "{message}");
        assert!(!message.contains("grant-secret"), "{message}");
    }
}
