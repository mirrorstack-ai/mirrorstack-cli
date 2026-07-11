//! `mirrorstack app web deploy` — ship a static build directory to the
//! platform's app hosting, served on `https://<slug>.mirrorstack.app`.
//!
//! Flow: walk the build dir into a manifest (path + size + sha256), POST
//! it for presigned S3 PUTs, upload every file (bounded fan-out), finalize
//! (the platform spot-checks the objects), then activate the deploy on the
//! stage unless `--no-activate`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};

use crate::api::{self, ApiError, CreateAppDeployInput, DeployFile};
use crate::commands::{
    DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, ok_mark, resolve_base, session_expired,
};
use crate::credentials;
use crate::http;

use super::with_spinner;

/// Platform caps on one deploy, mirrored client-side so the failure is a
/// local error before any bytes move (the server re-validates).
const MAX_TOTAL_BYTES: u64 = 26_214_400; // 25 MB
const MAX_FILES: usize = 500;

/// Bounded fan-out for the presigned PUTs. S3 happily takes more, but 8
/// keeps memory (one file body per in-flight PUT) and socket use small.
const UPLOAD_CONCURRENCY: usize = 8;

/// Generous per-PUT timeout: the largest legal deploy is 25 MB, which on
/// a slow uplink can far exceed the 15s used for the JSON API calls.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

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
}

pub fn run(args: DeployArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    if !dir.is_dir() {
        return Err(anyhow!("{} is not a directory", dir.display()));
    }

    let files = with_spinner("Scanning files…", || build_manifest(&dir))?;
    let bytes_total: u64 = files.iter().map(|f| f.size).sum();

    let mut creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let client = http::client(Duration::from_secs(15))?;

    // Resolve --app (ID or slug) to the app row: the deploy endpoints take
    // the ID, and the final URL needs the slug. Member-scoped, so this
    // doubles as an access check before any upload work.
    let app = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::get_app(&client, &apps_base, tok, &args.app)
    }) {
        Ok(Some(a)) => a,
        Ok(None) => {
            return Err(anyhow!(
                "app '{}' not found (pass an app ID or slug you're a member of)",
                args.app
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    eprintln!(
        "  {} {} → {} ({} files, {})",
        style("Deploying:").dim(),
        style(dir.display()).bold(),
        style(format!("{}@{}", app.slug, args.env)).cyan().bold(),
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
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::create_app_deploy(
                &client,
                &apps_base,
                tok,
                &app.id,
                &CreateAppDeployInput {
                    env: &args.env,
                    note: args.note.as_deref(),
                    files: &file_inputs,
                },
            )
        })
    })
    .map_err(api_err)?;

    // Presigned URLs carry their own auth — a dedicated client without the
    // bearer token and with an upload-sized timeout.
    let upload_client = http::client(UPLOAD_TIMEOUT)?;
    upload_all(&upload_client, &created.uploads, &files)?;

    with_spinner("Finalizing…", || {
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::finalize_app_deploy(&client, &apps_base, tok, &app.id, &created.deploy_id)
        })
    })
    .map_err(api_err)?;

    if args.no_activate {
        eprintln!(
            "{} deployed {} (not activated)",
            ok_mark(),
            style(format!("{}@{}", app.slug, args.env)).cyan().bold()
        );
        eprintln!("  {} {}", style("deploy:").dim(), created.deploy_id);
        eprintln!(
            "  {} activate it from the app's deployment settings, or re-run without --no-activate",
            style("next:").dim()
        );
        return Ok(());
    }

    with_spinner("Activating…", || {
        credentials::with_refresh_retry(&mut creds, |tok| {
            api::activate_app_stage(
                &client,
                &apps_base,
                tok,
                &app.id,
                &args.env,
                &created.deploy_id,
            )
        })
    })
    .map_err(api_err)?;

    eprintln!(
        "{} deployed {}",
        ok_mark(),
        style(format!("{}@{}", app.slug, args.env)).cyan().bold()
    );
    eprintln!("  {} {}", style("deploy:").dim(), created.deploy_id);
    eprintln!(
        "  {} {}",
        style("url:").dim(),
        style(format!("https://{}.mirrorstack.app", app.slug))
            .cyan()
            .bold()
    );
    Ok(())
}

/// Map the API error vocabulary onto command-level errors, the same shape
/// the other commands print (`code: message`, login hint on 401).
fn api_err(e: ApiError) -> anyhow::Error {
    match e {
        ApiError::Unauthenticated => session_expired(),
        ApiError::Server { code, message, .. } => anyhow!("{code}: {message}"),
        other => other.into(),
    }
}

/// One file under the deploy root: its manifest entry plus where to read
/// the bytes back at upload time.
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
    let resp = req.send()?;
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

/// `1023 B` / `4.2 KB` / `25.0 MB` — one decimal above bytes, enough for
/// a size line capped at 25 MB.
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
}
