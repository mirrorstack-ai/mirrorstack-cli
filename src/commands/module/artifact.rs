//! Linux/arm64 module build, Lambda packaging, and artifact upload.
//!
//! A deploy first cross-compiles the module into the custom-runtime
//! `bootstrap` executable, verifies the output matches the Graviton runtime,
//! and writes the single-file Lambda zip. Only after the local size guard
//! passes does the version-scoped create-upload → PUT → finalize flow begin.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use tempfile::TempDir;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::api::{self, ApiError};
use crate::http;

use super::{deploy_error_hint, session_expired, with_spinner};

/// Client-side sanity cap on the packaged (compressed) zip, mirroring the
/// platform's own finalize-time ceiling on the uploaded object so an oversize
/// artifact fails locally before any bytes move.
///
/// Deliberately NOT described as an AWS limit: Lambda's 250 MB quota applies
/// to the *unzipped* package, so a zip under this cap can still be rejected by
/// Lambda, and one over it is not necessarily over Lambda's. This is our
/// ceiling, not theirs.
const MAX_ARTIFACT_BYTES: u64 = 250 * 1024 * 1024; // 250 MB

/// The one artifact-flow error code that is not a failure: the platform in
/// front of us has no artifact object store wired at all.
const CODE_STORAGE_UNCONFIGURED: &str = "artifact_storage_unconfigured";

/// A Lambda package can be large enough to need substantially longer than
/// the JSON API client's timeout on a slow uplink.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Cross-compile the module in `dir` to a Linux/arm64 static binary named
/// `bootstrap` inside a fresh temp dir. The returned temp dir must remain
/// alive until the returned path has been uploaded.
///
/// The three build vars are set explicitly rather than inherited so a
/// developer whose shell already exports `GOARCH=amd64` (or a CI image that
/// does) still produces a Graviton binary — the platform's native-binary
/// guards assert `aarch64` and a host-arch build would only fail at cold
/// start, in prod.
///
/// `-trimpath` because this binary leaves the developer's machine: without it
/// the compiled paths and DWARF carry the absolute source tree (`/Users/…`,
/// `/home/…`, module cache paths) into an artifact stored on the platform.
pub(crate) fn build_bootstrap(dir: &Path) -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new().context("create temp module build directory")?;
    let bootstrap = tmp.path().join("bootstrap");
    let output = Command::new("go")
        .arg("build")
        .arg("-trimpath")
        .arg("-o")
        .arg(&bootstrap)
        .arg(".")
        .current_dir(dir)
        .env("GOOS", "linux")
        .env("GOARCH", "arm64")
        .env("CGO_ENABLED", "0")
        .output();

    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(anyhow!(
                "Go toolchain required to deploy a module — install Go or run the deploy from a machine that has it"
            ));
        }
        Err(error) => return Err(error).context("run Go compiler"),
    };
    if !output.status.success() {
        let mut compiler_output = output.stderr;
        compiler_output.extend_from_slice(&output.stdout);
        return Err(anyhow!(
            "Go build failed:\n{}",
            String::from_utf8_lossy(&compiler_output).trim()
        ));
    }

    assert_aarch64_elf(&bootstrap)?;
    set_executable(&bootstrap)?;
    Ok((tmp, bootstrap))
}

/// Zip `bootstrap_path` as the executable `bootstrap` entry at the archive
/// root, writing the archive alongside the binary.
///
/// Both details are load-bearing for `provided.al2023`: the runtime looks for
/// an entry named exactly `bootstrap` at the archive root (any directory
/// prefix and the function never starts), and it must carry the executable
/// bit — a 0644 entry fails at init with a permission error, which is the
/// classic silent packaging failure this function exists to prevent.
pub(crate) fn zip_bootstrap(bootstrap_path: &Path) -> Result<PathBuf> {
    let zip_path = bootstrap_path.with_extension("zip");
    let file = File::create(&zip_path).with_context(|| format!("create {}", zip_path.display()))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o755);
    zip.start_file("bootstrap", options)
        .context("add bootstrap to module artifact")?;
    let mut bootstrap =
        File::open(bootstrap_path).with_context(|| format!("open {}", bootstrap_path.display()))?;
    io::copy(&mut bootstrap, &mut zip).context("write bootstrap into module artifact")?;
    zip.finish().context("finalize module artifact")?;
    Ok(zip_path)
}

/// Whether the artifact actually reached the platform's object store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShipOutcome {
    /// Uploaded and finalized — the version is artifact-backed.
    Shipped,
    /// The platform answered `artifact_storage_unconfigured`: it has no
    /// artifact store wired, so there is nothing to upload to. Not an error —
    /// see the caller in `module::deploy` for why this stays non-fatal.
    StorageUnconfigured,
}

/// Create the upload → PUT → finalize the packaged artifact against the
/// real ceiling.
///
/// Thin wrapper over [`ship_artifact_with_cap`] for the same reason
/// `app::deploy::deploy_ssr` wraps its own: tests drive the identical
/// upload path against a tiny cap instead of needing a genuine 250 MB
/// fixture on disk to prove the guard rejects.
pub(crate) fn ship_artifact(
    api_client: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
    zip_path: &Path,
) -> Result<ShipOutcome> {
    ship_artifact_with_cap(
        api_client,
        apps_base,
        access_token,
        module_id,
        version_ref,
        zip_path,
        MAX_ARTIFACT_BYTES,
    )
}

/// Size of the packaged artifact, rejecting an oversize bundle here — before
/// the deploy has recorded anything remotely — so the failure costs nothing
/// but a local build. [`ship_artifact_with_cap`] re-checks at upload time;
/// that copy is the enforcement point, this one is the early exit.
pub(crate) fn packaged_size(zip_path: &Path) -> Result<u64> {
    let size = file_size(zip_path)?;
    guard_size(size, MAX_ARTIFACT_BYTES)?;
    Ok(size)
}

#[allow(clippy::too_many_arguments)]
fn ship_artifact_with_cap(
    api_client: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
    zip_path: &Path,
    max_artifact_bytes: u64,
) -> Result<ShipOutcome> {
    let size = file_size(zip_path)?;
    guard_size(size, max_artifact_bytes)?;

    // Both legs can answer `artifact_storage_unconfigured` (the platform's
    // handler maps store absence to it on create-upload *and* finalize), so
    // both are checked for it; every other code stays fatal.
    let outcome = with_spinner("Uploading artifact…", || -> Result<ShipOutcome> {
        let upload = match api::create_module_artifact_upload(
            api_client,
            apps_base,
            access_token,
            module_id,
            version_ref,
        ) {
            Ok(upload) => upload,
            Err(error) if storage_unconfigured(&error) => {
                return Ok(ShipOutcome::StorageUnconfigured);
            }
            Err(error) => return Err(api_error(error)),
        };
        // Presigned URLs carry their own auth, so this PUT goes out on a
        // client with no bearer token and an upload-sized timeout.
        let upload_client = http::client(UPLOAD_TIMEOUT)?;
        upload_one(&upload_client, &upload, zip_path)?;
        Ok(ShipOutcome::Shipped)
    })?;
    if outcome == ShipOutcome::StorageUnconfigured {
        return Ok(outcome);
    }

    match with_spinner("Finalizing artifact…", || {
        api::finalize_module_artifact(api_client, apps_base, access_token, module_id, version_ref)
    }) {
        Ok(_) => Ok(ShipOutcome::Shipped),
        Err(error) if storage_unconfigured(&error) => Ok(ShipOutcome::StorageUnconfigured),
        Err(error) => Err(api_error(error)),
    }
}

fn storage_unconfigured(error: &ApiError) -> bool {
    matches!(error, ApiError::Server { code, .. } if code == CODE_STORAGE_UNCONFIGURED)
}

fn guard_size(size: u64, max_artifact_bytes: u64) -> Result<()> {
    if size > max_artifact_bytes {
        return Err(anyhow!(
            "module artifact too large: {} (the packaged zip is capped at {}, matching the ceiling the platform enforces on the uploaded object) — trim unused dependencies from the module",
            human_bytes(size),
            human_bytes(max_artifact_bytes)
        ));
    }
    Ok(())
}

fn api_error(error: ApiError) -> anyhow::Error {
    match error {
        ApiError::Server { code, message, .. } => {
            anyhow!("{code}: {message}{hint}", hint = deploy_error_hint(&code))
        }
        ApiError::Unauthenticated => session_expired(),
        other => other.into(),
    }
}

/// One presigned PUT: the body is the archive verbatim and the headers are
/// exactly what the platform handed back — nothing added (no bearer token;
/// the signature IS the auth).
fn upload_one(client: &Client, upload: &api::ModuleArtifactUpload, path: &Path) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut req = client.put(&upload.url).body(bytes);
    for (name, value) in &upload.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    // `reqwest::Error` renders the URL it failed on, and this one carries a
    // live signature. In a CI log that is a usable write credential until it
    // expires, so strip the URL before the error can reach stderr.
    let resp = req
        .send()
        .map_err(|error| anyhow!("presigned PUT failed: {}", error.without_url()))?;
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

/// Size of a file on disk, without reading it — the only artifact fact the
/// CLI needs, since the platform HEADs the uploaded object for size and
/// digest at finalize rather than trusting a caller declaration.
fn file_size(path: &Path) -> Result<u64> {
    Ok(fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Refuse anything that isn't a 64-bit little-endian AArch64 ELF. A
/// host-arch binary is a perfectly valid file that only fails at cold start
/// in prod, so the check belongs here, next to the build that produced it.
fn assert_aarch64_elf(path: &Path) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut header = Vec::with_capacity(ELF_HEADER_PREFIX);
    // `take` + `read_to_end` rather than one `read`: a single read is allowed
    // to come back short, which would misreport a valid binary as non-ELF.
    file.take(ELF_HEADER_PREFIX as u64)
        .read_to_end(&mut header)
        .with_context(|| format!("read ELF header from {}", path.display()))?;
    assert_aarch64_elf_header(&header)
}

/// Bytes of the ELF header this check reads: through `e_machine` at 0x12.
const ELF_HEADER_PREFIX: usize = 20;

fn assert_aarch64_elf_header(header: &[u8]) -> Result<()> {
    if header.len() < ELF_HEADER_PREFIX || header.get(..4) != Some(b"\x7fELF") {
        return Err(anyhow!(
            "built bootstrap is not an ELF executable; every MirrorStack Lambda is Graviton/arm64 and requires a 64-bit little-endian AArch64 ELF"
        ));
    }
    let class = header[4];
    let data = header[5];
    let machine = u16::from_le_bytes([header[0x12], header[0x13]]);
    if class != 2 || data != 1 || machine != 183 {
        return Err(anyhow!(
            "built bootstrap has ELF class {class}, data encoding {data}, machine {machine}; required class 2, little-endian encoding 1, machine 183 (AArch64/arm64), because every MirrorStack Lambda is Graviton/arm64"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod +x {}", path.display()))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

/// `1023 B` / `4.2 KB` / `250.0 MB` — one decimal above bytes.
pub(crate) fn human_bytes(n: u64) -> String {
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

    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use mockito::Server;
    use serde_json::json;

    type UploadCapture = Arc<Mutex<(String, Vec<u8>)>>;

    fn elf_header(machine: u16) -> [u8; ELF_HEADER_PREFIX] {
        let mut header = [0u8; ELF_HEADER_PREFIX];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[0x12..0x14].copy_from_slice(&machine.to_le_bytes());
        header
    }

    #[test]
    fn aarch64_guard_accepts_arm64_and_rejects_other_inputs() {
        assert_aarch64_elf_header(&elf_header(183)).expect("AArch64 accepted");
        let x86 = assert_aarch64_elf_header(&elf_header(62)).expect_err("x86 rejected");
        assert!(x86.to_string().contains("arm64"));
        let text = assert_aarch64_elf_header(b"not an elf").expect_err("text rejected");
        assert!(text.to_string().contains("not an ELF"));
    }

    #[test]
    fn zip_bootstrap_produces_lambda_root_entry() {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"binary contents").expect("write bootstrap");
        let zip_path = zip_bootstrap(&bootstrap).expect("zip bootstrap");
        let mut archive =
            zip::ZipArchive::new(File::open(zip_path).expect("open zip")).expect("valid zip");
        assert_eq!(archive.len(), 1);
        let mut entry = archive.by_index(0).expect("bootstrap entry");
        assert_eq!(entry.name(), "bootstrap");
        assert_eq!(entry.unix_mode().map(|mode| mode & 0o777), Some(0o755));
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents).expect("read entry");
        assert!(!contents.is_empty());
    }

    #[test]
    fn ship_guard_rejects_before_network() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("bootstrap.zip");
        fs::write(&path, b"xx").expect("write artifact");
        let client = http::client(Duration::from_secs(1)).expect("client");
        let error = ship_artifact_with_cap(
            &client,
            "http://127.0.0.1:1",
            "AT",
            "module-id",
            "1.0.0",
            &path,
            1,
        )
        .expect_err("oversize rejected");
        assert!(error.to_string().contains("too large"));
        assert!(error.to_string().contains("1 B"));
    }

    fn spawn_upload_capture() -> (String, UploadCapture) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind capture listener");
        let port = listener.local_addr().expect("listener address").port();
        let captured = Arc::new(Mutex::new((String::new(), Vec::new())));
        let writer = Arc::clone(&captured);
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept upload");
            let mut request = Vec::new();
            let mut chunk = [0u8; 8192];
            let header_end = loop {
                let n = stream.read(&mut chunk).expect("read request");
                assert!(n > 0);
                request.extend_from_slice(&chunk[..n]);
                if let Some(pos) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_string();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            let mut body = request[header_end..].to_vec();
            while body.len() < length {
                let n = stream.read(&mut chunk).expect("read body");
                assert!(n > 0);
                body.extend_from_slice(&chunk[..n]);
            }
            *writer.lock().expect("capture mutex") = (headers, body);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("write response");
        });
        (format!("http://127.0.0.1:{port}/upload"), captured)
    }

    #[test]
    fn artifact_round_trip_creates_upload_puts_and_finalizes() {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"lambda bootstrap").expect("write bootstrap");
        let zip_path = zip_bootstrap(&bootstrap).expect("zip bootstrap");
        let size = fs::metadata(&zip_path).expect("artifact metadata").len();
        let (upload_url, captured) = spawn_upload_capture();

        let mut server = Server::new();
        // Both calls are bodiless by contract: the platform owns the key and
        // reads size/digest off the object itself, so there is nothing for
        // the CLI to declare or echo.
        let create = server
            .mock("POST", "/v1/modules/module-id/versions/1.2.3/artifact")
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "v-1",
                    "module_id": "module-id",
                    "key": "modules/module-id/versions/v-1/artifact.zip",
                    "url": upload_url,
                    "headers": {"Content-Type": "application/zip"},
                    "expires_at": "2026-08-02T00:00:00Z"
                })
                .to_string(),
            )
            .create();
        let finalize = server
            .mock(
                "POST",
                "/v1/modules/module-id/versions/1.2.3/artifact/finalize",
            )
            .match_header("authorization", "Bearer AT")
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "v-1",
                    "module_id": "module-id",
                    "key": "modules/module-id/versions/v-1/artifact.zip",
                    "status": "ready",
                    "size_bytes": size,
                    "created_at": "2026-08-02T00:00:00Z",
                    "updated_at": "2026-08-02T00:00:00Z"
                })
                .to_string(),
            )
            .create();
        let client = http::client(Duration::from_secs(15)).expect("client");
        ship_artifact(
            &client,
            &server.url(),
            "AT",
            "module-id",
            "1.2.3",
            &zip_path,
        )
        .expect("ship artifact");
        create.assert();
        finalize.assert();

        let (headers, bytes) = captured.lock().expect("capture mutex").clone();
        // The server-supplied headers must be replayed verbatim on the PUT.
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-type: application/zip"),
            "{headers}"
        );
        // …and the bearer token must never follow the presigned URL.
        assert!(
            !headers.to_ascii_lowercase().contains("authorization:"),
            "{headers}"
        );
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("uploaded zip");
        assert_eq!(archive.len(), 1);
        assert_eq!(archive.by_index(0).expect("entry").name(), "bootstrap");
    }

    fn ship_against_create_upload_error(status: usize, code: &str) -> Result<ShipOutcome> {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"lambda bootstrap").expect("write bootstrap");
        let zip_path = zip_bootstrap(&bootstrap).expect("zip bootstrap");
        let mut server = Server::new();
        let create = server
            .mock("POST", "/v1/modules/module-id/versions/1.2.3/artifact")
            .with_status(status)
            .with_body(json!({"error": {"code": code, "message": "nope"}}).to_string())
            .create();
        let client = http::client(Duration::from_secs(15)).expect("client");
        let result = ship_artifact(
            &client,
            &server.url(),
            "AT",
            "module-id",
            "1.2.3",
            &zip_path,
        );
        create.assert();
        result
    }

    /// A platform with no artifact store (local prod-sim, bucket-less prod)
    /// must not fail a deploy whose version record is already frozen.
    #[test]
    fn storage_unconfigured_is_reported_not_fatal() {
        let outcome = ship_against_create_upload_error(503, "artifact_storage_unconfigured")
            .expect("storage-unconfigured is not an error");
        assert_eq!(outcome, ShipOutcome::StorageUnconfigured);
    }

    #[test]
    fn other_artifact_errors_stay_fatal() {
        let error = ship_against_create_upload_error(422, "artifact_invalid")
            .expect_err("every other code still fails the deploy");
        assert!(error.to_string().contains("artifact_invalid"), "{error}");
    }

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4302), "4.2 KB");
        assert_eq!(human_bytes(MAX_ARTIFACT_BYTES), "250.0 MB");
    }
}
