//! Linux/arm64 module build, Lambda packaging, and artifact upload.
//!
//! A deploy first cross-compiles the module into the custom-runtime
//! `bootstrap` executable, verifies the output matches the Graviton runtime,
//! and writes the single-file Lambda zip. Only after the local size guard
//! passes does the version-scoped create-upload → PUT → finalize flow begin.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
#[cfg(test)]
use tempfile::TempDir;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use crate::api::{self, ApiError};
use crate::http;

use super::deploy::{deploy_error_hint, verify_operation_release_receipt};
use super::{session_expired, with_spinner};
use crate::commands::release_candidate::ReleaseCandidateReceipt;

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
const CODE_ALREADY_READY: &str = "artifact_already_ready";

/// A Lambda package can be large enough to need substantially longer than
/// the JSON API client's timeout on a slow uplink.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(300);

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
    /// the caller may make exactly one explicit server-gated local-simulator
    /// deploy attempt. Every other missing/failed artifact shape is fatal.
    StorageUnconfigured,
    /// An ambiguous response or a server-confirmed artifact race requires an
    /// authoritative reread and a fresh plan. The caller must not infer that
    /// the attempted transition either committed or failed.
    Replan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareOutcome {
    Uploaded,
    StorageUnconfigured,
    Replan,
}

#[derive(Debug)]
enum UploadError {
    Ambiguous,
    Rejected(anyhow::Error),
}

/// Create the upload → PUT → finalize the packaged artifact against the
/// real ceiling.
///
/// Thin wrapper over [`ship_artifact_with_cap`] for the same reason
/// `app::deploy::deploy_ssr` wraps its own: tests drive the identical
/// upload path against a tiny cap instead of needing a genuine 250 MB
/// fixture on disk to prove the guard rejects.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ship_artifact(
    api_client: &Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version_ref: &str,
    zip_path: &Path,
    candidate: &ReleaseCandidateReceipt,
    version_id: &str,
) -> Result<ShipOutcome> {
    ship_artifact_with_cap(
        api_client,
        apps_base,
        access_token,
        module_id,
        version_ref,
        zip_path,
        candidate,
        version_id,
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
    candidate: &ReleaseCandidateReceipt,
    version_id: &str,
    max_artifact_bytes: u64,
) -> Result<ShipOutcome> {
    let bytes = fs::read(zip_path).with_context(|| format!("read {}", zip_path.display()))?;
    let size_bytes = bytes.len() as u64;
    guard_size(size_bytes, max_artifact_bytes)?;
    let sha256 = sha256_hex(&bytes);
    if size_bytes != candidate.artifact.size_bytes || sha256 != candidate.artifact.sha256 {
        return Err(anyhow!(
            "module artifact changed after release-candidate attestation (expected {}, {} bytes; current {sha256}, {size_bytes} bytes)",
            candidate.artifact.sha256,
            candidate.artifact.size_bytes,
        ));
    }

    // Only an explicit create-upload `artifact_storage_unconfigured` response
    // may select the server-gated local simulator. Missing routes, legacy
    // platforms, and a failure after upload all fail closed.
    let prepared = with_spinner(
        "Preparing artifact upload…",
        || -> Result<PrepareOutcome> {
            let upload = match api::create_module_artifact_upload(
                api_client,
                apps_base,
                access_token,
                module_id,
                version_ref,
            ) {
                Ok(upload) => upload,
                Err(error) if storage_unconfigured(&error) => {
                    return Ok(PrepareOutcome::StorageUnconfigured);
                }
                // A concurrent invocation finalized these immutable bytes
                // after our owner-state read. Return to the authoritative
                // planner; do not send PUT or finalize from stale state.
                Err(ApiError::Server {
                    status: 409, code, ..
                }) if code == CODE_ALREADY_READY => {
                    return Ok(PrepareOutcome::Replan);
                }
                Err(error) if ambiguous_api_error(&error) => {
                    return Ok(PrepareOutcome::Replan);
                }
                Err(error) => return Err(api_error(error)),
            };
            verify_artifact_upload_response(
                &upload,
                module_id,
                version_id,
                version_ref,
                candidate,
            )?;
            // Presigned URLs carry their own auth, so this PUT goes out on a
            // client with no bearer token and an upload-sized timeout.
            let upload_client = http::client(UPLOAD_TIMEOUT)?;
            match upload_one(&upload_client, &upload, &bytes) {
                Ok(()) => {}
                Err(UploadError::Ambiguous) => return Ok(PrepareOutcome::Replan),
                Err(UploadError::Rejected(error)) => return Err(error),
            }
            Ok(PrepareOutcome::Uploaded)
        },
    )?;
    if prepared == PrepareOutcome::StorageUnconfigured {
        return Ok(ShipOutcome::StorageUnconfigured);
    }
    if prepared == PrepareOutcome::Replan {
        return Ok(ShipOutcome::Replan);
    }

    let finalized = match with_spinner("Finalizing artifact…", || {
        api::finalize_module_artifact(api_client, apps_base, access_token, module_id, version_ref)
    }) {
        Ok(finalized) => finalized,
        Err(error) if ambiguous_api_error(&error) || artifact_race(&error) => {
            return Ok(ShipOutcome::Replan);
        }
        Err(error) => return Err(api_error(error)),
    };
    verify_artifact_finalize_response(&finalized, module_id, version_id, version_ref, candidate)?;
    Ok(ShipOutcome::Shipped)
}

fn verify_artifact_upload_response(
    upload: &api::ModuleArtifactUpload,
    module_id: &str,
    version_id: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
) -> Result<()> {
    let mismatch = |field: &str| {
        anyhow!(
            "artifact create returned a {field} that does not match the immutable {}@{version} release candidate",
            candidate.slug
        )
    };
    if upload.module_id != module_id || upload.version_id != version_id {
        return Err(mismatch("version identity"));
    }
    if upload.url.is_empty() || upload.headers.is_empty() || upload.expires_at.is_empty() {
        return Err(mismatch("usable presigned upload"));
    }
    verify_operation_release_receipt(
        &upload.release_receipt,
        candidate,
        &candidate.slug,
        version,
        "artifact create",
    )
}

fn verify_artifact_finalize_response(
    artifact: &api::ModuleArtifact,
    module_id: &str,
    version_id: &str,
    version: &str,
    candidate: &ReleaseCandidateReceipt,
) -> Result<()> {
    let mismatch = |field: &str| {
        anyhow!(
            "artifact finalize returned a {field} that does not match the immutable {}@{version} release candidate",
            candidate.slug
        )
    };
    if artifact.module_id != module_id || artifact.version_id != version_id {
        return Err(mismatch("version identity"));
    }
    if artifact.status != "ready"
        || u64::try_from(artifact.size_bytes).ok() != Some(candidate.artifact.size_bytes)
        || artifact.sha256 != candidate.artifact.sha256
        || artifact.created_at.is_empty()
        || artifact.updated_at.is_empty()
        || artifact.finalized_at.as_deref().is_none_or(str::is_empty)
    {
        return Err(mismatch("ready artifact evidence"));
    }
    verify_operation_release_receipt(
        &artifact.release_receipt,
        candidate,
        &candidate.slug,
        version,
        "artifact finalize",
    )
}

fn storage_unconfigured(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Server {
            status: 503,
            code,
            ..
        } if code == CODE_STORAGE_UNCONFIGURED
    )
}

fn ambiguous_api_error(error: &ApiError) -> bool {
    match error {
        ApiError::Http(_) | ApiError::Decode(_) | ApiError::Unexpected { status: 500.., .. } => {
            true
        }
        ApiError::Server {
            status: 500..,
            code,
            ..
        } => code != CODE_STORAGE_UNCONFIGURED,
        _ => false,
    }
}

fn artifact_race(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Server { status: 409, code, .. }
            if matches!(code.as_str(), "artifact_superseded" | "artifact_already_ready")
    ) || matches!(
        error,
        ApiError::Server {
            status: 422,
            code,
            ..
        } if code == "artifact_missing"
    )
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
fn upload_one(
    client: &Client,
    upload: &api::ModuleArtifactUpload,
    bytes: &[u8],
) -> std::result::Result<(), UploadError> {
    let mut req = client.put(&upload.url).body(bytes.to_vec());
    for (name, value) in &upload.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    // `reqwest::Error` renders the URL it failed on, and this one carries a
    // live signature. In a CI log that is a usable write credential until it
    // expires, so strip the URL before the error can reach stderr.
    let resp = req.send().map_err(|error| {
        // Consume only the redacted rendering; the signed URL must never
        // escape through an ambiguity diagnostic.
        let _ = error.without_url();
        UploadError::Ambiguous
    })?;
    let status = resp.status();
    if status.is_server_error() {
        return Err(UploadError::Ambiguous);
    }
    if !status.is_success() {
        // Storage bodies may echo the full signed request URI. Never expose
        // bearer-like presign query parameters through a CLI error.
        return Err(UploadError::Rejected(anyhow!(
            "presigned PUT failed: HTTP {}",
            status.as_u16()
        )));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Size of a file on disk for the early packaging ceiling. The attested upload
/// path separately reads and hashes one exact byte buffer before any request.
fn file_size(path: &Path) -> Result<u64> {
    Ok(fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len())
}

/// Refuse anything that isn't a 64-bit little-endian AArch64 ELF. A
/// host-arch binary is a perfectly valid file that only fails at cold start
/// in prod, so the check belongs here, next to the build that produced it.
pub(crate) fn assert_aarch64_elf(path: &Path) -> Result<()> {
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

    fn candidate(sha256: String, size_bytes: u64) -> ReleaseCandidateReceipt {
        ReleaseCandidateReceipt {
            protocol: crate::commands::release_candidate::CANDIDATE_PROTOCOL.to_string(),
            module_id: "module-id".to_string(),
            slug: "media".to_string(),
            version: "1.2.3".to_string(),
            source_sha256: "a".repeat(64),
            manifest: crate::commands::release_candidate::ManifestEvidence {
                sha256: "b".repeat(64),
                base64: "e30K".to_string(),
            },
            web: None,
            artifact: crate::commands::release_candidate::ArtifactEvidence {
                sha256,
                size_bytes,
                os: "linux".to_string(),
                arch: "arm64".to_string(),
                format: "lambda-bootstrap-zip".to_string(),
            },
        }
    }

    fn operation_receipt(candidate: &ReleaseCandidateReceipt) -> serde_json::Value {
        json!({
            "protocol": candidate.protocol,
            "source_sha256": candidate.source_sha256,
            "manifest_sha256": candidate.manifest.sha256,
            "artifact": {
                "sha256": candidate.artifact.sha256,
                "size_bytes": candidate.artifact.size_bytes,
                "os": candidate.artifact.os,
                "arch": candidate.artifact.arch,
                "format": candidate.artifact.format
            },
            "web": null
        })
    }

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
        let candidate = candidate(sha256_hex(b"xx"), 2);
        let error = ship_artifact_with_cap(
            &client,
            "http://127.0.0.1:1",
            "AT",
            "module-id",
            "1.0.0",
            &path,
            &candidate,
            "v-1",
            1,
        )
        .expect_err("oversize rejected");
        assert!(error.to_string().contains("too large"));
        assert!(error.to_string().contains("1 B"));
    }

    #[test]
    fn ship_rehashes_exact_upload_bytes_against_candidate_evidence_before_network() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("bootstrap.zip");
        fs::write(&path, b"changed").expect("write artifact");
        let client = http::client(Duration::from_secs(1)).expect("client");
        let candidate = candidate(sha256_hex(b"original"), b"original".len() as u64);
        let error = ship_artifact(
            &client,
            "http://127.0.0.1:1",
            "AT",
            "module-id",
            "1.0.0",
            &path,
            &candidate,
            "v-1",
        )
        .expect_err("candidate mismatch rejected");
        assert!(
            error
                .to_string()
                .contains("changed after release-candidate"),
            "{error:#}"
        );
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
        let artifact_bytes = fs::read(&zip_path).expect("artifact bytes");
        let size = artifact_bytes.len() as u64;
        let sha256 = sha256_hex(&artifact_bytes);
        let candidate = candidate(sha256, size);
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
                    "url": upload_url,
                    "headers": {"Content-Type": "application/zip"},
                    "expires_at": "2026-08-02T00:00:00Z",
                    "release_receipt": operation_receipt(&candidate)
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
                    "status": "ready",
                    "size_bytes": size,
                    "sha256": candidate.artifact.sha256,
                    "created_at": "2026-08-02T00:00:00Z",
                    "updated_at": "2026-08-02T00:00:00Z",
                    "finalized_at": "2026-08-02T00:00:00Z",
                    "release_receipt": operation_receipt(&candidate)
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
            &candidate,
            "v-1",
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

    #[test]
    fn create_receipt_mismatch_stops_before_the_presigned_put() {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"lambda bootstrap").expect("write bootstrap");
        let zip_path = zip_bootstrap(&bootstrap).expect("zip bootstrap");
        let bytes = fs::read(&zip_path).unwrap();
        let candidate = candidate(sha256_hex(&bytes), bytes.len() as u64);
        let mut wrong_receipt = operation_receipt(&candidate);
        wrong_receipt["source_sha256"] = serde_json::Value::String("d".repeat(64));

        let mut server = Server::new();
        let create = server
            .mock("POST", "/v1/modules/module-id/versions/1.2.3/artifact")
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "v-1",
                    "module_id": "module-id",
                    "url": "http://127.0.0.1:1/must-not-upload",
                    "headers": {"Content-Type": "application/zip"},
                    "expires_at": "2026-08-02T00:00:00Z",
                    "release_receipt": wrong_receipt
                })
                .to_string(),
            )
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let error = ship_artifact(
            &client,
            &server.url(),
            "AT",
            "module-id",
            "1.2.3",
            &zip_path,
            &candidate,
            "v-1",
        )
        .unwrap_err();
        create.assert();
        assert!(error.to_string().contains("source/manifest"), "{error:#}");
    }

    #[test]
    fn finalize_requires_exact_ready_artifact_and_candidate_receipt() {
        let candidate = candidate("c".repeat(64), 2048);
        let mut body = json!({
            "version_id": "v-1",
            "module_id": "module-id",
            "status": "ready",
            "size_bytes": candidate.artifact.size_bytes,
            "sha256": candidate.artifact.sha256,
            "created_at": "2026-08-02T00:00:00Z",
            "updated_at": "2026-08-02T00:00:01Z",
            "finalized_at": "2026-08-02T00:00:01Z",
            "release_receipt": operation_receipt(&candidate)
        });
        let exact: api::ModuleArtifact = serde_json::from_value(body.clone()).unwrap();
        verify_artifact_finalize_response(&exact, "module-id", "v-1", "1.2.3", &candidate).unwrap();

        body["status"] = serde_json::Value::String("pending".to_string());
        let pending: api::ModuleArtifact = serde_json::from_value(body).unwrap();
        assert!(
            verify_artifact_finalize_response(&pending, "module-id", "v-1", "1.2.3", &candidate)
                .unwrap_err()
                .to_string()
                .contains("ready artifact evidence")
        );
    }

    /// Drive the whole ship flow against a create-upload leg that answers
    /// `status` with `body` verbatim — the body shape is the point, since a
    /// platform error envelope and an unrouted 404 are told apart by nothing
    /// else.
    fn ship_against_create_upload_body(status: usize, body: &str) -> Result<ShipOutcome> {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"lambda bootstrap").expect("write bootstrap");
        let zip_path = zip_bootstrap(&bootstrap).expect("zip bootstrap");
        let bytes = fs::read(&zip_path).expect("artifact bytes");
        let sha256 = sha256_hex(&bytes);
        let size = bytes.len() as u64;
        let candidate = candidate(sha256, size);
        let mut server = Server::new();
        let create = server
            .mock("POST", "/v1/modules/module-id/versions/1.2.3/artifact")
            .with_status(status)
            .with_body(body)
            .create();
        let client = http::client(Duration::from_secs(15)).expect("client");
        let result = ship_artifact(
            &client,
            &server.url(),
            "AT",
            "module-id",
            "1.2.3",
            &zip_path,
            &candidate,
            "v-1",
        );
        create.assert();
        result
    }

    fn ship_against_create_upload_error(status: usize, code: &str) -> Result<ShipOutcome> {
        ship_against_create_upload_body(
            status,
            &json!({"error": {"code": code, "message": "nope"}}).to_string(),
        )
    }

    /// The one non-fatal create response is handed to the caller, which may
    /// request the server-gated local simulator. Remote bucketless platforms
    /// will reject that deploy mode.
    #[test]
    fn storage_unconfigured_is_reported_not_fatal() {
        let outcome = ship_against_create_upload_error(503, "artifact_storage_unconfigured")
            .expect("storage-unconfigured is not an error");
        assert_eq!(outcome, ShipOutcome::StorageUnconfigured);
    }

    /// A platform build that predates the attested artifact routes must not
    /// receive an unsafe legacy deploy fallback.
    #[test]
    fn missing_artifact_routes_fail_closed() {
        let error = ship_against_create_upload_body(404, "404 page not found\n")
            .expect_err("a platform without attested routes must fail");
        assert!(error.to_string().contains("404"), "{error:#}");
    }

    /// …and the enveloped 404 the routes themselves emit (module, version or
    /// pending row not found) must NOT be mistaken for the routes being
    /// absent. Same status, opposite verdict — the envelope is the only
    /// discriminator, so it is asserted directly.
    #[test]
    fn enveloped_not_found_stays_fatal() {
        let error = ship_against_create_upload_error(404, "not_found")
            .expect_err("a real not_found still fails the deploy");
        assert!(error.to_string().contains("not_found"), "{error}");
    }

    #[test]
    fn other_artifact_errors_stay_fatal() {
        let error = ship_against_create_upload_error(422, "artifact_invalid")
            .expect_err("every other code still fails the deploy");
        assert!(error.to_string().contains("artifact_invalid"), "{error}");
    }

    #[test]
    fn ambiguous_create_response_requires_owner_state_replan() {
        let outcome = ship_against_create_upload_error(500, "internal_error")
            .expect("ambiguous server response is replanned");
        assert_eq!(outcome, ShipOutcome::Replan);
        let wrong_status = ship_against_create_upload_error(500, "artifact_already_ready")
            .expect("a race code on 500 remains ambiguous");
        assert_eq!(wrong_status, ShipOutcome::Replan);
        assert!(
            ship_against_create_upload_error(500, "artifact_storage_unconfigured").is_err(),
            "only exact 503 storage-unconfigured may authorize local simulation"
        );
    }

    #[test]
    fn storage_server_error_is_ambiguous_but_client_rejection_is_final() {
        for (status, ambiguous) in [(500, true), (400, false)] {
            let mut server = Server::new();
            let put = server.mock("PUT", "/upload").with_status(status).create();
            let upload: api::ModuleArtifactUpload = serde_json::from_value(json!({
                "url": format!("{}/upload", server.url()),
                "headers": {"Content-Type": "application/zip"},
                "version_id": "v-1",
                "module_id": "module-id",
                "expires_at": "2026-08-31T00:05:00Z",
                "release_receipt": operation_receipt(&candidate("a".repeat(64), 1))
            }))
            .unwrap();
            let error = upload_one(
                &http::client(Duration::from_secs(5)).unwrap(),
                &upload,
                b"x",
            )
            .unwrap_err();
            put.assert();
            assert_eq!(matches!(error, UploadError::Ambiguous), ambiguous);
        }
    }

    #[test]
    fn ready_race_returns_to_owner_planner_without_put_or_finalize() {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"lambda bootstrap").unwrap();
        let zip_path = zip_bootstrap(&bootstrap).unwrap();
        let bytes = fs::read(&zip_path).unwrap();
        let candidate = candidate(sha256_hex(&bytes), bytes.len() as u64);
        let mut server = Server::new();
        let create = server
            .mock("POST", "/v1/modules/module-id/versions/1.2.3/artifact")
            .with_status(409)
            .with_body(
                json!({
                    "error": {
                        "code": "artifact_already_ready",
                        "message": "artifact is already ready"
                    }
                })
                .to_string(),
            )
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let outcome = ship_artifact(
            &client,
            &server.url(),
            "AT",
            "module-id",
            "1.2.3",
            &zip_path,
            &candidate,
            "v-1",
        )
        .unwrap();
        create.assert();
        assert_eq!(outcome, ShipOutcome::Replan);
    }

    /// Create can succeed against a new platform build while finalize lands
    /// on an old one mid-rollout. That cannot safely select local simulation:
    /// bytes were already uploaded and finalization did not prove them.
    #[test]
    fn missing_finalize_route_fails_closed() {
        let dir = TempDir::new().expect("temp dir");
        let bootstrap = dir.path().join("bootstrap");
        fs::write(&bootstrap, b"lambda bootstrap").expect("write bootstrap");
        let zip_path = zip_bootstrap(&bootstrap).expect("zip bootstrap");
        let bytes = fs::read(&zip_path).expect("artifact bytes");
        let sha256 = sha256_hex(&bytes);
        let size = bytes.len() as u64;
        let candidate = candidate(sha256, size);
        let (upload_url, _captured) = spawn_upload_capture();

        let mut server = Server::new();
        let create = server
            .mock("POST", "/v1/modules/module-id/versions/1.2.3/artifact")
            .with_status(200)
            .with_body(
                json!({
                    "version_id": "v-1",
                    "module_id": "module-id",
                    "url": upload_url,
                    "headers": {"Content-Type": "application/zip"},
                    "expires_at": "2026-08-02T00:00:00Z",
                    "release_receipt": operation_receipt(&candidate)
                })
                .to_string(),
            )
            .create();
        let finalize = server
            .mock(
                "POST",
                "/v1/modules/module-id/versions/1.2.3/artifact/finalize",
            )
            .with_status(404)
            .with_body("404 page not found\n")
            .create();
        let client = http::client(Duration::from_secs(15)).expect("client");
        let error = ship_artifact(
            &client,
            &server.url(),
            "AT",
            "module-id",
            "1.2.3",
            &zip_path,
            &candidate,
            "v-1",
        )
        .expect_err("a platform without the finalize route must fail");
        create.assert();
        finalize.assert();
        assert!(error.to_string().contains("404"), "{error:#}");
    }

    #[test]
    fn human_bytes_formats() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(4302), "4.2 KB");
        assert_eq!(human_bytes(MAX_ARTIFACT_BYTES), "250.0 MB");
    }
}
