//! `mirrorstack module build` — the credential-free half of `module deploy`.
//!
//! `deploy` loads a login and reads the owned module from the platform before
//! it builds. An authoring sandbox has neither, so this verb builds the same
//! attested release candidate from the module source alone and writes the
//! receipt and the Lambda ZIP to a directory. It never touches `credentials`,
//! `http` or `api`: the only thing it needs besides the source is a Go
//! toolchain.

use super::*;
use std::fs;
use std::io::Write;

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::commands::release_candidate::{self, CandidateRequest, ReleaseCandidate};

const RECEIPT_FILE: &str = "receipt.json";
const ARTIFACT_FILE: &str = "bootstrap.zip";

#[derive(Args)]
pub struct BuildArgs {
    /// Module directory containing main.go. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Directory that receives receipt.json and bootstrap.zip (created if
    /// absent). Keep it outside the module's Git worktree, or git-ignored:
    /// the release candidate is built from the whole working set, so a file
    /// left inside it changes the next build's source hash.
    #[arg(long)]
    out: PathBuf,
    /// Platform module id, as a UUID or the SDK's `m<32 hex>` form. Defaults
    /// to MS_MODULE_ID_<SLUG> in the module's `.env`, which `module register`
    /// writes.
    #[arg(long)]
    module_id: Option<String>,
    /// Refuse a web bundle: a web/package.json, a web/esbuild.config.mjs, a
    /// declared UI surface or a declared Client. For agent-built modules.
    #[arg(long)]
    api_only: bool,
    /// Print the output paths and hashes as one JSON object on stdout.
    #[arg(long)]
    json: bool,
}

struct Outputs {
    receipt: PathBuf,
    artifact: PathBuf,
}

pub(super) fn run(args: BuildArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    let meta = read_meta(&dir)?;
    if !slug_valid(&meta.slug) {
        return Err(slug_invalid_error(&meta.slug));
    }
    if args.api_only && meta.client.is_some() {
        return Err(anyhow!(
            "--api-only refuses a module that declares a Client in main.go: agent-built modules ship no client code"
        ));
    }
    let raw = code_version(&meta, &dir)?;
    let version = canonical_version(&raw)?;
    let module_id = resolve_module_id(args.module_id.as_deref(), &meta)?;
    let out = prepare_out_dir(&args.out, &dir)?;

    let candidate = with_spinner("Building release candidate…", || {
        release_candidate::build(CandidateRequest {
            module_dir: &dir,
            slug: &meta.slug,
            module_id: &module_id,
            version: &version,
            source_version_key: &raw,
            api_only: args.api_only,
        })
    })?;
    let outputs = write_outputs(&candidate, &out)?;

    let receipt = candidate.build_receipt();
    if args.json {
        let summary = serde_json::json!({
            "receipt": outputs.receipt,
            "artifact": outputs.artifact,
            "module_id": receipt.module_id,
            "slug": receipt.slug,
            "version": receipt.version,
            "source_sha256": receipt.source_sha256,
            "artifact_sha256": receipt.artifact.sha256,
            "bootstrap_sha256": receipt.artifact.bootstrap_sha256,
        });
        println!("{summary}");
    } else {
        eprintln!(
            "{} built {} (bootstrap sha256 {})",
            ok_mark(),
            style(format!("{}@{}", receipt.slug, receipt.version))
                .cyan()
                .bold(),
            receipt.artifact.bootstrap_sha256.as_deref().unwrap_or("")
        );
        println!("receipt:  {}", outputs.receipt.display());
        println!("artifact: {}", outputs.artifact.display());
    }
    Ok(())
}

fn resolve_module_id(flag: Option<&str>, meta: &ModuleMeta) -> Result<String> {
    let id = flag
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(meta.id.as_str());
    if id.is_empty() {
        return Err(anyhow!(
            "no module id: pass --module-id <uuid>, or add {} to the module's .env (`module register` writes it)",
            module_meta::env_key_for_slug(&meta.slug)
        ));
    }
    if release_candidate::normalize_module_id(id).is_none() {
        return Err(anyhow!(
            "module id {id:?} is neither a UUID nor an m<32 hex> SDK module id"
        ));
    }
    Ok(id.to_string())
}

/// Create `out` and resolve it. Refused inside the module directory: the
/// outputs would become part of the source the next build attests.
fn prepare_out_dir(out: &Path, module_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(out).with_context(|| format!("create --out {}", out.display()))?;
    let out = fs::canonicalize(out).with_context(|| format!("resolve --out {}", out.display()))?;
    let module = fs::canonicalize(module_dir)
        .with_context(|| format!("resolve module directory {}", module_dir.display()))?;
    if out.starts_with(&module) {
        return Err(anyhow!(
            "--out {} is inside the module directory {}: the outputs would change the next build's source hash; pick a directory outside it",
            out.display(),
            module.display()
        ));
    }
    Ok(out)
}

/// Re-check the attested bytes, then publish the ZIP and finally the receipt:
/// the receipt is the marker that a complete build is present.
fn write_outputs(candidate: &ReleaseCandidate, out: &Path) -> Result<Outputs> {
    candidate.verify_live_source()?;
    let zip = fs::read(candidate.artifact_path())
        .with_context(|| format!("read {}", candidate.artifact_path().display()))?;
    let expected = &candidate.receipt().artifact;
    let actual = format!("{:x}", Sha256::digest(&zip));
    if actual != expected.sha256 || zip.len() as u64 != expected.size_bytes {
        return Err(anyhow!(
            "packaged artifact changed after attestation (expected {}, {} bytes; current {actual}, {} bytes)",
            expected.sha256,
            expected.size_bytes,
            zip.len()
        ));
    }
    let receipt = release_candidate::encode_receipt(&candidate.build_receipt())?;
    Ok(Outputs {
        artifact: write_atomic(out, ARTIFACT_FILE, &zip)?,
        receipt: write_atomic(out, RECEIPT_FILE, &receipt)?,
    })
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let mut temporary = NamedTempFile::new_in(dir)
        .with_context(|| format!("create {name} in {}", dir.display()))?;
    temporary
        .write_all(bytes)
        .with_context(|| format!("write {name}"))?;
    temporary
        .as_file_mut()
        .sync_all()
        .with_context(|| format!("sync {name}"))?;
    let path = dir.join(name);
    temporary
        .persist(&path)
        .map_err(|error| anyhow!("publish {}: {}", path.display(), error.error))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str) -> ModuleMeta {
        ModuleMeta {
            id: id.to_string(),
            slug: "user-core".to_string(),
            name: "User Core".to_string(),
            version: Some("v1.2.3".to_string()),
            client: None,
        }
    }

    #[test]
    fn module_id_flag_beats_the_env_id_and_both_are_validated() {
        let uuid = "11111111-1111-1111-1111-111111111111";
        let sdk = "m22222222222222222222222222222222";
        assert_eq!(resolve_module_id(Some(uuid), &meta(sdk)).unwrap(), uuid);
        assert_eq!(resolve_module_id(None, &meta(sdk)).unwrap(), sdk);
        assert_eq!(resolve_module_id(Some("  "), &meta(sdk)).unwrap(), sdk);
        assert!(resolve_module_id(Some("not-an-id"), &meta(sdk)).is_err());
        assert!(resolve_module_id(None, &meta("bogus")).is_err());
    }

    #[test]
    fn missing_module_id_names_the_env_key_and_the_flag() {
        let error = resolve_module_id(None, &meta("")).unwrap_err().to_string();
        assert!(error.contains("--module-id"), "{error}");
        assert!(error.contains("MS_MODULE_ID_"), "{error}");
    }

    #[test]
    fn out_dir_inside_the_module_is_refused_and_outside_is_created() {
        let root = tempfile::tempdir().unwrap();
        let module = root.path().join("module");
        fs::create_dir_all(&module).unwrap();

        let inside = prepare_out_dir(&module.join("dist"), &module).unwrap_err();
        assert!(inside.to_string().contains("inside the module"), "{inside}");

        let outside = root.path().join("out/nested");
        let resolved = prepare_out_dir(&outside, &module).unwrap();
        assert!(resolved.is_dir());
        assert!(resolved.starts_with(fs::canonicalize(root.path()).unwrap()));
    }

    #[test]
    fn write_atomic_replaces_an_existing_file_without_leaving_temporaries() {
        let dir = tempfile::tempdir().unwrap();
        write_atomic(dir.path(), RECEIPT_FILE, b"first\n").unwrap();
        let path = write_atomic(dir.path(), RECEIPT_FILE, b"second\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second\n");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
