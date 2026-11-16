//! Acceptance for `mirrorstack module build` (cli#147), against the REAL
//! binary and the REAL Go toolchain.
//!
//! `#[ignore]`d because they need a Go at or above the release floor: the
//! `scaffold` CI job (Go pinned to 1.26.10) runs them by name and checks the
//! pass count, the same way it runs the scaffold build test.

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const MODULE_ID: &str = "11111111-1111-1111-1111-111111111111";

/// A pure-stdlib module that answers the SDK's release-manifest probe, so the
/// fixture builds with no network and no module cache.
const MAIN_GO: &str = r#"package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type migrations struct{ App string }

type config struct {
	ID       string
	Slug     string
	Versions map[string]migrations
}

func main() {
	cfg := config{
		ID:   os.Getenv("MS_MODULE_ID"),
		Slug: "buildfixture",
		Versions: map[string]migrations{
			"v0.1.0": {App: "0001"},
		},
	}
	if os.Getenv("MS_SDK_TOOL_MODE") != "release-manifest-v1" {
		fmt.Println("fixture module")
		return
	}
	var in struct {
		SourceSHA256 string `json:"source_sha256"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	manifest, _ := json.Marshal(map[string]any{
		"id":       cfg.ID,
		"slug":     cfg.Slug,
		"versions": map[string]any{"v0.1.0": map[string]string{"app": "0001"}},
	})
	manifest = append(manifest, '\n')
	sum := sha256.Sum256(manifest)
	envelope, _ := json.Marshal(map[string]string{
		"protocol":        "mirrorstack.release-manifest/v1",
		"source_sha256":   in.SourceSHA256,
		"manifest_sha256": hex.EncodeToString(sum[:]),
		"manifest_base64": base64.StdEncoding.EncodeToString(manifest),
	})
	fmt.Println(string(envelope))
}
"#;

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.com",
        ])
        .args(args)
        .current_dir(root)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?}");
}

/// A committed Git repo holding the fixture module in `module/` (the CLI
/// refuses a module at the worktree root), plus an optional web dir.
fn fixture(web: bool) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "-q"]);
    let module = root.path().join("module");
    fs::create_dir_all(&module).unwrap();
    fs::write(module.join("main.go"), MAIN_GO).unwrap();
    fs::write(
        module.join("go.mod"),
        "module example.com/buildfixture\n\ngo 1.23\n",
    )
    .unwrap();
    fs::write(
        module.join("CHANGELOG.md"),
        "# Changelog\n\n## 0.1.0\n\n- first\n",
    )
    .unwrap();
    if web {
        fs::create_dir_all(module.join("web")).unwrap();
        fs::write(
            module.join("web/package.json"),
            r#"{"scripts":{"build":"true"}}"#,
        )
        .unwrap();
    }
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "-q", "-m", "fixture"]);
    (root, module)
}

/// A loopback port that nothing listens on.
fn closed_port_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("http://127.0.0.1:{port}")
}

/// The CLI with an empty HOME (no login file, no config), every platform URL
/// on a closed port, and no `.env` anywhere above the working directory.
fn cli(home: &Path, cwd: &Path, platform: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mirrorstack"));
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("APPDATA")
        .env("USERPROFILE", home);
    for key in [
        "MIRRORSTACK_API_URL",
        "MIRRORSTACK_APPS_API_URL",
        "MIRRORSTACK_WEB_URL",
        "MIRRORSTACK_DISPATCH_URL",
    ] {
        command.env(key, platform);
    }
    command
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            found.extend(walk(&path));
        }
        found.push(path);
    }
    found
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn zip_entry(zip: &Path, name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(fs::File::open(zip).unwrap()).unwrap();
    let mut entry = archive.by_name(name).unwrap();
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).unwrap();
    bytes
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

struct Built {
    receipt: serde_json::Value,
    zip: PathBuf,
    summary: serde_json::Value,
}

fn build(home: &Path, module: &Path, out: &Path, platform: &str) -> Built {
    let output = cli(home, module, platform)
        .args([
            "module",
            "build",
            "--json",
            "--api-only",
            "--module-id",
            MODULE_ID,
        ])
        .arg("--out")
        .arg(out)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "module build failed\n{}",
        text(&output)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!("stdout is not one JSON object ({error})\n{}", text(&output))
        });
    let receipt = serde_json::from_slice(&fs::read(out.join("receipt.json")).unwrap()).unwrap();
    Built {
        receipt,
        zip: out.join("bootstrap.zip"),
        summary,
    }
}

#[test]
#[ignore = "needs Go >= 1.26.10; run by the scaffold CI job"]
fn module_build_is_credential_free_and_deploy_is_not() {
    let platform = closed_port_url();
    let home = tempfile::tempdir().unwrap();
    let (_root, module) = fixture(false);
    let scratch = tempfile::tempdir().unwrap();

    // 1. Empty HOME + platform URLs on a closed port: build succeeds.
    let first = build(home.path(), &module, &scratch.path().join("one"), &platform);
    // The Go toolchain keeps its own local telemetry counters under the user
    // config dir; the CLI itself must leave nothing there (credentials live in
    // `<config>/mirrorstack/cli`).
    let cli_files: Vec<_> = walk(home.path())
        .into_iter()
        .filter(|path| {
            path.to_string_lossy()
                .to_lowercase()
                .contains("mirrorstack")
        })
        .collect();
    assert!(
        cli_files.is_empty(),
        "module build wrote into HOME: {cli_files:?}"
    );

    // 2. bootstrap_sha256 is the hash of the `bootstrap` entry read back out
    //    of the ZIP, in the receipt and in --json.
    let elf = zip_entry(&first.zip, "bootstrap");
    let bootstrap = first.receipt["artifact"]["bootstrap_sha256"]
        .as_str()
        .unwrap();
    assert_eq!(bootstrap, sha256_hex(&elf));
    assert_eq!(
        first.summary["bootstrap_sha256"].as_str().unwrap(),
        bootstrap
    );
    assert_eq!(
        first.receipt["artifact"]["sha256"].as_str().unwrap(),
        sha256_hex(&fs::read(&first.zip).unwrap()),
        "the receipt's artifact hash is the hash of the ZIP file"
    );
    assert_eq!(first.receipt["module_id"], MODULE_ID);
    assert_eq!(first.receipt["slug"], "buildfixture");
    assert_eq!(first.receipt["version"], "0.1.0");

    // 3. Two builds of the same source: same bootstrap hash (asserted), and
    //    the ZIP identity is a MEASURED fact printed for the PR.
    let second = build(home.path(), &module, &scratch.path().join("two"), &platform);
    assert_eq!(
        second.receipt["artifact"]["bootstrap_sha256"]
            .as_str()
            .unwrap(),
        bootstrap,
        "two builds of the same source must give the same bootstrap_sha256"
    );
    assert_eq!(
        second.receipt["source_sha256"],
        first.receipt["source_sha256"]
    );
    let identical = fs::read(&first.zip).unwrap() == fs::read(&second.zip).unwrap();
    let receipts_identical = fs::read(scratch.path().join("one/receipt.json")).unwrap()
        == fs::read(scratch.path().join("two/receipt.json")).unwrap();
    eprintln!(
        "MEASURED zip_byte_identical={identical} receipt_byte_identical={receipts_identical}"
    );

    // 4. Control, same environment: `module deploy` stops at the login step.
    let deploy = cli(home.path(), &module, &platform)
        .args(["module", "deploy", "--yes"])
        .output()
        .unwrap();
    assert!(
        !deploy.status.success(),
        "deploy must fail\n{}",
        text(&deploy)
    );
    let stderr = String::from_utf8_lossy(&deploy.stderr);
    assert!(stderr.contains("not signed in"), "{}", text(&deploy));
    assert!(
        !stderr.contains("127.0.0.1"),
        "deploy reached the network\n{}",
        text(&deploy)
    );
}

#[test]
#[ignore = "needs Go >= 1.26.10; run by the scaffold CI job"]
fn api_only_build_refuses_a_web_module_and_writes_nothing() {
    let platform = closed_port_url();
    let home = tempfile::tempdir().unwrap();
    let (_root, module) = fixture(true);
    let scratch = tempfile::tempdir().unwrap();
    let out = scratch.path().join("out");

    let output = cli(home.path(), &module, &platform)
        .args(["module", "build", "--api-only", "--module-id", MODULE_ID])
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("API-only build refuses web/package.json"),
        "{}",
        text(&output)
    );
    assert_eq!(
        fs::read_dir(&out).unwrap().count(),
        0,
        "a refused build wrote output"
    );
}
