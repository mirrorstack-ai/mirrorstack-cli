//! `mirrorstack module init --offline --module-id <uuid>` — the sandbox path.
//!
//! Runs the real binary with an empty HOME and every platform URL pointed at
//! a closed port, so any login or platform call would fail the run.

use std::path::Path;
use std::process::{Command, Output};

const UUID: &str = "bb8a3f8b-1234-5678-9abc-def012345678";

fn init(home: &Path, cwd: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mirrorstack"))
        .args([
            "module",
            "init",
            "--offline",
            "--name",
            "Media",
            "--dir",
            "out",
        ])
        .args(extra)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        // A call to any of these would be refused at once.
        .env("MIRRORSTACK_API_URL", "http://127.0.0.1:1")
        .env("MIRRORSTACK_APPS_API_URL", "http://127.0.0.1:1")
        .env("MIRRORSTACK_WEB_URL", "http://127.0.0.1:1")
        .output()
        .expect("run mirrorstack")
}

#[test]
fn offline_init_writes_the_tree_including_go_sum_with_no_login() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let out = init(home.path(), cwd.path(), &["--module-id", UUID]);
    assert!(
        out.status.success(),
        "init --offline failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = cwd.path().join("out");
    for rel in ["go.mod", "go.sum", "main.go", ".env"] {
        assert!(tree.join(rel).exists(), "missing {rel}");
    }
    let sum = std::fs::read_to_string(tree.join("go.sum")).unwrap();
    assert!(sum.contains("github.com/mirrorstack-ai/app-module-sdk"));
    let env = std::fs::read_to_string(tree.join(".env")).unwrap();
    assert_eq!(
        env,
        "MS_MODULE_ID_MEDIA=mbb8a3f8b123456789abcdef012345678\n"
    );
    // The empty HOME stayed empty: no credentials file was read or written.
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn offline_init_refuses_a_malformed_module_id() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let out = init(home.path(), cwd.path(), &["--module-id", "not-a-uuid"]);
    assert!(!out.status.success());
    assert!(!cwd.path().join("out").exists());
}

#[test]
fn offline_requires_module_id() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    assert!(!init(home.path(), cwd.path(), &[]).status.success());
}

/// The scaffold builds with the network OFF against a pre-populated module
/// cache — what the sandbox image bakes. Priming the cache needs the network,
/// so this is `#[ignore]` and CI runs it explicitly (scaffold job).
#[test]
#[ignore = "needs the Go toolchain and network to prime the cache; run explicitly in CI"]
fn offline_scaffold_builds_with_goproxy_off_against_a_baked_cache() {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let out = init(home.path(), cwd.path(), &["--module-id", UUID]);
    assert!(out.status.success());
    let tree = cwd.path().join("out");

    let go = |args: &[&str], env: &[(&str, &str)]| -> Output {
        let mut c = Command::new("go");
        c.args(args)
            .current_dir(&tree)
            .env("GOMODCACHE", cache.path())
            .env("GOFLAGS", "-mod=readonly");
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().expect("go on PATH")
    };
    // Bake: the only networked step.
    let o = go(&["mod", "download"], &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // Build: no proxy, readonly go.mod/go.sum, no tidy.
    let o = go(&["build", "./..."], &[("GOPROXY", "off")]);
    assert!(
        o.status.success(),
        "offline build failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}
