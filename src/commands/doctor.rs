//! `mirrorstack doctor` — name every missing tool, sign-in, or version
//! problem on this machine, with its fix, before it surfaces as a late
//! error inside `dev` or `module deploy`.
//!
//! Read-only: no writes, no containers, no `module deploy`. Each check is
//! independent — a missing tool never stops the rest from running, so one
//! `doctor` call names everything wrong at once.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use console::style;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::api::{self, ApiError};
use crate::commands::module::scaffold::MIN_SDK_FOR_DEPLOY;
use crate::commands::release_candidate::process::{
    ProcessOutput, ProcessRunner, ProcessSpec, SystemRunner,
};
use crate::commands::release_candidate::{GO_VERSION_FLOOR, parse_go_version};
use crate::credentials;
use crate::http;

use super::{DEFAULT_API_BASE, ENV_API_URL, resolve_base};

const SDK_PATH: &str = "github.com/mirrorstack-ai/app-module-sdk";

#[derive(Args)]
#[command(after_help = "Examples:\n  mirrorstack doctor\n  mirrorstack doctor --json")]
pub struct DoctorArgs {
    /// Emit {"checks":[...]} instead of human-readable lines.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Warn,
    Fail,
    Info,
}

#[derive(Debug, Serialize)]
struct Check {
    id: &'static str,
    status: Status,
    detail: String,
    fix: String,
}

fn ok(id: &'static str, detail: impl Into<String>) -> Check {
    Check {
        id,
        status: Status::Ok,
        detail: detail.into(),
        fix: String::new(),
    }
}

fn warn(id: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        id,
        status: Status::Warn,
        detail: detail.into(),
        fix: fix.into(),
    }
}

fn fail(id: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        id,
        status: Status::Fail,
        detail: detail.into(),
        fix: fix.into(),
    }
}

fn info(id: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        id,
        status: Status::Info,
        detail: detail.into(),
        fix: fix.into(),
    }
}

#[derive(Debug, Serialize)]
struct Report {
    checks: Vec<Check>,
}

fn has_fail(report: &Report) -> bool {
    report.checks.iter().any(|c| c.status == Status::Fail)
}

pub fn run(args: DoctorArgs) -> Result<()> {
    let client = http::client(Duration::from_secs(10))?;
    let cwd = std::env::current_dir().context("doctor: read current directory")?;
    let api_base = resolve_base(ENV_API_URL, DEFAULT_API_BASE);

    let report = build_report(&SystemRunner, &client, &api_base, &cwd);
    print_report(&report, args.json)?;

    if has_fail(&report) {
        std::process::exit(1);
    }
    Ok(())
}

fn print_report(report: &Report, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(report)?);
        return Ok(());
    }
    for check in &report.checks {
        let marker = match check.status {
            Status::Ok => style("ok").green().bold(),
            Status::Warn => style("warn").yellow().bold(),
            Status::Fail => style("fail").red().bold(),
            Status::Info => style("info").cyan().bold(),
        };
        println!("{marker:<4} {:<16} {}", check.id, check.detail);
        if !check.fix.is_empty() {
            println!("     fix: {}", check.fix);
        }
    }
    Ok(())
}

fn build_report(runner: &dyn ProcessRunner, client: &Client, api_base: &str, cwd: &Path) -> Report {
    let mut checks = Vec::new();

    let go_available = check_go(runner, cwd, &mut checks);
    check_git(runner, cwd, &mut checks);
    check_node(runner, cwd, &mut checks);
    check_pnpm(runner, cwd, &mut checks);
    check_docker(runner, cwd, &mut checks);

    let identity = check_signed_in(client, api_base, &mut checks);
    check_platform_reachable(client, api_base, &mut checks);

    if cwd.join("main.go").is_file() {
        check_module_main_go(cwd, &mut checks);
        if go_available {
            check_module_sdk(runner, cwd, &mut checks);
        }
    }

    if let Some(identity) = identity {
        check_developer_mode(&identity, &mut checks);
    }

    Report { checks }
}

fn tool_spec(program: &str, cwd: &Path) -> ProcessSpec {
    ProcessSpec::new(program, cwd)
        .timeout(Duration::from_secs(10))
        .limits(16 * 1024, 16 * 1024)
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Returns whether `go` was found on PATH at all (even if below the floor),
/// so [`check_module_sdk`] — which also shells out to `go` — knows whether
/// to bother trying.
fn check_go(runner: &dyn ProcessRunner, cwd: &Path, checks: &mut Vec<Check>) -> bool {
    let spec = tool_spec("go", cwd).args(["env", "GOVERSION"]);
    match runner.run(&spec) {
        Ok(ProcessOutput {
            success: true,
            stdout,
            ..
        }) => {
            let version = first_line(&stdout);
            let floor =
                parse_go_version(GO_VERSION_FLOOR).expect("GO_VERSION_FLOOR is a Go version");
            match parse_go_version(&version) {
                Some(have) if have >= floor => {
                    checks.push(ok("go", version));
                }
                Some(_) => {
                    checks.push(fail(
                        "go",
                        format!(
                            "Go toolchain {version} is below the required floor {GO_VERSION_FLOOR}"
                        ),
                        format!("install Go {GO_VERSION_FLOOR} or newer: https://go.dev/dl/"),
                    ));
                }
                None => {
                    checks.push(fail(
                        "go",
                        format!("could not read a Go version from `{version}`"),
                        "reinstall Go: https://go.dev/dl/",
                    ));
                }
            }
            true
        }
        _ => {
            checks.push(fail(
                "go",
                "not found on PATH",
                "install Go: https://go.dev/dl/",
            ));
            false
        }
    }
}

fn check_git(runner: &dyn ProcessRunner, cwd: &Path, checks: &mut Vec<Check>) {
    let spec = tool_spec("git", cwd).arg("--version");
    match runner.run(&spec) {
        Ok(ProcessOutput {
            success: true,
            stdout,
            ..
        }) => checks.push(ok("git", first_line(&stdout))),
        _ => checks.push(fail(
            "git",
            "not found on PATH",
            "install git: https://git-scm.com/downloads",
        )),
    }
}

fn check_node(runner: &dyn ProcessRunner, cwd: &Path, checks: &mut Vec<Check>) {
    let spec = tool_spec("node", cwd).arg("--version");
    match runner.run(&spec) {
        Ok(ProcessOutput {
            success: true,
            stdout,
            ..
        }) => checks.push(ok("node", first_line(&stdout))),
        _ => checks.push(warn(
            "node",
            "not found on PATH",
            "install Node.js: https://nodejs.org — a Go-only module needs neither node nor pnpm",
        )),
    }
}

fn check_pnpm(runner: &dyn ProcessRunner, cwd: &Path, checks: &mut Vec<Check>) {
    let spec = tool_spec("pnpm", cwd).arg("--version");
    match runner.run(&spec) {
        Ok(ProcessOutput {
            success: true,
            stdout,
            ..
        }) => checks.push(ok("pnpm", first_line(&stdout))),
        _ => checks.push(warn(
            "pnpm",
            "not found on PATH",
            "install pnpm: https://pnpm.io/installation — a Go-only module needs neither node nor pnpm",
        )),
    }
}

fn check_docker(runner: &dyn ProcessRunner, cwd: &Path, checks: &mut Vec<Check>) {
    let spec = tool_spec("docker", cwd).arg("--version");
    match runner.run(&spec) {
        Ok(ProcessOutput {
            success: true,
            stdout,
            ..
        }) => checks.push(ok("docker", first_line(&stdout))),
        _ => checks.push(warn(
            "docker",
            "not found on PATH",
            "needed only for `mirrorstack dev --docker`",
        )),
    }
}

/// Loads credentials (refreshing an expired access token) and confirms them
/// against the platform. Returns the identity on success so
/// [`check_developer_mode`] can reuse the one call instead of asking again.
fn check_signed_in(
    client: &Client,
    api_base: &str,
    checks: &mut Vec<Check>,
) -> Option<api::Identity> {
    let mut creds = match credentials::load_or_login_hint() {
        Ok(creds) => creds,
        Err(_) => {
            checks.push(fail(
                "signed_in",
                "not signed in",
                "run `mirrorstack login`",
            ));
            return None;
        }
    };
    match credentials::with_refresh_retry(&mut creds, |tok| api::me_detail(client, api_base, tok)) {
        Ok(identity) => {
            checks.push(ok("signed_in", identity.email.clone()));
            Some(identity)
        }
        Err(ApiError::Unauthenticated) => {
            checks.push(fail(
                "signed_in",
                "session expired",
                "run `mirrorstack login` to sign in again",
            ));
            None
        }
        Err(e) => {
            checks.push(fail(
                "signed_in",
                format!("could not verify sign-in: {e}"),
                "check network connectivity, or set MIRRORSTACK_API_URL",
            ));
            None
        }
    }
}

fn check_platform_reachable(client: &Client, api_base: &str, checks: &mut Vec<Check>) {
    match client.get(api_base).send() {
        Ok(_) => checks.push(ok(
            "platform",
            format!("{api_base} is reachable (override with MIRRORSTACK_API_URL)"),
        )),
        Err(e) => checks.push(fail(
            "platform",
            format!("{api_base} is not reachable: {e}"),
            "check network connectivity, or set MIRRORSTACK_API_URL to a reachable platform",
        )),
    }
}

fn check_developer_mode(identity: &api::Identity, checks: &mut Vec<Check>) {
    let on = identity.developer_mode.unwrap_or(false);
    checks.push(info(
        "developer_mode",
        if on { "on" } else { "off" },
        "the CLI never needs this — it only changes whether the console shows module tools; \
         turn it on at https://account.mirrorstack.ai/settings/developer",
    ));
}

/// `Slug: "..."` out of `main.go`. Tolerates variable whitespace, same as
/// `dev::module_meta::extract_field`, which this intentionally does not
/// import: doctor only ever needs this one field, read-only.
fn extract_slug(go_source: &str) -> Option<String> {
    let after_label = go_source.split_once("Slug:")?.1;
    let after_quote = after_label.split_once('"')?.1;
    let (value, _) = after_quote.split_once('"')?;
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn check_module_main_go(cwd: &Path, checks: &mut Vec<Check>) {
    let path = cwd.join("main.go");
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(e) => {
            checks.push(fail(
                "module_main_go",
                format!("could not read {}: {e}", path.display()),
                "check file permissions",
            ));
            return;
        }
    };
    match extract_slug(&body) {
        Some(slug) => checks.push(ok("module_main_go", format!("slug: {slug}"))),
        None => checks.push(fail(
            "module_main_go",
            "main.go has no `Slug: \"...\"` field — is this a MirrorStack module?",
            "add a Slug to Config in main.go",
        )),
    }
}

#[derive(Debug, Deserialize)]
struct GoModEditOutput {
    #[serde(rename = "Require", default)]
    require: Vec<GoModRequire>,
}

#[derive(Debug, Deserialize)]
struct GoModRequire {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Version")]
    version: String,
}

/// `v0.4.12` -> `Some((0, 4, 12, true))`; a pseudo-version such as
/// `v0.4.12-0.20260101000000-abcdef123456` -> `Some((0, 4, 12, false))`.
/// Standard SemVer precedence: a pre-release/pseudo-version sorts below the
/// plain release sharing its numeric triple, so the `bool` slot alone makes
/// ordinary tuple comparison correct.
fn parse_semver(version: &str) -> Option<(u64, u64, u64, bool)> {
    let rest = version.strip_prefix('v')?;
    let (core, stable) = match rest.find(['-', '+']) {
        Some(at) => (&rest[..at], false),
        None => (rest, true),
    };
    let mut parts = core.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, stable))
}

fn check_module_sdk(runner: &dyn ProcessRunner, cwd: &Path, checks: &mut Vec<Check>) {
    if !cwd.join("go.mod").is_file() {
        checks.push(fail(
            "module_sdk",
            "no go.mod in this module folder",
            "run `go mod init` for this module",
        ));
        return;
    }

    let spec = tool_spec("go", cwd)
        .args(["mod", "edit", "-json"])
        .limits(1024 * 1024, 64 * 1024);
    let output = match runner.run(&spec) {
        Ok(ProcessOutput {
            success: true,
            stdout,
            ..
        }) => stdout,
        _ => {
            checks.push(fail(
                "module_sdk",
                "could not read go.mod (`go mod edit -json` failed)",
                "run `go mod tidy` and retry",
            ));
            return;
        }
    };

    let edit: GoModEditOutput = match serde_json::from_slice(&output) {
        Ok(edit) => edit,
        Err(e) => {
            checks.push(fail(
                "module_sdk",
                format!("could not parse `go mod edit -json`: {e}"),
                "run `go mod tidy` and retry",
            ));
            return;
        }
    };

    let Some(dep) = edit.require.iter().find(|r| r.path == SDK_PATH) else {
        checks.push(fail(
            "module_sdk",
            format!("go.mod does not require {SDK_PATH}"),
            format!("run `go get {SDK_PATH}@latest`"),
        ));
        return;
    };

    match (parse_semver(&dep.version), parse_semver(MIN_SDK_FOR_DEPLOY)) {
        (Some(have), Some(floor)) if have >= floor => {
            checks.push(ok("module_sdk", format!("{SDK_PATH} {}", dep.version)));
        }
        (Some(_), Some(_)) => {
            checks.push(fail(
                "module_sdk",
                format!(
                    "{SDK_PATH} {} is below the deploy floor {MIN_SDK_FOR_DEPLOY}",
                    dep.version
                ),
                format!("run `go get {SDK_PATH}@latest`"),
            ));
        }
        _ => {
            checks.push(fail(
                "module_sdk",
                format!("could not parse {SDK_PATH} version `{}`", dep.version),
                format!("run `go get {SDK_PATH}@latest`"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::time::SystemTime;

    use mockito::Server;

    enum FakeResult {
        Output(bool, &'static str),
        Missing,
    }

    struct FakeRunner {
        responses: BTreeMap<&'static str, FakeResult>,
    }

    impl FakeRunner {
        fn new() -> Self {
            Self {
                responses: BTreeMap::new(),
            }
        }

        fn success(mut self, program: &'static str, stdout: &'static str) -> Self {
            self.responses
                .insert(program, FakeResult::Output(true, stdout));
            self
        }

        fn failure(mut self, program: &'static str, stdout: &'static str) -> Self {
            self.responses
                .insert(program, FakeResult::Output(false, stdout));
            self
        }

        fn missing(mut self, program: &'static str) -> Self {
            self.responses.insert(program, FakeResult::Missing);
            self
        }
    }

    impl ProcessRunner for FakeRunner {
        fn run(&self, spec: &ProcessSpec) -> Result<ProcessOutput> {
            let program = spec.program.to_string_lossy().into_owned();
            match self.responses.get(program.as_str()) {
                Some(FakeResult::Output(success, stdout)) => Ok(ProcessOutput {
                    success: *success,
                    stdout: stdout.as_bytes().to_vec(),
                    stderr: Vec::new(),
                }),
                Some(FakeResult::Missing) => Err(anyhow::anyhow!(
                    "required tool `{program}` was not found on PATH"
                )),
                None => panic!("unexpected fake command: {program} {:?}", spec.args),
            }
        }
    }

    fn test_client() -> Client {
        http::client(Duration::from_secs(5)).expect("client")
    }

    fn tmp_cwd() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // --- tool checks -------------------------------------------------

    #[test]
    fn go_missing_fails_and_names_a_fix() {
        let dir = tmp_cwd();
        let mut checks = Vec::new();
        let runner = FakeRunner::new().missing("go");
        check_go(&runner, dir.path(), &mut checks);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(checks[0].detail.contains("not found"), "{:?}", checks[0]);
        assert!(checks[0].fix.contains("go.dev"), "{:?}", checks[0]);
    }

    #[test]
    fn go_below_floor_fails_and_names_the_floor() {
        let dir = tmp_cwd();
        let mut checks = Vec::new();
        let runner = FakeRunner::new().success("go", "go1.26.9");
        check_go(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(checks[0].detail.contains("go1.26.9"), "{:?}", checks[0]);
        assert!(
            checks[0].detail.contains(GO_VERSION_FLOOR),
            "{:?}",
            checks[0]
        );
    }

    #[test]
    fn go_at_floor_is_ok() {
        let dir = tmp_cwd();
        let mut checks = Vec::new();
        let runner = FakeRunner::new().success("go", GO_VERSION_FLOOR);
        let available = check_go(&runner, dir.path(), &mut checks);
        assert!(available);
        assert_eq!(checks[0].status, Status::Ok);
    }

    #[test]
    fn git_missing_fails() {
        let dir = tmp_cwd();
        let mut checks = Vec::new();
        let runner = FakeRunner::new().missing("git");
        check_git(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
    }

    #[test]
    fn node_pnpm_docker_missing_warn_not_fail() {
        let dir = tmp_cwd();
        let runner = FakeRunner::new()
            .missing("node")
            .missing("pnpm")
            .missing("docker");

        let mut checks = Vec::new();
        check_node(&runner, dir.path(), &mut checks);
        check_pnpm(&runner, dir.path(), &mut checks);
        check_docker(&runner, dir.path(), &mut checks);

        assert_eq!(checks.len(), 3);
        for check in &checks {
            assert_eq!(check.status, Status::Warn, "{check:?}");
        }
        assert!(checks[2].fix.contains("mirrorstack dev --docker"));
    }

    #[test]
    fn tool_a_nonzero_exit_is_also_a_failure() {
        let dir = tmp_cwd();
        let mut checks = Vec::new();
        let runner = FakeRunner::new().failure("git", "");
        check_git(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
    }

    // --- signed in / platform -----------------------------------------

    fn write_credentials() {
        credentials::save(&credentials::Credentials {
            access_token: ["doctor", "test", "access", "token"].concat(),
            refresh_token: ["doctor", "test", "refresh", "token"].concat(),
            expires_at: SystemTime::now() + Duration::from_secs(900),
        })
        .expect("save fixture credentials");
    }

    #[test]
    fn signed_out_fails_with_login_hint() {
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tmp_cwd();
        let _restore = credentials::redirect_config_dir(dir.path());

        let mut checks = Vec::new();
        let client = test_client();
        let identity = check_signed_in(&client, "http://127.0.0.1:1", &mut checks);

        assert!(identity.is_none());
        assert_eq!(checks[0].id, "signed_in");
        assert_eq!(checks[0].status, Status::Fail);
        assert!(
            checks[0].fix.contains("mirrorstack login"),
            "{:?}",
            checks[0]
        );
    }

    #[test]
    fn signed_in_prints_the_email_and_never_a_token() {
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tmp_cwd();
        let _restore = credentials::redirect_config_dir(dir.path());
        write_credentials();

        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/auth/me")
            .match_query(mockito::Matcher::UrlEncoded("detail".into(), "true".into()))
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "id": "u-1",
                    "email": "dev@example.com",
                    "name": "Dev",
                    "developer_mode": true
                })
                .to_string(),
            )
            .create();

        let mut checks = Vec::new();
        let client = test_client();
        let identity = check_signed_in(&client, &server.url(), &mut checks);

        let identity = identity.expect("signed in");
        assert_eq!(identity.email, "dev@example.com");
        assert_eq!(checks[0].status, Status::Ok);
        assert_eq!(checks[0].detail, "dev@example.com");

        let serialized = serde_json::to_string(&checks).unwrap();
        assert!(!serialized.contains("doctortestaccesstoken"));
    }

    #[test]
    fn platform_reachable_reports_the_base_and_the_override_hint() {
        let mut server = Server::new();
        let _m = server.mock("GET", "/").with_status(200).create();

        let mut checks = Vec::new();
        check_platform_reachable(&test_client(), &server.url(), &mut checks);

        assert_eq!(checks[0].status, Status::Ok);
        assert!(checks[0].detail.contains(&server.url()));
        assert!(checks[0].detail.contains("MIRRORSTACK_API_URL"));
    }

    #[test]
    fn platform_unreachable_fails() {
        let client = http::client(Duration::from_millis(200)).unwrap();
        let mut checks = Vec::new();
        check_platform_reachable(&client, "http://127.0.0.1:1", &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
    }

    // --- module checks --------------------------------------------------

    #[test]
    fn module_checks_are_skipped_outside_a_module_folder() {
        let dir = tmp_cwd();
        let report = build_report(
            &FakeRunner::new()
                .missing("go")
                .missing("git")
                .missing("node")
                .missing("pnpm")
                .missing("docker"),
            &test_client(),
            "http://127.0.0.1:1",
            dir.path(),
        );
        assert!(!report.checks.iter().any(|c| c.id == "module_main_go"));
        assert!(!report.checks.iter().any(|c| c.id == "module_sdk"));
    }

    #[test]
    fn module_main_go_fails_without_a_slug() {
        let dir = tmp_cwd();
        std::fs::write(dir.path().join("main.go"), "package main\n").unwrap();
        let mut checks = Vec::new();
        check_module_main_go(dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
    }

    #[test]
    fn module_main_go_ok_with_a_slug() {
        let dir = tmp_cwd();
        std::fs::write(
            dir.path().join("main.go"),
            "var Config = system.Config{Slug: \"my-module\"}\n",
        )
        .unwrap();
        let mut checks = Vec::new();
        check_module_main_go(dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Ok);
        assert!(checks[0].detail.contains("my-module"));
    }

    #[test]
    fn module_sdk_fails_without_go_mod() {
        let dir = tmp_cwd();
        let mut checks = Vec::new();
        // No FakeRunner responses configured: a call here would panic,
        // proving the check returns before shelling out to `go`.
        let runner = FakeRunner::new();
        check_module_sdk(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(checks[0].detail.contains("go.mod"));
    }

    #[test]
    fn module_sdk_fails_below_the_deploy_floor() {
        let dir = tmp_cwd();
        std::fs::write(dir.path().join("go.mod"), "module example\n").unwrap();
        let runner = FakeRunner::new().success(
            "go",
            r#"{"Require":[{"Path":"github.com/mirrorstack-ai/app-module-sdk","Version":"v0.4.6"}]}"#,
        );
        let mut checks = Vec::new();
        check_module_sdk(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(checks[0].detail.contains("v0.4.6"));
        assert!(checks[0].detail.contains(MIN_SDK_FOR_DEPLOY));
    }

    #[test]
    fn module_sdk_ok_at_the_deploy_floor() {
        let dir = tmp_cwd();
        std::fs::write(dir.path().join("go.mod"), "module example\n").unwrap();
        let runner = FakeRunner::new().success(
            "go",
            r#"{"Require":[{"Path":"github.com/mirrorstack-ai/app-module-sdk","Version":"v0.4.12"}]}"#,
        );
        let mut checks = Vec::new();
        check_module_sdk(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Ok);
    }

    #[test]
    fn module_sdk_fails_without_the_dependency() {
        let dir = tmp_cwd();
        std::fs::write(dir.path().join("go.mod"), "module example\n").unwrap();
        let runner = FakeRunner::new().success("go", r#"{"Require":[]}"#);
        let mut checks = Vec::new();
        check_module_sdk(&runner, dir.path(), &mut checks);
        assert_eq!(checks[0].status, Status::Fail);
        assert!(checks[0].detail.contains(SDK_PATH));
    }

    // --- developer mode ---------------------------------------------------

    #[test]
    fn developer_mode_is_info_never_fail() {
        for on in [true, false] {
            let identity = api::Identity {
                id: "u-1".into(),
                email: "dev@example.com".into(),
                name: "Dev".into(),
                profile_url: None,
                slug: None,
                developer_mode: Some(on),
            };
            let mut checks = Vec::new();
            check_developer_mode(&identity, &mut checks);
            assert_eq!(checks[0].status, Status::Info);
            assert_ne!(checks[0].status, Status::Fail);
        }
    }

    // --- semver ----------------------------------------------------------

    #[test]
    fn parse_semver_reads_a_plain_release() {
        assert_eq!(parse_semver("v0.4.12"), Some((0, 4, 12, true)));
    }

    #[test]
    fn parse_semver_treats_a_pseudo_version_as_a_prerelease() {
        let pseudo = parse_semver("v0.4.12-0.20260101000000-abcdef123456").unwrap();
        assert_eq!((pseudo.0, pseudo.1, pseudo.2), (0, 4, 12));
        assert!(!pseudo.3);
        assert!(pseudo < parse_semver("v0.4.12").unwrap());
    }

    #[test]
    fn parse_semver_rejects_a_version_without_v() {
        assert_eq!(parse_semver("0.4.12"), None);
    }

    // --- report shape / ids -----------------------------------------------

    #[test]
    fn json_report_has_one_object_per_check_with_the_stable_fields() {
        let checks = vec![
            ok("go", "go1.26.10"),
            warn(
                "docker",
                "not found on PATH",
                "needed only for dev --docker",
            ),
            fail("signed_in", "not signed in", "run `mirrorstack login`"),
            info("developer_mode", "off", "turn it on in the console"),
        ];
        let report = Report { checks };
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        let checks = value["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 4);
        for check in checks {
            assert!(check["id"].is_string());
            assert!(check["status"].is_string());
            assert!(check["detail"].is_string());
            assert!(check["fix"].is_string());
        }
        assert_eq!(value["checks"][2]["status"], "fail");
        assert_eq!(value["checks"][3]["status"], "info");
    }

    #[test]
    fn check_ids_are_stable() {
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tmp_cwd();
        let _restore = credentials::redirect_config_dir(dir.path());
        write_credentials();

        std::fs::write(
            dir.path().join("main.go"),
            "var Config = system.Config{Slug: \"my-module\"}\n",
        )
        .unwrap();
        // No go.mod: `module_sdk` still appears (id-stable), it just fails
        // fast without shelling out to `go` — so the fake, keyed only on
        // program name, doesn't need to distinguish `go env GOVERSION` from
        // `go mod edit -json`.

        let mut server = Server::new();
        let _m = server
            .mock("GET", "/v1/auth/me")
            .match_query(mockito::Matcher::UrlEncoded("detail".into(), "true".into()))
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "id": "u-1",
                    "email": "dev@example.com",
                    "name": "Dev",
                    "developer_mode": false
                })
                .to_string(),
            )
            .create();
        let _root = server.mock("GET", "/").with_status(200).create();

        let runner = FakeRunner::new()
            .success("go", GO_VERSION_FLOOR)
            .success("git", "git version 2.43.0")
            .missing("node")
            .missing("pnpm")
            .missing("docker");

        let report = build_report(&runner, &test_client(), &server.url(), dir.path());
        let ids: Vec<&str> = report.checks.iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            vec![
                "go",
                "git",
                "node",
                "pnpm",
                "docker",
                "signed_in",
                "platform",
                "module_main_go",
                "module_sdk",
                "developer_mode",
            ]
        );
    }
}
