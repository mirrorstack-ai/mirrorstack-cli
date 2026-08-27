//! `mirrorstack app module …` — developer module management.
//!
//! Today: `module init` registers the module on the platform AND scaffolds a
//! local source tree from the SDK template. The scaffolded tree is what
//! `mirrorstack dev` (future) launches and tunnels into the platform.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use console::style;
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};

use crate::api::{
    self, ApiError, CreateModuleInput, RecordModuleVersionInput, SetModuleDeployInput,
};
use crate::commands::dev::module_meta::{self, ModuleMeta};
use crate::credentials;
use crate::http;

mod artifact;
pub(crate) mod capabilities;
mod changelog;
mod deploy;
mod init;
mod readme;
mod register;
mod rename;
mod scaffold;
mod version_move;

use super::{
    DEFAULT_API_BASE, DEFAULT_APPS_API_BASE, DEFAULT_DISPATCH_BASE, DEFAULT_WEB_BASE, ENV_API_URL,
    ENV_APPS_API_URL, ENV_DISPATCH_URL, ENV_WEB_URL, ok_mark, resolve_base, session_expired,
    warn_prefix,
};

#[derive(Args)]
pub struct ModuleArgs {
    #[command(subcommand)]
    command: ModuleCommand,
}

#[derive(Subcommand)]
enum ModuleCommand {
    /// Report the joined capability index for co-located or installed modules.
    Capabilities(capabilities::CapabilitiesArgs),
    /// Create a new module on the platform and scaffold locally.
    /// Interactive by default; pass --yes for non-interactive use.
    Init(InitArgs),
    /// Register all unregistered modules in the workspace with the
    /// platform. Scans go.work, finds modules with no MS_MODULE_ID_<SLUG>
    /// key in the workspace root's .env, creates them via the API, and
    /// writes the assigned ID back under that module's key in .env.
    Register(RegisterArgs),
    /// Rename a module slug while preserving its platform ID, installs, and
    /// tables. This is the safe alternative to re-registering after a rename.
    Rename(rename::RenameArgs),
    /// Deploy the version your code declares (the newest Config.Versions
    /// key in ./main.go). Cross-compiles the module for Linux/arm64 and
    /// packages it as a Lambda `bootstrap` zip, records the version with its
    /// CHANGELOG.md section when it isn't recorded yet — records are
    /// immutable, bump the key to ship a new entry — then uploads the
    /// artifact and points the deploy at it. The prod transport target is
    /// derived by the platform from the module's own identity, never
    /// supplied by the caller.
    Deploy(DeployArgs),
    /// Move one app's installed module onto another published version of
    /// that module. Forward by default; moving backwards needs an explicit
    /// --allow-downgrade. Omit --to to pick from the published versions.
    Move(version_move::MoveArgs),
}

#[derive(Args)]
pub struct InitArgs {
    /// Module name (human-readable). When omitted, prompts interactively.
    #[arg(long)]
    name: Option<String>,
    /// URL slug. When omitted, derived from --name. 3-16 chars, must start
    /// with a letter, end with a letter or digit, lowercase + hyphen only.
    /// The 16-char ceiling is the SDK's, and it is the binding one — see
    /// SLUG_MAX_BYTES.
    #[arg(long)]
    slug: Option<String>,
    /// Skip prompts. Requires --name; --slug optional (derived from name).
    #[arg(long, short)]
    yes: bool,
    /// If the slug is already registered to you, treat that as success and
    /// continue. Useful for re-running init in CI without conditional logic.
    #[arg(long)]
    used: bool,
    /// Skip filesystem scaffolding. Only register the module on the platform.
    #[arg(long)]
    no_scaffold: bool,
    /// Where to scaffold the new module source tree. Defaults to ./<slug>/
    /// in the current directory. Pass `.` to scaffold into the cwd directly.
    #[arg(long)]
    dir: Option<PathBuf>,
}

#[derive(Args)]
pub struct RegisterArgs {
    /// Working directory containing go.work. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Skip confirmation prompts.
    #[arg(long, short)]
    yes: bool,
    /// Create a new module even when the workspace `.env` holds module IDs
    /// that match no module here — only correct when this really is a
    /// brand-new module.
    #[arg(long)]
    allow_new: bool,
}

#[derive(Args)]
pub struct DeployArgs {
    /// Module slug. Defaults to Config.Slug parsed from ./main.go.
    #[arg(long)]
    module: Option<String>,
    /// Module directory containing main.go, CHANGELOG.md, and optional
    /// README.md. Defaults to cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Deploy transport status. Defaults to the platform's default ("active").
    #[arg(long, value_parser = ["active", "draining", "disabled"])]
    status: Option<String>,
    /// Non-interactive mode. Refuses `-dev` versions instead of offering
    /// to promote them.
    #[arg(long, short)]
    yes: bool,
}

pub fn run(args: ModuleArgs) -> Result<()> {
    match args.command {
        ModuleCommand::Capabilities(c) => capabilities::run(c),
        ModuleCommand::Init(i) => init::run(i),
        ModuleCommand::Register(r) => register::run(r),
        ModuleCommand::Rename(r) => rename::run(r),
        ModuleCommand::Deploy(d) => deploy::run(d),
        ModuleCommand::Move(m) => version_move::run(m),
    }
}

/// Read main.go metadata with a deploy-flavoured error. `deploy` runs
/// standalone against a single module directory (no `go.work` requirement,
/// unlike `register`/`dev`), so `dir` doubles as both the module dir and the
/// root its `.env` is read from — the same "root == scaffold target" rule
/// `init` uses for a fresh standalone module.
fn read_meta(dir: &Path) -> Result<ModuleMeta> {
    module_meta::read_module_meta(dir, dir).map_err(|e| {
        anyhow!(
            "couldn't read the module from {}: {e}. Run from the module directory, or pass --module <slug> / --dir <path>.",
            dir.display()
        )
    })
}

/// The version the code declares — the newest Config.Versions key.
fn code_version(meta: &ModuleMeta, dir: &Path) -> Result<String> {
    meta.version.clone().ok_or_else(|| {
        anyhow!(
            "no Config.Versions entry found in {}/main.go — declare your release, e.g. Versions: map[string]system.MigrationVersions{{\"v0.1.0\": {{App: \"0001\"}}}}.",
            dir.display()
        )
    })
}

/// Strip the SDK's `v` key prefix and validate canonical SemVer — the form
/// the platform stores and deploy sends on the wire.
fn canonical_version(raw: &str) -> Result<String> {
    let canonical = raw.strip_prefix('v').unwrap_or(raw);
    if module_meta::parse_semver(canonical).is_none() {
        return Err(anyhow!(
            "version '{raw}' in main.go is not SemVer (expected e.g. v1.2.0 or v1.2.0-beta.1)"
        ));
    }
    Ok(canonical.to_string())
}

/// Resolve the platform UUID by slug. The workspace root `.env`'s
/// `MS_MODULE_ID_<SLUG>` value is the sanitized `m<hex>` form, not the raw
/// UUID the version endpoints take. GET /v1/modules/{slug} is caller-scoped,
/// so this doubles as an ownership check.
fn get_owned_module(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    slug: &str,
) -> Result<api::Module> {
    match api::get_module(client, apps_base, access_token, slug) {
        Ok(Some(m)) => Ok(m),
        Ok(None) => Err(anyhow!(
            "module '{slug}' not found on the platform. The platform may still hold the OLD slug; use `mirrorstack app module rename --from <old-slug> --to {slug}`. `register` mints a new ID and orphans the existing install, so it is only correct if the module was never created."
        )),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

/// Parse `use` directives from go.work content (same logic as workspace.rs
/// but returns raw strings since we don't need abs paths here).
fn parse_go_work_use_dirs(body: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut in_block = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if in_block {
            if trimmed == ")" {
                in_block = false;
                continue;
            }
            if let Some(dir) = clean_go_work_path(trimmed) {
                result.push(dir);
            }
        } else if let Some(rest) = trimmed.strip_prefix("use") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
            } else if let Some(dir) = clean_go_work_path(rest) {
                result.push(dir);
            }
        }
    }
    result
}

fn clean_go_work_path(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.starts_with("//") {
        return None;
    }
    let s = match s.find("//") {
        Some(pos) => s[..pos].trim(),
        None => s,
    };
    let s = s.strip_prefix("./").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

/// Convert platform UUID to SDK-compatible module ID (same as scaffold.rs).
fn sanitize_module_id(uuid: &str) -> String {
    // If it already looks sanitized (starts with 'm', no hyphens), return as-is
    if uuid.starts_with('m') && !uuid.contains('-') {
        return uuid.to_string();
    }
    let mut out = String::with_capacity(33);
    out.push('m');
    for c in uuid.chars() {
        if c == '-' {
            continue;
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// Wrap a blocking call with a tick-driven spinner. Skipped entirely when
/// stderr isn't a TTY so CI logs and piped output stay clean — indicatif
/// can detect a non-tty target but `enable_steady_tick` still spawns the
/// timer thread, so we short-circuit before that.
fn with_spinner<T, F>(message: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    if !std::io::stderr().is_terminal() {
        return f();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(message.to_string());
    let result = f();
    pb.finish_and_clear();
    result
}

/// Same regex as the platform service and api-client-shared:
/// `^[a-z][a-z0-9-]{1,38}[a-z0-9]$`. Inlined as a manual check to avoid a
/// `regex` dependency for one pattern — the rule is small enough.
/// Upper bound on a module slug, in bytes.
///
/// 🔴 THIS NUMBER COMES FROM THE SDK, NOT FROM THE CATALOG. Three validators
/// see a slug and they did not agree: the platform catalog accepts 3-40, this
/// CLI accepted 3-40, and the SDK's `moduleSlugPattern`
/// (`^[a-z][a-z0-9-]{0,15}$`) caps it at 16. The SDK runs LAST — at `ms.Init`,
/// after `module init` has already POSTed the slug and the catalog has already
/// minted an ID for it. So a 17-char slug sailed through both remote checks and
/// then killed the module on every boot, leaving a registered module nobody can
/// run and a slug nobody else can claim.
///
/// The rule for a cross-repo validator chain is that the CALLER enforces the
/// narrowest link, because the narrowest link is the one that fails after the
/// side effects have landed. Keep this at the SDK's cap; if the SDK widens
/// `moduleSlugPattern`, widen this in the same wave.
const SLUG_MAX_BYTES: usize = 16;

/// The one rejection message for an invalid slug. It was written out twice,
/// which is how both copies came to advertise a bound neither validator held.
fn slug_invalid_error(slug: &str) -> anyhow::Error {
    anyhow!(
        "slug '{slug}' is invalid: must be 3-{SLUG_MAX_BYTES} chars, start with a letter, \
         end with a letter or digit, lowercase + hyphen only."
    )
}

fn slug_valid(s: &str) -> bool {
    let len = s.len();
    if !(3..=SLUG_MAX_BYTES).contains(&len) {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let last = bytes[len - 1];
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// Lowercase, replace runs of non-[a-z0-9] with single hyphens, trim leading
/// and trailing hyphens. Mirrors the web client's auto-suggest in
/// `useCreateModuleForm` so CLI users see the same default as web users.
fn derive_slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true; // skip leading hyphens
    for c in name.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_lowercase() || lc.is_ascii_digit() {
            out.push(lc);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn slug_error_hint(code: &str) -> &'static str {
    match code {
        "slug_taken" => " (pass --used to ignore when re-running)",
        "slug_reserved" => " (try a different slug — this name is reserved)",
        "slug_invalid" => "",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::init::is_cwd;
    // The deploy verb moved to deploy.rs; its hint helpers are tested here.
    use super::deploy::{changelog_preview, deploy_error_hint, record_error_hint};
    use super::*;

    #[test]
    fn slug_valid_accepts() {
        for s in ["media", "my-mod", "abc123", "a1-b2-c3", "ana-lytics"] {
            assert!(slug_valid(s), "expected {s:?} valid");
        }
    }

    #[test]
    fn slug_valid_rejects() {
        for s in ["", "ab", "AB", "1abc", "media-", "-media", "ab_cd"] {
            assert!(!slug_valid(s), "expected {s:?} invalid");
        }
    }

    #[test]
    fn slug_valid_rejects_too_long() {
        // 17 bytes: one past the SDK's cap, and the exact width that used to
        // register fine and then die at ms.Init.
        let s = "a".repeat(SLUG_MAX_BYTES + 1);
        assert!(!slug_valid(&s));
        assert!(
            slug_valid(&"a".repeat(SLUG_MAX_BYTES)),
            "16 must still pass"
        );
    }

    /// The CLI must never accept a slug the SDK's regex rejects — that
    /// direction strands a registration. Mirrors moduleSlugPattern
    /// (`^[a-z][a-z0-9-]{0,15}$`) rather than importing it: they are different
    /// languages in different repos, so the tie is kept by an assertion.
    #[test]
    fn slug_valid_never_looser_than_the_sdk_pattern() {
        let sdk_ok = |s: &str| {
            let b = s.as_bytes();
            (1..=16).contains(&s.len())
                && b[0].is_ascii_lowercase()
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        };
        for s in [
            "media",
            "a".repeat(16).as_str(),
            &"a".repeat(17),
            "my-really-long-module-slug",
            "Media",
            "1media",
        ] {
            assert!(
                !(slug_valid(s) && !sdk_ok(s)),
                "CLI accepts {s:?} but the SDK would reject it at ms.Init"
            );
        }
    }

    #[test]
    fn derive_slug_basic() {
        assert_eq!(derive_slug("Analytics"), "analytics");
        assert_eq!(derive_slug("My Cool Module"), "my-cool-module");
        assert_eq!(derive_slug("  Media!! "), "media");
        assert_eq!(derive_slug("foo___bar"), "foo-bar");
        assert_eq!(derive_slug("foo--bar"), "foo-bar");
    }

    #[test]
    fn derive_slug_strips_leading_and_trailing_hyphens() {
        assert_eq!(derive_slug("--media"), "media");
        assert_eq!(derive_slug("media--"), "media");
    }

    #[test]
    fn slug_error_hint_for_taken() {
        assert!(slug_error_hint("slug_taken").contains("--used"));
    }

    #[test]
    fn deploy_error_hint_for_known_codes() {
        // `not_found` has three emitters on these routes, so the hint may
        // carry only the remedy — naming one of the three would be wrong for
        // the other two.
        let not_found = deploy_error_hint("not_found");
        assert!(
            not_found.contains("mirrorstack app module deploy"),
            "{not_found}"
        );
        assert!(
            not_found.contains("mirrorstack app module register"),
            "{not_found}"
        );
        assert!(deploy_error_hint("invoke_target_invalid").contains("platform"));
        assert!(deploy_error_hint("status_invalid").contains("--status"));
        assert!(deploy_error_hint("artifact_missing").contains("module deploy"));
        // The platform only checks the ZIP magic and the size, so the hint
        // must not claim it inspected the archive for a `bootstrap` entry.
        let invalid = deploy_error_hint("artifact_invalid");
        assert!(invalid.contains("ZIP"), "{invalid}");
        assert!(!invalid.contains("bootstrap"), "{invalid}");
        assert!(deploy_error_hint("artifact_storage_unconfigured").contains("platform"));
        assert!(deploy_error_hint("conflict").contains("finalized"));
        assert!(deploy_error_hint("artifact_superseded").contains("another deploy"));
        assert!(deploy_error_hint("internal_error").contains("platform"));
        assert_eq!(deploy_error_hint("something_else"), "");
    }

    /// Every error code api-platform#440 can emit on the three platform
    /// routes `module deploy` calls — create-upload, finalize and deploy —
    /// must carry a hint. A bare `code: message` line with no explanation is
    /// exactly what this table exists to prevent, so the coverage is asserted
    /// rather than left to review.
    #[test]
    fn deploy_error_hint_covers_every_platform_code() {
        for code in [
            "not_found",                     // 404 — module, version, or pending artifact row
            "artifact_missing",              // 422 — finalize, object absent
            "artifact_invalid",              // 422 — finalize, empty/oversize/non-ZIP
            "artifact_superseded",           // 409 — finalize lost the compare-and-set
            "artifact_storage_unconfigured", // 503 — both artifact legs, no store wired
            "invoke_target_invalid",         // 422 — deploy
            "status_invalid",                // 422 — deploy
            "conflict",                      // 409 — deploy, artifact not ready
            "internal_error",                // 500 — all three
        ] {
            assert!(!deploy_error_hint(code).is_empty(), "no hint for `{code}`");
        }
    }

    #[test]
    fn record_error_hint_for_known_codes() {
        assert!(record_error_hint("version_invalid").contains("SemVer"));
        assert!(record_error_hint("changelog_too_large").contains("CHANGELOG.md"));
        assert!(record_error_hint("readme_too_large").contains("README.md"));
        // `version_exists` is intercepted by deploy (already-recorded path),
        // so the hint table deliberately has no entry for it.
        assert_eq!(record_error_hint("version_exists"), "");
        assert_eq!(record_error_hint("something_else"), "");
    }

    #[test]
    fn canonical_version_strips_v_prefix() {
        assert_eq!(canonical_version("v0.1.0").unwrap(), "0.1.0");
        assert_eq!(canonical_version("1.2.3-beta.1").unwrap(), "1.2.3-beta.1");
    }

    #[test]
    fn canonical_version_rejects_non_semver() {
        for s in ["v1.0", "one.two.three", "v1.2.3.4", ""] {
            assert!(canonical_version(s).is_err(), "expected {s:?} rejected");
        }
    }

    #[test]
    fn changelog_preview_truncates_with_ellipsis() {
        let body = "- a\n\n- b\n- c\n- d\n";
        assert_eq!(changelog_preview(body, 3), vec!["- a", "- b", "- c", "…"]);
        assert_eq!(changelog_preview("- only\n", 3), vec!["- only"]);
    }

    #[test]
    fn is_cwd_matches_cwd_variants() {
        assert!(is_cwd(Path::new(".")));
        assert!(is_cwd(Path::new("./")));
    }

    #[test]
    fn is_cwd_rejects_non_cwd_paths() {
        assert!(!is_cwd(Path::new("media")));
        assert!(!is_cwd(Path::new("./media")));
        assert!(!is_cwd(Path::new("a/b")));
        assert!(!is_cwd(Path::new("/tmp")));
    }
}
