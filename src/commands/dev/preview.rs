//! `mirrorstack preview` — serve a module's own review harness on localhost.
//!
//! 🔴 THIS IS NOT `dev`, AND THE DIFFERENCE IS THE POINT. `dev` brings up the
//! module binaries, a proxy, ports and optionally tunnels, because it runs the
//! module. A review of a module's SURFACE needs none of that: the harness
//! answers its own requests from fixtures, so there is no backend to start and
//! nothing to bind but one static server. Reviews were being blocked on a
//! running platform (or a live tunnel — one held four containers, the whole
//! machine's budget, for a day) when the only thing under review was a page.
//!
//! 🔴 AND THE HARNESS IS THE MODULE'S, NOT THE CLI'S. This command discovers a
//! `preview` script in the module's `web/package.json` and runs it, exactly as
//! the build path runs the module's declared `build`/`watch` — the CLI is Rust
//! and cannot build TS/React at all, and the chrome a harness needs lives in
//! web-ui-kit (`@mirrorstack-ai/module-preview`), on the module's own kit
//! version. A shell compiled into this binary would render a different
//! DevToolbar than the module's own pages on every kit release.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow};
use clap::Args;

use super::{spawn_forwarder, web_install_command};
use crate::commands::{ok_mark, warn_prefix};

/// The npm script a module declares to serve its review harness.
pub(crate) const PREVIEW_SCRIPT: &str = "preview";

/// Port the harness binds when nothing asks for another.
///
/// Deliberately NOT 3000/3011 (the review session's) and not in `dev`'s
/// 18080+/8089+ ranges, so a preview can run beside a dev stack.
pub(crate) const DEFAULT_PREVIEW_PORT: u16 = 5174;

#[derive(Args)]
pub struct PreviewArgs {
    /// Working directory containing go.work. Default: cwd.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Which module to preview. Required when more than one declares a
    /// `preview` script.
    #[arg(long, value_name = "SLUG")]
    module: Option<String>,
    /// Port to serve on. Default: 5174.
    #[arg(long)]
    port: Option<u16>,
    /// Print the URL without opening a browser.
    #[arg(long)]
    no_open: bool,
}

/// A module that can be previewed: its slug and its `web/` directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Previewable {
    pub slug: String,
    pub web_dir: PathBuf,
}

pub fn run(args: PreviewArgs) -> Result<()> {
    let root = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));
    let found = previewable_modules(&root)?;
    let chosen = choose(&found, args.module.as_deref())?;
    let port = args.port.unwrap_or(DEFAULT_PREVIEW_PORT);
    let url = format!("http://localhost:{port}");

    // Install before serving, and say so rather than failing later inside a
    // bundler with nothing pointing at the installer.
    let install = web_install_command(&chosen.web_dir)
        .current_dir(&chosen.web_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !matches!(install, Ok(s) if s.success()) {
        eprintln!(
            "{} {}: pnpm install failed — starting the preview anyway",
            warn_prefix(),
            chosen.slug
        );
    }

    // 🔴 THE URL IS PRINTED BEFORE ANY BROWSER IS OPENED, always. Opening is
    // best-effort (headless, SSH, a broken handler), and a command whose only
    // output was a failed open would look like it did nothing.
    println!("{} {} preview: {url}", ok_mark(), chosen.slug);
    if !args.no_open
        && let Err(err) = crate::browser::open(&url)
    {
        eprintln!("{} could not open a browser: {err}", warn_prefix());
    }

    let label: &'static str = Box::leak(format!("{}:preview", chosen.slug).into_boxed_str());
    let mut child = preview_command(port)
        .current_dir(&chosen.web_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| preview_spawn_error(err, &chosen.slug))?;
    spawn_forwarder(
        child.stdout.take().expect("piped stdout"),
        label,
        false,
        None,
    );
    spawn_forwarder(
        child.stderr.take().expect("piped stderr"),
        label,
        true,
        None,
    );

    let status = child.wait()?;
    if !status.success() {
        // A harness that exits non-zero has usually failed to bind or failed to
        // build; either way the operator needs the code, not a bare "error".
        return Err(anyhow!(
            "{}: the preview exited with {status} — its output is above",
            chosen.slug
        ));
    }
    Ok(())
}

/// The command that serves the harness, as a command nobody has run yet.
///
/// `PORT` is how the port reaches it: the script is the module's, so the CLI
/// cannot pass a flag it does not define. Every scaffolded harness reads
/// `process.env.PORT`.
pub(crate) fn preview_command(port: u16) -> Command {
    let mut cmd = Command::new("pnpm");
    cmd.args(["run", PREVIEW_SCRIPT]);
    cmd.env("PORT", port.to_string());
    cmd
}

/// Say which program is missing when the spawn itself fails.
///
/// `NotFound` here is pnpm, not the script: the module's own scripts say
/// `pnpm build:css && …`, so pnpm is required on PATH and a machine without it
/// gets one sentence naming it instead of an OS errno.
fn preview_spawn_error(err: io::Error, slug: &str) -> anyhow::Error {
    if err.kind() == io::ErrorKind::NotFound {
        return anyhow!("pnpm is not on PATH — install it to preview {slug}'s surface");
    }
    anyhow!("{slug}: could not start the preview: {err}")
}

/// Every module reachable from `dir` that declares a `preview` script.
///
/// 🔴 A WORKSPACE ROOT *OR* ONE MODULE'S DIRECTORY, AND THAT IS NOT A
/// CONVENIENCE. `dev` requires go.work because it runs the whole fleet; a
/// preview runs one static server against fixtures. Found by measuring rather
/// than reading: ms-app-modules' `go.work` is GITIGNORED, so it exists in the
/// shared checkout and in no worktree — `mirrorstack preview` inside a fresh
/// worktree of the very module under review failed on a missing workspace
/// file while the module's harness sat one directory away. A review tool that
/// needs more setup than the page it renders does not get used.
///
/// Workspace order (go.work) is preserved, so `--module` is never needed for a
/// deterministic choice — only to pick a different one.
pub(crate) fn previewable_modules(dir: &Path) -> Result<Vec<Previewable>> {
    if dir.join("go.work").is_file() {
        let mut out = Vec::new();
        for module in super::workspace::discover_dev_modules(dir)? {
            let web_dir = module.abs_dir.join("web");
            if !declares_preview(&web_dir) {
                continue;
            }
            out.push(Previewable {
                slug: slug_of(&module.abs_dir, dir),
                web_dir,
            });
        }
        return Ok(out);
    }

    let web_dir = dir.join("web");
    if declares_preview(&web_dir) {
        // The module's own root is the workspace root for the env lookup that
        // reads its id — which a preview never needs, so a miss is harmless.
        return Ok(vec![Previewable {
            slug: slug_of(dir, dir),
            web_dir,
        }]);
    }
    if dir.join("main.go").is_file() || web_dir.is_dir() {
        // A module, without a harness: the how-to is the useful answer.
        return Ok(Vec::new());
    }
    Err(anyhow!(
        "{} is neither a module workspace (no go.work) nor a module directory \
         (no main.go, no web/). Run this from one, or pass --dir.",
        dir.display()
    ))
}

/// Whether `web_dir` declares a non-empty `preview` script.
///
/// A declared-but-empty script is not a harness: running it would exit 0 having
/// served nothing, which is the silent-success shape the build path already
/// refuses for `build`/`watch`.
fn declares_preview(web_dir: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(web_dir.join("package.json")) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    parsed
        .get("scripts")
        .and_then(|s| s.get(PREVIEW_SCRIPT))
        .and_then(|s| s.as_str())
        .is_some_and(|body| !body.trim().is_empty())
}

/// The module's declared slug, falling back to its directory name.
///
/// A preview needs no platform binding — no app, no MS_MODULE_ID — so a module
/// whose main.go cannot be parsed is still previewable, named by its folder.
/// Refusing here would make the harness need more setup than the page does.
fn slug_of(module_dir: &Path, root: &Path) -> String {
    if let Ok(meta) = super::module_meta::read_module_meta(module_dir, root)
        && !meta.slug.trim().is_empty()
    {
        return meta.slug;
    }
    module_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "module".into())
}

/// Pick the module to preview, or explain what to pass.
pub(crate) fn choose<'a>(found: &'a [Previewable], asked: Option<&str>) -> Result<&'a Previewable> {
    if let Some(slug) = asked {
        return found
            .iter()
            .find(|m| m.slug == slug)
            .ok_or_else(|| unknown_module_error(found, slug));
    }
    match found {
        [] => Err(no_preview_error()),
        [only] => Ok(only),
        several => Err(anyhow!(
            "several modules declare a preview ({}) — pass --module <slug>",
            slugs(several)
        )),
    }
}

fn slugs(found: &[Previewable]) -> String {
    found
        .iter()
        .map(|m| m.slug.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn unknown_module_error(found: &[Previewable], slug: &str) -> anyhow::Error {
    if found.is_empty() {
        return no_preview_error();
    }
    anyhow!(
        "no module named {slug} declares a preview — available: {}",
        slugs(found)
    )
}

/// 🔴 SAY HOW TO GET ONE. "No previewable module" is a dead end; a module
/// author reading this needs the two facts that make one exist.
fn no_preview_error() -> anyhow::Error {
    anyhow!(
        "no module in this workspace declares a `preview` script in web/package.json.\n  \
         Add one that serves the module's own harness, e.g.\n    \
         \"preview\": \"node dev/serve.mjs\"\n  \
         and build the page with @mirrorstack-ai/module-preview, which renders the console's \
         real frame and header around your mount."
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    /// A workspace with one module per (slug, preview-script) pair. A `None`
    /// script writes a package.json without one.
    fn workspace(modules: &[(&str, Option<&str>)]) -> TempDir {
        let tmp = TempDir::new().expect("tempdir");
        let mut uses = String::from("go 1.24\n\nuse (\n");
        for (slug, script) in modules {
            let dir = tmp.path().join(slug);
            fs::create_dir_all(dir.join("web")).expect("mkdir");
            fs::write(
                dir.join("main.go"),
                format!("package main\n// Slug: \"{slug}\"\n"),
            )
            .expect("main.go");
            let scripts = match script {
                Some(body) => format!("{{\"preview\": \"{body}\"}}"),
                None => "{\"build\": \"node build.mjs\"}".to_string(),
            };
            fs::write(
                dir.join("web/package.json"),
                format!("{{\"name\": \"{slug}-web\", \"scripts\": {scripts}}}"),
            )
            .expect("package.json");
            uses.push_str(&format!("\t./{slug}\n"));
        }
        uses.push_str(")\n");
        fs::write(tmp.path().join("go.work"), uses).expect("go.work");
        tmp
    }

    #[test]
    fn discovers_only_modules_that_declare_a_preview() {
        let tmp = workspace(&[
            ("ai-assistant", Some("node dev/serve.mjs")),
            ("video-core", None),
            ("quiz-core", Some("node dev/serve.mjs")),
        ]);

        let found = previewable_modules(tmp.path()).expect("discover");

        // 🔴 A MODULE WITHOUT A HARNESS IS NOT SILENTLY SELECTED. It would be
        // "previewed" by running a script that does not exist, and pnpm's
        // error would read as a broken CLI rather than a missing harness.
        let names: Vec<&str> = found.iter().map(|m| m.slug.as_str()).collect();
        assert_eq!(names, vec!["ai-assistant", "quiz-core"]);
        assert!(found[0].web_dir.ends_with("ai-assistant/web"));
    }

    #[test]
    fn an_empty_preview_script_is_not_a_harness() {
        let tmp = workspace(&[("ai-assistant", Some("   "))]);

        assert!(
            previewable_modules(tmp.path())
                .expect("discover")
                .is_empty(),
            "a blank script would serve nothing and exit 0"
        );
    }

    #[test]
    fn one_module_needs_no_flag_and_several_do() {
        let one = workspace(&[("ai-assistant", Some("node dev/serve.mjs"))]);
        let found = previewable_modules(one.path()).expect("discover");
        assert_eq!(choose(&found, None).expect("single").slug, "ai-assistant");

        let many = workspace(&[
            ("ai-assistant", Some("node dev/serve.mjs")),
            ("quiz-core", Some("node dev/serve.mjs")),
        ]);
        let found = previewable_modules(many.path()).expect("discover");
        let err = choose(&found, None).expect_err("ambiguous").to_string();
        // The message has to carry the choices, or the operator has to go
        // reading package.json files to answer it.
        assert!(err.contains("--module"), "{err}");
        assert!(
            err.contains("ai-assistant") && err.contains("quiz-core"),
            "{err}"
        );

        assert_eq!(
            choose(&found, Some("quiz-core")).expect("named").slug,
            "quiz-core"
        );
    }

    #[test]
    fn an_unknown_module_lists_the_real_ones() {
        let tmp = workspace(&[("ai-assistant", Some("node dev/serve.mjs"))]);
        let found = previewable_modules(tmp.path()).expect("discover");

        let err = choose(&found, Some("video-core"))
            .expect_err("unknown")
            .to_string();
        assert!(err.contains("video-core"), "{err}");
        assert!(
            err.contains("ai-assistant"),
            "names what IS available: {err}"
        );
    }

    #[test]
    fn no_harness_anywhere_says_how_to_add_one() {
        let tmp = workspace(&[("video-core", None)]);
        let found = previewable_modules(tmp.path()).expect("discover");

        let err = choose(&found, None).expect_err("none").to_string();
        // 🔴 THE ERROR IS THE DOCUMENTATION. A module author hitting this needs
        // the script name, an example body, and where the shell comes from.
        assert!(err.contains("preview"), "{err}");
        assert!(err.contains("dev/serve.mjs"), "{err}");
        assert!(err.contains("@mirrorstack-ai/module-preview"), "{err}");
    }

    /// 🔴 THE CASE THAT SENT ME BACK TO THE DESIGN. ms-app-modules' go.work is
    /// GITIGNORED, so it exists in the shared checkout and in no worktree —
    /// running this from a fresh worktree of the very module under review
    /// failed on a missing workspace file while the harness sat one directory
    /// away. Found by running the command, not by reading it.
    #[test]
    fn a_module_directory_needs_no_workspace_file() {
        let tmp = workspace(&[("ai-assistant", Some("node dev/serve.mjs"))]);
        let module_dir = tmp.path().join("ai-assistant");
        fs::remove_file(tmp.path().join("go.work")).expect("rm go.work");

        let found = previewable_modules(&module_dir).expect("discover");

        assert_eq!(found.len(), 1, "the module's own directory is enough");
        assert_eq!(found[0].slug, "ai-assistant");
        assert!(found[0].web_dir.ends_with("ai-assistant/web"));
    }

    #[test]
    fn a_module_directory_without_a_harness_still_explains_itself() {
        let tmp = workspace(&[("video-core", None)]);
        let module_dir = tmp.path().join("video-core");
        fs::remove_file(tmp.path().join("go.work")).expect("rm go.work");

        // A module, no harness: the answer is the how-to, not "wrong place".
        let found = previewable_modules(&module_dir).expect("discover");
        assert!(found.is_empty());
        let err = choose(&found, None).expect_err("none").to_string();
        assert!(err.contains("dev/serve.mjs"), "{err}");
    }

    #[test]
    fn somewhere_that_is_neither_says_which_two_things_it_looked_for() {
        let tmp = TempDir::new().expect("tempdir");

        let err = previewable_modules(tmp.path())
            .expect_err("neither")
            .to_string();
        // Not "no previewable module": the operator is in the wrong directory,
        // and being told a module has no harness would send them editing one.
        assert!(err.contains("go.work"), "{err}");
        assert!(err.contains("main.go"), "{err}");
    }

    #[test]
    fn the_port_reaches_the_module_script_through_the_environment() {
        let cmd = preview_command(5199);

        assert_eq!(cmd.get_program(), "pnpm");
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(args, vec!["run", "preview"]);
        // The script is the module's, so a flag the CLI invented would not
        // reach it. PORT is the contract.
        let port = cmd
            .get_envs()
            .find(|(key, _)| *key == "PORT")
            .and_then(|(_, value)| value)
            .expect("PORT is set");
        assert_eq!(port, "5199");
    }

    #[test]
    fn the_default_port_avoids_the_ports_that_are_already_taken() {
        // 3000/3011 belong to the review session and dev binds 18080+/8089+;
        // a default that collided would make the first preview of the day fail
        // for a reason nobody would connect to this command.
        assert_ne!(DEFAULT_PREVIEW_PORT, 3000);
        assert_ne!(DEFAULT_PREVIEW_PORT, 3011);
        assert!(!(18080..18180).contains(&DEFAULT_PREVIEW_PORT));
        assert!(!(8089..8189).contains(&DEFAULT_PREVIEW_PORT));
    }

    #[test]
    fn a_missing_pnpm_is_named() {
        let err = preview_spawn_error(
            io::Error::new(io::ErrorKind::NotFound, "no such file"),
            "ai-assistant",
        )
        .to_string();
        assert!(err.contains("pnpm"), "{err}");

        let other = preview_spawn_error(
            io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
            "ai-assistant",
        )
        .to_string();
        assert!(
            other.contains("ai-assistant") && other.contains("denied"),
            "{other}"
        );
    }
}
