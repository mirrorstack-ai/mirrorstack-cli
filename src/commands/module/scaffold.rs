//! Scaffold a new local module source tree from the embedded template.
//!
//! Templates are vendored under `templates/module/` and embedded at build
//! time via `include_str!`. Substitution is straight string replace using
//! `__MS_*__` markers — no template engine, no Go-template syntax conflicts.
//!
//! Source of truth for the template shape is the SDK's
//! `examples/template/`. When the SDK changes shape, the vendored copy here
//! must be re-synced — there is no automatic mirroring yet.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

const MAIN_GO: &str = include_str!("../../../templates/module/main.go.tmpl");
const MCP_GO: &str = include_str!("../../../templates/module/mcp.go.tmpl");
const ROUTES_GO: &str = include_str!("../../../templates/module/routes.go.tmpl");
const GO_MOD: &str = include_str!("../../../templates/module/go.mod.tmpl");
const SQL_INIT: &str = include_str!("../../../templates/module/sql/app/0001_init.up.sql.tmpl");

// Placeholder tokens. Kept in one place so the contract between the .tmpl
// files and this renderer is auditable from a single grep.
const SLUG_TOKEN: &str = "__MS_SLUG__";
const NAME_TOKEN: &str = "__MS_NAME__";
const MODULE_ID_TOKEN: &str = "__MS_MODULE_ID__";

/// Inputs collected by the caller before scaffolding.
///
/// `module_id` is the platform-assigned UUID — stable across slug renames,
/// which is why both `Config.ID` and the table prefix derive from it rather
/// than from the URL slug.
pub(super) struct Inputs<'a> {
    pub slug: &'a str,
    pub name: &'a str,
    pub module_id: &'a str,
}

/// Refuse if `target` already contains files. Empty dir or missing dir = OK.
pub(super) fn ensure_target_writable(target: &Path) -> Result<()> {
    match fs::read_dir(target) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(anyhow!(
                    "{} is not empty — pick a different --dir or remove it",
                    target.display()
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("scaffold: read {}: {e}", target.display())),
    }
}

pub(super) fn write_tree(target: &Path, inputs: &Inputs<'_>) -> Result<()> {
    fs::create_dir_all(target.join("sql/app"))
        .with_context(|| format!("scaffold: mkdir {}/sql/app", target.display()))?;

    write_file(target, "main.go", MAIN_GO, inputs)?;
    write_file(target, "mcp.go", MCP_GO, inputs)?;
    write_file(target, "routes.go", ROUTES_GO, inputs)?;
    write_file(target, "go.mod", GO_MOD, inputs)?;
    write_file(target, "sql/app/0001_init.up.sql", SQL_INIT, inputs)?;
    Ok(())
}

/// Write a rendered template using `create_new` semantics so a file racing
/// in between `ensure_target_writable` and here surfaces as an error rather
/// than a silent overwrite. The caller's own `--dir` is the source of truth
/// for what's safe to write — anything that appeared after we checked is
/// not ours to clobber.
fn write_file(target: &Path, rel: &str, body: &str, inputs: &Inputs<'_>) -> Result<()> {
    let path = target.join(rel);
    let rendered = render(body, inputs);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("scaffold: create {}", path.display()))?;
    f.write_all(rendered.as_bytes())
        .with_context(|| format!("scaffold: write {}", path.display()))?;
    Ok(())
}

fn render(body: &str, inputs: &Inputs<'_>) -> String {
    body.replace(SLUG_TOKEN, inputs.slug)
        .replace(NAME_TOKEN, inputs.name)
        .replace(MODULE_ID_TOKEN, &sanitize_module_id(inputs.module_id))
}

/// Convert a platform UUID (`bb8a3f8b-1234-5678-9abc-def012345678`) into a
/// valid Postgres identifier and `Config.ID`: strip hyphens, prepend a
/// literal `m` so the result always starts with a letter (UUIDs may begin
/// with a digit), and lowercase the hex (already lowercase out of
/// `gen_random_uuid()`, but normalize defensively for any other source).
///
/// The SDK's `moduleIDPattern` regex caps `Config.ID` at 36 chars; this
/// produces 33 (`m` + 32 hex), which fits with margin.
fn sanitize_module_id(uuid: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_UUID: &str = "bb8a3f8b-1234-5678-9abc-def012345678";
    const SAMPLE_SANITIZED: &str = "mbb8a3f8b123456789abcdef012345678";

    fn ins<'a>(slug: &'a str, name: &'a str) -> Inputs<'a> {
        Inputs {
            slug,
            name,
            module_id: SAMPLE_UUID,
        }
    }

    #[test]
    fn render_substitutes_module_id_into_config_id() {
        let out = render(MAIN_GO, &ins("my-mod", "My Mod"));
        assert!(
            out.contains(&format!(r#"ID:   "{}""#, SAMPLE_SANITIZED)),
            "rendered main.go missing UUID-derived Config.ID"
        );
        assert!(out.contains(r#"Name: "My Mod""#));
        assert!(!out.contains("__MS_SLUG__"));
        assert!(!out.contains("__MS_NAME__"));
        assert!(!out.contains("__MS_MODULE_ID__"));
    }

    #[test]
    fn render_substitutes_slug_into_config_slug() {
        // Slug field is the SDK v0.2.0 catalog handle. The scaffolded
        // module needs it set so the manifest carries it from day one;
        // missing-slug behavior (dev-only mode) is for hand-written
        // never-deployed modules, not the CLI scaffold.
        let out = render(MAIN_GO, &ins("oauth", "OAuth"));
        assert!(
            out.contains(r#"Slug: "oauth""#),
            "rendered main.go missing Config.Slug substitution"
        );
    }

    #[test]
    fn render_versions_default_is_dev_prerelease() {
        // Pre-1.0 dev builds use `v0.1.0-dev` so `mirrorstack module deploy` can
        // refuse `-dev` versions in CI (--yes) by convention. Promotion
        // happens at deploy time. See docs/module-identity-and-storage-prefix.md.
        let out = render(MAIN_GO, &ins("media", "Media"));
        assert!(
            out.contains(r#""v0.1.0-dev": {App: "0001"}"#),
            "expected v0.1.0-dev as scaffold default version"
        );
        assert!(!out.contains(r#""v0.1.0": {App: "0001"}"#));
    }

    #[test]
    fn render_dependson_example_matches_v0_2_shape() {
        // The doc-comment example must reflect the v0.2.0 contract:
        // owner-prefixed id with version constraint, plus the Need
        // callback declaring tables/events. The pre-v0.2.0 bare-id
        // example (`ms.DependsOn("oauth-core")`) misled scaffolded
        // modules into a shape the catalog won't accept anymore.
        let out = render(MAIN_GO, &ins("media", "Media"));
        assert!(
            out.contains(r#"ms.DependsOn("@anna/oauth@^1.0.0", func(n *ms.Need)"#),
            "DependsOn example must use @<owner>/<id>@<version> + Need callback"
        );
        assert!(
            !out.contains(r#"ms.DependsOn("oauth-core")"#),
            "stale bare-id DependsOn example still present"
        );
    }

    #[test]
    fn render_substitutes_in_go_mod() {
        let out = render(GO_MOD, &ins("media", "Media"));
        assert!(out.starts_with("module media\n"));
        assert!(!out.contains("__MS_SLUG__"));
    }

    #[test]
    fn render_go_mod_pins_sdk_v0_2() {
        // Scaffolded modules must link against SDK v0.2.0+ to get Need /
        // OptionalDependOn — the template's main.go uses both.
        let out = render(GO_MOD, &ins("media", "Media"));
        assert!(
            out.contains("github.com/mirrorstack-ai/app-module-sdk v0.2.0"),
            "go.mod must pin SDK v0.2.0 to match scaffolded API surface"
        );
    }

    #[test]
    fn sanitize_module_id_strips_hyphens_and_prepends_letter() {
        assert_eq!(sanitize_module_id(SAMPLE_UUID), SAMPLE_SANITIZED);
        // UUIDs that start with a digit still produce an identifier-safe ID.
        assert_eq!(
            sanitize_module_id("01234567-89ab-cdef-0123-456789abcdef"),
            "m0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn sanitize_module_id_normalizes_uppercase() {
        assert_eq!(
            sanitize_module_id("BB8A3F8B-1234-5678-9ABC-DEF012345678"),
            SAMPLE_SANITIZED
        );
    }

    #[test]
    fn sanitize_module_id_fits_under_sdk_regex_ceiling() {
        // SDK's moduleIDPattern allows up to 36 chars. We emit "m" + 32 hex = 33.
        let out = sanitize_module_id(SAMPLE_UUID);
        assert!(
            out.len() <= 36,
            "sanitized ID {out} exceeds SDK regex limit"
        );
        assert!(out.starts_with('m'));
    }

    #[test]
    fn render_sql_uses_module_id_table_prefix() {
        let out = render(SQL_INIT, &ins("my-mod", "My Mod"));
        let expected = format!("CREATE TABLE IF NOT EXISTS {}_items", SAMPLE_SANITIZED);
        assert!(out.contains(&expected), "missing {expected:?}");
        assert!(!out.contains("__MS_MODULE_ID__"));
    }

    #[test]
    fn render_routes_substitutes_slug_in_response_body() {
        // Slug stays the user-facing label even though Config.ID is UUID-derived.
        let out = render(ROUTES_GO, &ins("media", "Media"));
        assert!(out.contains(r#""hello from media""#));
    }

    #[test]
    fn ensure_target_writable_accepts_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        ensure_target_writable(&missing).unwrap();
    }

    #[test]
    fn ensure_target_writable_accepts_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_target_writable(tmp.path()).unwrap();
    }

    #[test]
    fn ensure_target_writable_rejects_non_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("anything"), b"x").unwrap();
        let err = ensure_target_writable(tmp.path()).unwrap_err();
        assert!(err.to_string().contains("not empty"));
    }

    #[test]
    fn write_tree_creates_expected_files() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("media");
        write_tree(&target, &ins("media", "Media")).unwrap();
        for rel in [
            "main.go",
            "mcp.go",
            "routes.go",
            "go.mod",
            "sql/app/0001_init.up.sql",
        ] {
            let p = target.join(rel);
            assert!(p.exists(), "missing {}", p.display());
        }
        let main = fs::read_to_string(target.join("main.go")).unwrap();
        assert!(main.contains(&format!(r#"ID:   "{}""#, SAMPLE_SANITIZED)));
    }

    #[test]
    fn write_tree_refuses_to_clobber_a_racing_file() {
        // Mirrors the TOCTOU window between ensure_target_writable and
        // write_tree: a file slipped in after the empty-dir check should
        // surface as an error, not be silently overwritten.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().to_path_buf();
        fs::create_dir_all(target.join("sql/app")).unwrap();
        fs::write(target.join("main.go"), b"do not clobber").unwrap();
        let err = write_tree(&target, &ins("media", "Media")).unwrap_err();
        assert!(err.to_string().contains("create"));
        // Original file still intact.
        assert_eq!(
            fs::read_to_string(target.join("main.go")).unwrap(),
            "do not clobber"
        );
    }
}
