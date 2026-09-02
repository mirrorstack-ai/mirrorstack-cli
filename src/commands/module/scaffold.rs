//! Scaffold a module using the canonical layered source tree.

use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow};

use crate::commands::dev::module_meta;

const MAIN_GO: &str = include_str!("../../../templates/module/main.go.tmpl");
const GO_MOD: &str = include_str!("../../../templates/module/go.mod.tmpl");
const GITIGNORE: &str = include_str!("../../../templates/module/.gitignore.tmpl");
const README: &str = include_str!("../../../templates/module/README.md.tmpl");
const CONTRIBUTING: &str = include_str!("../../../templates/module/CONTRIBUTING.md.tmpl");
const MANIFEST: &str = include_str!("../../../templates/module/manifest/register.go.tmpl");
const REST_ROUTES: &str =
    include_str!("../../../templates/module/internal/transport/rest/routes.go.tmpl");
const MCP_TOOLS: &str =
    include_str!("../../../templates/module/internal/transport/mcp/tools.go.tmpl");
const DOCS_README: &str = include_str!("../../../templates/module/docs/README.md.tmpl");
const CHANGELOG: &str = include_str!("../../../templates/module/docs/CHANGELOG.md.tmpl");
const SQL_APP_UP: &str = include_str!("../../../templates/module/sql/app/0001_init.up.sql.tmpl");
const SQL_APP_DOWN: &str =
    include_str!("../../../templates/module/sql/app/0001_init.down.sql.tmpl");
const SQL_MODULE_README: &str = include_str!("../../../templates/module/sql/module/README.md.tmpl");
const CLIENT_README: &str = include_str!("../../../templates/module/client/README.md.tmpl");
const WEB_README: &str = include_str!("../../../templates/module/web/README.md.tmpl");

const FILES: &[(&str, &str)] = &[
    ("main.go", MAIN_GO),
    ("go.mod", GO_MOD),
    (".gitignore", GITIGNORE),
    ("README.md", README),
    ("CONTRIBUTING.md", CONTRIBUTING),
    ("manifest/register.go", MANIFEST),
    ("internal/transport/rest/routes.go", REST_ROUTES),
    ("internal/transport/mcp/tools.go", MCP_TOOLS),
    ("docs/README.md", DOCS_README),
    ("docs/CHANGELOG.md", CHANGELOG),
    ("sql/app/0001_init.up.sql", SQL_APP_UP),
    ("sql/app/0001_init.down.sql", SQL_APP_DOWN),
    ("sql/module/README.md", SQL_MODULE_README),
    ("client/README.md", CLIENT_README),
    ("web/README.md", WEB_README),
];

const SLUG_TOKEN: &str = "__MS_SLUG__";
const NAME_TOKEN: &str = "__MS_NAME__";
const MODULE_ID_TOKEN: &str = "__MS_MODULE_ID__";
const RUNTIME_MODULE_ID_PLACEHOLDER: &str = "__MODULE_ID__";

pub(super) struct Inputs<'a> {
    pub slug: &'a str,
    pub name: &'a str,
    pub module_id: &'a str,
}

pub(super) fn ensure_target_writable(target: &Path) -> Result<()> {
    match fs::read_dir(target) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(anyhow!(
                    "{} is not empty - pick a different --dir or remove it",
                    target.display()
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(anyhow!("scaffold: read {}: {error}", target.display())),
    }
}

pub(super) fn write_tree(target: &Path, inputs: &Inputs<'_>) -> Result<()> {
    fs::create_dir_all(target).with_context(|| format!("scaffold: mkdir {}", target.display()))?;
    for (relative, body) in FILES {
        write_file(target, relative, body, inputs)?;
    }
    write_env_file(target, inputs)
}

fn write_env_file(target: &Path, inputs: &Inputs<'_>) -> Result<()> {
    let path = target.join(".env");
    let key = module_meta::env_key_for_slug(inputs.slug);
    let body = format!("{key}={}\n", sanitize_module_id(inputs.module_id));
    write_new(&path, body.as_bytes())
}

fn write_file(target: &Path, relative: &str, body: &str, inputs: &Inputs<'_>) -> Result<()> {
    let path = target.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("scaffold: mkdir {}", parent.display()))?;
    }
    write_new(&path, render(body, inputs).as_bytes())
}

fn write_new(path: &Path, body: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("scaffold: create {}", path.display()))?;
    file.write_all(body)
        .with_context(|| format!("scaffold: write {}", path.display()))
}

fn render(body: &str, inputs: &Inputs<'_>) -> String {
    body.replace(SLUG_TOKEN, inputs.slug)
        .replace(NAME_TOKEN, inputs.name)
        .replace(MODULE_ID_TOKEN, RUNTIME_MODULE_ID_PLACEHOLDER)
}

fn sanitize_module_id(uuid: &str) -> String {
    let mut output = String::with_capacity(33);
    output.push('m');
    for character in uuid.chars() {
        if character != '-' {
            output.extend(character.to_lowercase());
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_UUID: &str = "bb8a3f8b-1234-5678-9abc-def012345678";
    const SAMPLE_ID: &str = "mbb8a3f8b123456789abcdef012345678";

    fn inputs<'a>(slug: &'a str, name: &'a str) -> Inputs<'a> {
        Inputs {
            slug,
            name,
            module_id: SAMPLE_UUID,
        }
    }

    #[test]
    fn render_uses_runtime_identity_and_current_sdk() {
        let values = inputs("media", "Media");
        let main = render(MAIN_GO, &values);
        let go_mod = render(GO_MOD, &values);
        assert!(main.contains(r#"ID:   os.Getenv("MS_MODULE_ID")"#));
        assert!(main.contains(r#"Slug: "media""#));
        assert!(main.contains(r#""v0.1.0-dev": {App: "0001"}"#));
        assert!(go_mod.contains("github.com/mirrorstack-ai/app-module-sdk v0.4.7"));
        assert!(!main.contains("__MS_"));
    }

    #[test]
    fn render_sql_keeps_runtime_table_prefix() {
        let sql = render(SQL_APP_UP, &inputs("media", "Media"));
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS __MODULE_ID___items"));
        assert!(!sql.contains(SAMPLE_ID));
    }

    #[test]
    fn ensure_target_writable_accepts_missing_or_empty_directory() {
        let temp = tempfile::tempdir().unwrap();
        ensure_target_writable(&temp.path().join("missing")).unwrap();
        ensure_target_writable(temp.path()).unwrap();
    }

    #[test]
    fn ensure_target_writable_rejects_non_empty_directory() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("file"), "x").unwrap();
        assert!(ensure_target_writable(temp.path()).is_err());
    }

    #[test]
    fn write_tree_creates_canonical_shape() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("media");
        write_tree(&target, &inputs("media", "Media")).unwrap();

        for relative in [
            "main.go",
            "manifest/register.go",
            "internal/transport/rest/routes.go",
            "internal/transport/mcp/tools.go",
            "docs/README.md",
            "docs/CHANGELOG.md",
            "sql/app/0001_init.up.sql",
            "sql/app/0001_init.down.sql",
            "sql/module/README.md",
            "client/README.md",
            "web/README.md",
            ".env",
            ".gitignore",
        ] {
            assert!(target.join(relative).is_file(), "missing {relative}");
        }
        assert!(!target.join("CHANGELOG.md").exists());
        assert_eq!(
            fs::read_to_string(target.join(".env")).unwrap(),
            format!("MS_MODULE_ID_MEDIA={SAMPLE_ID}\n")
        );
    }

    #[test]
    fn write_tree_never_clobbers_a_racing_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("main.go"), "keep").unwrap();
        assert!(write_tree(temp.path(), &inputs("media", "Media")).is_err());
        assert_eq!(
            fs::read_to_string(temp.path().join("main.go")).unwrap(),
            "keep"
        );
    }
}
