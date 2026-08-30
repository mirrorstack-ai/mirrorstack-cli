//! Provenance checks for package-manager local inputs.
//!
//! A frozen lockfile is not sufficient when it can name `file:`, `link:`, a
//! workspace, or a patch outside the staged Git tree. Npm's JSON lock formats
//! are inspected recursively and may use local packages only when their
//! package manifests are exact `SourceSnapshot` entries. Pnpm's YAML formats
//! have a much broader local/workspace grammar, so attested releases accept
//! only registry-backed pnpm locks and fail closed on every local indicator.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use yaml_serde::Value as YamlValue;

use super::source::BuildView;
use super::{NpmLockfile, PackageManager};

const MAX_PACKAGE_METADATA_BYTES: u64 = 8 * 1024 * 1024;
const MAX_JSON_WALK_DEPTH: usize = 96;
const DEPENDENCY_FIELDS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) fn validate(view: &BuildView, web_dir: &Path, manager: PackageManager) -> Result<()> {
    let mut validator = Validator::new(view);
    validator.enqueue_manifest(
        web_dir.join("package.json"),
        "web package manifest".to_string(),
    )?;
    validate_project_config(view, web_dir)?;

    let lockfile = web_dir.join(manager.lockfile());
    match manager {
        PackageManager::Pnpm => validator.validate_pnpm_lock(&lockfile)?,
        PackageManager::Npm(NpmLockfile::PackageLock | NpmLockfile::Shrinkwrap) => {
            validator.validate_npm_lock(&lockfile)?
        }
    }
    validator.validate_queued_manifests()
}

struct Validator<'a> {
    view: &'a BuildView,
    pending_manifests: Vec<(PathBuf, String)>,
    seen_manifests: HashSet<String>,
}

impl<'a> Validator<'a> {
    fn new(view: &'a BuildView) -> Self {
        Self {
            view,
            pending_manifests: Vec::new(),
            seen_manifests: HashSet::new(),
        }
    }

    fn validate_queued_manifests(&mut self) -> Result<()> {
        while let Some((manifest, origin)) = self.pending_manifests.pop() {
            let bytes = self
                .view
                .read_snapshotted_file(
                    &manifest,
                    MAX_PACKAGE_METADATA_BYTES,
                    "local package manifest",
                )
                .with_context(|| format!("release candidate: {origin}"))?;
            let value: Value = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "release candidate: parse snapshotted package manifest {}",
                    manifest.display()
                )
            })?;
            if !value.is_object() {
                return Err(anyhow!(
                    "release candidate: package manifest must be a JSON object: {}",
                    manifest.display()
                ));
            }
            let base = manifest.parent().ok_or_else(|| {
                anyhow!(
                    "release candidate: package manifest has no parent: {}",
                    manifest.display()
                )
            })?;
            self.walk_manifest_config(&value, base, &manifest.display().to_string(), 0)?;
        }
        Ok(())
    }

    fn enqueue_manifest(&mut self, manifest: PathBuf, origin: String) -> Result<()> {
        let relative = manifest.strip_prefix(self.view.root()).map_err(|_| {
            anyhow!(
                "release candidate: local package escaped the frozen source view: {}",
                manifest.display()
            )
        })?;
        let key = relative.to_string_lossy().replace('\\', "/");
        #[cfg(any(windows, target_os = "macos"))]
        let key = key.to_ascii_lowercase();
        if self.seen_manifests.insert(key) {
            self.pending_manifests.push((manifest, origin));
        }
        Ok(())
    }

    fn walk_manifest_config(
        &mut self,
        value: &Value,
        base: &Path,
        context: &str,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_JSON_WALK_DEPTH {
            return Err(anyhow!(
                "release candidate: package configuration is nested too deeply in {context}"
            ));
        }
        let Some(object) = value.as_object() else {
            return Ok(());
        };
        for (key, child) in object {
            if DEPENDENCY_FIELDS.contains(&key.as_str()) || (key == "requires" && child.is_object())
            {
                self.inspect_manifest_dependency_map(child, base, context)?;
                continue;
            }
            match key.as_str() {
                "overrides" | "resolutions" => {
                    self.walk_override_values(child, base, context, depth + 1)?;
                }
                "workspaces" => {
                    if !json_empty(child) {
                        return Err(anyhow!(
                            "release candidate: workspace package linking is not supported in {context}; use explicit snapshotted file: dependencies"
                        ));
                    }
                }
                "patchedDependencies" | "patches" => {
                    if !json_empty(child) {
                        return Err(anyhow!(
                            "release candidate: local package patches are not supported in {context}"
                        ));
                    }
                }
                "configDependencies" => {
                    if !json_empty(child) {
                        return Err(anyhow!(
                            "release candidate: package-manager config dependencies are not supported in {context}"
                        ));
                    }
                }
                "onlyBuiltDependenciesFile" => {
                    if !json_empty(child) {
                        return Err(anyhow!(
                            "release candidate: external pnpm build-policy files are not supported in {context}"
                        ));
                    }
                }
                "pnpm" => {
                    self.walk_manifest_config(child, base, context, depth + 1)?;
                }
                // Each package extension is itself a partial package manifest
                // and may add dependency maps.
                "packageExtensions" => {
                    let extensions = child.as_object().ok_or_else(|| {
                        anyhow!(
                            "release candidate: pnpm packageExtensions must be an object in {context}"
                        )
                    })?;
                    for extension in extensions.values() {
                        self.walk_manifest_config(extension, base, context, depth + 1)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn inspect_manifest_dependency_map(
        &mut self,
        value: &Value,
        base: &Path,
        context: &str,
    ) -> Result<()> {
        let dependencies = value.as_object().ok_or_else(|| {
            anyhow!("release candidate: dependency map must be an object in {context}")
        })?;
        for (name, value) in dependencies {
            let spec = value.as_str().ok_or_else(|| {
                anyhow!(
                    "release candidate: dependency {name:?} must use a string specifier in {context}"
                )
            })?;
            self.inspect_spec(
                spec,
                base,
                false,
                &format!("dependency {name:?} in {context}"),
            )?;
        }
        Ok(())
    }

    fn walk_override_values(
        &mut self,
        value: &Value,
        base: &Path,
        context: &str,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_JSON_WALK_DEPTH {
            return Err(anyhow!(
                "release candidate: package overrides are nested too deeply in {context}"
            ));
        }
        match value {
            Value::String(spec) => self.inspect_spec(spec, base, false, context),
            Value::Array(values) => {
                for value in values {
                    self.walk_override_values(value, base, context, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                for value in values.values() {
                    self.walk_override_values(value, base, context, depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn validate_npm_lock(&mut self, lockfile: &Path) -> Result<()> {
        let bytes = self.view.read_snapshotted_file(
            lockfile,
            MAX_PACKAGE_METADATA_BYTES,
            "npm lockfile",
        )?;
        let value: Value = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "release candidate: parse snapshotted npm lockfile {}",
                lockfile.display()
            )
        })?;
        if !value.is_object() {
            return Err(anyhow!(
                "release candidate: npm lockfile must be a JSON object: {}",
                lockfile.display()
            ));
        }
        let base = lockfile.parent().ok_or_else(|| {
            anyhow!(
                "release candidate: npm lockfile has no parent: {}",
                lockfile.display()
            )
        })?;
        self.walk_npm_lock(&value, base, &lockfile.display().to_string(), 0)
    }

    fn walk_npm_lock(
        &mut self,
        value: &Value,
        base: &Path,
        context: &str,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_JSON_WALK_DEPTH {
            return Err(anyhow!(
                "release candidate: npm lockfile is nested too deeply: {context}"
            ));
        }
        let Some(object) = value.as_object() else {
            return Ok(());
        };

        if object.get("link").and_then(Value::as_bool) == Some(true) {
            let resolved = object
                .get("resolved")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!(
                        "release candidate: npm link record has no string resolved path in {context}"
                    )
                })?;
            self.inspect_spec(
                resolved,
                base,
                true,
                &format!("npm link record in {context}"),
            )?;
        }

        for (key, child) in object {
            if key == "requires" && child.is_array() {
                return Err(anyhow!(
                    "release candidate: npm requires must not be an array in {context}"
                ));
            }
            if DEPENDENCY_FIELDS.contains(&key.as_str()) || (key == "requires" && child.is_object())
            {
                let dependencies = child.as_object().ok_or_else(|| {
                    anyhow!("release candidate: npm {key} must be an object in {context}")
                })?;
                for (name, dependency) in dependencies {
                    if let Some(spec) = dependency.as_str() {
                        self.inspect_spec(
                            spec,
                            base,
                            false,
                            &format!("npm dependency {name:?} in {context}"),
                        )?;
                    } else {
                        self.walk_npm_lock(dependency, base, context, depth + 1)?;
                    }
                }
                continue;
            }
            match key.as_str() {
                "resolved" | "version" | "from" => {
                    if let Some(spec) = child.as_str() {
                        self.inspect_spec(spec, base, false, context)?;
                    }
                }
                "directory" => {
                    let path = child.as_str().ok_or_else(|| {
                        anyhow!(
                            "release candidate: npm directory resolution must be a string in {context}"
                        )
                    })?;
                    self.inspect_spec(path, base, true, context)?;
                }
                "path" | "patch" | "patchedDependencies" => {
                    if !json_empty(child) {
                        return Err(anyhow!(
                            "release candidate: local patch/path metadata is not supported in npm lockfile {context}"
                        ));
                    }
                }
                "workspaces" => {
                    if !json_empty(child) {
                        return Err(anyhow!(
                            "release candidate: npm workspace records are not supported in {context}"
                        ));
                    }
                }
                "packages" => {
                    let packages = child.as_object().ok_or_else(|| {
                        anyhow!("release candidate: npm packages must be an object in {context}")
                    })?;
                    for (package_path, package) in packages {
                        if !package_path.is_empty()
                            && !normalized_node_modules_location(package_path, context)?
                        {
                            self.inspect_spec(
                                package_path,
                                base,
                                true,
                                &format!("npm package record {package_path:?} in {context}"),
                            )?;
                        }
                        self.walk_npm_lock(package, base, context, depth + 1)?;
                    }
                }
                "overrides" | "resolutions" => {
                    self.walk_override_values(child, base, context, depth + 1)?;
                }
                _ => self.walk_npm_lock(child, base, context, depth + 1)?,
            }
        }
        Ok(())
    }

    fn validate_pnpm_lock(&self, lockfile: &Path) -> Result<()> {
        let bytes = self.view.read_snapshotted_file(
            lockfile,
            MAX_PACKAGE_METADATA_BYTES,
            "pnpm lockfile",
        )?;
        let value: YamlValue = yaml_serde::from_slice(&bytes).with_context(|| {
            format!(
                "release candidate: parse snapshotted pnpm lockfile {}",
                lockfile.display()
            )
        })?;
        if !value.is_mapping() {
            return Err(anyhow!(
                "release candidate: pnpm lockfile must be a YAML mapping: {}",
                lockfile.display()
            ));
        }
        inspect_pnpm_value(&value, &lockfile.display().to_string(), 0)
    }

    fn inspect_spec(
        &mut self,
        spec: &str,
        base: &Path,
        force_path: bool,
        context: &str,
    ) -> Result<()> {
        let Some(path) = local_path_from_spec(spec, force_path, context)? else {
            return Ok(());
        };
        let package_dir = resolve_portable_inside(self.view.root(), base, &path, context)?;
        self.enqueue_manifest(
            package_dir.join("package.json"),
            format!("{context} points to an unsnapshotted local package {spec:?}"),
        )
    }
}

fn validate_project_config(view: &BuildView, web_dir: &Path) -> Result<()> {
    let mut current = Some(web_dir);
    while let Some(directory) = current {
        if !directory.starts_with(view.root()) {
            break;
        }
        for hook_name in [".pnpmfile.cjs", "pnpmfile.cjs"] {
            let hook = directory.join(hook_name);
            if view.is_snapshotted_file(&hook)? {
                return Err(anyhow!(
                    "release candidate: package-manager hook files are not supported by an attested build: {}",
                    hook.display()
                ));
            }
        }
        let config = directory.join(".npmrc");
        if view.is_snapshotted_file(&config)? {
            let bytes = view.read_snapshotted_file(
                &config,
                MAX_PACKAGE_METADATA_BYTES,
                "package-manager project config",
            )?;
            let text = std::str::from_utf8(&bytes).with_context(|| {
                format!(
                    "release candidate: package-manager project config is not UTF-8: {}",
                    config.display()
                )
            })?;
            for (index, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with(['#', ';']) {
                    continue;
                }
                let key = line.split_once('=').map_or(line, |(key, _)| key).trim();
                let normalized = key
                    .bytes()
                    .filter(u8::is_ascii_alphanumeric)
                    .map(|byte| byte.to_ascii_lowercase() as char)
                    .collect::<String>();
                if matches!(
                    normalized.as_str(),
                    "lockfile"
                        | "uselockfile"
                        | "lockfiledir"
                        | "frozenlockfile"
                        | "preferfrozenlockfile"
                        | "fixlockfile"
                        | "lockfileonly"
                        | "gitbranchlockfile"
                        | "mergegitbranchlockfiles"
                        | "pnpmfile"
                        | "globalpnpmfile"
                        | "sharedworkspacelockfile"
                        | "workspacedir"
                        | "workspace"
                        | "workspaces"
                        | "virtualstoredir"
                        | "modulesdir"
                        | "storedir"
                        | "packageimportmethod"
                        | "sideeffectscache"
                        | "userconfig"
                        | "globalconfig"
                        | "packagelock"
                        | "nodeoptions"
                        | "scriptshell"
                ) {
                    return Err(anyhow!(
                        "release candidate: provenance-affecting package-manager setting {key:?} is not allowed at {}:{}",
                        config.display(),
                        index + 1
                    ));
                }
            }
        }
        if directory == view.root() {
            break;
        }
        current = directory.parent();
    }
    Ok(())
}

fn normalized_node_modules_location(location: &str, context: &str) -> Result<bool> {
    if location.trim() != location || portable_absolute(location) {
        return Err(anyhow!(
            "release candidate: npm package location must be a relative portable path in {context}: {location:?}"
        ));
    }
    let normalized = location.replace('\\', "/");
    let mut components = Vec::new();
    for component in normalized.split('/') {
        match component {
            "" | "." => {
                return Err(anyhow!(
                    "release candidate: npm package location is not normalized in {context}: {location:?}"
                ));
            }
            ".." => {
                if components.pop().is_none() {
                    return Ok(false);
                }
            }
            value => {
                validate_portable_component(value, context)?;
                components.push(value);
            }
        }
    }
    Ok(components.first() == Some(&"node_modules"))
}

fn local_path_from_spec(spec: &str, force_path: bool, context: &str) -> Result<Option<String>> {
    if spec.trim() != spec || spec.is_empty() || spec.chars().any(char::is_control) {
        return Err(anyhow!(
            "release candidate: malformed package specifier {spec:?} in {context}"
        ));
    }
    let lower = spec.to_ascii_lowercase();
    for protocol in ["workspace:", "portal:", "patch:", "exec:"] {
        if lower.starts_with(protocol) {
            return Err(anyhow!(
                "release candidate: package protocol {protocol} is not supported in {context}"
            ));
        }
    }
    let (path, explicitly_local) = if lower.starts_with("file:") {
        (&spec["file:".len()..], true)
    } else if lower.starts_with("link:") {
        (&spec["link:".len()..], true)
    } else {
        (spec, false)
    };
    if !explicitly_local
        && ["file:", "link:", "workspace:", "portal:", "patch:"]
            .iter()
            .any(|marker| contains_local_protocol(&lower, marker))
    {
        return Err(anyhow!(
            "release candidate: embedded local package protocol is not supported in {context}: {spec:?}"
        ));
    }

    let path_like = force_path
        || explicitly_local
        || path.starts_with("./")
        || path.starts_with("../")
        || path.starts_with(".\\")
        || path.starts_with("..\\")
        || path.starts_with('~')
        || portable_absolute(path);
    if !path_like {
        return Ok(None);
    }
    if path.is_empty()
        || path.contains('%')
        || path.contains(['?', '#', '$'])
        || path.starts_with('~')
    {
        return Err(anyhow!(
            "release candidate: encoded, expanded, or empty local package path is not supported in {context}: {spec:?}"
        ));
    }
    if portable_absolute(path) {
        return Err(anyhow!(
            "release candidate: absolute local package path is not allowed in {context}: {spec:?}"
        ));
    }
    Ok(Some(path.replace('\\', "/")))
}

fn resolve_portable_inside(root: &Path, base: &Path, path: &str, context: &str) -> Result<PathBuf> {
    let base_relative = base.strip_prefix(root).map_err(|_| {
        anyhow!("release candidate: local package base escaped the frozen source view in {context}")
    })?;
    let mut components = base_relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(anyhow!(
                        "release candidate: local package path escapes the frozen Git worktree in {context}: {path:?}"
                    ));
                }
            }
            value => {
                validate_portable_component(value, context)?;
                components.push(value.to_string());
            }
        }
    }
    if components.is_empty() {
        return Err(anyhow!(
            "release candidate: local package path resolves to the source root in {context}: {path:?}"
        ));
    }
    let mut resolved = root.to_path_buf();
    for component in components {
        resolved.push(component);
    }
    Ok(resolved)
}

fn validate_portable_component(value: &str, context: &str) -> Result<()> {
    if value.contains(':') || value.ends_with(['.', ' ']) || value.chars().any(char::is_control) {
        return Err(anyhow!(
            "release candidate: non-portable local package path component {value:?} in {context}"
        ));
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    if reserved {
        return Err(anyhow!(
            "release candidate: Windows-reserved local package path component {value:?} in {context}"
        ));
    }
    Ok(())
}

fn portable_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['/', '\\'])
        || bytes
            .get(1)
            .is_some_and(|separator| *separator == b':' && bytes[0].is_ascii_alphabetic())
}

fn inspect_pnpm_value(value: &YamlValue, context: &str, depth: usize) -> Result<()> {
    if depth > MAX_JSON_WALK_DEPTH {
        return Err(anyhow!(
            "release candidate: pnpm lockfile is nested too deeply: {context}"
        ));
    }
    match value {
        YamlValue::Mapping(mapping) => {
            for (key, child) in mapping {
                let key = key.as_str().ok_or_else(|| {
                    anyhow!("release candidate: pnpm lockfile keys must be strings in {context}")
                })?;
                inspect_pnpm_scalar(key, context)?;
                let normalized = key.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "directory"
                        | "patch"
                        | "patches"
                        | "patcheddependencies"
                        | "packageextensions"
                        | "pnpmfile"
                        | "globalpnpmfile"
                ) && !yaml_empty(child)
                {
                    return Err(pnpm_local_input_error(context));
                }
                if normalized == "type"
                    && child
                        .as_str()
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("directory"))
                {
                    return Err(pnpm_local_input_error(context));
                }
                inspect_pnpm_value(child, context, depth + 1)?;
            }
            Ok(())
        }
        YamlValue::Sequence(values) => {
            for child in values {
                inspect_pnpm_value(child, context, depth + 1)?;
            }
            Ok(())
        }
        YamlValue::String(value) => inspect_pnpm_scalar(value, context),
        YamlValue::Tagged(_) => Err(anyhow!(
            "release candidate: tagged YAML values are not supported in pnpm lockfile {context}"
        )),
        YamlValue::Null | YamlValue::Bool(_) | YamlValue::Number(_) => Ok(()),
    }
}

fn inspect_pnpm_scalar(value: &str, context: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    let local_protocol = [
        "file:",
        "link:",
        "workspace:",
        "portal:",
        "patch:",
        "git+file:",
    ]
    .iter()
    .any(|protocol| contains_local_protocol(&lower, protocol));
    let local_path = value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || value.starts_with('~')
        || portable_absolute(value);
    if local_protocol || local_path {
        return Err(pnpm_local_input_error(context));
    }
    Ok(())
}

fn contains_local_protocol(value: &str, protocol: &str) -> bool {
    value.match_indices(protocol).any(|(index, _)| {
        index == 0
            || value[..index].chars().next_back().is_some_and(|before| {
                !before.is_ascii_alphanumeric() && before != '_' && before != '-'
            })
    })
}

fn pnpm_local_input_error(context: &str) -> anyhow::Error {
    anyhow!(
        "release candidate: pnpm lockfile {context} contains local, workspace, patch, or platform-path input; attested pnpm releases require a registry-only lockfile"
    )
}

fn yaml_empty(value: &YamlValue) -> bool {
    match value {
        YamlValue::Null => true,
        YamlValue::String(value) => value.is_empty(),
        YamlValue::Sequence(values) => values.is_empty(),
        YamlValue::Mapping(values) => values.is_empty(),
        YamlValue::Tagged(tagged) => yaml_empty(&tagged.value),
        YamlValue::Bool(_) | YamlValue::Number(_) => false,
    }
}

fn json_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.is_empty(),
        Value::Object(values) => values.is_empty(),
        Value::String(value) => value.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::commands::release_candidate::source::SourceSnapshot;
    use crate::commands::release_candidate::{NpmLockfile, PackageManager, package_manager};

    fn git(root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }

    fn fixture(package: Value, lock: Value) -> (TempDir, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "-q"]);
        let module = root.path().join("module");
        let web = module.join("web");
        fs::create_dir_all(&web).unwrap();
        fs::write(
            module.join("go.mod"),
            "module example.com/module\n\ngo 1.23\n",
        )
        .unwrap();
        fs::write(module.join("main.go"), "package main\n").unwrap();
        fs::write(web.join("package.json"), package.to_string()).unwrap();
        fs::write(web.join("package-lock.json"), lock.to_string()).unwrap();
        git(root.path(), &["add", "."]);
        (root, module)
    }

    fn pnpm_fixture(package: Value, lock: &str) -> (TempDir, PathBuf) {
        let (root, module) = fixture(package, base_lock());
        let web = module.join("web");
        fs::remove_file(web.join("package-lock.json")).unwrap();
        fs::write(web.join("pnpm-lock.yaml"), lock).unwrap();
        git(root.path(), &["add", "-A"]);
        (root, module)
    }

    fn staged(module: &Path) -> BuildView {
        SourceSnapshot::create(module)
            .unwrap()
            .fresh_web_view()
            .unwrap()
    }

    fn root_package(dependencies: Value) -> Value {
        json!({
            "name": "web",
            "version": "1.0.0",
            "dependencies": dependencies,
            "scripts": {"build": "build"}
        })
    }

    fn base_lock() -> Value {
        json!({
            "name": "web",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {"": {"name": "web", "version": "1.0.0"}}
        })
    }

    #[test]
    fn valid_recursive_in_snapshot_file_dependency_is_accepted() {
        let (root, module) = fixture(
            root_package(json!({"shared": "file:../shared"})),
            json!({
                "name": "web",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"shared": "file:../shared"}},
                    "node_modules/shared": {"resolved": "../shared", "link": true}
                }
            }),
        );
        let shared = module.join("shared");
        fs::create_dir_all(&shared).unwrap();
        fs::write(
            shared.join("package.json"),
            root_package(json!({})).to_string(),
        )
        .unwrap();
        fs::write(shared.join("index.js"), "export const value = 1;\n").unwrap();
        git(root.path(), &["add", "."]);

        let view = staged(&module);
        validate(
            &view,
            &view.module_dir().join("web"),
            PackageManager::Npm(NpmLockfile::PackageLock),
        )
        .unwrap();
    }

    #[test]
    fn manifest_rejects_absolute_traversal_encoded_and_cross_platform_paths() {
        for spec in [
            "/tmp/outside",
            "file:../../../../outside",
            "file:C:\\outside",
            "link:\\\\server\\share",
            "file:\\root-relative",
            "file:%2Fetc%2Fpasswd",
            "file:..\\..\\..\\outside",
        ] {
            let (_root, module) = fixture(root_package(json!({"outside": spec})), base_lock());
            let view = staged(&module);
            let error = validate(
                &view,
                &view.module_dir().join("web"),
                PackageManager::Npm(NpmLockfile::PackageLock),
            )
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains("local package") || message.contains("absolute"),
                "{spec}: {message}"
            );
        }
    }

    #[test]
    fn another_worktree_and_lockfile_only_external_paths_are_rejected() {
        let (_root, module) = fixture(
            root_package(json!({})),
            json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/other": {
                        "resolved": "file:../../../other-worktree",
                        "link": true
                    }
                }
            }),
        );
        let view = staged(&module);
        let error = validate(
            &view,
            &view.module_dir().join("web"),
            PackageManager::Npm(NpmLockfile::PackageLock),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("escapes the frozen Git worktree"));
    }

    #[test]
    fn transitive_local_manifest_cannot_escape_the_snapshot() {
        let (root, module) = fixture(
            root_package(json!({"first": "file:../first"})),
            json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"first": "file:../first"}},
                    "node_modules/first": {"resolved": "../first", "link": true}
                }
            }),
        );
        let first = module.join("first");
        fs::create_dir_all(&first).unwrap();
        fs::write(
            first.join("package.json"),
            root_package(json!({"outside": "file:../../../other-worktree"})).to_string(),
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        let view = staged(&module);
        let error = validate(
            &view,
            &view.module_dir().join("web"),
            PackageManager::Npm(NpmLockfile::PackageLock),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("escapes the frozen Git worktree"));
    }

    #[cfg(unix)]
    #[test]
    fn local_dependency_symlink_is_never_admitted_to_the_snapshot() {
        use std::os::unix::fs::symlink;

        let (root, module) = fixture(
            root_package(json!({"shared": "file:../shared"})),
            base_lock(),
        );
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("package.json"), "{}").unwrap();
        symlink(outside.path(), module.join("shared")).unwrap();
        git(root.path(), &["add", "."]);
        let error = SourceSnapshot::create(&module)
            .err()
            .expect("symlinked local package rejected");
        assert!(format!("{error:#}").contains("symlink source input"));
    }

    #[test]
    fn workspace_patch_and_pnpm_local_records_fail_closed() {
        let cases = [
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      x:\n        specifier: file:../x\n",
            "lockfileVersion: '9.0'\npackages:\n  x:\n    resolution: {directory: ../x}\n",
            "lockfileVersion: '9.0'\npatchedDependencies:\n  x@1.0.0:\n    path: patches/x.patch\n",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      x:\n        specifier: C:\\outside\n",
        ];
        for lock in cases {
            let (root, module) = fixture(root_package(json!({})), base_lock());
            let web = module.join("web");
            fs::remove_file(web.join("package-lock.json")).unwrap();
            fs::write(web.join("pnpm-lock.yaml"), lock).unwrap();
            git(root.path(), &["add", "-A"]);
            let view = staged(&module);
            let error =
                validate(&view, &view.module_dir().join("web"), PackageManager::Pnpm).unwrap_err();
            assert!(format!("{error:#}").contains("registry-only"));
        }
    }

    #[test]
    fn conflicting_lock_precedence_is_rejected_but_ignored_workspace_metadata_is_safe() {
        let (root, module) = fixture(root_package(json!({})), base_lock());
        fs::write(
            module.join("web/npm-shrinkwrap.json"),
            base_lock().to_string(),
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        assert!(package_manager(&module.join("web")).is_err());

        fs::remove_file(module.join("web/npm-shrinkwrap.json")).unwrap();
        fs::write(
            root.path().join("pnpm-workspace.yaml"),
            "packages:\n  - module/web\n",
        )
        .unwrap();
        git(root.path(), &["add", "-A"]);
        let view = staged(&module);
        validate(
            &view,
            &view.module_dir().join("web"),
            PackageManager::Npm(NpmLockfile::PackageLock),
        )
        .unwrap();
    }

    #[test]
    fn npm_v1_requires_and_non_normalized_package_locations_are_rejected() {
        for lock in [
            json!({
                "lockfileVersion": 1,
                "dependencies": {
                    "parent": {
                        "version": "1.0.0",
                        "requires": {"child": "file:/outside"}
                    }
                }
            }),
            json!({
                "lockfileVersion": 1,
                "dependencies": {
                    "parent": {
                        "version": "1.0.0",
                        "requires": ["file:/outside"]
                    }
                }
            }),
            json!({
                "lockfileVersion": 3,
                "packages": {"node_modules/../../../outside": {}}
            }),
            json!({
                "lockfileVersion": 3,
                "packages": {"node_modules\\..\\..\\outside": {}}
            }),
        ] {
            let (_root, module) = fixture(root_package(json!({})), lock);
            let view = staged(&module);
            let error = validate(
                &view,
                &view.module_dir().join("web"),
                PackageManager::Npm(NpmLockfile::PackageLock),
            )
            .unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains("absolute")
                    || message.contains("escaped")
                    || message.contains("unsnapshotted")
                    || message.contains("must not be an array"),
                "{message}"
            );
        }
    }

    #[test]
    fn structured_pnpm_validation_rejects_flow_json_and_block_scalar_local_inputs() {
        let locks = [
            r#"{"lockfileVersion":"9.0","importers":{".":{"dependencies":{"x":{"specifier":"1.0.0","version":"x@1.0.0"}}}},"packages":{"x@1.0.0":{"resolution":{"type":"directory","directory":"/tmp/outside"}}},"snapshots":{"x@1.0.0":{}}}"#,
            "lockfileVersion: '9.0'\npackages:\n  x:\n    resolution: {tarball: /tmp/outside.tgz}\n",
            "lockfileVersion: '9.0'\npackages:\n  x:\n    resolution:\n      \"type\": >-\n        directory\n      \"directory\": >-\n        /tmp/outside\n",
        ];
        for lock in locks {
            let (_root, module) = pnpm_fixture(root_package(json!({})), lock);
            let view = staged(&module);
            let error =
                validate(&view, &view.module_dir().join("web"), PackageManager::Pnpm).unwrap_err();
            assert!(format!("{error:#}").contains("registry-only"), "{error:#}");
        }
    }

    #[test]
    fn registry_only_pnpm_lock_accepts_flow_integrity_vfile_and_ignored_workspace_file() {
        let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      vfile:\n        specifier: ^6.0.3\n        version: 6.0.3\npackages:\n  vfile@6.0.3:\n    resolution: {integrity: sha512-AbCd/123==, tarball: https://registry.npmjs.org/vfile/-/vfile-6.0.3.tgz}\nsnapshots:\n  vfile@6.0.3: {}\n";
        let (root, module) = pnpm_fixture(root_package(json!({})), lock);
        fs::write(
            module.join("web/pnpm-workspace.yaml"),
            "packages:\n  - ignored-neighbor\n",
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        let view = staged(&module);
        validate(&view, &view.module_dir().join("web"), PackageManager::Pnpm).unwrap();
    }

    #[test]
    fn project_config_hooks_and_provenance_redirectors_are_rejected() {
        for config in [
            "lockfile-dir=/tmp/other\n",
            "lockfile=false\n",
            "git-branch-lockfile=true\n",
            "pnpmfile=/tmp/hook.cjs\n",
            "global-pnpmfile=/tmp/hook.cjs\n",
            "userconfig=/tmp/other-npmrc\n",
            "node-options=--require=/tmp/inject.cjs\n",
            "script-shell=/tmp/external-shell\n",
        ] {
            let (root, module) = fixture(root_package(json!({})), base_lock());
            fs::write(module.join("web/.npmrc"), config).unwrap();
            git(root.path(), &["add", "."]);
            let view = staged(&module);
            let error = validate(
                &view,
                &view.module_dir().join("web"),
                PackageManager::Npm(NpmLockfile::PackageLock),
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("provenance-affecting"),
                "{config}: {error:#}"
            );
        }

        let (root, module) = fixture(root_package(json!({})), base_lock());
        fs::write(
            module.join("web/.npmrc"),
            "registry=https://registry.npmjs.org/\n@mirrorstack-ai:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}\n",
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        let view = staged(&module);
        validate(
            &view,
            &view.module_dir().join("web"),
            PackageManager::Npm(NpmLockfile::PackageLock),
        )
        .unwrap();

        let (root, module) = fixture(root_package(json!({})), base_lock());
        fs::write(module.join("web/.pnpmfile.cjs"), "module.exports = {};\n").unwrap();
        git(root.path(), &["add", "."]);
        let view = staged(&module);
        let error = validate(
            &view,
            &view.module_dir().join("web"),
            PackageManager::Npm(NpmLockfile::PackageLock),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("hook files"));
    }

    #[test]
    fn package_manifest_cannot_load_external_pnpm_policy_or_extension_dependencies() {
        for (pnpm, expected) in [
            (
                json!({
                    "onlyBuiltDependenciesFile": "../../../../outside-build-policy.json"
                }),
                "build-policy",
            ),
            (
                json!({
                    "packageExtensions": {
                        "parent@1": {
                            "dependencies": {"outside": "file:../../../../outside"}
                        }
                    }
                }),
                "escapes the frozen Git worktree",
            ),
        ] {
            let (root, module) = fixture(
                json!({
                    "name": "web",
                    "version": "1.0.0",
                    "scripts": {"build": "build"},
                    "pnpm": pnpm
                }),
                base_lock(),
            );
            git(root.path(), &["add", "."]);
            let view = staged(&module);
            let error = validate(
                &view,
                &view.module_dir().join("web"),
                PackageManager::Npm(NpmLockfile::PackageLock),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }

    #[test]
    fn shrinkwrap_is_validated_when_it_is_the_only_npm_lock() {
        let (root, module) = fixture(root_package(json!({})), base_lock());
        let web = module.join("web");
        fs::remove_file(web.join("package-lock.json")).unwrap();
        fs::write(
            web.join("npm-shrinkwrap.json"),
            json!({
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/outside": {
                        "resolved": "file:../../../outside",
                        "link": true
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        git(root.path(), &["add", "-A"]);
        assert_eq!(
            package_manager(&web).unwrap(),
            PackageManager::Npm(NpmLockfile::Shrinkwrap)
        );
        let view = staged(&module);
        assert!(
            validate(
                &view,
                &view.module_dir().join("web"),
                PackageManager::Npm(NpmLockfile::Shrinkwrap),
            )
            .is_err()
        );
    }
}
