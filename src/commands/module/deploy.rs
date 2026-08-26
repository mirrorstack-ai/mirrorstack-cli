//! `mirrorstack app module deploy` — record a version and ship it.
//!
//! Split out of a 1468-line mod.rs so the command surface (the Args structs
//! and the run() dispatcher) is readable without scrolling past every verb's
//! implementation.

use super::*;

pub(super) fn run(args: DeployArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"));

    // The version always comes from code, so main.go is read even when
    // --module overrides the slug.
    let meta = read_meta(&dir)?;
    let slug = args.module.clone().unwrap_or_else(|| meta.slug.clone());
    if !slug_valid(&slug) {
        return Err(slug_invalid_error(&slug));
    }

    let raw = code_version(&meta, &dir)?;
    // `-dev` marks local iteration (scaffold convention). Interactively we
    // offer to promote (rename the Versions key, dropping the tag); with
    // --yes the caller must rename it in code first.
    let (target_raw, promote_from) = match raw.strip_suffix("-dev") {
        Some(promoted) => {
            if args.yes {
                return Err(anyhow!(
                    "Config version '{raw}' is a -dev prerelease. Rename the Versions key in main.go (e.g. \"{promoted}\") before deploying with --yes."
                ));
            }
            (promoted.to_string(), Some(raw.clone()))
        }
        None => (raw.clone(), None),
    };
    let version = canonical_version(&target_raw)?;

    let creds = credentials::load_or_login_hint()?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    let dispatch_base = resolve_base(ENV_DISPATCH_URL, DEFAULT_DISPATCH_BASE);
    let client = http::client(Duration::from_secs(15))?;
    let module = get_owned_module(&client, &apps_base, &creds.access_token, &slug)?;

    if let Some(from) = &promote_from {
        eprintln!();
        eprintln!("  {} {}", style("Module:").dim(), style(&slug).bold());
        eprintln!(
            "  {} {}",
            style("Version:").dim(),
            style(&version).cyan().bold()
        );
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Promote {from} → {target_raw} in main.go and deploy {slug}@{version}?"
            ))
            .default(true)
            .interact()?;
        if !confirmed {
            eprintln!("{}", style("aborted.").yellow());
            return Ok(());
        }
    }

    // Build, package and size-check before anything irreversible happens: a
    // compile error or an oversize bundle must not first freeze an immutable
    // version record. Same posture as `app web deploy`, which packages and
    // checks the SSR bundle before it creates the deploy.
    let (_artifact_dir, bootstrap) =
        with_spinner("Building module…", || artifact::build_bootstrap(&dir))?;
    let zip_path = artifact::zip_bootstrap(&bootstrap)?;
    let artifact_size = artifact::packaged_size(&zip_path)?;

    eprintln!(
        "  {} {} → {} (arm64 bundle, {})",
        style("Deploying:").dim(),
        style(dir.display()).bold(),
        style(format!("{slug}@{version}")).cyan().bold(),
        artifact::human_bytes(artifact_size)
    );

    ensure_version_recorded(
        &client,
        &apps_base,
        &dispatch_base,
        &creds.access_token,
        &module,
        &slug,
        &version,
        &dir,
    )?;

    // Version-scoped, so it can only run once the record above exists.
    // `_artifact_dir` (the temp dir backing `zip_path`) stays alive across
    // this call by still being in scope — dropping it earlier would delete
    // the archive out from under the upload.
    //
    // `artifact_storage_unconfigured` is a WARN, not a failure. Two reasons:
    //
    //   1. It describes environments the platform deliberately keeps working.
    //      api-platform#440's own deploy gate is conditional, and its comment
    //      says so: "Local prod-sim and today's bucket-less production still
    //      deploy without an upload, so an unconditional gate would brick
    //      both." Local prod-sim has no bucket BY DESIGN — this is permanent
    //      there, not a rollout-ordering artifact that disappears once prod
    //      gets its bucket. Failing here would make `module deploy`
    //      unusable locally.
    //   2. `ensure_version_recorded` above has ALREADY frozen an immutable
    //      module_versions row by the time the upload runs. Aborting here
    //      strands that row: the version exists, nothing is deployed, and a
    //      re-run just 409-skips the record and fails the same way.
    //
    // A 404 with no error envelope — the artifact routes not existing at all —
    // is a WARN for the same two reasons, plus a third: a platform that
    // predates those routes also predates #440's deploy gate, so the
    // `set_module_deploy` below still succeeds and the deploy ends up exactly
    // where it did before this CLI learned to upload. Failing instead would
    // turn "your platform is a version behind" into "you cannot deploy at
    // all", with no flag to opt out of the upload.
    //
    // Every other artifact error stays fatal — `ship_artifact` only collapses
    // these two shapes.
    let shipped = artifact::ship_artifact(
        &client,
        &apps_base,
        &creds.access_token,
        &module.id,
        &version,
        &zip_path,
    )?;
    match shipped {
        artifact::ShipOutcome::Shipped => eprintln!(
            "{} uploaded {} ({})",
            ok_mark(),
            style(format!("{slug}@{version}")).cyan().bold(),
            artifact::human_bytes(artifact_size)
        ),
        artifact::ShipOutcome::StorageUnconfigured => {
            eprintln!(
                "{} no artifact was uploaded for {}: this platform is not configured for module artifact storage.",
                warn_prefix(),
                style(format!("{slug}@{version}")).cyan().bold(),
            );
            eprintln!(
                "  {} the version was recorded and the deploy continues, but it is not artifact-backed — the module runs from whatever transport this environment already resolves (local prod-sim, or an existing production function).",
                style("note:").dim(),
            );
        }
        artifact::ShipOutcome::EndpointsMissing => {
            eprintln!(
                "{} no artifact was uploaded for {}: this platform build has no module-artifact endpoints (the upload route answered 404).",
                warn_prefix(),
                style(format!("{slug}@{version}")).cyan().bold(),
            );
            eprintln!(
                "  {} upgrade the platform to a build that serves them. Until then the deploy continues without an artifact — the version is recorded and the module runs from whatever transport this environment already resolves.",
                style("note:").dim(),
            );
        }
    }

    let result = with_spinner("Deploying…", || {
        api::set_module_deploy(
            &client,
            &apps_base,
            &creds.access_token,
            &module.id,
            &version,
            &SetModuleDeployInput {
                // Platform-derived from the module's own identity
                // (Milestone H P4 / decision 12) — the server ignores
                // whatever is sent here, so there is nothing meaningful
                // for the caller to supply.
                invoke_target: "",
                status: args.status.as_deref(),
            },
        )
    });

    let deploy = match result {
        Ok(d) => d,
        Err(ApiError::Server { code, message, .. }) => {
            return Err(anyhow!(
                "{code}: {message}{hint}",
                hint = deploy_error_hint(&code)
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(e) => return Err(e.into()),
    };

    // Write the promoted key back only after the platform accepted the
    // whole operation — a failed deploy must not leave main.go
    // half-promoted (re-running just prompts and 409-skips the record).
    if let Some(from) = &promote_from {
        match module_meta::promote_version(&dir, from, &target_raw) {
            Ok(()) => eprintln!(
                "{} promoted {} → {} in main.go",
                ok_mark(),
                style(from).dim(),
                style(&target_raw).bold()
            ),
            Err(e) => eprintln!(
                "{} deployed, but couldn't update main.go: {e}. Rename the Versions key \"{from}\" → \"{target_raw}\" manually.",
                warn_prefix()
            ),
        }
    }

    eprintln!(
        "{} deployed {}",
        ok_mark(),
        style(format!("{slug}@{version}")).cyan().bold()
    );
    eprintln!("  {} {}", style("target:").dim(), deploy.invoke_target);
    eprintln!("  {} {}", style("status:").dim(), deploy.status);
    Ok(())
}

/// Make sure `version` exists as a recorded module_versions row before the
/// deploy row is written. Recording is just that — an immutable snapshot +
/// changelog with no visibility semantics ("publish" is the future
/// marketplace listing act, not a prerequisite to run).
///
/// The record attempt is 409-tolerant so no pre-flight existence check is
/// needed and concurrent deploys can't race: `version_exists` means someone
/// (usually an earlier run) already recorded it, and the deploy proceeds.
/// Local inputs to the record — the changelog and the manifest read off the
/// dev tunnel — are only fatal when the version isn't recorded yet: an
/// existing record froze both, so on failure each branch checks the versions
/// list and proceeds when the record already exists.
#[allow(clippy::too_many_arguments)]
fn ensure_version_recorded(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    dispatch_base: &str,
    access_token: &str,
    module: &api::Module,
    slug: &str,
    version: &str,
    dir: &Path,
) -> Result<()> {
    let entry = match changelog::lint(dir, version) {
        Ok(entry) => entry,
        Err(lint_err) => {
            if version_is_recorded(client, apps_base, access_token, &module.id, version)? {
                print_already_recorded(slug, version);
                return Ok(());
            }
            return Err(lint_err);
        }
    };

    // The record freezes the manifest the platform mounts this version with
    // (pages, routes, permissions), so it must be the module's real declared
    // surface — read off the live dev tunnel, not reconstructed locally.
    let fetched = with_spinner("Reading module manifest…", || {
        api::get_tunnel_manifest(client, dispatch_base, access_token, &module.id)
    });
    let manifest = match fetched {
        Ok(m) => m,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(fetch_err) => {
            if version_is_recorded(client, apps_base, access_token, &module.id, version)? {
                print_already_recorded(slug, version);
                return Ok(());
            }
            return Err(anyhow!(
                "recording a new version needs the module running under `mirrorstack dev` (its manifest is captured at record time) — start it or record later ({fetch_err})"
            ));
        }
    };

    // README files are the module's long-form description — optional and
    // free-form (no lint). `README.md` is the `default`; `README.<tag>.md`
    // adds a locale translation. They're frozen on the version row alongside
    // the changelog, so they're read here on the fresh-record path only; an
    // empty map (no README files) is omitted from the request.
    let readme = readme::read(dir)?;

    let result = with_spinner("Recording version…", || {
        api::record_module_version(
            client,
            apps_base,
            access_token,
            &module.id,
            &RecordModuleVersionInput {
                version,
                changelog: &entry.map,
                readme: &readme.map,
                manifest: &manifest,
            },
        )
    });

    match result {
        Ok(recorded) => {
            // Warnings describe the changelog/readme just frozen; on the
            // already-recorded path they'd be noise about files the platform
            // no longer reads.
            for w in &entry.warnings {
                eprintln!("{} {w}", warn_prefix());
            }
            if readme.truncated {
                eprintln!(
                    "{} a README file exceeded {} bytes and was truncated for the version record",
                    warn_prefix(),
                    readme::MAX_README_BYTES
                );
            }
            eprintln!(
                "{} recorded {}",
                ok_mark(),
                style(format!("{slug}@{version}")).cyan().bold()
            );
            eprintln!("  {} {}", style("id:").dim(), recorded.id);
            // `default` (CHANGELOG.md) is always present after a clean lint.
            for line in changelog_preview(&entry.map["default"], 3) {
                eprintln!("  {} {line}", style("│").dim());
            }
            Ok(())
        }
        Err(ApiError::Server { code, .. }) if code == "version_exists" => {
            print_already_recorded(slug, version);
            Ok(())
        }
        Err(ApiError::Server { code, message, .. }) => Err(anyhow!(
            "{code}: {message}{hint}",
            hint = record_error_hint(&code)
        )),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

/// Whether `version` already exists as a recorded row. Used to downgrade
/// failures of the record's local inputs (changelog lint, manifest fetch):
/// when the record already happened those inputs are frozen server-side and
/// the deploy proceeds without them.
fn version_is_recorded(
    client: &reqwest::blocking::Client,
    apps_base: &str,
    access_token: &str,
    module_id: &str,
    version: &str,
) -> Result<bool> {
    let listed = with_spinner("Checking recorded versions…", || {
        api::list_module_versions(client, apps_base, access_token, module_id)
    });
    match listed {
        Ok(versions) => Ok(versions.iter().any(|v| v.version == version)),
        Err(ApiError::Unauthenticated) => Err(session_expired()),
        Err(e) => Err(e.into()),
    }
}

fn print_already_recorded(slug: &str, version: &str) {
    eprintln!(
        "{} {} is already recorded — its changelog is frozen. Bump the Versions key in main.go to ship a new entry.",
        ok_mark(),
        style(format!("{slug}@{version}")).cyan()
    );
}

/// First `max_lines` non-empty changelog lines for the record summary,
/// with a trailing ellipsis when the section continues.
pub(super) fn changelog_preview(body: &str, max_lines: usize) -> Vec<String> {
    let mut nonempty = body.lines().filter(|l| !l.trim().is_empty());
    let mut out: Vec<String> = nonempty
        .by_ref()
        .take(max_lines)
        .map(|l| l.trim().to_string())
        .collect();
    if nonempty.next().is_some() {
        out.push("…".to_string());
    }
    out
}

/// Hints for the record step. `version_exists` never reaches here — deploy
/// treats it as "already recorded" and proceeds.
pub(super) fn record_error_hint(code: &str) -> &'static str {
    match code {
        "version_invalid" => " (versions must be canonical SemVer, e.g. 1.2.0 or 1.2.0-beta.1)",
        "changelog_too_large" => " (trim this version's CHANGELOG.md section to 16KB)",
        "readme_too_large" => " (trim README.md to 64KB)",
        _ => "",
    }
}

pub(super) fn deploy_error_hint(code: &str) -> &'static str {
    match code {
        // Three routes collapse onto this one code, and api-platform#440
        // gives each its own message ("module not found", "version not found
        // for this module", "artifact upload not found"), so the hint must
        // not name a cause the message hasn't. It only carries the remedy,
        // which is the same for all three except when the module itself is
        // the missing record.
        "not_found" => {
            " (the message says which record the platform couldn't find — re-run `mirrorstack app module deploy` to re-create the version record and its upload; if the module is what's missing, `mirrorstack app module register` it first)"
        }
        // The platform derives invoke_target from the module's own slug and
        // only sanity-checks that derivation — this can't be triggered by
        // anything the CLI sends, but the code is still surfaced if the
        // platform ever rejects a slug shape.
        "invoke_target_invalid" => {
            " (the platform couldn't derive a valid deploy target from this module's slug — this is a platform-side issue, not something to fix locally)"
        }
        "status_invalid" => " (--status must be one of: active, draining, disabled)",
        "artifact_missing" => {
            " (the upload didn't land in object storage — re-run `mirrorstack module deploy`)"
        }
        // The platform's finalize check is a non-empty object under its size
        // ceiling whose first four bytes are the ZIP local-file magic — it
        // does NOT open the archive, so don't claim it verified a `bootstrap`
        // entry. (The CLI is what guarantees the executable root entry, in
        // `artifact::zip_bootstrap`.)
        "artifact_invalid" => {
            " (the platform rejected the uploaded object — it must be a non-empty ZIP under 250.0 MB)"
        }
        // Not reachable from the deploy call itself: the deploy gate is
        // conditional on the platform having an artifact store, and the
        // upload step already downgrades this code to a warning. Kept so the
        // code never surfaces bare if another leg starts returning it.
        "artifact_storage_unconfigured" => {
            " (module artifact storage is not configured on the platform — expected for local prod-sim and bucket-less environments, not something to fix locally)"
        }
        // 409 from finalize only. A second `module deploy` of this same
        // version presigned a fresh upload while this one was verifying, so
        // the platform refuses to certify a readiness verdict for bytes that
        // are no longer the ones behind the key.
        "artifact_superseded" => {
            " (another deploy of this version started a new upload — let that one finish, or re-run `mirrorstack module deploy` to upload and finalize again)"
        }
        // What `httputil.Conflict` emits when a deploy is attempted for a
        // version whose artifact never finalized.
        "conflict" => {
            " (the artifact for this version isn't finalized — re-run `mirrorstack module deploy` so the upload completes before the deploy)"
        }
        // The platform's catch-all 500. Nothing local produced it — a presign
        // failure or a database error behind the artifact row would both land
        // here — so rebuilding and re-uploading changes nothing.
        "internal_error" => {
            " (the platform failed on its side — retry; if it persists it is a platform issue, not something to fix locally)"
        }
        _ => "",
    }
}
