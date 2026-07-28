use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::api::{self, ApiError};
use crate::commands::dev::module_meta::{self, ModuleMeta};
use crate::commands::dev::{
    DEFAULT_MODULE_PORT, INTERNAL_PORT_BASE, MODULE_ROUTE_PREFIX, PROXY_PORT_DEFAULT,
    platform_token_file, workspace,
};
use crate::commands::{DEFAULT_APPS_API_BASE, ENV_APPS_API_URL, resolve_base, session_expired};
use crate::{credentials, http};

use super::index::{Diagnostic, Resolved, Severity, Tier};
use super::wire::Manifest;

pub(crate) struct Unreachable {
    pub slug: String,
    pub reason: String,
}

pub(crate) fn request_headers(
    mut request: reqwest::blocking::RequestBuilder,
    root: &Path,
    slug: &str,
) -> reqwest::blocking::RequestBuilder {
    if let Ok(token) = std::fs::read_to_string(platform_token_file(root, slug))
        && !token.trim().is_empty()
    {
        request = request.header("X-MS-Platform-Token", token.trim());
    }
    if let Ok(secret) = std::env::var("MS_INTERNAL_SECRET")
        && !secret.is_empty()
    {
        request = request.header("X-MS-Internal-Secret", secret);
    }
    request
}

/// Every address a co-located module's manifest can answer on, most direct
/// first: its own internal runner port (the in-container path, and the path a
/// host-side `dev --all` binds), then the dev-proxy as published to the host,
/// then the dev-proxy's in-container port.
pub(crate) fn manifest_urls(internal_port: u16, slug: &str) -> [String; 3] {
    [
        format!("http://127.0.0.1:{internal_port}{MANIFEST_PATH}"),
        format!("http://127.0.0.1:{DEFAULT_MODULE_PORT}{MODULE_ROUTE_PREFIX}{slug}{MANIFEST_PATH}"),
        format!("http://127.0.0.1:{PROXY_PORT_DEFAULT}{MODULE_ROUTE_PREFIX}{slug}{MANIFEST_PATH}"),
    ]
}

pub(crate) const MANIFEST_PATH: &str = "/__mirrorstack/platform/manifest";

fn serving_tier(verdict: &str) -> Result<Option<Tier>, String> {
    match verdict {
        "tunnel" => Ok(Some(Tier::L)),
        "deployed" => Ok(Some(Tier::D)),
        "none" => Ok(None),
        verdict => Err(format!(
            "the platform returned unsupported serving verdict {verdict:?}"
        )),
    }
}

/// Walk `go.work` and pair each module `dev` would actually start with the
/// internal port it would bind. Port assignment must mirror `dev::run_inner`
/// exactly — only modules carrying a platform ID are started, and they take
/// 18080+ in go.work order — because an off-by-one here would read a SIBLING
/// module's manifest and report its capabilities under the wrong name.
/// Filesystem-only, so it is testable without a dev session.
pub(crate) fn ready_modules(root: &Path) -> Result<Vec<(ModuleMeta, u16)>> {
    let mut ready = Vec::new();
    for module in workspace::discover_modules(root)? {
        let Ok(meta) = module_meta::read_module_meta(&module.abs_dir, root) else {
            continue;
        };
        if meta.id.is_empty() {
            continue;
        }
        let port = INTERNAL_PORT_BASE + u16::try_from(ready.len()).unwrap_or(u16::MAX);
        ready.push((meta, port));
    }
    Ok(ready)
}

pub(crate) fn tier_local(root: &Path) -> Result<(Vec<Resolved>, Vec<Unreachable>)> {
    let client = http::client(Duration::from_secs(2))?;
    let mut resolved = Vec::new();
    let mut unreachable = Vec::new();
    for (meta, internal) in ready_modules(root)? {
        let urls = manifest_urls(internal, &meta.slug);
        let mut manifest = None;
        let mut last_status = None;
        for url in &urls {
            match request_headers(client.get(url), root, &meta.slug).send() {
                Ok(resp) if resp.status() == reqwest::StatusCode::OK => {
                    match resp.json::<Manifest>() {
                        Ok(value) => {
                            manifest = Some(value);
                            break;
                        }
                        Err(error) => {
                            last_status = Some(format!(
                                "200 from {url} but the manifest did not parse: {error}"
                            ));
                        }
                    }
                }
                // A 503 here is the SDK failing closed on an unreadable
                // MS_PLATFORM_TOKEN_FILE — the state a non-tunnel `mirrorstack
                // dev` leaves modules in, so say what unblocks it.
                Ok(resp) if resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE => {
                    last_status = Some(format!(
                        "HTTP 503 from {url} — the module's internal routes are failing closed; run `mirrorstack dev --tunnel` so it gets a readable platform token"
                    ));
                }
                Ok(resp) => {
                    last_status = Some(format!("HTTP {} from {url}", resp.status().as_u16()))
                }
                Err(_) => {}
            }
        }
        let Some(manifest) = manifest else {
            let reason = last_status.unwrap_or_else(|| format!(
                "no dev session answered on :{internal}, :{DEFAULT_MODULE_PORT} or :{PROXY_PORT_DEFAULT}"
            ));
            unreachable.push(Unreachable {
                slug: meta.slug,
                reason,
            });
            continue;
        };
        let keys: Vec<_> = manifest.versions.keys().cloned().collect();
        let version = module_meta::latest_version(&keys)
            .or(meta.version)
            .unwrap_or_else(|| "unknown".into());
        resolved.push(Resolved {
            slug: if manifest.slug.is_empty() {
                meta.slug
            } else {
                manifest.slug.clone()
            },
            id: if manifest.id.is_empty() {
                meta.id
            } else {
                manifest.id.clone()
            },
            version: version.strip_prefix('v').unwrap_or(&version).into(),
            tier: Tier::L,
            manifest,
        });
    }
    Ok((resolved, unreachable))
}

pub(crate) fn tier_app(app_ref: &str) -> Result<(Vec<Resolved>, Vec<Unreachable>)> {
    let mut creds = credentials::load_or_login_hint()?;
    let client = http::client(Duration::from_secs(15))?;
    let apps_base = resolve_base(ENV_APPS_API_URL, DEFAULT_APPS_API_BASE);
    // Both calls go through with_refresh_retry so an expired access token
    // refreshes in place instead of surfacing as "session expired".
    let app = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::get_app(&client, &apps_base, tok, app_ref)
    }) {
        Ok(Some(app)) => app,
        Ok(None) => {
            return Err(anyhow!(
                "app '{app_ref}' not found (or you are not a member)"
            ));
        }
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(error) => return Err(error.into()),
    };
    let installs = match credentials::with_refresh_retry(&mut creds, |tok| {
        api::list_app_installs(&client, &apps_base, tok, &app.id)
    }) {
        Ok(installs) => installs,
        Err(ApiError::Unauthenticated) => return Err(session_expired()),
        Err(error) => return Err(error.into()),
    };
    let mut resolved = Vec::new();
    let mut unreachable = Vec::new();
    for install in installs {
        let name = if install.slug.is_empty() {
            install.name.clone()
        } else {
            install.slug.clone()
        };
        let tier = match serving_tier(&install.serving) {
            Ok(Some(tier)) => tier,
            Ok(None) => {
                unreachable.push(Unreachable {
                    slug: name,
                    reason: "the platform reports that this install has no serving tunnel or deployed version".into(),
                });
                continue;
            }
            Err(reason) => {
                unreachable.push(Unreachable { slug: name, reason });
                continue;
            }
        };
        let Some(value) = install.manifest else {
            unreachable.push(Unreachable {
                slug: name,
                reason: format!(
                    "installed at {} but the platform stored no manifest for that version",
                    install.installed_version
                ),
            });
            continue;
        };
        let manifest: Manifest = serde_json::from_value(value)
            .with_context(|| format!("decode stored manifest for {name}"))?;
        resolved.push(Resolved {
            slug: if manifest.slug.is_empty() {
                install.slug
            } else {
                manifest.slug.clone()
            },
            id: if manifest.id.is_empty() {
                install.module_id
            } else {
                manifest.id.clone()
            },
            version: install.installed_version,
            tier,
            manifest,
        });
    }
    Ok((resolved, unreachable))
}

/// A co-located module we could not read becomes a `host_unresolvable`
/// diagnostic so a `--json` consumer can tell "not co-located at all" from
/// "co-located but not answering".
pub(crate) fn unreachable_diagnostics(unreachable: &[Unreachable]) -> Vec<Diagnostic> {
    unreachable
        .iter()
        .map(|u| Diagnostic {
            severity: Severity::Error,
            code: "host_unresolvable",
            module: u.slug.clone(),
            detail: u.reason.clone(),
            related_host: Some(u.slug.clone()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_urls_cover_the_runner_port_and_both_proxy_ports() {
        let urls = manifest_urls(18081, "oauth-core");
        assert_eq!(
            urls[0],
            "http://127.0.0.1:18081/__mirrorstack/platform/manifest"
        );
        assert_eq!(
            urls[1],
            "http://127.0.0.1:9080/_m/oauth-core/__mirrorstack/platform/manifest"
        );
        assert_eq!(
            urls[2],
            "http://127.0.0.1:8080/_m/oauth-core/__mirrorstack/platform/manifest"
        );
    }

    #[test]
    fn platform_serving_verdict_selects_the_runtime_tier() {
        assert_eq!(serving_tier("tunnel"), Ok(Some(Tier::L)));
        assert_eq!(serving_tier("deployed"), Ok(Some(Tier::D)));
        assert_eq!(serving_tier("none"), Ok(None));
        assert!(serving_tier("").unwrap_err().contains("unsupported"));
    }

    /// The internal port is positional, so a module in go.work that `dev` skips
    /// (no platform ID) must NOT consume a port — otherwise every module after
    /// it is probed at its neighbour's address and reported under the wrong name.
    #[test]
    fn unregistered_modules_do_not_consume_an_internal_port() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(
            root.join("go.work"),
            "go 1.26\n\nuse (\n\t./unregistered\n\t./first\n\t./second\n)\n",
        )
        .unwrap();
        for slug in ["unregistered", "first", "second"] {
            std::fs::create_dir(root.join(slug)).unwrap();
            std::fs::write(
                root.join(slug).join("main.go"),
                format!("package main\n\nvar c = ms.Config{{Slug: \"{slug}\"}}\n"),
            )
            .unwrap();
        }
        std::fs::write(
            root.join(".env"),
            "MS_MODULE_ID_FIRST=m-first\nMS_MODULE_ID_SECOND=m-second\n",
        )
        .unwrap();

        let ready = ready_modules(root).expect("walk");
        assert_eq!(
            ready
                .iter()
                .map(|(m, port)| (m.slug.as_str(), *port))
                .collect::<Vec<_>>(),
            [("first", 18080), ("second", 18081)]
        );
    }
}
