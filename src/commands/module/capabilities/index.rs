use serde::Serialize;
use serde_json::Value;

use super::schema;
use super::version;
use super::wire::{Manifest, parse_ref};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum Tier {
    #[serde(rename = "L")]
    L,
    #[serde(rename = "D")]
    D,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::L => "L",
            Self::D => "D",
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Resolved {
    pub slug: String,
    pub id: String,
    pub version: String,
    pub tier: Tier,
    pub manifest: Manifest,
}

impl Resolved {
    fn name(&self) -> &str {
        if self.slug.is_empty() {
            &self.id
        } else {
            &self.slug
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Report {
    pub resolved: Vec<ResolvedEntry>,
    pub slots: Vec<SlotEntry>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedEntry {
    pub module: String,
    pub version: String,
    pub tier: Tier,
    pub provides: Vec<SlotSummary>,
    pub exposes: ExposesOut,
    pub permissions: Vec<String>,
    pub events: EventsOut,
}

#[derive(Debug, Serialize)]
pub(crate) struct SlotSummary {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExposesOut {
    pub tables: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct EventsOut {
    pub emits: Vec<String>,
    pub subscribes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SlotEntry {
    pub key: String,
    pub host: String,
    pub host_version: String,
    pub tier: Tier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    pub filled_by: Vec<FilledBy>,
}

#[derive(Debug, Serialize)]
pub(crate) struct FilledBy {
    pub module: String,
    pub version: String,
    pub tier: Tier,
}

#[derive(Debug, Serialize)]
pub(crate) struct Diagnostic {
    pub severity: Severity,
    pub code: &'static str,
    pub module: String,
    pub detail: String,
    #[serde(skip)]
    pub related_host: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Severity {
    Error,
    Info,
}

fn diagnostic(
    severity: Severity,
    code: &'static str,
    module: &Resolved,
    detail: String,
    related_host: Option<String>,
) -> Diagnostic {
    Diagnostic {
        severity,
        code,
        module: module.name().into(),
        detail,
        related_host,
    }
}

fn find<'a>(resolved: &'a [Resolved], reference: &str) -> Option<&'a Resolved> {
    resolved
        .iter()
        .find(|r| r.slug == reference || r.id == reference)
}

/// Cross-check every resolved module's declared surface against every other.
pub(crate) fn classify(resolved: &[Resolved]) -> Report {
    let mut report = Report {
        resolved: Vec::new(),
        slots: Vec::new(),
        diagnostics: Vec::new(),
    };
    for module in resolved {
        report.resolved.push(ResolvedEntry {
            module: module.name().into(),
            version: module.version.clone(),
            tier: module.tier,
            provides: module
                .manifest
                .provides
                .iter()
                .map(|s| SlotSummary {
                    key: s.key.clone(),
                    payload: s.payload.clone(),
                })
                .collect(),
            exposes: ExposesOut {
                tables: module.manifest.exposes.tables.clone(),
            },
            permissions: module
                .manifest
                .permissions
                .iter()
                .map(|p| p.name.clone())
                .collect(),
            events: EventsOut {
                emits: module.manifest.events.emits.clone(),
                subscribes: module.manifest.events.subscribes.clone(),
            },
        });
        report
            .slots
            .extend(module.manifest.provides.iter().map(|slot| SlotEntry {
                key: slot.key.clone(),
                host: module.name().into(),
                host_version: module.version.clone(),
                tier: module.tier,
                payload: slot.payload.clone(),
                filled_by: Vec::new(),
            }));
    }
    for contributor in resolved {
        for contribution in &contributor.manifest.contributes_to {
            let (host_slug, embedded) = parse_ref(&contribution.host);
            let constraint = contribution.constraint.as_ref().or(embedded.as_ref());
            let Some(host) = find(resolved, &host_slug) else {
                report.diagnostics.push(diagnostic(Severity::Error, "host_unresolvable", contributor,
                    format!("contributes to {}/{slot}; no resolvable module provides host \"{host_slug}\"", contribution.host, slot = contribution.slot),
                    Some(host_slug)));
                continue;
            };
            // Past this point the host has RESOLVED, so every message names the
            // resolved module rather than echoing the raw `id@constraint` spec
            // back — the slot reference has to read as `host/slot`.
            let host_name = host.name();
            if let Some(constraint) = constraint.filter(|c| !c.is_empty())
                && !version::satisfies(constraint, &host.version)
            {
                report.diagnostics.push(diagnostic(Severity::Error, "version_skew", contributor,
                    format!("contributes to {host_name}/{slot} pinned {constraint}, but the resolved host is {host_name}@{} (tier {})", host.version, host.tier, slot = contribution.slot),
                    Some(host_name.into())));
            }
            let Some(host_slot) = host
                .manifest
                .provides
                .iter()
                .find(|s| s.key == contribution.slot)
            else {
                let mut declared: Vec<_> = host
                    .manifest
                    .provides
                    .iter()
                    .map(|s| s.key.as_str())
                    .collect();
                declared.sort_unstable();
                let suffix = if declared.is_empty() {
                    "declares no slots".into()
                } else {
                    format!("declares: {}", declared.join(", "))
                };
                report.diagnostics.push(diagnostic(Severity::Error, "slot_unknown", contributor,
                    format!("contributes to {host_name}/{slot}; {host_name}@{} (tier {}) declares no such slot ({suffix})", host.version, host.tier, slot = contribution.slot),
                    Some(host_name.into())));
                continue;
            };
            if let Some(slot) = report
                .slots
                .iter_mut()
                .find(|s| s.host == host_name && s.key == contribution.slot)
            {
                slot.filled_by.push(FilledBy {
                    module: contributor.name().into(),
                    version: contributor.version.clone(),
                    tier: contributor.tier,
                });
            }
            if let (Some(schema), Some(payload)) = (&host_slot.payload, &contribution.payload)
                && let Err(reason) = schema::validate(schema, payload)
            {
                report.diagnostics.push(diagnostic(
                    Severity::Error,
                    "payload_mismatch",
                    contributor,
                    format!(
                        "payload for {host_name}/{slot} does not match the host slot schema: {reason}",
                        slot = contribution.slot
                    ),
                    Some(host_name.into()),
                ));
            }
        }
        for dependency in &contributor.manifest.dependencies {
            let (dep_slug, embedded) = parse_ref(&dependency.id);
            // A dependency not co-located is normal; only contributions require
            // their host to resolve because they must join a declared slot.
            let Some(dep) = find(resolved, &dep_slug) else {
                continue;
            };
            let constraint = dependency
                .version
                .as_ref()
                .filter(|v| !v.is_empty())
                .or(embedded.as_ref());
            if let Some(constraint) = constraint
                && !version::satisfies(constraint, &dep.version)
            {
                report.diagnostics.push(diagnostic(
                    Severity::Error,
                    "version_skew",
                    contributor,
                    format!(
                        "depends on {} {constraint}, but the resolved module is {}@{} (tier {})",
                        dependency.id,
                        dep.name(),
                        dep.version,
                        dep.tier
                    ),
                    Some(dep.name().into()),
                ));
            }
            for table in dependency
                .tables
                .iter()
                .filter(|t| !dep.manifest.exposes.tables.contains(t))
            {
                // This catches the live-403 class where local source expects an
                // exposure absent from the version that actually resolved.
                let exposed = list_or_none(&dep.manifest.exposes.tables, "tables");
                report.diagnostics.push(diagnostic(
                    Severity::Error,
                    "version_skew",
                    contributor,
                    format!(
                        "depends on {} table \"{table}\", but {}@{} (tier {}) exposes {exposed}",
                        dep.name(),
                        dep.name(),
                        dep.version,
                        dep.tier
                    ),
                    Some(dep.name().into()),
                ));
            }
            for event in dependency
                .events
                .iter()
                .filter(|e| !dep.manifest.events.emits.contains(e))
            {
                let emitted = list_or_none(&dep.manifest.events.emits, "events");
                report.diagnostics.push(diagnostic(
                    Severity::Error,
                    "version_skew",
                    contributor,
                    format!(
                        "depends on {} event \"{event}\", but {}@{} (tier {}) emits {emitted}",
                        dep.name(),
                        dep.name(),
                        dep.version,
                        dep.tier
                    ),
                    Some(dep.name().into()),
                ));
            }
        }
    }
    for slot in report.slots.iter().filter(|s| s.filled_by.is_empty()) {
        report.diagnostics.push(Diagnostic {
            severity: Severity::Info,
            code: "slot_unfilled",
            module: slot.host.clone(),
            detail: format!(
                "slot {}/{} is declared but no resolvable module contributes to it",
                slot.host, slot.key
            ),
            related_host: Some(slot.host.clone()),
        });
    }
    sort_report(&mut report);
    report
}

fn list_or_none(values: &[String], noun: &str) -> String {
    if values.is_empty() {
        format!("no {noun}")
    } else {
        values.join(", ")
    }
}

pub(crate) fn sort_report(report: &mut Report) {
    report.resolved.sort_by(|a, b| a.module.cmp(&b.module));
    report
        .slots
        .sort_by(|a, b| (&a.host, &a.key).cmp(&(&b.host, &b.key)));
    for slot in &mut report.slots {
        slot.filled_by.sort_by(|a, b| a.module.cmp(&b.module));
    }
    report.diagnostics.sort_by(|a, b| {
        (a.severity, a.code, &a.module, &a.detail).cmp(&(b.severity, b.code, &b.module, &b.detail))
    });
}

/// Keep only the host, its contributors, slots, and related diagnostics.
pub(crate) fn filter_host(mut report: Report, host: &str) -> Report {
    let contributors: std::collections::BTreeSet<_> = report
        .slots
        .iter()
        .filter(|s| s.host == host)
        .flat_map(|s| s.filled_by.iter().map(|f| f.module.clone()))
        .collect();
    report
        .resolved
        .retain(|r| r.module == host || contributors.contains(&r.module));
    report.slots.retain(|s| s.host == host);
    report
        .diagnostics
        .retain(|d| d.module == host || d.related_host.as_deref() == Some(host));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Fixtures are built by DESERIALIZING manifest JSON rather than by
    /// constructing `Manifest` directly, so every test doubles as a wire-shape
    /// test against what a module actually serves.
    fn module(slug: &str, version: &str, manifest: Value) -> Resolved {
        Resolved {
            slug: slug.into(),
            id: format!("m-{slug}"),
            version: version.into(),
            tier: Tier::L,
            manifest: serde_json::from_value(manifest).expect("fixture manifest"),
        }
    }

    /// Modeled on the real oauth-core: one slot carrying a payload schema, one
    /// exposed table, one emitted event.
    fn oauth_core() -> Resolved {
        module(
            "oauth-core",
            "0.1.0",
            json!({
                "slug": "oauth-core",
                "provides": [
                    {"key": "auth-provider", "payload": {
                        "type": "object", "required": ["slug"],
                        "properties": {"slug": {"type": "string"}, "name": {"type": "string"}}
                    }},
                    {"key": "user-detail-blocks"}
                ],
                "exposes": {"tables": ["users"]},
                "permissions": [{"name": "users.read"}],
                "events": {"emits": ["user.created"]}
            }),
        )
    }

    fn contributor(slug: &str, manifest: Value) -> Resolved {
        module(slug, "0.1.0", manifest)
    }

    fn codes(report: &Report) -> Vec<&str> {
        report.diagnostics.iter().map(|d| d.code).collect()
    }

    fn only(report: &Report, code: &str) -> String {
        let matching: Vec<_> = report
            .diagnostics
            .iter()
            .filter(|d| d.code == code)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "expected one {code} in {:?}",
            codes(report)
        );
        matching[0].detail.clone()
    }

    #[test]
    fn a_contribution_to_a_known_slot_fills_it_and_raises_nothing() {
        let report = classify(&[
            oauth_core(),
            contributor(
                "oauth-google",
                json!({"slug": "oauth-google", "contributesTo": [
                    {"host": "oauth-core", "slot": "auth-provider", "payload": {"slug": "google"}}
                ]}),
            ),
        ]);
        let slot = report
            .slots
            .iter()
            .find(|s| s.key == "auth-provider")
            .expect("slot");
        assert_eq!(slot.filled_by.len(), 1);
        assert_eq!(slot.filled_by[0].module, "oauth-google");
        assert_eq!(slot.filled_by[0].version, "0.1.0");
        assert_eq!(slot.filled_by[0].tier, Tier::L);
        // Only the second, genuinely unfilled slot is reported.
        assert_eq!(codes(&report), ["slot_unfilled"]);
    }

    /// The `profile-store` bug, pinned: users-profile contributes into a slot
    /// oauth-core does not declare, and nothing anywhere caught it.
    #[test]
    fn a_contribution_to_an_undeclared_slot_is_slot_unknown() {
        let report = classify(&[
            oauth_core(),
            contributor(
                "users-profile",
                json!({"slug": "users-profile", "contributesTo": [
                    {"host": "oauth-core", "slot": "profile-store",
                     "payload": {"profileUrl": "/internal/profile"}}
                ]}),
            ),
        ]);
        let detail = only(&report, "slot_unknown");
        assert!(detail.contains("oauth-core/profile-store"), "{detail}");
        // The message must name what the host DOES declare, or the author still
        // has to go grepping — the exact step that produced the bug.
        assert!(
            detail.contains("auth-provider, user-detail-blocks"),
            "{detail}"
        );
        assert!(detail.contains("0.1.0"), "{detail}");
    }

    #[test]
    fn a_declared_slot_with_no_contributor_is_info_only() {
        let report = classify(&[oauth_core()]);
        assert_eq!(codes(&report), ["slot_unfilled", "slot_unfilled"]);
        assert!(
            report
                .diagnostics
                .iter()
                .all(|d| d.severity == Severity::Info)
        );
    }

    #[test]
    fn a_contribution_whose_host_resolves_nowhere_is_host_unresolvable() {
        let report = classify(&[contributor(
            "users-profile",
            json!({"contributesTo": [{"host": "@mirrorstack/absent@^0.1", "slot": "x"}]}),
        )]);
        let detail = only(&report, "host_unresolvable");
        assert!(detail.contains("\"absent\""), "{detail}");
    }

    #[test]
    fn a_payload_failing_the_slot_schema_is_payload_mismatch() {
        let report = classify(&[
            oauth_core(),
            contributor(
                "oauth-google",
                json!({"contributesTo": [
                    {"host": "oauth-core", "slot": "auth-provider", "payload": {"slug": 7}}
                ]}),
            ),
        ]);
        let detail = only(&report, "payload_mismatch");
        assert!(detail.contains("expected string"), "{detail}");
    }

    #[test]
    fn a_constraint_excluding_the_resolved_host_version_is_version_skew() {
        let report = classify(&[
            oauth_core(),
            contributor(
                "oauth-google",
                json!({"contributesTo": [
                    {"host": "oauth-core", "slot": "auth-provider",
                     "constraint": "^1", "payload": {"slug": "google"}}
                ]}),
            ),
        ]);
        let detail = only(&report, "version_skew");
        assert!(detail.contains("^1"), "{detail}");
        assert!(detail.contains("oauth-core@0.1.0"), "{detail}");
    }

    /// The live-403 class: local source declares a dependency read the resolved
    /// version does not expose.
    #[test]
    fn a_dependency_on_an_unexposed_table_is_version_skew() {
        let report = classify(&[
            oauth_core(),
            contributor(
                "users-profile",
                json!({"dependencies": [
                    {"id": "@mirrorstack/oauth-core@^0.1", "tables": ["users", "sessions"]}
                ]}),
            ),
        ]);
        let detail = only(&report, "version_skew");
        assert!(detail.contains("\"sessions\""), "{detail}");
        assert!(detail.contains("exposes users"), "{detail}");
    }

    #[test]
    fn a_dependency_on_a_module_outside_the_workspace_is_silent() {
        // Depending on a module that simply is not co-located is normal; only
        // contributions require their host to resolve.
        let report = classify(&[contributor(
            "users-profile",
            json!({"dependencies": [{"id": "@mirrorstack/absent@^0.1", "tables": ["users"]}]}),
        )]);
        assert!(report.diagnostics.is_empty(), "{:?}", codes(&report));
    }

    /// The wire shape BEFORE the SDK adds `provides[].payload` and
    /// `contributesTo[].constraint`. Their absence must never raise anything.
    #[test]
    fn the_pre_schema_wire_shape_raises_nothing() {
        let report = classify(&[
            module(
                "oauth-core",
                "0.1.0",
                json!({"provides": [{"key": "auth-provider"}]}),
            ),
            contributor(
                "oauth-google",
                json!({"contributesTo": [{"host": "oauth-core", "slot": "auth-provider"}]}),
            ),
        ]);
        assert!(report.diagnostics.is_empty(), "{:?}", codes(&report));
    }

    #[test]
    fn output_order_is_deterministic() {
        let report = classify(&[
            module(
                "z",
                "0.1.0",
                json!({"provides": [{"key": "b"}, {"key": "a"}]}),
            ),
            module("a", "0.1.0", json!({})),
        ]);
        assert_eq!(
            report
                .resolved
                .iter()
                .map(|e| e.module.as_str())
                .collect::<Vec<_>>(),
            ["a", "z"]
        );
        assert_eq!(
            report
                .slots
                .iter()
                .map(|s| s.key.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn filter_host_keeps_the_host_its_contributors_and_its_diagnostics() {
        let report = classify(&[
            oauth_core(),
            contributor(
                "oauth-google",
                json!({"contributesTo": [
                    {"host": "oauth-core", "slot": "auth-provider", "payload": {"slug": "google"}}
                ]}),
            ),
            contributor("unrelated", json!({"provides": [{"key": "elsewhere"}]})),
        ]);
        let filtered = filter_host(report, "oauth-core");
        assert_eq!(
            filtered
                .resolved
                .iter()
                .map(|r| r.module.as_str())
                .collect::<Vec<_>>(),
            ["oauth-core", "oauth-google"]
        );
        assert!(filtered.slots.iter().all(|s| s.host == "oauth-core"));
        assert!(
            filtered
                .diagnostics
                .iter()
                .all(|d| d.module == "oauth-core")
        );
    }
}
