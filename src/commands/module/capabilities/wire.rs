use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Manifest {
    pub id: String,
    pub slug: String,
    pub versions: BTreeMap<String, Value>,
    pub provides: Vec<Slot>,
    pub contributes_to: Vec<Contribution>,
    pub dependencies: Vec<Dependency>,
    pub exposes: Exposes,
    pub permissions: Vec<Permission>,
    pub events: Events,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Slot {
    pub key: String,
    pub schema_tag: Option<String>,
    pub payload: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Contribution {
    pub host: String,
    pub slot: String,
    pub payload: Option<Value>,
    pub constraint: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Dependency {
    pub id: String,
    pub version: Option<String>,
    pub optional: bool,
    pub tables: Vec<String>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Exposes {
    pub tables: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Permission {
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Events {
    pub emits: Vec<String>,
    pub subscribes: BTreeMap<String, String>,
}

/// Split a module reference into (slug, optional version constraint).
pub(crate) fn parse_ref(spec: &str) -> (String, Option<String>) {
    let stripped = spec.strip_prefix('@').unwrap_or(spec);
    let name = stripped.rsplit('/').next().unwrap_or(stripped);
    match name.split_once('@') {
        Some((slug, constraint)) => (slug.into(), Some(constraint.into())),
        None => (name.into(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ref;

    #[test]
    fn parses_supported_reference_forms() {
        assert_eq!(parse_ref("oauth-core"), ("oauth-core".into(), None));
        assert_eq!(
            parse_ref("@mirrorstack/oauth-core"),
            ("oauth-core".into(), None)
        );
        assert_eq!(
            parse_ref("@mirrorstack/oauth-core@^0.1"),
            ("oauth-core".into(), Some("^0.1".into()))
        );
        assert_eq!(
            parse_ref("oauth-core@^0.1"),
            ("oauth-core".into(), Some("^0.1".into()))
        );
        assert_eq!(
            parse_ref("550e8400-e29b-41d4-a716-446655440000"),
            ("550e8400-e29b-41d4-a716-446655440000".into(), None)
        );
    }
}
