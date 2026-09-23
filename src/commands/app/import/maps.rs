//! The owner-filled D-3 map file: alpha role / approval state / extra_fields
//! key / category / visibility → V2 keys. The import refuses anything unmapped
//! (an exception, never an auto-created V2 key).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Maps {
    /// V2 user id recorded as `granted_by` / `decided_by` on imported rows.
    pub import_actor: String,
    /// alpha role → V2 user-roles key. An empty value drops the role on purpose.
    #[serde(default)]
    pub roles: BTreeMap<String, String>,
    /// alpha role that is an approval state (T631: `wait_review`, `wait_info`)
    /// → the user-approval category and state it becomes.
    #[serde(default)]
    pub approval_states: BTreeMap<String, ApprovalState>,
    /// alpha profile key (`phone`, `id_number`, or an `extra_fields` key) →
    /// V2 user-profile field key.
    #[serde(default)]
    pub profile_fields: BTreeMap<String, String>,
    /// alpha category → V2 video-category key.
    #[serde(default)]
    pub categories: BTreeMap<String, String>,
    /// alpha `videos.visibility` → V2 `access_mode` (public / auth / credit).
    #[serde(default)]
    pub visibility: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalState {
    pub category: String,
    pub state: String,
}

impl Maps {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read map file {}", path.display()))?;
        let maps: Maps = yaml_serde::from_str(&raw)
            .with_context(|| format!("parse map file {}", path.display()))?;
        maps.validate()?;
        Ok(maps)
    }

    pub fn validate(&self) -> Result<()> {
        if uuid::Uuid::parse_str(&self.import_actor).is_err() {
            return Err(anyhow!("import_actor must be the V2 user id of the import actor"));
        }
        for (alpha, mode) in &self.visibility {
            if !matches!(mode.as_str(), "public" | "auth" | "credit") {
                return Err(anyhow!("visibility.{alpha}: {mode:?} is not public, auth or credit"));
            }
        }
        if let Some(r) = self.roles.keys().find(|r| self.approval_states.contains_key(*r)) {
            return Err(anyhow!("{r} is in both roles and approval_states"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "import_actor: 5b0f6a3e-0a57-4d1c-9a55-3d2f7f1c9e10\n\
roles: {active: active, admin: admin}\n\
approval_states: {wait_review: {category: membership, state: pending}}\n\
profile_fields: {phone: phone}\n\
categories: {special: special}\n\
visibility: {credit: credit}\n";

    #[test]
    fn sample_map_parses_and_validates() {
        let m: Maps = yaml_serde::from_str(SAMPLE).unwrap();
        m.validate().unwrap();
        assert_eq!(m.roles["active"], "active");
        assert_eq!(m.approval_states["wait_review"].category, "membership");
    }

    #[test]
    fn bad_actor_mode_and_overlap_are_refused() {
        let mut m: Maps = yaml_serde::from_str(SAMPLE).unwrap();
        m.import_actor = "import".into();
        assert!(m.validate().is_err());
        let mut m: Maps = yaml_serde::from_str(SAMPLE).unwrap();
        m.visibility.insert("x".into(), "paid".into());
        assert!(m.validate().is_err());
        let mut m: Maps = yaml_serde::from_str(SAMPLE).unwrap();
        m.roles.insert("wait_review".into(), "x".into());
        assert!(m.validate().is_err());
    }
}
