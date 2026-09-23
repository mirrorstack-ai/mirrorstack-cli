use super::*;
use crate::commands::app::import::extract::{AlphaSegmentFetch, AlphaUnlock};
use crate::commands::app::import::maps::ApprovalState;

fn maps() -> Maps {
    Maps {
        import_actor: "5b0f6a3e-0a57-4d1c-9a55-3d2f7f1c9e10".into(),
        roles: [("active", "active"), ("admin", "admin"), ("suspended", "suspended")]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        approval_states: [(
            "wait_review".to_string(),
            ApprovalState { category: "membership".into(), state: "pending".into() },
        )]
        .into(),
        profile_fields: [("phone".to_string(), "phone".to_string())].into(),
        categories: [("special".to_string(), "special".to_string())].into(),
        visibility: [("credit".to_string(), "credit".to_string())].into(),
    }
}

fn user(id: &str, roles: &[&str]) -> AlphaUser {
    AlphaUser {
        id: id.into(),
        provider: "google".into(),
        provider_uid: "104857600123456789012".into(),
        name: "A".into(),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        created_at: "2025-01-01T00:00:00.000000Z".into(),
        updated_at: "2025-01-02T00:00:00.000000Z".into(),
        ..Default::default()
    }
}

fn video(id: &str, cost: i64) -> AlphaVideo {
    AlphaVideo {
        id: id.into(),
        title: "T".into(),
        s3_source_key: format!("k/video-{id}/source/original.mp4"),
        s3_hls_prefix: format!("k/video-{id}/hls/"),
        status: "ready".into(),
        visibility: "credit".into(),
        credit_cost: cost,
        sections: "[]".into(),
        allowed_roles: vec!["active".into()],
        declined_roles: vec!["suspended".into()],
        encryption_key: Some(vec![7; 16]),
        ..Default::default()
    }
}

fn ready() -> MediaOutcome {
    MediaOutcome::Ready { rungs: vec!["144p".into()], original: true }
}

#[test]
fn users_keep_their_google_id_and_refuse_what_cannot_sign_in() {
    let mut snap = Snapshot::default();
    snap.users = vec![user("u1", &["active"]), user("u2", &[]), user("u3", &[])];
    snap.users[1].provider = "anonymous".into();
    snap.users[2].provider_uid = "someone@example.com".into();
    let mut plan = Plan::default();
    let planned = users(&snap, &mut plan);
    assert_eq!(planned.into_iter().collect::<Vec<_>>(), ["u1"]);
    let row = &plan.rows["user"][0];
    assert_eq!(row.data["provider"], "google");
    assert_eq!(row.data["providerUid"], "104857600123456789012");
    assert_eq!(row.data["email"], Value::Null, "'' becomes NULL");
    assert_eq!(row.data["lastSignInAt"], "2025-01-01T00:00:00.000000Z");
    let reasons: Vec<_> = plan.exceptions.iter().map(|e| e.reason.as_str()).collect();
    assert_eq!(reasons, ["anonymous_user", "provider_uid_not_numeric"]);
}

#[test]
fn ids_are_deterministic() {
    assert_eq!(video_id("VaPcNc9Y8SMu"), video_id("VaPcNc9Y8SMu"));
    assert_ne!(video_id("VaPcNc9Y8SMu"), video_id("VaPcNc9Y8SMv"));
    assert_eq!(video_id("x").get_version_num(), 5);
    assert_eq!(instructor_id(" Dr. Lin "), instructor_id("dr. lin"));
    let p = video_plan(&video("abc", 4));
    assert_eq!(p, video_plan(&video("abc", 4)));
    assert!(p.v2_hls_prefix.starts_with("_gated/videos/"));
    assert!(p.v2_source_key.ends_with("/source.mp4"));
    let token = p.v2_source_key.split('/').nth(3).unwrap();
    assert_eq!(token.len(), 32, "video-core's source token shape");
}

#[test]
fn roles_approvals_and_unmapped_roles() {
    let mut snap = Snapshot::default();
    snap.users = vec![
        user("u1", &["active", "video_manager"]),
        user("u2", &["wait_review"]),
        user("u3", &["wait_info"]),
    ];
    let ids = snap.users.iter().map(|u| (u.id.clone(), u.id.clone())).collect();
    let m = maps();
    let ctx = Ctx { maps: &m, user_ids: &ids, media: &BTreeMap::new() };
    let mut plan = Plan::default();
    dependents(&snap, &ctx, &mut plan);
    assert_eq!(plan.rows["user_role"].len(), 1);
    assert_eq!(plan.rows["user_role"][0].data["grantedVia"], "import");
    assert_eq!(plan.rows["user_approval"][0].data["categoryKey"], "membership");
    let ex: Vec<_> = plan
        .exceptions
        .iter()
        .map(|e| (e.source_key.as_str(), e.reason.as_str()))
        .collect();
    assert!(ex.contains(&("u1/video_manager", "unmapped_role")));
    assert!(ex.contains(&("u3/wait_info", "unmapped_role")));
    assert!(ex.contains(&("u3", "no_mapped_role")));
    assert!(!ex.iter().any(|(k, _)| *k == "u2"));
}

#[test]
fn dependents_use_the_mapped_v2_user_id() {
    let mut snap = Snapshot::default();
    snap.users = vec![user("alpha-u", &["active"])];
    snap.videos = vec![video("v1", 4), video("v0", 0)];
    snap.unlocks = vec![
        AlphaUnlock { id: "n1".into(), user_id: "alpha-u".into(), video_id: "v1".into(), ..Default::default() },
        AlphaUnlock { id: "n0".into(), user_id: "alpha-u".into(), video_id: "v0".into(), ..Default::default() },
    ];
    snap.segment_fetches = vec![AlphaSegmentFetch {
        user_id: "alpha-u".into(),
        video_id: "v1".into(),
        segment_index: 0,
        ..Default::default()
    }];
    // D-9: this person signed in on V2 first and keeps the V2 id.
    let ids = [("alpha-u".to_string(), "v2-u".to_string())].into();
    let media = [("v1".to_string(), ready()), ("v0".to_string(), ready())].into();
    let m = maps();
    let mut plan = Plan::default();
    dependents(&snap, &Ctx { maps: &m, user_ids: &ids, media: &media }, &mut plan);
    let ent = &plan.rows["video_entitlement"];
    assert_eq!(ent.len(), 1);
    assert_eq!(ent[0].data["userId"], "v2-u");
    assert_eq!(ent[0].data["chargeReference"], "alpha-import:n1");
    assert_eq!(plan.rows["watch_position"][0].data["userId"], "v2-u");
    assert_eq!(plan.rows["watch_position"][0].data["positionIndex"], 0);
    let ex: Vec<_> = plan.exceptions.iter().map(|e| (e.source_key.as_str(), e.reason.as_str())).collect();
    assert!(ex.contains(&("n0", "zero_credit_unlock")));
    assert!(ex.contains(&("v0", "policy_credit_without_cost")));
}

#[test]
fn refused_media_makes_the_video_and_its_rows_exceptions() {
    let mut snap = Snapshot::default();
    snap.users = vec![user("u", &["active"])];
    snap.videos = vec![video("v", 4)];
    snap.unlocks = vec![AlphaUnlock { id: "n".into(), user_id: "u".into(), video_id: "v".into(), ..Default::default() }];
    let ids = [("u".to_string(), "u".to_string())].into();
    let media = [("v".to_string(), MediaOutcome::Refused(Refusal::Plaintext("720p".into())))].into();
    let m = maps();
    let mut plan = Plan::default();
    dependents(&snap, &Ctx { maps: &m, user_ids: &ids, media: &media }, &mut plan);
    assert!(!plan.rows.contains_key("video"));
    assert!(!plan.rows.contains_key("video_key"));
    let ex: Vec<_> = plan.exceptions.iter().map(|e| (e.entity.as_str(), e.reason.as_str())).collect();
    assert!(ex.contains(&("video", "hls_plaintext_variant")));
    assert!(ex.contains(&("video_entitlement", "video_not_imported")));
}

#[test]
fn hash_is_stable_and_changes_with_the_payload() {
    let a = json!({"a": 1, "b": "x"});
    assert_eq!(hash(&a), hash(&json!({"a": 1, "b": "x"})));
    assert_ne!(hash(&a), hash(&json!({"a": 2, "b": "x"})));
    assert_eq!(hash(&a).len(), 64);
}
