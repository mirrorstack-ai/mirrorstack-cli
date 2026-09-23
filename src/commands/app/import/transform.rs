//! Transformer (§3.2): a pure function of (snapshot rows, maps, namespace
//! UUIDs) → target batches + exceptions. Dry-run and apply use exactly this.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::extract::{AlphaUser, AlphaVideo, Snapshot};
use super::hls::Refusal;
use super::maps::Maps;

/// Committed with the runner (§2.2, §6); never change them after the first apply.
pub const NS_ALPHA_VIDEO: Uuid = Uuid::from_u128(0x5d8a3f2e_9c41_4b7a_8e16_2f0c7d9b1a43);
pub const NS_ALPHA_INSTRUCTOR: Uuid = Uuid::from_u128(0xb1e7c9d4_3a52_4f86_9d0e_6c2a8f4b7e15);
pub const NS_ALPHA_MEDIA: Uuid = Uuid::from_u128(0x2c6f0e8a_71d3_4e5b_a4c9_8b1d3f6e2a07);

/// The ladder the importer writes is a transcode "job" of its own.
pub const IMPORT_JOB: &str = "alpha-import";

/// (entity, module) in load order (§6).
pub const ENTITIES: &[(&str, &str)] = &[
    ("user", "user-core"),
    ("user_profile", "user-profile"),
    ("user_role", "user-roles"),
    ("user_approval", "user-approval"),
    ("video", "video-core"),
    ("video_key", "video-core"),
    ("instructor", "video-core"),
    ("video_section", "video-core"),
    ("video_category", "video-category"),
    ("video_policy", "video-category"),
    ("video_entitlement", "video-category"),
    ("video_view", "video-core"),
    ("watch_event", "video-watched"),
    ("video_watch_event", "video-core"),
    ("watch_position", "video-watched"),
];

pub fn module_of(entity: &str) -> &'static str {
    ENTITIES
        .iter()
        .find(|(e, _)| *e == entity)
        .map(|(_, m)| *m)
        .unwrap_or("video-core")
}

#[derive(Debug, Clone, PartialEq)]
pub struct TargetRow {
    pub source_key: String,
    pub source_hash: String,
    pub data: Value,
}

impl TargetRow {
    fn new(source_key: impl Into<String>, data: Value) -> Self {
        Self {
            source_key: source_key.into(),
            source_hash: hash(&data),
            data,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Exception {
    pub entity: String,
    pub source_key: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Plan {
    pub rows: BTreeMap<&'static str, Vec<TargetRow>>,
    pub exceptions: Vec<Exception>,
    pub read: BTreeMap<&'static str, i64>,
}

impl Plan {
    fn push(&mut self, entity: &'static str, row: TargetRow) {
        self.rows.entry(entity).or_default().push(row);
    }
    fn except(&mut self, entity: &str, key: impl Into<String>, reason: &str) {
        self.exceptions.push(Exception {
            entity: entity.into(),
            source_key: key.into(),
            reason: reason.into(),
        });
    }
    fn read(&mut self, entity: &'static str, n: usize) {
        *self.read.entry(entity).or_default() += n as i64;
    }
}

/// sha256 over the target payload: a changed map (a role remapped) reloads the
/// row too, and no secret or PII ever lands in the ledger in the clear.
pub fn hash(v: &Value) -> String {
    hex(&Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn video_id(nanoid: &str) -> Uuid {
    Uuid::new_v5(&NS_ALPHA_VIDEO, nanoid.as_bytes())
}

pub fn instructor_id(name: &str) -> Uuid {
    Uuid::new_v5(&NS_ALPHA_INSTRUCTOR, name.trim().to_lowercase().as_bytes())
}

/// Where one ready video's media lands, relative to video-core's storage
/// root (the keys video-core's own upload and transcode flows would issue).
#[derive(Debug, Clone, PartialEq)]
pub struct VideoPlan {
    pub alpha_id: String,
    pub v2_id: Uuid,
    pub alpha_hls_prefix: String,
    pub v2_hls_prefix: String,
    /// `cover_key`, else `thumbnail_key`; `None` = MediaConvert's own frame.
    pub alpha_cover: Option<String>,
    pub v2_cover_key: String,
    pub alpha_source_key: Option<String>,
    pub v2_source_key: String,
}

pub fn video_plan(v: &AlphaVideo) -> VideoPlan {
    let id = video_id(&v.id);
    let token = |kind: &str| {
        Uuid::new_v5(&NS_ALPHA_MEDIA, format!("{kind}:{}", v.id).as_bytes())
            .simple()
            .to_string()
    };
    let ext = |key: &str, default: &str| {
        key.rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase())
            .filter(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric()))
            .unwrap_or_else(|| default.into())
    };
    let alpha_cover = [&v.cover_key, &v.thumbnail_key]
        .into_iter()
        .find(|k| !k.is_empty())
        .cloned();
    let cover_ext = ext(alpha_cover.as_deref().unwrap_or("x.jpg"), "jpg");
    VideoPlan {
        alpha_id: v.id.clone(),
        v2_id: id,
        alpha_hls_prefix: v.s3_hls_prefix.trim_end_matches('/').to_string(),
        v2_hls_prefix: format!("_gated/videos/{id}/transcodes/{IMPORT_JOB}"),
        alpha_cover,
        v2_cover_key: format!(
            "videos/{id}/manual-covers/{}/cover.{cover_ext}",
            token("cover")
        ),
        alpha_source_key: Some(v.s3_source_key.clone()).filter(|k| !k.is_empty()),
        v2_source_key: format!(
            "videos/{id}/sources/{}/source.{}",
            token("source"),
            ext(&v.s3_source_key, "mp4")
        ),
    }
}

/// What the copier found for one video (§3.5), fed back into the transform.
#[derive(Debug, Clone, PartialEq)]
pub enum MediaOutcome {
    Ready {
        rungs: Vec<String>,
        /// The original exists with a non-zero size (D-2).
        original: bool,
        /// A cover (or MediaConvert's frame grab) was copied.
        cover: bool,
    },
    Refused(Refusal),
}

/// Stage 1: users → `user` rows. Returns the alpha ids that were planned.
pub fn users(snap: &Snapshot, plan: &mut Plan) -> BTreeSet<String> {
    let mut planned = BTreeSet::new();
    plan.read("user", snap.users.len());
    for u in &snap.users {
        match user_row(u) {
            Ok(row) => {
                planned.insert(u.id.clone());
                plan.push("user", row);
            }
            Err(reason) => plan.except("user", &u.id, reason),
        }
    }
    planned
}

fn user_row(u: &AlphaUser) -> Result<TargetRow, &'static str> {
    match u.provider.as_str() {
        "google" => {}
        "anonymous" => return Err("anonymous_user"),
        _ => return Err("unsupported_provider"),
    }
    // §14.2 precondition 1: the Google v2-userinfo id, byte-for-byte.
    if u.provider_uid.is_empty() || !u.provider_uid.bytes().all(|b| b.is_ascii_digit()) {
        return Err("provider_uid_not_numeric");
    }
    let email = Some(u.email.trim()).filter(|e| !e.is_empty());
    if email.is_some_and(|e| e.chars().count() > 320) {
        return Err("email_too_long");
    }
    if u.name.chars().count() > 256 {
        return Err("name_too_long");
    }
    if u.avatar.as_ref().is_some_and(|a| a.chars().count() > 2048) {
        return Err("avatar_too_long");
    }
    Ok(TargetRow::new(
        &u.id,
        json!({
            "id": u.id,
            "provider": "google",
            "providerUid": u.provider_uid,
            "email": email,
            "displayName": u.name,
            "displayNameSource": "provider",
            "avatarUrl": u.avatar,
            "avatarUrlSource": "provider",
            "createdAt": u.created_at,
            "lastSignInAt": u.last_session_at.as_deref().unwrap_or(&u.created_at),
        }),
    ))
}

pub struct Ctx<'a> {
    pub maps: &'a Maps,
    /// alpha user id → V2 user id, from the ledger map and this run's user
    /// results (D-9: a user who signed in on V2 first keeps the V2 id).
    pub user_ids: &'a BTreeMap<String, String>,
    /// Keyed by alpha video id; a ready video absent here was not copied.
    pub media: &'a BTreeMap<String, MediaOutcome>,
}

/// Stage 2: everything that hangs off a user or a video.
pub fn dependents(snap: &Snapshot, ctx: &Ctx, plan: &mut Plan) {
    for u in &snap.users {
        profile_roles(u, ctx, plan);
    }
    let mut imported: BTreeMap<&str, &AlphaVideo> = BTreeMap::new();
    let mut instructors = BTreeSet::new();
    plan.read("video", snap.videos.len());
    for v in &snap.videos {
        if v.status != "ready" {
            plan.except("video", &v.id, "video_not_ready");
            continue;
        }
        let vp = video_plan(v);
        let (rungs, original, cover) = match ctx.media.get(&v.id) {
            Some(MediaOutcome::Ready {
                rungs,
                original,
                cover,
            }) => (rungs, *original, *cover),
            Some(MediaOutcome::Refused(r)) => {
                plan.except("video", &v.id, r.reason());
                continue;
            }
            None => {
                plan.except("video", &v.id, "media_not_copied");
                continue;
            }
        };
        if !original {
            plan.except("video_original", &v.id, "original_missing");
        }
        if !cover {
            plan.except("video_cover", &v.id, "cover_missing");
        }
        imported.insert(&v.id, v);
        let id = vp.v2_id.to_string();
        let instructor = Some(v.instructor.trim()).filter(|n| !n.is_empty());
        let instructor_id = instructor.map(|n| instructor_id(n).to_string());
        if let (Some(name), Some(iid)) = (instructor, &instructor_id)
            && instructors.insert(iid.clone())
        {
            plan.push(
                "instructor",
                TargetRow::new(
                    iid.clone(),
                    json!({"id": iid, "name": name, "bio": v.instructor_bio}),
                ),
            );
        }
        plan.push(
            "video",
            TargetRow::new(
                &v.id,
                json!({
                    "id": id,
                    "title": v.title,
                    "description": v.description,
                    "sourceFilename": v.source_filename,
                    "sourceKey": original.then_some(&vp.v2_source_key),
                    "published": v.published,
                    "createdBy": v.created_by,
                    "createdAt": v.created_at,
                    "durationSec": v.duration_sec,
                    "viewCount": v.view_count,
                    "transcodeProgress": v.transcode_progress,
                    "status": "ready",
                    "hlsPrefix": vp.v2_hls_prefix,
                    "publishedRenditions": rungs,
                    "publishedRenditionsKnown": true,
                    "version": 1,
                    "coverKey": cover.then_some(&vp.v2_cover_key),
                    "instructorId": instructor_id,
                }),
            ),
        );
        if let Some(key) = &v.encryption_key {
            plan.push(
                "video_key",
                TargetRow::new(
                    &v.id,
                    json!({"videoId": id, "key": base64::engine::general_purpose::STANDARD.encode(key)}),
                ),
            );
        }
        sections(v, &id, plan);
        categories_policy(v, &id, ctx.maps, plan);
    }

    let video = |alpha: &str| {
        imported
            .get(alpha)
            .map(|v| (video_id(&v.id).to_string(), *v))
    };
    let user = |alpha: &str| ctx.user_ids.get(alpha).cloned();

    plan.read("video_entitlement", snap.unlocks.len());
    for u in &snap.unlocks {
        let Some((vid, v)) = video(&u.video_id) else {
            plan.except("video_entitlement", &u.id, "video_not_imported");
            continue;
        };
        let Some(uid) = user(&u.user_id) else {
            plan.except("video_entitlement", &u.id, "user_not_imported");
            continue;
        };
        if v.credit_cost <= 0 {
            // D-5: price > 0 is a video_entitlements CHECK.
            plan.except("video_entitlement", &u.id, "zero_credit_unlock");
            continue;
        }
        plan.push(
            "video_entitlement",
            TargetRow::new(
                &u.id,
                json!({
                    "userId": uid, "videoId": vid, "purchasedAt": u.unlocked_at,
                    "price": v.credit_cost, "chargeReference": format!("alpha-import:{}", u.id),
                }),
            ),
        );
    }

    plan.read("video_view", snap.views.len());
    for w in &snap.views {
        let key = w.id.to_string();
        match (video(&w.video_id), user(&w.user_id)) {
            (None, _) => plan.except("video_view", key, "video_not_imported"),
            (_, None) => plan.except("video_view", key, "user_not_imported"),
            (Some((vid, _)), Some(uid)) => plan.push(
                "video_view",
                TargetRow::new(
                    key,
                    json!({"videoId": vid, "userId": uid, "viewedDate": w.viewed_date, "createdAt": w.created_at}),
                ),
            ),
        }
    }

    plan.read("watch_event", snap.watch_events.len());
    plan.read("video_watch_event", snap.watch_events.len());
    for e in &snap.watch_events {
        let key = e.id.to_string();
        match (video(&e.video_id), user(&e.user_id)) {
            (None, _) => plan.except("watch_event", key, "video_not_imported"),
            (_, None) => plan.except("watch_event", key, "user_not_imported"),
            (Some((vid, _)), Some(uid)) => {
                let data = json!({
                    "importSourceId": key, "userId": uid, "videoId": vid, "videoVersion": 1,
                    "positionSec": e.position_sec, "watchedSec": e.watched_sec,
                    "playbackRate": e.playback_rate, "createdAt": e.created_at,
                });
                plan.push("watch_event", TargetRow::new(key.clone(), data.clone()));
                plan.push("video_watch_event", TargetRow::new(key, data));
            }
        }
    }

    plan.read("watch_position", snap.segment_fetches.len());
    for f in &snap.segment_fetches {
        let key = format!("{}/{}/{}", f.user_id, f.video_id, f.segment_index);
        match (video(&f.video_id), user(&f.user_id)) {
            (None, _) => plan.except("watch_position", key, "video_not_imported"),
            (_, None) => plan.except("watch_position", key, "user_not_imported"),
            // T631: 6 s segments, 0-based `segment_index` = V2's 6 s
            // `position_index` grid, one to one.
            (Some((vid, _)), Some(uid)) => plan.push(
                "watch_position",
                TargetRow::new(
                    key,
                    json!({"userId": uid, "videoId": vid, "videoVersion": 1,
                           "positionIndex": f.segment_index, "fetchedAt": f.fetched_at}),
                ),
            ),
        }
    }
}

fn profile_roles(u: &AlphaUser, ctx: &Ctx, plan: &mut Plan) {
    let Some(uid) = ctx.user_ids.get(&u.id) else {
        return;
    };
    let maps = ctx.maps;
    plan.read("user_profile", 1);
    let mut fields = serde_json::Map::new();
    let mut sensitive = Vec::new();
    let mut alpha_fields: Vec<(String, Value)> = Vec::new();
    if let Some(p) = u.phone.as_ref().filter(|p| !p.is_empty()) {
        alpha_fields.push(("phone".into(), json!(p)));
    }
    if let Some(n) = u.id_number.as_ref().filter(|n| !n.is_empty()) {
        alpha_fields.push(("id_number".into(), json!(n)));
    }
    match u.extra_fields.as_deref().map(serde_json::from_str::<Value>) {
        None | Some(Ok(Value::Null)) => {}
        Some(Ok(Value::Object(m))) => alpha_fields.extend(m),
        Some(_) => plan.except("user_profile", &u.id, "extra_fields_not_an_object"),
    }
    for (k, v) in alpha_fields {
        match maps.profile_fields.get(&k).filter(|t| !t.is_empty()) {
            Some(target) => {
                if k == "id_number" {
                    sensitive.push(target.clone());
                }
                fields.insert(target.clone(), v);
            }
            None if maps.profile_fields.contains_key(&k) => {}
            None => plan.except(
                "user_profile",
                format!("{}/{k}", u.id),
                "unmapped_profile_field",
            ),
        }
    }
    if !fields.is_empty() {
        plan.push(
            "user_profile",
            TargetRow::new(
                &u.id,
                json!({"userId": uid, "fields": fields, "sensitiveFields": sensitive, "actor": maps.import_actor}),
            ),
        );
    }

    plan.read("user_role", u.roles.len());
    let mut mapped = 0;
    for role in &u.roles {
        let key = format!("{}/{role}", u.id);
        if let Some(target) = maps.roles.get(role) {
            if target.is_empty() {
                continue;
            }
            mapped += 1;
            plan.push(
                "user_role",
                TargetRow::new(
                    key,
                    json!({"userId": uid, "roleKey": target, "grantedBy": maps.import_actor,
                           "grantedVia": "import", "reason": "alpha import"}),
                ),
            );
        } else if let Some(state) = maps.approval_states.get(role) {
            mapped += 1;
            plan.push(
                "user_approval",
                TargetRow::new(
                    key,
                    json!({"userId": uid, "categoryKey": state.category, "state": state.state,
                           "note": u.reject_reason, "decidedBy": maps.import_actor,
                           "decidedAt": u.updated_at}),
                ),
            );
        } else {
            plan.except("user_role", key, "unmapped_role");
        }
    }
    if mapped == 0 {
        // §14.2 precondition 4: without a role row the member lands on wait-info.
        plan.except("user_role", &u.id, "no_mapped_role");
    }
}

fn sections(v: &AlphaVideo, id: &str, plan: &mut Plan) {
    let list = match serde_json::from_str::<Value>(if v.sections.is_empty() {
        "[]"
    } else {
        &v.sections
    }) {
        Ok(Value::Array(list)) => list,
        _ => return plan.except("video_section", &v.id, "sections_not_a_list"),
    };
    plan.read("video_section", list.len());
    let video = Uuid::parse_str(id).unwrap_or_default();
    for (pos, section) in list.into_iter().enumerate() {
        let Value::Object(mut fields) = section else {
            plan.except(
                "video_section",
                format!("{}/{pos}", v.id),
                "section_not_an_object",
            );
            continue;
        };
        let sid = Uuid::new_v5(&video, pos.to_string().as_bytes()).to_string();
        fields.insert("id".into(), json!(sid));
        fields.insert("videoId".into(), json!(id));
        fields.insert("position".into(), json!(pos));
        plan.push(
            "video_section",
            TargetRow::new(format!("{}/{pos}", v.id), Value::Object(fields)),
        );
    }
}

fn categories_policy(v: &AlphaVideo, id: &str, maps: &Maps, plan: &mut Plan) {
    plan.read("video_category", v.categories.len());
    for c in &v.categories {
        let key = format!("{}/{c}", v.id);
        match maps.categories.get(c) {
            Some(target) => plan.push(
                "video_category",
                TargetRow::new(key, json!({"videoId": id, "categoryKey": target})),
            ),
            None => plan.except("video_category", key, "unmapped_category"),
        }
    }

    plan.read("video_policy", 1);
    let Some(mode) = maps.visibility.get(&v.visibility) else {
        return plan.except("video_policy", &v.id, "unmapped_visibility");
    };
    let map_roles = |roles: &[String]| -> Option<Vec<String>> {
        roles
            .iter()
            .map(|r| maps.roles.get(r).filter(|t| !t.is_empty()).cloned())
            .collect()
    };
    let (Some(allowed), Some(denied)) = (map_roles(&v.allowed_roles), map_roles(&v.declined_roles))
    else {
        return plan.except("video_policy", &v.id, "unmapped_policy_role");
    };
    // The video_policy_overrides CHECKs, refused here rather than by the DB.
    let reason = match (mode.as_str(), v.credit_cost) {
        ("credit", c) if c <= 0 => Some("policy_credit_without_cost"),
        (m, c) if m != "credit" && c != 0 => Some("policy_cost_without_credit"),
        _ if allowed.iter().any(|r| denied.contains(r)) => Some("policy_roles_overlap"),
        _ => None,
    };
    if let Some(reason) = reason {
        return plan.except("video_policy", &v.id, reason);
    }
    // video-category writes an override only where this differs from the
    // category's own policy (§2.2); it owns that comparison.
    plan.push(
        "video_policy",
        TargetRow::new(
            &v.id,
            json!({"videoId": id, "accessMode": mode, "creditCost": v.credit_cost,
                   "allowedRoles": allowed, "deniedRoles": denied}),
        ),
    );
}

#[cfg(test)]
mod tests;
