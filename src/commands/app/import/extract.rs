//! Extractor (§3.1): one `REPEATABLE READ READ ONLY` transaction on alpha per
//! run, every table read from that snapshot in keyset batches of 1,000, and
//! `snapshot_at = now()` taken inside it on the ALPHA clock.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use postgres::types::ToSql;
use postgres::{Client, IsolationLevel, NoTls, Row, Transaction};

pub const BATCH: i64 = 1000;

/// Alpha timestamps come out as RFC 3339 UTC text, so no clock crate is needed
/// and the value round-trips into the ledger's `snapshot_at` unchanged.
macro_rules! ts {
    ($col:literal) => {
        concat!(
            "to_char(",
            $col,
            " AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
        )
    };
}

#[derive(Debug, Clone, Default)]
pub struct AlphaUser {
    pub id: String,
    pub public_id: String,
    pub provider: String,
    pub provider_uid: String,
    pub email: String,
    pub name: String,
    pub avatar: Option<String>,
    pub roles: Vec<String>,
    pub phone: Option<String>,
    pub id_number: Option<String>,
    pub extra_fields: Option<String>,
    pub reject_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_session_at: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AlphaVideo {
    pub id: String,
    pub title: String,
    pub description: String,
    pub s3_source_key: String,
    pub source_filename: String,
    pub s3_hls_prefix: String,
    pub status: String,
    pub visibility: String,
    pub credit_cost: i64,
    pub duration_sec: Option<f64>,
    pub thumbnail_key: String,
    pub transcode_progress: i64,
    pub published: bool,
    pub cover_key: String,
    pub categories: Vec<String>,
    pub sections: String,
    pub allowed_roles: Vec<String>,
    pub declined_roles: Vec<String>,
    pub view_count: i64,
    pub encryption_key: Option<Vec<u8>>,
    pub instructor: String,
    pub instructor_bio: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct AlphaUnlock {
    pub id: String,
    pub user_id: String,
    pub video_id: String,
    pub unlocked_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct AlphaView {
    pub id: i64,
    pub video_id: String,
    pub user_id: String,
    pub viewed_date: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct AlphaWatchEvent {
    pub id: i64,
    pub user_id: String,
    pub video_id: String,
    pub position_sec: f64,
    pub watched_sec: f64,
    pub playback_rate: f64,
    pub created_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct AlphaSegmentFetch {
    pub user_id: String,
    pub video_id: String,
    pub segment_index: i32,
    pub fetched_at: String,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// `now()` inside the run's transaction, on the alpha clock.
    pub snapshot_at: String,
    pub window_from: Option<String>,
    /// `users` and `videos` are read in full every run: no trigger bumps
    /// `users.updated_at` (T631) and both are small, so the key+hash
    /// reconciliation (§5) sees every row and every hard delete.
    pub users: Vec<AlphaUser>,
    pub videos: Vec<AlphaVideo>,
    pub unlocks: Vec<AlphaUnlock>,
    pub views: Vec<AlphaView>,
    pub watch_events: Vec<AlphaWatchEvent>,
    pub segment_fetches: Vec<AlphaSegmentFetch>,
    /// `video_completions.completed = true` pairs: the verification oracle
    /// (§2.3), never written to V2.
    pub completed: Vec<(String, String)>,
}

pub struct Source {
    pub url: String,
    pub schema: String,
    pub ca_file: Option<PathBuf>,
}

pub fn valid_schema(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_lowercase() || ch == '_')
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        && s.len() <= 63
}

fn connect(src: &Source) -> Result<Client> {
    let cfg: postgres::Config = src.url.parse().context("parse the alpha database URL")?;
    let client = match &src.ca_file {
        Some(path) => {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_file_iter(path)
                .with_context(|| format!("read CA bundle {}", path.display()))?
            {
                roots.add(cert.context("parse CA bundle")?)?;
            }
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            cfg.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
        }
        None => cfg.connect(NoTls),
    };
    client.context("connect to alpha (read-only role)")
}

/// Reads the whole run from one alpha snapshot. `window_from` is the previous
/// watermark minus the 10-minute overlap (§5); `None` is the first, full run.
pub fn extract(src: &Source, window_from: Option<&str>) -> Result<Snapshot> {
    if !valid_schema(&src.schema) {
        return Err(anyhow!("alpha schema {:?} is not a schema name", src.schema));
    }
    let mut client = connect(src)?;
    // Belt and braces: the role is read-only (§3.1), the session and the
    // transaction are too, so no statement here can write to alpha.
    client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")?;
    let mut tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()?;
    tx.batch_execute(&format!(
        "SET LOCAL statement_timeout = '30s'; SET LOCAL search_path TO {}",
        src.schema
    ))?;
    let snapshot_at: String = tx
        .query_one(concat!("SELECT ", ts!("now()")), &[])?
        .get(0);
    let from = window_from.map(str::to_string);
    let to = Some(snapshot_at.clone());
    let win = [&from as &(dyn ToSql + Sync), &to];

    let users = paged(
        &mut tx,
        concat!(
            "SELECT u.id::text, u.public_id, u.provider, u.provider_uid, u.email, u.name, u.avatar,
                    u.roles, u.phone, u.id_number, u.extra_fields::text, u.reject_reason, ",
            ts!("u.created_at"),
            ", ",
            ts!("u.updated_at"),
            ", ",
            ts!("(SELECT max(s.created_at) FROM user_sessions s WHERE s.user_id = u.id)"),
            " FROM users u WHERE u.id > $1::text::uuid ORDER BY u.id LIMIT 1000"
        ),
        vec!["00000000-0000-0000-0000-000000000000".into()],
        &[],
        |r| AlphaUser {
            id: r.get(0),
            public_id: r.get(1),
            provider: r.get(2),
            provider_uid: r.get(3),
            email: r.get(4),
            name: r.get(5),
            avatar: r.get(6),
            roles: r.get(7),
            phone: r.get(8),
            id_number: r.get(9),
            extra_fields: r.get(10),
            reject_reason: r.get(11),
            created_at: r.get(12),
            updated_at: r.get(13),
            last_session_at: r.get(14),
        },
        |u| vec![u.id.clone()],
    )?;

    let videos = paged(
        &mut tx,
        concat!(
            "SELECT id, title, description, s3_source_key, source_filename, s3_hls_prefix, status,
                    visibility, credit_cost::int8, duration_sec::float8, thumbnail_key,
                    transcode_progress::int8, published, cover_key, categories, sections,
                    allowed_roles, declined_roles, view_count::int8, encryption_key, instructor,
                    instructor_bio, created_by, ",
            ts!("created_at"),
            ", ",
            ts!("updated_at"),
            " FROM videos WHERE id > $1 ORDER BY id LIMIT 1000"
        ),
        vec![String::new()],
        &[],
        |r| AlphaVideo {
            id: r.get(0),
            title: r.get(1),
            description: r.get(2),
            s3_source_key: r.get(3),
            source_filename: r.get(4),
            s3_hls_prefix: r.get(5),
            status: r.get(6),
            visibility: r.get(7),
            credit_cost: r.get(8),
            duration_sec: r.get(9),
            thumbnail_key: r.get(10),
            transcode_progress: r.get(11),
            published: r.get(12),
            cover_key: r.get(13),
            categories: r.get(14),
            sections: r.get(15),
            allowed_roles: r.get(16),
            declined_roles: r.get(17),
            view_count: r.get(18),
            encryption_key: r.get(19),
            instructor: r.get(20),
            instructor_bio: r.get(21),
            created_by: r.get(22),
            created_at: r.get(23),
            updated_at: r.get(24),
        },
        |v| vec![v.id.clone()],
    )?;

    let unlocks = paged(
        &mut tx,
        concat!(
            "SELECT id::text, user_id::text, video_id, ",
            ts!("unlocked_at"),
            " FROM video_unlocks WHERE id > $1::text::uuid
              AND ($2::text IS NULL OR unlocked_at > $2::text::timestamptz)
              AND unlocked_at <= $3::text::timestamptz ORDER BY id LIMIT 1000"
        ),
        vec!["00000000-0000-0000-0000-000000000000".into()],
        &win,
        |r| AlphaUnlock {
            id: r.get(0),
            user_id: r.get(1),
            video_id: r.get(2),
            unlocked_at: r.get(3),
        },
        |u| vec![u.id.clone()],
    )?;

    let views = paged(
        &mut tx,
        concat!(
            "SELECT id, video_id, user_id::text, viewed_date::text, ",
            ts!("created_at"),
            " FROM video_views WHERE id > $1::text::int8
              AND ($2::text IS NULL OR created_at > $2::text::timestamptz)
              AND created_at <= $3::text::timestamptz ORDER BY id LIMIT 1000"
        ),
        vec!["0".into()],
        &win,
        |r| AlphaView {
            id: r.get(0),
            video_id: r.get(1),
            user_id: r.get(2),
            viewed_date: r.get(3),
            created_at: r.get(4),
        },
        |v| vec![v.id.to_string()],
    )?;

    let watch_events = paged(
        &mut tx,
        concat!(
            "SELECT id, user_id::text, video_id, position_sec::float8, watched_sec::float8,
                    playback_rate::float8, ",
            ts!("created_at"),
            " FROM video_watch_events WHERE id > $1::text::int8
              AND ($2::text IS NULL OR created_at > $2::text::timestamptz)
              AND created_at <= $3::text::timestamptz ORDER BY id LIMIT 1000"
        ),
        vec!["0".into()],
        &win,
        |r| AlphaWatchEvent {
            id: r.get(0),
            user_id: r.get(1),
            video_id: r.get(2),
            position_sec: r.get(3),
            watched_sec: r.get(4),
            playback_rate: r.get(5),
            created_at: r.get(6),
        },
        |e| vec![e.id.to_string()],
    )?;

    let segment_fetches = paged(
        &mut tx,
        concat!(
            "SELECT user_id::text, video_id, segment_index, ",
            ts!("fetched_at"),
            " FROM video_segment_fetches
              WHERE (user_id, video_id, segment_index) > ($1::text::uuid, $2::text, $3::text::int4)
              AND ($4::text IS NULL OR fetched_at > $4::text::timestamptz)
              AND fetched_at <= $5::text::timestamptz
              ORDER BY user_id, video_id, segment_index LIMIT 1000"
        ),
        vec![
            "00000000-0000-0000-0000-000000000000".into(),
            String::new(),
            "-1".into(),
        ],
        &win,
        |r| AlphaSegmentFetch {
            user_id: r.get(0),
            video_id: r.get(1),
            segment_index: r.get(2),
            fetched_at: r.get(3),
        },
        |f| {
            vec![
                f.user_id.clone(),
                f.video_id.clone(),
                f.segment_index.to_string(),
            ]
        },
    )?;

    let completed = paged(
        &mut tx,
        "SELECT user_id::text, video_id FROM video_completions
          WHERE completed AND (user_id, video_id) > ($1::text::uuid, $2::text)
          ORDER BY user_id, video_id LIMIT 1000",
        vec!["00000000-0000-0000-0000-000000000000".into(), String::new()],
        &[],
        |r| (r.get::<_, String>(0), r.get::<_, String>(1)),
        |c| vec![c.0.clone(), c.1.clone()],
    )?;

    tx.rollback()?;
    Ok(Snapshot {
        snapshot_at,
        window_from: from,
        users,
        videos,
        unlocks,
        views,
        watch_events,
        segment_fetches,
        completed,
    })
}

/// Keyset pagination: the cursor columns are the first params (as text), the
/// fixed params follow. Stops on a short page.
fn paged<T>(
    tx: &mut Transaction<'_>,
    sql: &str,
    mut cursor: Vec<String>,
    fixed: &[&(dyn ToSql + Sync)],
    row: impl Fn(&Row) -> T,
    next: impl Fn(&T) -> Vec<String>,
) -> Result<Vec<T>> {
    let stmt = tx.prepare(sql)?;
    let mut out = Vec::new();
    loop {
        let mut params: Vec<&(dyn ToSql + Sync)> =
            cursor.iter().map(|c| c as &(dyn ToSql + Sync)).collect();
        params.extend_from_slice(fixed);
        let rows = tx.query(&stmt, &params)?;
        let n = rows.len() as i64;
        let start = out.len();
        out.extend(rows.iter().map(&row));
        if n < BATCH {
            return Ok(out);
        }
        cursor = next(&out[out.len() - 1]);
        debug_assert!(out.len() > start);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_are_checked_before_they_reach_sql() {
        assert!(valid_schema("app_pouxbdhg"));
        assert!(!valid_schema("app; DROP TABLE users"));
        assert!(!valid_schema("App"));
        assert!(!valid_schema(""));
    }
}
