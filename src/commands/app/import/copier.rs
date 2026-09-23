//! Media copier (§3.5): alpha's HLS ladders, covers and (D-2) originals onto
//! video-core's layout in the V2 bucket. Server-side copies only; an object
//! already copied (same size, same source ETag) is skipped, so a failed run
//! resumes where it stopped. Alpha's bucket is only ever read.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::extract::AlphaVideo;
use super::hls::{self, Layout, Refusal};
use super::s3::{Bucket, ObjectMeta, S3};
use super::transform::{MediaOutcome, VideoPlan, hex, video_plan};

pub struct Copier<'a> {
    s3: &'a S3,
    alpha: Bucket,
    dest: Bucket,
    /// Video-core's storage root in the V2 bucket (`apps/<app>/video-core/`).
    dest_prefix: String,
    apply: bool,
    concurrency: usize,
}

/// One video's media, as the report shows it (no key material: its sha256).
#[derive(Debug, Clone, Default, Serialize)]
pub struct VideoMedia {
    pub v2_id: String,
    pub rungs: Vec<String>,
    pub segments: usize,
    pub key_sha256: Option<String>,
    pub cover_from: Option<String>,
    pub original_size: Option<u64>,
    pub original_etag: Option<String>,
    pub refused: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub objects_copied: u64,
    pub objects_skipped: u64,
    pub objects_planned: u64,
    pub bytes_copied: u64,
}

#[derive(Debug, Default)]
pub struct Ladders {
    pub outcomes: BTreeMap<String, MediaOutcome>,
    pub videos: BTreeMap<String, VideoMedia>,
    pub stats: Stats,
}

enum CopyErr {
    Missing(String),
    Failed(String),
}

impl From<CopyErr> for Refusal {
    fn from(e: CopyErr) -> Self {
        match e {
            CopyErr::Missing(k) => Refusal::MissingObject(k),
            CopyErr::Failed(m) => Refusal::CopyFailed(m),
        }
    }
}

/// What the scan found for one ready video, before any write.
struct Scan {
    plan: VideoPlan,
    media: VideoMedia,
    result: Result<Ladder, Refusal>,
}

struct Ladder {
    rungs: Vec<String>,
    master: (String, Vec<u8>),
    /// (alpha key, V2 key): variant playlists and their segments, verbatim.
    objects: Vec<(String, String)>,
    cover: Option<(String, String)>,
    original: bool,
}

impl<'a> Copier<'a> {
    pub fn new(
        s3: &'a S3,
        alpha: Bucket,
        dest: Bucket,
        dest_prefix: &str,
        apply: bool,
        concurrency: usize,
    ) -> Result<Self> {
        if alpha.name == dest.name {
            bail!(
                "the destination bucket is alpha's bucket ({}): the importer never writes to alpha",
                alpha.name
            );
        }
        let dest_prefix = format!("{}/", dest_prefix.trim_matches('/'));
        if dest_prefix == "/" {
            bail!("--dest-prefix must name video-core's storage root");
        }
        Ok(Self {
            s3,
            alpha,
            dest,
            dest_prefix,
            apply,
            concurrency: concurrency.max(1),
        })
    }

    fn dest_key(&self, rel: &str) -> String {
        format!("{}{rel}", self.dest_prefix)
    }

    /// Every V2 prefix one imported video owns: the rollback deletes these.
    pub fn owned_prefixes(&self, v: &VideoPlan) -> Vec<String> {
        let dir = |k: &str| {
            k.rsplit_once('/')
                .map(|(d, _)| format!("{d}/"))
                .unwrap_or_default()
        };
        vec![
            self.dest_key(&format!("{}/", v.v2_hls_prefix)),
            self.dest_key(&dir(&v.v2_cover_key)),
            self.dest_key(&dir(&v.v2_source_key)),
        ]
    }

    pub fn dest_bucket(&self) -> &Bucket {
        &self.dest
    }

    /// Phase 1: HLS ladders, covers and the key check for every ready video.
    /// A dry run reads the playlists and HEADs covers and originals only.
    pub fn ladders(&self, videos: &[&AlphaVideo]) -> Ladders {
        let scans = pool(self.concurrency, videos, |v| self.scan(v));
        let mut out = Ladders::default();
        let mut copies: Vec<(usize, String, String)> = Vec::new();
        for (i, s) in scans.iter().enumerate() {
            if let Ok(l) = &s.result {
                copies.extend(
                    l.objects
                        .iter()
                        .chain(&l.cover)
                        .map(|(a, d)| (i, a.clone(), d.clone())),
                );
            }
        }
        out.stats.objects_planned = copies.len() as u64;
        let mut failed: BTreeMap<usize, Refusal> = BTreeMap::new();
        if self.apply {
            let results = pool(self.concurrency, &copies, |(_, a, d)| self.copy_one(a, d));
            for ((i, a, _), r) in copies.iter().zip(results) {
                match r {
                    Ok(Some(n)) => {
                        out.stats.objects_copied += 1;
                        out.stats.bytes_copied += n;
                    }
                    Ok(None) => out.stats.objects_skipped += 1,
                    // A missing cover falls back below; a missing segment refuses the video.
                    Err(CopyErr::Missing(_))
                        if scans[*i]
                            .result
                            .as_ref()
                            .is_ok_and(|l| l.cover.as_ref().is_some_and(|(c, _)| c == a)) => {}
                    Err(e) => {
                        failed.entry(*i).or_insert_with(|| e.into());
                    }
                }
            }
        }
        for (i, s) in scans.into_iter().enumerate() {
            let mut media = s.media;
            let outcome = match (s.result, failed.remove(&i)) {
                (Err(r), _) | (Ok(_), Some(r)) => {
                    media.refused = Some(r.to_string());
                    MediaOutcome::Refused(r)
                }
                (Ok(l), None) => {
                    // The master goes last: V2 serves a ladder only once every rung is there.
                    let put = if self.apply {
                        let sha = hex(&Sha256::digest(&l.master.1));
                        self.s3
                            .put(
                                &self.dest,
                                &l.master.0,
                                l.master.1,
                                "application/vnd.apple.mpegurl",
                                &sha,
                            )
                            .map_err(|e| Refusal::CopyFailed(format!("{e:#}")))
                    } else {
                        Ok(())
                    };
                    match put {
                        Ok(()) => MediaOutcome::Ready {
                            rungs: l.rungs,
                            original: l.original,
                            cover: l.cover.is_some(),
                        },
                        Err(r) => {
                            media.refused = Some(r.to_string());
                            MediaOutcome::Refused(r)
                        }
                    }
                }
            };
            out.outcomes.insert(s.plan.alpha_id.clone(), outcome);
            out.videos.insert(s.plan.alpha_id, media);
        }
        out
    }

    fn scan(&self, v: &AlphaVideo) -> Scan {
        let plan = video_plan(v);
        let mut media = VideoMedia {
            v2_id: plan.v2_id.to_string(),
            key_sha256: v.encryption_key.as_deref().map(|k| hex(&Sha256::digest(k))),
            ..VideoMedia::default()
        };
        let result = self.ladder(v, &plan, &mut media);
        Scan {
            plan,
            media,
            result,
        }
    }

    fn ladder(
        &self,
        v: &AlphaVideo,
        plan: &VideoPlan,
        media: &mut VideoMedia,
    ) -> Result<Ladder, Refusal> {
        hls::check_key(v.encryption_key.as_deref())?;
        if plan.alpha_hls_prefix.is_empty() {
            return Err(Refusal::NoHls);
        }
        let layout = Layout::new(&plan.alpha_hls_prefix, &self.dest_key(&plan.v2_hls_prefix));
        let (alpha_master, v2_master) = layout.master();
        let master = hls::rewrite_master(&self.text(&alpha_master)?)?;
        let mut objects = Vec::new();
        for q in &master.rungs {
            let (a, d) = layout.variant(q);
            let files = hls::variant_files(q, &self.text(&a)?)?;
            media.segments += files.len();
            objects.push((a, d));
            objects.extend(files.iter().map(|f| layout.file(q, f)));
        }
        media.rungs = master.rungs.clone();

        let dest_cover = self.dest_key(&plan.v2_cover_key);
        let candidates: Vec<String> = plan
            .alpha_cover
            .iter()
            .cloned()
            .chain(layout.thumbnails())
            .collect();
        let mut cover = None;
        for c in candidates {
            if self.head(&c)?.is_some_and(|m| m.size > 0) {
                media.cover_from = Some(c.clone());
                cover = Some((c, dest_cover));
                break;
            }
        }

        let original = match &plan.alpha_source_key {
            Some(k) => self.head(k)?.filter(|m| m.size > 0),
            None => None,
        };
        media.original_size = original.as_ref().map(|m| m.size);
        media.original_etag = original.as_ref().map(|m| m.etag.clone());
        Ok(Ladder {
            rungs: master.rungs,
            master: (v2_master, master.text.into_bytes()),
            objects,
            cover,
            original: original.is_some(),
        })
    }

    fn text(&self, key: &str) -> Result<String, Refusal> {
        match self.s3.get(&self.alpha, key) {
            Ok(Some(b)) => {
                String::from_utf8(b).map_err(|_| Refusal::BadSegment(format!("{key} is not UTF-8")))
            }
            Ok(None) => Err(Refusal::MissingObject(key.into())),
            Err(e) => Err(Refusal::CopyFailed(format!("{e:#}"))),
        }
    }

    fn head(&self, key: &str) -> Result<Option<ObjectMeta>, Refusal> {
        self.s3
            .head(&self.alpha, key)
            .map_err(|e| Refusal::CopyFailed(format!("{e:#}")))
    }

    /// `Ok(Some(bytes))` copied, `Ok(None)` already there.
    fn copy_one(&self, alpha_key: &str, dest_key: &str) -> Result<Option<u64>, CopyErr> {
        let failed = |e: anyhow::Error| CopyErr::Failed(format!("{e:#}"));
        let src = self.s3.head(&self.alpha, alpha_key).map_err(failed)?;
        let Some(src) = src else {
            return Err(CopyErr::Missing(alpha_key.into()));
        };
        if let Some(d) = self.s3.head(&self.dest, dest_key).map_err(failed)?
            && d.is_copy_of(&src)
        {
            return Ok(None);
        }
        self.s3
            .copy(&self.alpha, alpha_key, &src, &self.dest, dest_key)
            .map_err(failed)?;
        Ok(Some(src.size))
    }

    /// Phase 2 (D-2): the originals, after every ladder, cover and key. Its
    /// own resumable pass: `--phase originals` re-runs only this.
    pub fn originals(&self, videos: &[&AlphaVideo]) -> Originals {
        let jobs: Vec<(String, String, String)> = videos
            .iter()
            .map(|v| video_plan(v))
            .filter_map(|p| {
                let src = p.alpha_source_key?;
                Some((p.alpha_id, src, self.dest_key(&p.v2_source_key)))
            })
            .collect();
        let mut out = Originals {
            planned: jobs.len() as u64,
            ..Originals::default()
        };
        let results = pool(self.concurrency, &jobs, |(_, a, d)| {
            if !self.apply {
                return self
                    .s3
                    .head(&self.alpha, a)
                    .map(|m| m.filter(|m| m.size > 0).map(|m| m.size))
                    .map_err(|e| CopyErr::Failed(format!("{e:#}")))
                    .and_then(|s| s.ok_or_else(|| CopyErr::Missing(a.clone())))
                    .map(Some);
            }
            self.copy_one(a, d)
        });
        for ((id, _, _), r) in jobs.into_iter().zip(results) {
            match r {
                Ok(Some(n)) if self.apply => {
                    out.copied += 1;
                    out.bytes += n;
                }
                Ok(Some(n)) => out.bytes += n,
                Ok(None) => out.skipped += 1,
                Err(CopyErr::Missing(_)) => {
                    out.missing.push(id);
                }
                Err(CopyErr::Failed(m)) => {
                    out.failed.insert(id, m);
                }
            }
        }
        out
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Originals {
    pub planned: u64,
    pub copied: u64,
    pub skipped: u64,
    /// Copied, or (dry run) that would be copied.
    pub bytes: u64,
    /// No object or zero bytes: `original_missing`, the video still imports.
    pub missing: Vec<String>,
    /// Retried by the next `--phase originals` run.
    pub failed: BTreeMap<String, String>,
}

/// Runs `f` over `items` on `n` threads; results keep the input order.
pub fn pool<T: Sync, R: Send>(n: usize, items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let out = Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..n.clamp(1, items.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let r = f(item);
                    out.lock().expect("pool results").push((i, r));
                }
            });
        }
    });
    let mut out = out.into_inner().expect("pool results");
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

#[cfg(test)]
mod tests {
    use super::super::s3::Creds;
    use super::*;

    fn video() -> AlphaVideo {
        AlphaVideo {
            id: "vid1".into(),
            status: "ready".into(),
            s3_hls_prefix: "hls/vid1/".into(),
            s3_source_key: "src/vid1.mp4".into(),
            encryption_key: Some(vec![7; 16]),
            ..AlphaVideo::default()
        }
    }

    #[test]
    fn the_pool_keeps_input_order() {
        let items: Vec<u32> = (0..50).collect();
        assert_eq!(
            pool(8, &items, |i| i * 2),
            items.iter().map(|i| i * 2).collect::<Vec<_>>()
        );
        assert!(pool(4, &[] as &[u32], |i| *i).is_empty());
    }

    #[test]
    fn copies_a_ladder_then_writes_the_rewritten_master_last() {
        let mut server = mockito::Server::new();
        let creds = Creds {
            access_key: "a".into(),
            secret_key: "s".into(),
            session_token: None,
        };
        let s3 = S3::with_endpoint(creds, Some(server.url())).unwrap();
        let alpha = Bucket {
            name: "alpha".into(),
            region: "r".into(),
        };
        let prod = Bucket {
            name: "prod".into(),
            region: "r".into(),
        };
        let c = Copier::new(
            &s3,
            alpha.clone(),
            prod.clone(),
            "apps/app1/video-core",
            true,
            4,
        )
        .unwrap();
        let v = video();
        let id = video_plan(&v).v2_id;
        let gated =
            format!("/prod/apps/app1/video-core/_gated/videos/{id}/transcodes/alpha-import");

        server
            .mock("GET", "/alpha/hls/vid1/original.m3u8")
            .with_body("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\noriginal720p/index.m3u8\n")
            .create();
        server
            .mock("GET", "/alpha/hls/vid1/original720p/index.m3u8")
            .with_body("#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"k\"\nseg_0.ts\nseg_1.ts\n")
            .create();
        for k in [
            "original720p/index.m3u8",
            "original720p/seg_0.ts",
            "original720p/seg_1.ts",
            "originalthumb.0000001.jpg",
        ] {
            server
                .mock("HEAD", format!("/alpha/hls/vid1/{k}").as_str())
                .with_header("content-length", "5")
                .with_header("etag", "\"e\"")
                .create();
        }
        server
            .mock("HEAD", "/alpha/hls/vid1/originalthumb.0000000.jpg")
            .with_status(404)
            .create();
        server
            .mock("HEAD", "/alpha/src/vid1.mp4")
            .with_status(404)
            .create();
        // seg_0 is already there from an earlier run: skipped.
        server
            .mock("HEAD", format!("{gated}/720p/seg_0.ts").as_str())
            .with_header("content-length", "5")
            .with_header("x-amz-meta-alpha-etag", "e")
            .create();
        server
            .mock("HEAD", mockito::Matcher::Regex("^/prod/".into()))
            .with_status(404)
            .create();
        let copies = server
            .mock("PUT", mockito::Matcher::Regex("^/prod/".into()))
            .match_header("x-amz-copy-source", mockito::Matcher::Any)
            .with_body("<CopyObjectResult/>")
            .expect(3)
            .create();
        let master = server
            .mock("PUT", format!("{gated}/master.m3u8").as_str())
            .match_body("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\n720p/index.m3u8\n")
            .create();

        let out = c.ladders(&[&v]);
        copies.assert();
        master.assert();
        assert_eq!(
            out.outcomes["vid1"],
            MediaOutcome::Ready {
                rungs: vec!["720p".into()],
                original: false,
                cover: true
            }
        );
        assert_eq!(
            (out.stats.objects_copied, out.stats.objects_skipped),
            (3, 1)
        );
        let m = &out.videos["vid1"];
        assert_eq!(
            (m.segments, m.cover_from.as_deref()),
            (2, Some("hls/vid1/originalthumb.0000001.jpg"))
        );
        assert_eq!(m.key_sha256.as_ref().map(String::len), Some(64));
    }

    #[test]
    fn a_short_key_refuses_before_any_request() {
        let creds = Creds {
            access_key: "a".into(),
            secret_key: "s".into(),
            session_token: None,
        };
        let s3 = S3::with_endpoint(creds, Some("http://127.0.0.1:9".into())).unwrap();
        let b = |n: &str| Bucket {
            name: n.into(),
            region: "r".into(),
        };
        let c = Copier::new(&s3, b("alpha"), b("prod"), "p", false, 1).unwrap();
        let v = AlphaVideo {
            encryption_key: Some(vec![1; 28]),
            ..video()
        };
        assert_eq!(
            c.ladders(&[&v]).outcomes["vid1"],
            MediaOutcome::Refused(Refusal::KeyLength(28))
        );
        assert!(Copier::new(&s3, b("alpha"), b("alpha"), "p", true, 1).is_err());
    }
}
