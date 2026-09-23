//! §3.5 key remap: alpha's MediaConvert/ffmpeg object names onto video-core's
//! HLS layout, and the refusals that turn a video into an exception instead of
//! a copy that would not play on V2 (T607 §14.1: a verbatim copy 404s, a
//! renamed master keeps 0 rungs).

/// video-core `allowedQualities` (`video-core/internal/handlers/stream.go`).
/// A rung outside this set is dropped by `rewriteMaster`, so it is refused here.
pub const V2_QUALITIES: &[&str] = &[
    "144p", "240p", "360p", "480p", "720p", "1080p", "1440p", "2k", "4k",
];

pub const ALPHA_MASTER: &str = "original.m3u8";
pub const V2_MASTER: &str = "master.m3u8";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `#EXT-X-MEDIA … URI=`: V2's `rewriteMaster` would not rewrite the group.
    MediaGroup,
    /// A variant line not of the form `original<q>/index.m3u8`.
    OddVariant(String),
    QualityNotAllowed(String),
    NoRungs,
    /// A variant without `#EXT-X-KEY` (or `METHOD=NONE`): alpha's local-ffmpeg
    /// path never encrypted, and V2 only serves keyed ladders.
    Plaintext(String),
    BadSegment(String),
    KeyLength(usize),
    MissingObject(String),
    NoHls,
}

impl Refusal {
    /// Exception reason for the ledger: stable, no PII, `^[a-z][a-z0-9_]*$`.
    pub fn reason(&self) -> &'static str {
        match self {
            Refusal::MediaGroup => "hls_media_group",
            Refusal::OddVariant(_) => "hls_odd_variant_line",
            Refusal::QualityNotAllowed(_) => "hls_quality_not_allowed",
            Refusal::NoRungs => "hls_no_rungs",
            Refusal::Plaintext(_) => "hls_plaintext_variant",
            Refusal::BadSegment(_) => "hls_bad_segment_name",
            Refusal::KeyLength(_) => "key_not_16_bytes",
            Refusal::MissingObject(_) => "media_missing_object",
            Refusal::NoHls => "hls_missing",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::OddVariant(s)
            | Refusal::QualityNotAllowed(s)
            | Refusal::Plaintext(s)
            | Refusal::BadSegment(s)
            | Refusal::MissingObject(s) => write!(f, "{} ({s})", self.reason()),
            Refusal::KeyLength(n) => write!(f, "{} ({n} bytes)", self.reason()),
            _ => f.write_str(self.reason()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Master {
    /// The master as V2 serves it: variant lines `original<q>/index.m3u8`
    /// become `<q>/index.m3u8`; every tag line is untouched.
    pub text: String,
    pub rungs: Vec<String>,
}

/// Rewrites alpha's `original.m3u8` into V2's `master.m3u8`.
pub fn rewrite_master(src: &str) -> Result<Master, Refusal> {
    let mut out = Vec::new();
    let mut rungs = Vec::new();
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("#EXT-X-MEDIA") && t.contains("URI=") {
            return Err(Refusal::MediaGroup);
        }
        if t.is_empty() || t.starts_with('#') {
            out.push(line.to_string());
            continue;
        }
        let q = t
            .strip_prefix("original")
            .and_then(|r| r.strip_suffix("/index.m3u8"))
            .filter(|q| !q.is_empty() && !q.contains('/'))
            .ok_or_else(|| Refusal::OddVariant(t.to_string()))?;
        if !V2_QUALITIES.contains(&q) {
            return Err(Refusal::QualityNotAllowed(q.to_string()));
        }
        out.push(format!("{q}/index.m3u8"));
        rungs.push(q.to_string());
    }
    if rungs.is_empty() {
        return Err(Refusal::NoRungs);
    }
    let mut text = out.join("\n");
    if src.ends_with('\n') {
        text.push('\n');
    }
    Ok(Master { text, rungs })
}

/// Checks one variant playlist and returns the files it names (segments plus
/// an `#EXT-X-MAP` init segment, if any), which are copied byte-for-byte.
/// Both key styles T631 found pass: MediaConvert's key-per-segment with IV
/// and ffmpeg's single key line.
pub fn variant_files(q: &str, src: &str) -> Result<Vec<String>, Refusal> {
    let mut keyed = false;
    let mut files = Vec::new();
    for line in src.lines() {
        let t = line.trim();
        if let Some(attrs) = t.strip_prefix("#EXT-X-KEY:") {
            if !attrs.contains("METHOD=NONE") {
                keyed = true;
            }
            continue;
        }
        if let Some(attrs) = t.strip_prefix("#EXT-X-MAP:") {
            let uri = attr(attrs, "URI").unwrap_or_default();
            files.push(segment_name(uri)?);
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        files.push(segment_name(t)?);
    }
    if !keyed {
        return Err(Refusal::Plaintext(q.to_string()));
    }
    if files.is_empty() {
        return Err(Refusal::MissingObject(format!("{q}/index.m3u8 lists no segments")));
    }
    Ok(files)
}

/// video-core `validSegmentFilename`: `^[A-Za-z0-9_.-]+\.(ts|m4s|mp4)$`.
fn segment_name(s: &str) -> Result<String, Refusal> {
    let ok_ext = [".ts", ".m4s", ".mp4"].iter().any(|e| s.ends_with(e));
    let ok_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if ok_ext && ok_chars && !s.starts_with('.') {
        Ok(s.to_string())
    } else {
        Err(Refusal::BadSegment(s.to_string()))
    }
}

fn attr<'a>(attrs: &'a str, name: &str) -> Option<&'a str> {
    let at = attrs.find(&format!("{name}="))? + name.len() + 1;
    let rest = &attrs[at..];
    match rest.strip_prefix('"') {
        Some(q) => q.split('"').next(),
        None => rest.split(',').next(),
    }
}

pub fn check_key(key: Option<&[u8]>) -> Result<(), Refusal> {
    match key {
        Some(k) if k.len() == 16 => Ok(()),
        Some(k) => Err(Refusal::KeyLength(k.len())),
        None => Err(Refusal::KeyLength(0)),
    }
}

/// Source and destination object names for one video's ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub alpha_prefix: String,
    pub v2_prefix: String,
}

impl Layout {
    pub fn new(alpha_prefix: &str, v2_prefix: &str) -> Self {
        Self {
            alpha_prefix: alpha_prefix.trim_end_matches('/').to_string(),
            v2_prefix: v2_prefix.trim_end_matches('/').to_string(),
        }
    }
    pub fn master(&self) -> (String, String) {
        (
            format!("{}/{ALPHA_MASTER}", self.alpha_prefix),
            format!("{}/{V2_MASTER}", self.v2_prefix),
        )
    }
    pub fn variant(&self, q: &str) -> (String, String) {
        self.file(q, "index.m3u8")
    }
    pub fn file(&self, q: &str, file: &str) -> (String, String) {
        (
            format!("{}/original{q}/{file}", self.alpha_prefix),
            format!("{}/{q}/{file}", self.v2_prefix),
        )
    }
    /// MediaConvert's own frame grab, used when the row has no cover.
    pub fn thumbnails(&self) -> [String; 2] {
        [
            format!("{}/originalthumb.0000001.jpg", self.alpha_prefix),
            format!("{}/originalthumb.0000000.jpg", self.alpha_prefix),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "#EXTM3U\n#EXT-X-VERSION:5\n#EXT-X-INDEPENDENT-SEGMENTS\n\
#EXT-X-STREAM-INF:BANDWIDTH=300000,RESOLUTION=256x144\noriginal144p/index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080\noriginal1080p/index.m3u8\n";

    #[test]
    fn master_variant_lines_are_remapped_and_tags_kept() {
        let m = rewrite_master(MASTER).unwrap();
        assert_eq!(m.rungs, ["144p", "1080p"]);
        assert!(m.text.contains("\n144p/index.m3u8\n"));
        assert!(m.text.contains("\n1080p/index.m3u8\n"));
        assert!(!m.text.contains("original"));
        assert!(m.text.contains("#EXT-X-STREAM-INF:BANDWIDTH=300000,RESOLUTION=256x144"));
        assert!(m.text.ends_with('\n'));
    }

    #[test]
    fn master_refusals() {
        let media = format!("{MASTER}#EXT-X-MEDIA:TYPE=AUDIO,URI=\"a/index.m3u8\"\n");
        assert_eq!(rewrite_master(&media), Err(Refusal::MediaGroup));
        assert_eq!(
            rewrite_master("#EXTM3U\n#EXT-X-STREAM-INF:X=1\nhigh/index.m3u8\n"),
            Err(Refusal::OddVariant("high/index.m3u8".into()))
        );
        assert_eq!(
            rewrite_master("#EXTM3U\n#EXT-X-STREAM-INF:X=1\noriginal900p/index.m3u8\n"),
            Err(Refusal::QualityNotAllowed("900p".into()))
        );
        assert_eq!(rewrite_master("#EXTM3U\n"), Err(Refusal::NoRungs));
    }

    #[test]
    fn variant_accepts_both_key_styles() {
        let mediaconvert = "#EXTM3U\n#EXT-X-TARGETDURATION:6\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://placeholder/key\",IV=0x01\n#EXTINF:6,\nindex_00001.ts\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://placeholder/key\",IV=0x02\n#EXTINF:1,\nindex_00002.ts\n#EXT-X-ENDLIST\n";
        assert_eq!(
            variant_files("720p", mediaconvert).unwrap(),
            ["index_00001.ts", "index_00002.ts"]
        );
        let ffmpeg = "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-KEY:METHOD=AES-128,URI=\"https://placeholder/key\"\n\
#EXTINF:6,\nindex_00001.ts\n#EXT-X-ENDLIST\n";
        assert_eq!(variant_files("144p", ffmpeg).unwrap(), ["index_00001.ts"]);
    }

    #[test]
    fn variant_refusals() {
        let plain = "#EXTM3U\n#EXTINF:6,\nindex_00001.ts\n";
        assert_eq!(variant_files("720p", plain), Err(Refusal::Plaintext("720p".into())));
        let none = "#EXTM3U\n#EXT-X-KEY:METHOD=NONE\n#EXTINF:6,\nindex_00001.ts\n";
        assert!(matches!(variant_files("720p", none), Err(Refusal::Plaintext(_))));
        let url = "#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,URI=\"k\"\n#EXTINF:6,\nhttps://cdn/x.ts\n";
        assert!(matches!(variant_files("720p", url), Err(Refusal::BadSegment(_))));
    }

    #[test]
    fn layout_maps_alpha_names_onto_v2() {
        let l = Layout::new("apps/k/video-abc/hls/", "_gated/videos/u/transcodes/alpha-import");
        assert_eq!(
            l.master(),
            (
                "apps/k/video-abc/hls/original.m3u8".into(),
                "_gated/videos/u/transcodes/alpha-import/master.m3u8".into()
            )
        );
        assert_eq!(
            l.file("720p", "index_00001.ts"),
            (
                "apps/k/video-abc/hls/original720p/index_00001.ts".into(),
                "_gated/videos/u/transcodes/alpha-import/720p/index_00001.ts".into()
            )
        );
    }

    #[test]
    fn key_must_be_16_bytes() {
        assert!(check_key(Some(&[0u8; 16])).is_ok());
        assert_eq!(check_key(Some(&[0u8; 8])), Err(Refusal::KeyLength(8)));
        assert_eq!(check_key(None), Err(Refusal::KeyLength(0)));
    }
}
