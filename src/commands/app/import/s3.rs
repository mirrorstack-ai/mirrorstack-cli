//! The few S3 calls the media copier needs (§3.5), SigV4-signed over the
//! blocking reqwest client: no AWS SDK in a CLI whose importer is removed
//! after P5. `MIRRORSTACK_IMPORT_S3_ENDPOINT` switches to path-style requests
//! against that endpoint (tests, a local MinIO rehearsal).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Method;
use reqwest::blocking::{Client, Response};
use sha2::{Digest, Sha256};

use super::transform::hex;

pub const ENV_ENDPOINT: &str = "MIRRORSTACK_IMPORT_S3_ENDPOINT";
/// S3's CopyObject ceiling; anything larger goes through UploadPartCopy.
pub const COPY_MAX: u64 = 5 * 1024 * 1024 * 1024;
pub const PART: u64 = 512 * 1024 * 1024;
const META_ALPHA_ETAG: &str = "x-amz-meta-alpha-etag";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// SigV4's unreserved set: everything but `A-Za-z0-9-_.~` is escaped.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Clone)]
pub struct Creds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds")
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

impl Creds {
    pub fn from_env() -> Result<Self> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Ok(Self {
            access_key: var("AWS_ACCESS_KEY_ID").ok_or_else(|| {
                anyhow!("AWS_ACCESS_KEY_ID is not set (the media copy needs S3 credentials)")
            })?,
            secret_key: var("AWS_SECRET_ACCESS_KEY")
                .ok_or_else(|| anyhow!("AWS_SECRET_ACCESS_KEY is not set"))?,
            session_token: var("AWS_SESSION_TOKEN"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    pub name: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub size: u64,
    /// Without the quotes S3 wraps it in.
    pub etag: String,
    pub content_type: Option<String>,
    /// The source ETag this object was copied from (a multipart copy gets a
    /// new ETag, so the skip check compares this one).
    pub alpha_etag: Option<String>,
}

impl ObjectMeta {
    /// §3.5 resume rule: same size and the same source ETag.
    pub fn is_copy_of(&self, src: &ObjectMeta) -> bool {
        self.size == src.size
            && (self.etag == src.etag || self.alpha_etag.as_deref() == Some(&src.etag))
    }
}

pub struct S3 {
    http: Client,
    creds: Creds,
    endpoint: Option<String>,
}

struct Req<'a> {
    method: Method,
    bucket: &'a Bucket,
    key: &'a str,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl<'a> Req<'a> {
    fn new(method: Method, bucket: &'a Bucket, key: &'a str) -> Self {
        Self {
            method,
            bucket,
            key,
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
    fn q(mut self, k: &str, v: impl Into<String>) -> Self {
        self.query.push((k.into(), v.into()));
        self
    }
    fn h(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_ascii_lowercase(), v.into()));
        self
    }
}

impl S3 {
    pub fn new(creds: Creds) -> Result<Self> {
        let endpoint = std::env::var(ENV_ENDPOINT).ok().filter(|v| !v.is_empty());
        Self::with_endpoint(creds, endpoint)
    }

    pub fn with_endpoint(creds: Creds, endpoint: Option<String>) -> Result<Self> {
        // A part copy of 512 MiB is server-side, but S3 answers only when done.
        let http = crate::http::client(Duration::from_secs(900))?;
        Ok(Self {
            http,
            creds,
            endpoint: endpoint.map(|e| e.trim_end_matches('/').to_string()),
        })
    }

    fn send(&self, r: Req) -> Result<Response> {
        let path = encode_key(r.key);
        let (url, uri) = match &self.endpoint {
            Some(e) => {
                let uri = format!("/{}/{path}", r.bucket.name);
                (format!("{e}{uri}"), uri)
            }
            None => (
                format!(
                    "https://{}.s3.{}.amazonaws.com/{path}",
                    r.bucket.name, r.bucket.region
                ),
                format!("/{path}"),
            ),
        };
        let parsed = url::Url::parse(&url).with_context(|| format!("S3 url {url}"))?;
        let host = match parsed.port() {
            Some(p) => format!("{}:{p}", parsed.host_str().unwrap_or_default()),
            None => parsed.host_str().unwrap_or_default().to_string(),
        };
        let payload = if r.body.is_empty() {
            EMPTY_SHA256.to_string()
        } else {
            hex(&Sha256::digest(&r.body))
        };
        let mut headers = r.headers;
        headers.push(("x-amz-content-sha256".into(), payload.clone()));
        if let Some(t) = &self.creds.session_token {
            headers.push(("x-amz-security-token".into(), t.clone()));
        }
        let amz_date = amz_date(SystemTime::now());
        let auth = sign(&Signing {
            creds: &self.creds,
            region: &r.bucket.region,
            method: r.method.as_str(),
            host: &host,
            uri: &uri,
            query: &r.query,
            headers: &headers,
            payload: &payload,
            amz_date: &amz_date,
        });
        let mut url = parsed;
        if !r.query.is_empty() {
            url.set_query(Some(&canonical_query(&r.query)));
        }
        let mut req = self
            .http
            .request(r.method, url)
            .header("x-amz-date", &amz_date)
            .header("authorization", auth);
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if !r.body.is_empty() {
            req = req.body(r.body);
        }
        Ok(req.send()?)
    }

    fn check(resp: Response, what: &str) -> Result<Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let body = resp.text().unwrap_or_default();
        let code = tag(&body, "Code").unwrap_or("");
        bail!("S3 {what}: HTTP {} {code}", status.as_u16())
    }

    pub fn head(&self, b: &Bucket, key: &str) -> Result<Option<ObjectMeta>> {
        let resp = self.send(Req::new(Method::HEAD, b, key))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = Self::check(resp, &format!("HEAD {}/{key}", b.name))?;
        let h = |k: &str| {
            resp.headers()
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim_matches('"').to_string())
        };
        Ok(Some(ObjectMeta {
            size: h("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            etag: h("etag").unwrap_or_default(),
            content_type: h("content-type"),
            alpha_etag: h(META_ALPHA_ETAG),
        }))
    }

    /// Small objects only (playlists).
    pub fn get(&self, b: &Bucket, key: &str) -> Result<Option<Vec<u8>>> {
        let resp = self.send(Req::new(Method::GET, b, key))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = Self::check(resp, &format!("GET {}/{key}", b.name))?;
        Ok(Some(resp.bytes()?.to_vec()))
    }

    pub fn put(
        &self,
        b: &Bucket,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
        alpha_etag: &str,
    ) -> Result<()> {
        let r = Req {
            body,
            ..Req::new(Method::PUT, b, key)
                .h("content-type", content_type)
                .h(META_ALPHA_ETAG, alpha_etag)
        };
        Self::check(self.send(r)?, &format!("PUT {}/{key}", b.name))?;
        Ok(())
    }

    /// Server-side copy that records the source ETag on the destination.
    /// Picks CopyObject or a multipart UploadPartCopy by size.
    pub fn copy(
        &self,
        src: &Bucket,
        src_key: &str,
        meta: &ObjectMeta,
        dst: &Bucket,
        dst_key: &str,
    ) -> Result<()> {
        if meta.size > COPY_MAX {
            return self.copy_multipart(src, src_key, meta, dst, dst_key);
        }
        let r = Req::new(Method::PUT, dst, dst_key)
            .h("x-amz-copy-source", copy_source(src, src_key))
            .h("x-amz-copy-source-if-match", format!("\"{}\"", meta.etag))
            .h("x-amz-metadata-directive", "REPLACE")
            .h("content-type", content_type(meta))
            .h(META_ALPHA_ETAG, &meta.etag);
        let what = format!("copy {}/{src_key} → {}/{dst_key}", src.name, dst.name);
        let body = Self::check(self.send(r)?, &what)?.text()?;
        // CopyObject can answer 200 with an error document.
        if body.contains("<Error>") {
            bail!("{what}: {}", tag(&body, "Code").unwrap_or("error"));
        }
        Ok(())
    }

    fn copy_multipart(
        &self,
        src: &Bucket,
        src_key: &str,
        meta: &ObjectMeta,
        dst: &Bucket,
        dst_key: &str,
    ) -> Result<()> {
        let what = format!(
            "multipart copy {}/{src_key} → {}/{dst_key}",
            src.name, dst.name
        );
        let r = Req::new(Method::POST, dst, dst_key)
            .q("uploads", "")
            .h("content-type", content_type(meta))
            .h(META_ALPHA_ETAG, &meta.etag);
        let body = Self::check(self.send(r)?, &what)?.text()?;
        let upload_id = tag(&body, "UploadId")
            .map(unescape)
            .ok_or_else(|| anyhow!("{what}: no UploadId"))?;
        let parts = (|| -> Result<Vec<String>> {
            let mut etags = Vec::new();
            let mut start = 0;
            while start < meta.size {
                let end = (start + PART).min(meta.size) - 1;
                let n = etags.len() + 1;
                let r = Req::new(Method::PUT, dst, dst_key)
                    .q("partNumber", n.to_string())
                    .q("uploadId", upload_id.clone())
                    .h("x-amz-copy-source", copy_source(src, src_key))
                    .h("x-amz-copy-source-if-match", format!("\"{}\"", meta.etag))
                    .h("x-amz-copy-source-range", format!("bytes={start}-{end}"));
                let body = Self::check(self.send(r)?, &format!("{what} part {n}"))?.text()?;
                let etag = tag(&body, "ETag")
                    .map(|e| unescape(e).trim_matches('"').to_string())
                    .ok_or_else(|| anyhow!("{what} part {n}: no ETag"))?;
                etags.push(etag);
                start = end + 1;
            }
            Ok(etags)
        })();
        let parts = match parts {
            Ok(p) => p,
            Err(e) => {
                let abort = Req::new(Method::DELETE, dst, dst_key).q("uploadId", upload_id.clone());
                let _ = self.send(abort);
                return Err(e);
            }
        };
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (i, e) in parts.iter().enumerate() {
            xml.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>\"{e}\"</ETag></Part>",
                i + 1
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let r = Req {
            body: xml.into_bytes(),
            ..Req::new(Method::POST, dst, dst_key).q("uploadId", upload_id)
        };
        let body = Self::check(self.send(r)?, &what)?.text()?;
        if body.contains("<Error>") {
            bail!("{what}: {}", tag(&body, "Code").unwrap_or("error"));
        }
        Ok(())
    }

    /// Every key under `prefix` (ListObjectsV2).
    pub fn list(&self, b: &Bucket, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut r = Req::new(Method::GET, b, "")
                .q("list-type", "2")
                .q("prefix", prefix);
            if let Some(t) = &token {
                r = r.q("continuation-token", t.clone());
            }
            let body = Self::check(self.send(r)?, &format!("list {}/{prefix}", b.name))?.text()?;
            keys.extend(
                body.split("<Contents>")
                    .skip(1)
                    .filter_map(|c| tag(c, "Key"))
                    .map(unescape),
            );
            match tag(&body, "NextContinuationToken") {
                Some(t) if tag(&body, "IsTruncated") == Some("true") => token = Some(unescape(t)),
                _ => return Ok(keys),
            }
        }
    }

    /// Rollback only; the caller passes the V2 bucket, never alpha's.
    pub fn delete(&self, b: &Bucket, key: &str) -> Result<()> {
        let resp = self.send(Req::new(Method::DELETE, b, key))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        Self::check(resp, &format!("DELETE {}/{key}", b.name))?;
        Ok(())
    }
}

fn content_type(meta: &ObjectMeta) -> &str {
    meta.content_type
        .as_deref()
        .unwrap_or("application/octet-stream")
}

fn copy_source(b: &Bucket, key: &str) -> String {
    format!("/{}/{}", b.name, encode_key(key))
}

fn encode_key(key: &str) -> String {
    key.split('/')
        .map(|s| utf8_percent_encode(s, UNRESERVED).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn canonical_query(q: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = q
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, UNRESERVED).to_string(),
                utf8_percent_encode(v, UNRESERVED).to_string(),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

struct Signing<'a> {
    creds: &'a Creds,
    region: &'a str,
    method: &'a str,
    host: &'a str,
    uri: &'a str,
    query: &'a [(String, String)],
    /// Lower-case names; `host` and `x-amz-date` are added here.
    headers: &'a [(String, String)],
    payload: &'a str,
    amz_date: &'a str,
}

/// The `Authorization` header value (AWS SigV4, service `s3`).
fn sign(s: &Signing) -> String {
    let mut headers: Vec<(String, String)> = s
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    headers.push(("host".into(), s.host.into()));
    headers.push(("x-amz-date".into(), s.amz_date.into()));
    headers.sort();
    let signed = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed}\n{}",
        s.method,
        s.uri,
        canonical_query(s.query),
        s.payload
    );
    let date = &s.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", s.region);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        s.amz_date,
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let key = [date, s.region, "s3", "aws4_request"].iter().fold(
        format!("AWS4{}", s.creds.secret_key).into_bytes(),
        |k, part| hmac(&k, part.as_bytes()),
    );
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
        s.creds.access_key,
        hex(&hmac(&key, to_sign.as_bytes()))
    )
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// `YYYYMMDDTHHMMSSZ` from the system clock, without a date crate.
fn amz_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The text of the first `<name>…</name>`; S3's XML has no attributes on
/// the elements read here.
fn tag<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(&xml[start..end])
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#34;", "\"")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Creds {
        Creds {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    #[test]
    fn signs_the_aws_documented_get_object_example() {
        // docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        let auth = sign(&Signing {
            creds: &creds(),
            region: "us-east-1",
            method: "GET",
            host: "examplebucket.s3.amazonaws.com",
            uri: "/test.txt",
            query: &[],
            headers: &[
                ("range".into(), "bytes=0-9".into()),
                ("x-amz-content-sha256".into(), EMPTY_SHA256.into()),
            ],
            payload: EMPTY_SHA256,
            amz_date: "20130524T000000Z",
        });
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn dates_come_from_the_epoch_without_a_clock_crate() {
        let at = |s| amz_date(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(1_369_353_600), "20130524T000000Z");
        assert_eq!(at(0), "19700101T000000Z");
        assert_eq!(at(1_709_208_000 + 3661), "20240229T130101Z");
    }

    #[test]
    fn keys_and_queries_are_escaped_the_way_s3_signs_them() {
        assert_eq!(encode_key("a b/c+d/é.ts"), "a%20b/c%2Bd/%C3%A9.ts");
        let q = [
            ("uploads".to_string(), String::new()),
            ("a".to_string(), "x/y".to_string()),
        ];
        assert_eq!(canonical_query(&q), "a=x%2Fy&uploads=");
    }

    #[test]
    fn a_copy_matches_its_source_by_size_and_etag() {
        let src = ObjectMeta {
            size: 10,
            etag: "abc-2".into(),
            content_type: None,
            alpha_etag: None,
        };
        let same = ObjectMeta {
            etag: "abc-2".into(),
            ..src.clone()
        };
        let multipart = ObjectMeta {
            etag: "zzz-1".into(),
            alpha_etag: Some("abc-2".into()),
            ..src.clone()
        };
        let short = ObjectMeta {
            size: 9,
            ..same.clone()
        };
        let other = ObjectMeta {
            etag: "zzz".into(),
            ..src.clone()
        };
        assert!(same.is_copy_of(&src));
        assert!(multipart.is_copy_of(&src));
        assert!(!short.is_copy_of(&src));
        assert!(!other.is_copy_of(&src));
    }

    #[test]
    fn head_get_put_copy_and_list_against_a_path_style_endpoint() {
        let mut server = mockito::Server::new();
        let s3 = S3::with_endpoint(creds(), Some(server.url())).unwrap();
        let alpha = Bucket {
            name: "alpha".into(),
            region: "ap-northeast-1".into(),
        };
        let prod = Bucket {
            name: "prod".into(),
            region: "us-east-1".into(),
        };
        let head = server
            .mock("HEAD", "/alpha/hls/v1/original.m3u8")
            .match_header(
                "authorization",
                mockito::Matcher::Regex("ap-northeast-1/s3/aws4_request".into()),
            )
            .with_header("content-length", "42")
            .with_header("etag", "\"e1\"")
            .with_header("content-type", "application/vnd.apple.mpegurl")
            .create();
        let missing = server.mock("HEAD", "/alpha/nope").with_status(404).create();
        let get = server
            .mock("GET", "/alpha/hls/v1/original.m3u8")
            .with_body("#EXTM3U\n")
            .create();
        let copy = server
            .mock("PUT", "/prod/v2/master.m3u8")
            .match_header("x-amz-copy-source", "/alpha/hls/v1/original.m3u8")
            .match_header("x-amz-meta-alpha-etag", "e1")
            .match_header("x-amz-metadata-directive", "REPLACE")
            .with_body("<CopyObjectResult><ETag>\"e1\"</ETag></CopyObjectResult>")
            .create();
        let failed = server
            .mock("PUT", "/prod/v2/bad")
            .with_body("<Error><Code>InternalError</Code></Error>")
            .create();
        let list = server
            .mock("GET", "/prod/")
            .match_query(mockito::Matcher::UrlEncoded("list-type".into(), "2".into()))
            .with_body("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>v2/a&amp;b.ts</Key></Contents><Contents><Key>v2/c.ts</Key></Contents></ListBucketResult>")
            .create();

        let meta = s3.head(&alpha, "hls/v1/original.m3u8").unwrap().unwrap();
        assert_eq!((meta.size, meta.etag.as_str()), (42, "e1"));
        assert!(s3.head(&alpha, "nope").unwrap().is_none());
        assert_eq!(
            s3.get(&alpha, "hls/v1/original.m3u8").unwrap().unwrap(),
            b"#EXTM3U\n"
        );
        s3.copy(
            &alpha,
            "hls/v1/original.m3u8",
            &meta,
            &prod,
            "v2/master.m3u8",
        )
        .unwrap();
        assert!(
            s3.copy(&alpha, "hls/v1/original.m3u8", &meta, &prod, "v2/bad")
                .is_err()
        );
        assert_eq!(s3.list(&prod, "v2/").unwrap(), ["v2/a&b.ts", "v2/c.ts"]);
        for m in [head, missing, get, copy, failed, list] {
            m.assert();
        }
    }

    #[test]
    fn a_large_original_is_copied_in_parts_and_completed() {
        let mut server = mockito::Server::new();
        let s3 = S3::with_endpoint(creds(), Some(server.url())).unwrap();
        let b = Bucket {
            name: "b".into(),
            region: "r".into(),
        };
        let meta = ObjectMeta {
            size: COPY_MAX + 1,
            etag: "big-9".into(),
            content_type: None,
            alpha_etag: None,
        };
        let create = server
            .mock("POST", "/b/dst")
            .match_query(mockito::Matcher::UrlEncoded("uploads".into(), String::new()))
            .with_body("<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>")
            .create();
        let parts = server
            .mock("PUT", "/b/dst")
            .match_query(mockito::Matcher::UrlEncoded("uploadId".into(), "u1".into()))
            .match_header(
                "x-amz-copy-source-range",
                mockito::Matcher::Regex("^bytes=\\d+-\\d+$".into()),
            )
            .with_body("<CopyPartResult><ETag>&quot;p&quot;</ETag></CopyPartResult>")
            .expect(11)
            .create();
        let complete = server
            .mock("POST", "/b/dst")
            .match_query(mockito::Matcher::UrlEncoded("uploadId".into(), "u1".into()))
            .match_body(mockito::Matcher::Regex(
                "<PartNumber>11</PartNumber>".into(),
            ))
            .with_body("<CompleteMultipartUploadResult/>")
            .create();
        s3.copy(&b, "src", &meta, &b, "dst").unwrap();
        create.assert();
        parts.assert();
        complete.assert();
    }
}
