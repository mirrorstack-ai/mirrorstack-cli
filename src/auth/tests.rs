use super::*;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

#[test]
fn pkce_challenge_matches_sha256_of_verifier() {
    let p = Pkce::generate().expect("generate");
    let want = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
    assert_eq!(p.challenge, want);
}

#[test]
fn pkce_unique_across_calls() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..50 {
        let p = Pkce::generate().expect("generate");
        assert!(seen.insert(p.verifier), "duplicate verifier");
    }
}

#[test]
fn authorize_url_carries_required_params() {
    let p = Pkce {
        verifier: "v".into(),
        challenge: "abc".into(),
    };
    let raw = authorize_url("https://example.com", "STATE", &p);
    let u = url::Url::parse(&raw).expect("parse");
    assert_eq!(u.path(), "/authorize");

    let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
    assert_eq!(q.get("client_id").map(String::as_str), Some(CLIENT_ID));
    assert_eq!(
        q.get("redirect_uri").map(String::as_str),
        Some(REDIRECT_URI)
    );
    assert_eq!(q.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(q.get("code_challenge").map(String::as_str), Some("abc"));
    assert_eq!(
        q.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert_eq!(q.get("state").map(String::as_str), Some("STATE"));
}

#[test]
fn authorize_url_trims_trailing_slash() {
    let p = Pkce {
        verifier: "v".into(),
        challenge: "c".into(),
    };
    let raw = authorize_url("https://example.com/", "s", &p);
    assert!(
        raw.starts_with("https://example.com/authorize?"),
        "got {raw}"
    );
}

mod exchange {
    use super::*;

    use mockito::{Matcher, Server};
    use reqwest::blocking::Client;
    use serde_json::json;
    use std::time::Duration;

    fn http() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    #[test]
    fn success_returns_tokens() {
        let mut server = Server::new();
        let m = server
            .mock("POST", "/v1/oauth/token")
            .match_header("accept", "application/json")
            .match_body(Matcher::AllOf(vec![
                Matcher::UrlEncoded("grant_type".into(), "authorization_code".into()),
                Matcher::UrlEncoded("code".into(), "AUTHCODE".into()),
                Matcher::UrlEncoded("code_verifier".into(), "VERIFIER".into()),
            ]))
            .with_status(200)
            .with_body(
                json!({"access_token":"AT","token_type":"Bearer","expires_in":900,"refresh_token":"RT"})
                    .to_string(),
            )
            .create();

        let pkce = Pkce {
            verifier: "VERIFIER".into(),
            challenge: "C".into(),
        };
        let tr = exchange_code(&http(), &server.url(), "AUTHCODE", &pkce).expect("ok");
        m.assert();
        assert_eq!(tr.access_token, "AT");
        assert_eq!(tr.refresh_token, "RT");
        assert_eq!(tr.expires_in, 900);
    }

    #[test]
    fn typed_sentinels() {
        for (oauth_code, want_match) in [
            ("invalid_grant", "InvalidGrant"),
            ("invalid_request", "InvalidRequest"),
            ("invalid_client", "InvalidClient"),
            ("unsupported_grant_type", "UnsupportedGrant"),
        ] {
            let mut server = Server::new();
            let _m = server
                .mock("POST", "/v1/oauth/token")
                .with_status(400)
                .with_body(json!({"error": oauth_code, "error_description": "x"}).to_string())
                .create();

            let err = exchange_code(
                &http(),
                &server.url(),
                "X",
                &Pkce {
                    verifier: "v".into(),
                    challenge: "c".into(),
                },
            )
            .unwrap_err();
            let actual = format!("{err:?}");
            assert!(
                actual.contains(want_match),
                "for {oauth_code}: got {actual}, want {want_match}"
            );
        }
    }

    #[test]
    fn server_5xx_is_typed() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/oauth/token")
            .with_status(503)
            .with_body(json!({"error":"server_error","error_description":"boom"}).to_string())
            .create();

        let err = exchange_code(
            &http(),
            &server.url(),
            "X",
            &Pkce {
                verifier: "v".into(),
                challenge: "c".into(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::Server { .. }), "got {err:?}");
    }

    #[test]
    fn unknown_oauth_code_is_other() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/v1/oauth/token")
            .with_status(400)
            .with_body(json!({"error":"made_up","error_description":"x"}).to_string())
            .create();

        let err = exchange_code(
            &http(),
            &server.url(),
            "X",
            &Pkce {
                verifier: "v".into(),
                challenge: "c".into(),
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::Other { ref code, .. } if code == "made_up"),
            "got {err:?}"
        );
    }
}
