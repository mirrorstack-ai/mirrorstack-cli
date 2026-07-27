use super::*;

use std::time::{Duration, SystemTime};

/// Redirect `dirs::config_dir()` for the duration of the test by setting
/// the per-platform env var the dirs crate consults. Returns the temp
/// dir guard — drop releases the dir.
fn with_temp_config_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(target_os = "macos")]
    unsafe {
        std::env::set_var("HOME", dir.path())
    };
    #[cfg(target_os = "windows")]
    unsafe {
        std::env::set_var("APPDATA", dir.path())
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", dir.path())
    };
    dir
}

/// Cargo test runs cases in parallel by default, but every case here
/// mutates the same per-platform env var that `dirs::config_dir` reads.
/// Merging into a single test avoids the race without pulling in the
/// `serial_test` crate.
#[test]
fn credentials_lifecycle() {
    let _env = TEST_ENV_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _g = with_temp_config_dir();

    // load() before save() returns NotFound.
    assert!(matches!(load(), Err(LoadError::NotFound)));

    // load_or_login_hint() before save() surfaces the login hint.
    let hint_err = load_or_login_hint().unwrap_err();
    assert!(
        hint_err.to_string().contains("mirrorstack login"),
        "expected login hint, got: {hint_err}"
    );

    // save → load roundtrip preserves token strings + expires_at.
    let want = Credentials {
        access_token: "AT".into(),
        refresh_token: "RT".into(),
        expires_at: SystemTime::now() + Duration::from_secs(900),
    };
    save(&want).expect("save");
    let got = load().expect("load");

    // load_or_login_hint() after save() returns the same data as load().
    let got_hint = load_or_login_hint().expect("load_or_login_hint");
    assert_eq!(got_hint, got);
    assert_eq!(got.access_token, want.access_token);
    assert_eq!(got.refresh_token, want.refresh_token);
    let skew = got
        .expires_at
        .duration_since(want.expires_at)
        .or_else(|_| want.expires_at.duration_since(got.expires_at))
        .unwrap();
    assert!(skew < Duration::from_millis(1), "skew = {skew:?}");

    // File mode 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = path().expect("path");
        let mode = std::fs::metadata(&p).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}, want 0600");
    }

    // delete() wipes the file; subsequent load() returns NotFound.
    delete().expect("delete");
    assert!(matches!(load(), Err(LoadError::NotFound)));

    // delete() is idempotent — no error when called against missing file.
    delete().expect("delete idempotent");

    // --- with_refresh_retry: refresh-on-401 paths ---
    // These exercise the network refresh, so they live inside this single
    // serial test (it already owns the per-platform config-dir env var that
    // `refresh_and_save`'s `save()` writes through). The api-base env var is
    // also set here, where no other test races on it.

    use crate::api::ApiError;
    use mockito::Server;

    // Refresh-then-retry succeeds: first call 401s, refresh mints a new
    // pair, the retried call sees the rotated token and succeeds. The
    // rotated pair is written back through `creds`.
    {
        let mut server = Server::new();
        let _refresh = server
            .mock("POST", "/v1/auth/sessions/refresh")
            .with_status(200)
            .with_body(
                r#"{"access_token":"AT2","refresh_token":"RT2","expires_at":"2026-01-01T00:00:00Z"}"#,
            )
            .create();
        unsafe { std::env::set_var("MIRRORSTACK_API_URL", server.url()) };

        let mut creds = Credentials {
            access_token: "AT1".into(),
            refresh_token: "RT1".into(),
            expires_at: SystemTime::now() + Duration::from_secs(900),
        };
        let mut attempts = 0;
        let out = with_refresh_retry(&mut creds, |tok| {
            attempts += 1;
            if tok == "AT1" {
                Err(ApiError::Unauthenticated)
            } else {
                Ok(tok.to_string())
            }
        });
        assert_eq!(out.unwrap(), "AT2");
        assert_eq!(attempts, 2, "exactly one retry");
        assert_eq!(creds.access_token, "AT2");
        assert_eq!(creds.refresh_token, "RT2", "rotated refresh persisted");
    }

    // Refresh itself 401s (revoked/expired session): the original
    // Unauthenticated is returned and the call is NOT retried.
    {
        let mut server = Server::new();
        let _refresh = server
            .mock("POST", "/v1/auth/sessions/refresh")
            .with_status(401)
            .create();
        unsafe { std::env::set_var("MIRRORSTACK_API_URL", server.url()) };

        let mut creds = Credentials {
            access_token: "AT1".into(),
            refresh_token: "RT-gone".into(),
            expires_at: SystemTime::now() + Duration::from_secs(900),
        };
        let mut attempts = 0;
        let out = with_refresh_retry(&mut creds, |_tok| {
            attempts += 1;
            Err::<(), _>(ApiError::Unauthenticated)
        });
        assert!(matches!(out, Err(ApiError::Unauthenticated)));
        assert_eq!(attempts, 1, "no retry when refresh fails");
    }

    unsafe { std::env::remove_var("MIRRORSTACK_API_URL") };
}

/// Happy path needs no network: the call succeeds on the first token, so
/// the refresh branch is never entered.
#[test]
fn with_refresh_retry_passes_through_success() {
    let mut creds = Credentials {
        access_token: "AT".into(),
        refresh_token: "RT".into(),
        expires_at: SystemTime::now() + Duration::from_secs(900),
    };
    let mut attempts = 0;
    let out = with_refresh_retry(&mut creds, |tok| {
        attempts += 1;
        Ok::<_, crate::api::ApiError>(tok.to_string())
    });
    assert_eq!(out.unwrap(), "AT");
    assert_eq!(attempts, 1);
    assert_eq!(creds.access_token, "AT", "unchanged on success");
}

/// A non-401 error short-circuits without touching the refresh path, so
/// no network is needed.
#[test]
fn with_refresh_retry_propagates_non_401_without_refresh() {
    let mut creds = Credentials {
        access_token: "AT".into(),
        refresh_token: "RT".into(),
        expires_at: SystemTime::now() + Duration::from_secs(900),
    };
    let mut attempts = 0;
    let out: Result<(), _> = with_refresh_retry(&mut creds, |_tok| {
        attempts += 1;
        Err(crate::api::ApiError::Unexpected {
            status: 503,
            body: "down".into(),
        })
    });
    assert!(matches!(
        out,
        Err(crate::api::ApiError::Unexpected { status: 503, .. })
    ));
    assert_eq!(attempts, 1, "no refresh, no retry on non-401");
}
