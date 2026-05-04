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
}
