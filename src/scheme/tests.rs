//! Tests for callback parsing and the unix socket relay.

use super::{Callback, CallbackError};

#[test]
fn callback_parses_code_and_state() {
    let callback =
        Callback::parse("mirrorstack://callback?code=X&state=Y").expect("parse callback");
    assert_eq!(callback.code, "X");
    assert_eq!(callback.state, "Y");
}

#[test]
fn callback_ignores_extra_params() {
    let callback =
        Callback::parse("mirrorstack://callback?code=X&state=Y&foo=bar").expect("parse callback");
    assert_eq!(callback.code, "X");
    assert_eq!(callback.state, "Y");
}

#[test]
fn callback_requires_code() {
    let error = Callback::parse("mirrorstack://callback?state=Y").expect_err("missing code");
    assert!(matches!(error, CallbackError::MissingCode));
}

#[test]
fn callback_requires_state() {
    let error = Callback::parse("mirrorstack://callback?code=X").expect_err("missing state");
    assert!(matches!(error, CallbackError::MissingState));
}

#[test]
fn callback_reports_denial() {
    let error = Callback::parse("mirrorstack://callback?error=access_denied&state=Y")
        .expect_err("authorization denied");
    assert!(matches!(
        error,
        CallbackError::Denied(ref value) if value == "access_denied"
    ));
}

#[cfg(unix)]
mod unix {
    use std::thread;
    use std::time::Duration;

    use super::super::relay::{UnixRelay, deliver_to, socket_key};
    use super::super::{RelayHandle, WaitError};

    // Bind at a caller-owned temp path (via a short `$TMPDIR`, not the mutable
    // global config dir) so these cases stay hermetic and off the `HOME`
    // env-var that other suites mutate in parallel.
    #[test]
    fn relay_round_trip_is_single_use() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rt.sock");
        let relay = UnixRelay::bind_path(path.clone()).expect("bind relay");

        let callback_url = "mirrorstack://callback?code=RT&state=RTSTATE".to_owned();
        let delivered = (path.clone(), callback_url.clone());
        let sender = thread::spawn(move || deliver_to(&delivered.0, &delivered.1));

        let callback = relay
            .wait(Duration::from_secs(2))
            .expect("receive callback");
        sender.join().expect("delivery thread").expect("deliver");
        assert_eq!(callback.code, "RT");
        assert_eq!(callback.state, "RTSTATE");

        drop(relay);
        assert!(!path.exists(), "socket should be removed after relay drops");
        assert!(
            deliver_to(&path, &callback_url).is_err(),
            "socket should be single-use"
        );
    }

    #[test]
    fn relay_times_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        let relay = UnixRelay::bind_path(dir.path().join("to.sock")).expect("bind relay");
        let result = relay.wait(Duration::from_millis(250));
        assert!(matches!(result, Err(WaitError::Timeout)));
    }

    #[test]
    fn socket_key_stays_within_the_af_unix_limit() {
        assert_eq!(socket_key(&"a".repeat(22)).len(), 16);
        assert_eq!(socket_key("short"), "short");
    }
}
