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

    use super::super::relay::{UnixRelay, deliver_to, is_nonce, socket_key};
    use super::super::{RelayHandle, WaitError};

    // Bind at a caller-owned temp path (via a short `$TMPDIR`, not the mutable
    // global config dir) so these cases stay hermetic and off the `HOME`
    // env-var that other suites mutate in parallel.
    #[test]
    fn relay_round_trip_is_single_use() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rt.sock");
        let relay = UnixRelay::bind_path(path.clone(), "RTSTATE").expect("bind relay");

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
        let relay = UnixRelay::bind_path(dir.path().join("to.sock"), "TOSTATE").expect("bind relay");
        let result = relay.wait(Duration::from_millis(250));
        assert!(matches!(result, Err(WaitError::Timeout)));
    }

    // A same-UID peer that connects with the wrong `state` (or none) must not
    // be able to end the attempt: it is ignored and the relay waits out its
    // deadline for the authentic callback.
    #[test]
    fn relay_ignores_unauthenticated_peer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auth.sock");
        let relay = UnixRelay::bind_path(path.clone(), "REALSTATE").expect("bind relay");

        // Wrong state, and an error callback with no state — both must be
        // ignored rather than aborting or short-circuiting the wait.
        let _ = deliver_to(&path, "mirrorstack://callback?code=SPOOF&state=WRONG");
        let _ = deliver_to(&path, "mirrorstack://callback?error=access_denied");

        let result = relay.wait(Duration::from_millis(400));
        assert!(
            matches!(result, Err(WaitError::Timeout)),
            "unauthenticated peers must not end the wait: {result:?}"
        );
    }

    #[test]
    fn socket_key_stays_within_the_af_unix_limit() {
        assert_eq!(socket_key(&"a".repeat(22)).len(), 16);
        assert_eq!(socket_key("short"), "short");
    }

    // A malicious `state` (any web page can invoke the registered scheme
    // handler) must not escape the per-user oauth dir when turned into a
    // socket filename.
    #[test]
    fn nonce_validation_rejects_path_escape() {
        assert!(is_nonce("abcDEF123-_"));
        assert!(!is_nonce("/run/docker"));
        assert!(!is_nonce("../../../../tmp/evil"));
        assert!(!is_nonce("has space"));
        assert!(!is_nonce(""));
        assert!(!is_nonce(&"a".repeat(200)));
    }
}
