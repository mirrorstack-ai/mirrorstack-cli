//! Headless tests for the login transport state machine.

use std::io;
use std::time::Duration;

use mockito::{Matcher, Server};
use serde_json::json;

use super::{LoginCfg, LoginIo, run_with};
use crate::auth;
use crate::scheme::{
    Callback, Registrar, RegistrationOutcome, RelayFactory, RelayHandle, WaitError,
};

struct FakeRegistrar {
    outcome: RegistrationOutcome,
}

impl Registrar for FakeRegistrar {
    fn register(&self) -> RegistrationOutcome {
        self.outcome.clone()
    }
}

#[derive(Clone, Copy)]
enum RelayBehavior {
    GoodCallback,
    Mismatch,
    Timeout,
}

struct FakeRelayFactory {
    behavior: RelayBehavior,
}

impl RelayFactory for FakeRelayFactory {
    fn bind(&self, state: &str) -> io::Result<Box<dyn RelayHandle>> {
        Ok(Box::new(FakeRelay {
            behavior: self.behavior,
            state: state.to_string(),
        }))
    }
}

struct FakeRelay {
    behavior: RelayBehavior,
    state: String,
}

impl RelayHandle for FakeRelay {
    fn wait(&self, _timeout: Duration) -> Result<Callback, WaitError> {
        match self.behavior {
            RelayBehavior::GoodCallback => Ok(Callback {
                code: "SCHEME_CODE".into(),
                state: self.state.clone(),
            }),
            RelayBehavior::Mismatch => Ok(Callback {
                code: "x".into(),
                state: "WRONG".into(),
            }),
            RelayBehavior::Timeout => Err(WaitError::Timeout),
        }
    }
}

struct FakeIo {
    code: String,
    opened: Vec<String>,
    warns: Vec<String>,
}

impl FakeIo {
    fn new(code: &str) -> Self {
        Self {
            code: code.into(),
            opened: Vec::new(),
            warns: Vec::new(),
        }
    }
}

impl LoginIo for FakeIo {
    fn open_browser(&mut self, authorize_url: &str) {
        self.opened.push(authorize_url.into());
    }

    fn note(&mut self, _msg: &str) {}

    fn warn(&mut self, msg: &str) {
        self.warns.push(msg.into());
    }

    fn read_code(&mut self) -> anyhow::Result<String> {
        Ok(self.code.clone())
    }
}

fn cfg(server: &Server) -> LoginCfg {
    LoginCfg {
        web_base: "https://example.com".into(),
        api_base: server.url(),
        no_browser: false,
        http: reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build client"),
        wait_timeout: Duration::from_secs(1),
    }
}

fn token_mock(server: &mut Server, redirect_uri: &str, code: &str) -> mockito::Mock {
    server
        .mock("POST", "/v1/oauth/token")
        .match_body(Matcher::AllOf(vec![
            Matcher::UrlEncoded("redirect_uri".into(), redirect_uri.into()),
            Matcher::UrlEncoded("code".into(), code.into()),
        ]))
        .with_status(200)
        .with_body(
            json!({
                "access_token": "AT",
                "token_type": "Bearer",
                "expires_in": 900,
                "refresh_token": "RT"
            })
            .to_string(),
        )
        .create()
}

#[test]
fn registered_good_callback_exchanges_with_scheme() {
    let mut server = Server::new();
    let mock = token_mock(&mut server, auth::REDIRECT_URI_SCHEME, "SCHEME_CODE");
    let cfg = cfg(&server);
    let reg = FakeRegistrar {
        outcome: RegistrationOutcome::Registered,
    };
    let factory = FakeRelayFactory {
        behavior: RelayBehavior::GoodCallback,
    };
    let mut io = FakeIo::new("");

    let result = run_with(&reg, &factory, &mut io, &cfg);

    assert!(result.is_ok(), "got {result:?}");
    mock.assert();
    assert!(
        io.opened[0].contains("redirect_uri=mirrorstack%3A%2F%2Fcallback"),
        "got {}",
        io.opened[0]
    );
}

#[test]
fn registered_timeout_falls_back_to_oob() {
    let mut server = Server::new();
    let mock = token_mock(&mut server, auth::REDIRECT_URI_OOB, "OOBCODE");
    let cfg = cfg(&server);
    let reg = FakeRegistrar {
        outcome: RegistrationOutcome::Registered,
    };
    let factory = FakeRelayFactory {
        behavior: RelayBehavior::Timeout,
    };
    let mut io = FakeIo::new("OOBCODE");

    let result = run_with(&reg, &factory, &mut io, &cfg);

    assert!(result.is_ok(), "got {result:?}");
    mock.assert();
}

#[test]
fn unsupported_uses_oob() {
    let mut server = Server::new();
    let mock = token_mock(&mut server, auth::REDIRECT_URI_OOB, "OOBCODE");
    let cfg = cfg(&server);
    let reg = FakeRegistrar {
        outcome: RegistrationOutcome::Unsupported,
    };
    let factory = FakeRelayFactory {
        behavior: RelayBehavior::GoodCallback,
    };
    let mut io = FakeIo::new("OOBCODE");

    let result = run_with(&reg, &factory, &mut io, &cfg);

    assert!(result.is_ok(), "got {result:?}");
    mock.assert();
    assert!(io.warns.is_empty(), "unexpected warnings: {:?}", io.warns);
}

#[test]
fn state_mismatch_falls_back_to_oob() {
    let mut server = Server::new();
    let mock = token_mock(&mut server, auth::REDIRECT_URI_OOB, "OOBCODE");
    let cfg = cfg(&server);
    let reg = FakeRegistrar {
        outcome: RegistrationOutcome::Registered,
    };
    let factory = FakeRelayFactory {
        behavior: RelayBehavior::Mismatch,
    };
    let mut io = FakeIo::new("OOBCODE");

    let result = run_with(&reg, &factory, &mut io, &cfg);

    assert!(result.is_ok(), "got {result:?}");
    mock.assert();
    assert!(!io.warns.is_empty(), "expected a state mismatch warning");
}
