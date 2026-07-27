//! Credential selection for app deploys. Deploy grants and deploy tokens
//! deliberately never enter the persisted OAuth credential lifecycle.

use std::fmt;

use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use serde::Deserialize;
use url::Url;

use crate::api::{self, ApiError, DeployGrantError, DeployGrantInput};
use crate::commands::{DEFAULT_OIDC_AUDIENCE, ENV_OIDC_AUDIENCE, session_expired};
use crate::credentials::{self, Credentials};
use crate::http;

pub(super) const ENV_DEPLOY_TOKEN: &str = "MIRRORSTACK_TOKEN";
const ENV_ACTIONS_ID_TOKEN_REQUEST_URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const ENV_ACTIONS_ID_TOKEN_REQUEST_TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
const ENV_GITHUB_ACTIONS: &str = "GITHUB_ACTIONS";

pub(super) enum DeployAuth {
    User(Credentials),
    Grant(String),
    Token(String),
}

impl fmt::Debug for DeployAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(_) => f.write_str("User(<redacted>)"),
            Self::Grant(_) => f.write_str("Grant(<redacted>)"),
            Self::Token(_) => f.write_str("Token(<redacted>)"),
        }
    }
}

impl DeployAuth {
    /// OAuth sessions retain their one refresh attempt. App-bound deploy
    /// credentials have no refresh path and are called exactly once.
    pub(super) fn with_retry<T>(
        &mut self,
        mut call: impl FnMut(&str) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        match self {
            Self::User(creds) => credentials::with_refresh_retry(creds, call),
            Self::Grant(grant) | Self::Token(grant) => call(grant),
        }
    }

    pub(super) fn deploy_error(&self, error: ApiError) -> anyhow::Error {
        match self {
            Self::Grant(secret) => bound_credential_error(secret, true, error),
            Self::Token(secret) => bound_credential_error(secret, false, error),
            Self::User(_) => match error {
                ApiError::Unauthenticated => session_expired(),
                ApiError::Server { code, message, .. } => anyhow!("{code}: {message}"),
                other => other.into(),
            },
        }
    }
}

fn bound_credential_error(secret: &str, grant: bool, error: ApiError) -> anyhow::Error {
    match error {
        ApiError::Unauthenticated if grant => anyhow!(
            "the OIDC deploy grant expired or was revoked; re-run the workflow to obtain a new grant"
        ),
        ApiError::Unauthenticated => anyhow!(
            "MIRRORSTACK_TOKEN was rejected; it may be revoked or bound to a different app or environment. Create a new deploy token in the app's deployment settings"
        ),
        ApiError::Server { code, message, .. } => {
            anyhow!("{}: {}", redact(&code, secret), redact(&message, secret))
        }
        ApiError::Unexpected { status, body } => anyhow!(
            "api: unexpected response {status}: {}",
            redact(&body, secret)
        ),
        ApiError::Http(error) => anyhow!("api: HTTP error: {error}"),
        ApiError::Decode(error) => anyhow!("api: decode response: {error}"),
    }
}

fn redact(value: &str, secret: &str) -> String {
    if secret.is_empty() {
        value.to_string()
    } else {
        value.replace(secret, "<redacted>")
    }
}

pub(super) enum SelectedDeployAuth {
    Oidc {
        request_url: String,
        request_token: String,
    },
    Ready(DeployAuth),
}

impl fmt::Debug for SelectedDeployAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oidc { .. } => f.write_str("Oidc(<redacted>)"),
            Self::Ready(auth) => f.debug_tuple("Ready").field(auth).finish(),
        }
    }
}

/// Resolve credential precedence without doing network I/O. In particular,
/// choosing OIDC returns only its runtime inputs, so an exchange failure
/// has no code path back to either the env token or stored credentials.
pub(super) fn select_deploy_auth(
    oidc: bool,
    mut env_lookup: impl FnMut(&str) -> Option<String>,
    credential_loader: impl FnOnce() -> Result<Credentials>,
) -> Result<SelectedDeployAuth> {
    if oidc {
        let request_url = nonempty_env(&mut env_lookup, ENV_ACTIONS_ID_TOKEN_REQUEST_URL);
        let request_token = nonempty_env(&mut env_lookup, ENV_ACTIONS_ID_TOKEN_REQUEST_TOKEN);
        if request_url.is_none() || request_token.is_none() {
            let mut missing = Vec::new();
            if request_url.is_none() {
                missing.push(ENV_ACTIONS_ID_TOKEN_REQUEST_URL);
            }
            if request_token.is_none() {
                missing.push(ENV_ACTIONS_ID_TOKEN_REQUEST_TOKEN);
            }
            let outside_actions = request_url.is_none()
                && request_token.is_none()
                && nonempty_env(&mut env_lookup, ENV_GITHUB_ACTIONS).is_none();
            let mut message = format!(
                "--oidc requires {}. Add this to the workflow job:\npermissions:\n  id-token: write",
                missing.join(" and ")
            );
            if outside_actions {
                message.push_str("\n--oidc only works inside GitHub Actions.");
            }
            return Err(anyhow!(message));
        }
        return Ok(SelectedDeployAuth::Oidc {
            request_url: request_url.expect("checked"),
            request_token: request_token.expect("checked"),
        });
    }

    if let Some(token) = nonempty_env(&mut env_lookup, ENV_DEPLOY_TOKEN) {
        return Ok(SelectedDeployAuth::Ready(DeployAuth::Token(token)));
    }

    Ok(SelectedDeployAuth::Ready(DeployAuth::User(
        credential_loader()?,
    )))
}

fn nonempty_env(env_lookup: &mut impl FnMut(&str) -> Option<String>, name: &str) -> Option<String> {
    env_lookup(name).filter(|value| !value.trim().is_empty())
}

/// The audience is what stops a token minted for someone else being replayed
/// at the exchange, so an override that erases that separation is refused here
/// rather than silently requested from GitHub. The two dangerous values are
/// exactly the ones someone might reach for: GitHub's own default audience
/// (`https://github.com/<owner>`, which every repo under that owner gets for
/// free) and the AWS one.
pub(super) fn resolve_oidc_audience(
    mut env_lookup: impl FnMut(&str) -> Option<String>,
) -> Result<String> {
    let audience = nonempty_env(&mut env_lookup, ENV_OIDC_AUDIENCE)
        .unwrap_or_else(|| DEFAULT_OIDC_AUDIENCE.into());
    let lowered = audience.to_ascii_lowercase();
    if lowered == "sts.amazonaws.com" || lowered.starts_with("https://github.com/") {
        return Err(anyhow!(
            "{ENV_OIDC_AUDIENCE}={audience} is not MirrorStack-specific — \
             GitHub's default audience and sts.amazonaws.com are shared with \
             other consumers, so a token minted for them could be replayed. \
             Unset it to use the default `{DEFAULT_OIDC_AUDIENCE}`."
        ));
    }
    Ok(audience)
}

#[derive(Deserialize)]
struct ActionsIdToken {
    value: String,
}

pub(super) fn request_actions_id_token(
    client: &Client,
    request_url: &str,
    request_token: &str,
    audience: &str,
) -> Result<String> {
    let mut url = Url::parse(request_url).context("invalid ACTIONS_ID_TOKEN_REQUEST_URL")?;
    url.query_pairs_mut().append_pair("audience", audience);

    let resp = client
        .get(url)
        .bearer_auth(request_token)
        .header("Accept", "application/json")
        .send()
        .map_err(|_| anyhow!("GitHub Actions OIDC token request failed"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!(
            "GitHub Actions OIDC token request failed with HTTP {}; verify the workflow job has `permissions:\n  id-token: write`",
            status.as_u16()
        ));
    }
    let body = http::read_capped(resp).context("read GitHub Actions OIDC response")?;
    let response: ActionsIdToken =
        serde_json::from_slice(&body).context("decode GitHub Actions OIDC response")?;
    if response.value.trim().is_empty() {
        return Err(anyhow!(
            "GitHub Actions OIDC token response did not contain a token"
        ));
    }
    Ok(response.value)
}

pub(super) fn exchange_oidc(
    client: &Client,
    apps_base: &str,
    request_url: &str,
    request_token: &str,
    audience: &str,
    app: &str,
    env: &str,
) -> Result<api::DeployGrant> {
    let jwt = request_actions_id_token(client, request_url, request_token, audience)?;
    api::exchange_deploy_grant(
        client,
        apps_base,
        &DeployGrantInput {
            token: &jwt,
            app,
            env,
        },
    )
    .map_err(|error| exchange_error(app, &jwt, error))
}

fn exchange_error(app: &str, jwt: &str, error: DeployGrantError) -> anyhow::Error {
    match error {
        DeployGrantError::BindingPending {
            sub, approval_url, ..
        } => anyhow!(
            "This repo is not yet authorised to deploy `{app}`. A pending binding was created for `{}`. Approve it at {}, then re-run.",
            redact(&sub, jwt),
            redact(&approval_url, jwt)
        ),
        DeployGrantError::BindingRevoked { .. } => anyhow!(
            "The deploy binding for `{app}` was revoked and must be re-approved in the app's deployment settings."
        ),
        DeployGrantError::Server { code, message, .. } if code == "invalid_token" => anyhow!(
            "OIDC deploy-grant exchange failed: {}: {}. Set {} to match the server's configured audience.",
            redact(&code, jwt),
            redact(&message, jwt),
            ENV_OIDC_AUDIENCE
        ),
        DeployGrantError::Server { code, message, .. } => anyhow!(
            "OIDC deploy-grant exchange failed: {}: {}",
            redact(&code, jwt),
            redact(&message, jwt)
        ),
        DeployGrantError::Unexpected { status } => {
            anyhow!("OIDC deploy-grant exchange returned HTTP {status}")
        }
        DeployGrantError::Http(_) => anyhow!("OIDC deploy-grant request failed"),
        DeployGrantError::Io(_) => anyhow!("OIDC deploy-grant response could not be read"),
        DeployGrantError::Decode(_) => anyhow!("OIDC deploy-grant response was invalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use mockito::{Matcher, Server};
    use serde_json::json;

    fn stored() -> Credentials {
        Credentials {
            access_token: "stored-access".into(),
            refresh_token: "stored-refresh".into(),
            expires_at: SystemTime::now() + Duration::from_secs(900),
        }
    }

    #[test]
    fn credential_precedence_and_empty_token() {
        let loads = Cell::new(0);
        let selected = select_deploy_auth(
            true,
            |name| match name {
                ENV_ACTIONS_ID_TOKEN_REQUEST_URL => Some("https://actions.example/token".into()),
                ENV_ACTIONS_ID_TOKEN_REQUEST_TOKEN => Some("runtime-secret".into()),
                ENV_DEPLOY_TOKEN => Some("deploy-secret".into()),
                _ => None,
            },
            || {
                loads.set(loads.get() + 1);
                Ok(stored())
            },
        )
        .expect("oidc selected");
        assert!(matches!(selected, SelectedDeployAuth::Oidc { .. }));
        assert_eq!(loads.get(), 0, "OIDC must not load stored credentials");

        let selected = select_deploy_auth(
            false,
            |name| (name == ENV_DEPLOY_TOKEN).then(|| "deploy-secret".into()),
            || {
                loads.set(loads.get() + 1);
                Ok(stored())
            },
        )
        .expect("token selected");
        assert!(matches!(
            selected,
            SelectedDeployAuth::Ready(DeployAuth::Token(_))
        ));
        assert_eq!(loads.get(), 0, "env token must not load stored credentials");

        let selected = select_deploy_auth(
            false,
            |name| (name == ENV_DEPLOY_TOKEN).then(|| " \t ".into()),
            || {
                loads.set(loads.get() + 1);
                Ok(stored())
            },
        )
        .expect("stored selected");
        assert!(matches!(
            selected,
            SelectedDeployAuth::Ready(DeployAuth::User(_))
        ));
        assert_eq!(loads.get(), 1);
    }

    #[test]
    fn grant_and_token_never_retry_a_rejected_call() {
        for mut auth in [
            DeployAuth::Grant("grant-secret".into()),
            DeployAuth::Token("token-secret".into()),
        ] {
            let mut attempts = 0;
            let error = auth
                .with_retry::<()>(|_| {
                    attempts += 1;
                    Err(ApiError::Unauthenticated)
                })
                .expect_err("rejected");
            assert!(matches!(error, ApiError::Unauthenticated));
            assert_eq!(attempts, 1);

            let message = auth.deploy_error(error).to_string();
            assert!(!message.contains("mirrorstack login"), "{message}");
            match auth {
                DeployAuth::Grant(_) => assert!(message.contains("re-run"), "{message}"),
                DeployAuth::Token(_) => {
                    assert!(message.contains("deployment settings"), "{message}")
                }
                DeployAuth::User(_) => unreachable!(),
            }
        }
    }

    #[test]
    fn presented_credentials_are_redacted_from_server_errors() {
        let grant = DeployAuth::Grant("grant-secret".into());
        let message = grant
            .deploy_error(ApiError::Unexpected {
                status: 500,
                body: "backend echoed grant-secret".into(),
            })
            .to_string();
        assert!(!message.contains("grant-secret"), "{message}");
        assert!(message.contains("<redacted>"), "{message}");

        let token = DeployAuth::Token("token-secret".into());
        let message = token
            .deploy_error(ApiError::Server {
                status: 403,
                code: "token-secret".into(),
                message: "backend echoed token-secret".into(),
            })
            .to_string();
        assert!(!message.contains("token-secret"), "{message}");

        let message = exchange_error(
            "company",
            "github-jwt",
            DeployGrantError::Server {
                status: 401,
                code: "invalid_token".into(),
                message: "backend echoed github-jwt".into(),
            },
        )
        .to_string();
        assert!(!message.contains("github-jwt"), "{message}");

        let message = exchange_error(
            "company",
            "github-jwt",
            DeployGrantError::BindingRevoked {
                message: "revoked".into(),
            },
        )
        .to_string();
        assert!(message.contains("revoked"), "{message}");
        assert!(message.contains("re-approved"), "{message}");
        assert!(message.contains("deployment settings"), "{message}");
    }

    #[test]
    fn missing_oidc_runtime_fails_before_http() {
        let error = select_deploy_auth(
            true,
            |name| {
                (name == ENV_ACTIONS_ID_TOKEN_REQUEST_URL)
                    .then(|| "https://actions.invalid/must-not-be-called".into())
            },
            || Ok(stored()),
        )
        .expect_err("missing runtime token");
        let message = error.to_string();
        assert!(message.contains("permissions:"), "{message}");
        assert!(message.contains("id-token: write"), "{message}");
        assert!(
            message.contains(ENV_ACTIONS_ID_TOKEN_REQUEST_TOKEN),
            "{message}"
        );

        let error = select_deploy_auth(true, |_| None, || Ok(stored()))
            .expect_err("outside GitHub Actions");
        assert!(
            error
                .to_string()
                .contains("--oidc only works inside GitHub Actions"),
            "{error}"
        );
    }

    #[test]
    fn oidc_audience_override_and_default_are_requested() {
        for (configured, expected) in [
            (Some("custom-aud"), "custom-aud"),
            (None, DEFAULT_OIDC_AUDIENCE),
        ] {
            let audience = resolve_oidc_audience(|_| configured.map(str::to_owned)).unwrap();
            let mut actions = Server::new();
            let request = actions
                .mock("GET", "/token")
                .match_query(Matcher::UrlEncoded("audience".into(), expected.into()))
                .match_header("authorization", "Bearer runtime-bearer")
                .with_status(200)
                .with_body(json!({"value": "github-jwt"}).to_string())
                .create();

            let jwt = request_actions_id_token(
                &http::client(Duration::from_secs(15)).unwrap(),
                &format!("{}/token", actions.url()),
                "runtime-bearer",
                &audience,
            )
            .expect("Actions ID token");
            assert_eq!(jwt, "github-jwt");
            request.assert();
        }

        for empty in ["", " \t "] {
            assert_eq!(
                resolve_oidc_audience(|_| Some(empty.into())).unwrap(),
                DEFAULT_OIDC_AUDIENCE
            );
        }
    }

    /// An audience shared with other consumers is not domain separation: a
    /// token minted for GitHub's default audience or for AWS could be replayed
    /// at the exchange. Refuse before asking GitHub to mint one.
    #[test]
    fn oidc_audience_rejects_non_separated_overrides() {
        for bad in [
            "sts.amazonaws.com",
            "https://github.com/mirrorstack-ai",
            "HTTPS://GitHub.com/acme",
        ] {
            let error = resolve_oidc_audience(|_| Some(bad.into()))
                .expect_err("expected rejection")
                .to_string();
            assert!(error.contains(ENV_OIDC_AUDIENCE), "{error}");
            assert!(error.contains(DEFAULT_OIDC_AUDIENCE), "{error}");
        }
        for good in [
            "mirrorstack",
            "mirrorstack-staging",
            "https://api.mirrorstack.ai",
        ] {
            assert_eq!(resolve_oidc_audience(|_| Some(good.into())).unwrap(), good);
        }
    }

    #[test]
    fn invalid_token_diagnostic_names_audience_override() {
        let message = exchange_error(
            "company",
            "github-jwt",
            DeployGrantError::Server {
                status: 401,
                code: "invalid_token".into(),
                message: "audience mismatch".into(),
            },
        )
        .to_string();
        assert!(
            message.contains("invalid_token: audience mismatch"),
            "{message}"
        );
        assert!(message.contains(ENV_OIDC_AUDIENCE), "{message}");
    }

    #[test]
    fn oidc_requests_and_binding_diagnostic_match_contract_without_fallback() {
        let mut actions = Server::new();
        let actions_request = actions
            .mock("GET", "/token")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded("existing".into(), "1".into()),
                Matcher::UrlEncoded("audience".into(), "mirrorstack".into()),
            ]))
            .match_header("authorization", "Bearer runtime-bearer")
            .with_status(200)
            .with_body(json!({"value": "github-jwt"}).to_string())
            .create();

        let sub = "repo:org/repo:ref:refs/heads/main";
        let approval_url = "https://apps.mirrorstack.ai/apps/app-1/settings/deployment";
        let mut apps = Server::new();
        let exchange = apps
            .mock("POST", "/v1/oidc/deploy-grant")
            .match_header("authorization", Matcher::Missing)
            .match_body(Matcher::Json(json!({
                "token": "github-jwt",
                "app": "company",
                "env": "prod"
            })))
            .with_status(403)
            .with_body(
                json!({
                    "code": "binding_pending",
                    "message": "approval required",
                    "sub": sub,
                    "approval_url": approval_url
                })
                .to_string(),
            )
            .create();
        let stored_bearer = apps
            .mock("GET", "/v1/apps/company")
            .match_header("authorization", "Bearer stored-access")
            .expect(0)
            .create();

        let loads = Cell::new(0);
        let selected = select_deploy_auth(
            true,
            |name| match name {
                ENV_ACTIONS_ID_TOKEN_REQUEST_URL => {
                    Some(format!("{}/token?existing=1", actions.url()))
                }
                ENV_ACTIONS_ID_TOKEN_REQUEST_TOKEN => Some("runtime-bearer".into()),
                ENV_DEPLOY_TOKEN => Some("deploy-secret".into()),
                _ => None,
            },
            || {
                loads.set(loads.get() + 1);
                Ok(stored())
            },
        )
        .expect("OIDC selected");
        let SelectedDeployAuth::Oidc {
            request_url,
            request_token,
        } = selected
        else {
            panic!("OIDC must win");
        };

        let error = exchange_oidc(
            &http::client(Duration::from_secs(15)).unwrap(),
            &apps.url(),
            &request_url,
            &request_token,
            DEFAULT_OIDC_AUDIENCE,
            "company",
            "prod",
        )
        .expect_err("binding pending");
        let message = error.to_string();
        assert!(message.contains(sub), "{message}");
        assert!(message.contains(approval_url), "{message}");
        assert!(!message.contains("401"), "{message}");
        assert!(!message.contains("mirrorstack login"), "{message}");
        assert_eq!(loads.get(), 0, "failed exchange must not load OAuth");
        actions_request.assert();
        exchange.assert();
        stored_bearer.assert();
    }

    #[test]
    fn grant_and_token_http_401_are_single_attempt_and_actionable() {
        let mut server = Server::new();
        let grant_call = server
            .mock("POST", "/v1/apps/app-1/deploys")
            .match_header("authorization", "Bearer grant-secret")
            .with_status(401)
            .expect(1)
            .create();
        let token_call = server
            .mock("POST", "/v1/apps/app-1/deploys")
            .match_header("authorization", "Bearer token-secret")
            .with_status(401)
            .expect(1)
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let input = api::CreateAppDeployInput {
            env: "prod",
            note: None,
            runtime: None,
            files: &[],
        };

        let mut grant = DeployAuth::Grant("grant-secret".into());
        let error = grant
            .with_retry(|credential| {
                api::create_app_deploy(&client, &server.url(), credential, "app-1", &input)
            })
            .expect_err("grant rejected");
        let message = grant.deploy_error(error).to_string();
        assert!(message.contains("expired or was revoked"), "{message}");
        assert!(message.contains("re-run"), "{message}");

        let mut token = DeployAuth::Token("token-secret".into());
        let error = token
            .with_retry(|credential| {
                api::create_app_deploy(&client, &server.url(), credential, "app-1", &input)
            })
            .expect_err("token rejected");
        let message = token.deploy_error(error).to_string();
        assert!(message.contains("MIRRORSTACK_TOKEN"), "{message}");
        assert!(message.contains("deployment settings"), "{message}");
        grant_call.assert();
        token_call.assert();
    }

    struct EnvRestore {
        name: &'static str,
        previous: Option<OsString>,
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.name, value),
                    None => std::env::remove_var(self.name),
                }
            }
        }
    }

    fn redirect_config(path: &Path) -> EnvRestore {
        #[cfg(target_os = "macos")]
        let name = "HOME";
        #[cfg(target_os = "windows")]
        let name = "APPDATA";
        #[cfg(all(unix, not(target_os = "macos")))]
        let name = "XDG_CONFIG_HOME";
        let previous = std::env::var_os(name);
        unsafe { std::env::set_var(name, path) };
        EnvRestore { name, previous }
    }

    #[test]
    fn exchanged_grant_never_changes_credentials_file() {
        let _env = credentials::TEST_ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = tempfile::tempdir().expect("config tempdir");
        let _restore = redirect_config(config.path());

        let mut actions = Server::new();
        let actions_request = actions
            .mock("GET", "/token")
            .match_query(Matcher::UrlEncoded("audience".into(), "mirrorstack".into()))
            .match_header("authorization", "Bearer runtime-bearer")
            .with_status(200)
            .with_body(json!({"value": "github-jwt"}).to_string())
            .expect(2)
            .create();
        let mut apps = Server::new();
        let exchange = apps
            .mock("POST", "/v1/oidc/deploy-grant")
            .match_header("authorization", Matcher::Missing)
            .with_status(200)
            .with_body(
                json!({
                    "grant": "grant-secret",
                    "expires_at": "2026-07-27T05:30:00Z",
                    "app_id": "app-1",
                    "env": "prod"
                })
                .to_string(),
            )
            .expect(2)
            .create();
        let client = http::client(Duration::from_secs(15)).unwrap();
        let request_url = format!("{}/token", actions.url());

        let grant = exchange_oidc(
            &client,
            &apps.url(),
            &request_url,
            "runtime-bearer",
            DEFAULT_OIDC_AUDIENCE,
            "company",
            "prod",
        )
        .expect("exchange without credential file");
        assert_eq!(grant.grant, "grant-secret");
        let credentials_path = credentials::path().expect("credentials path");
        assert!(
            !credentials_path.exists(),
            "grant exchange created credentials.json"
        );

        fs::create_dir_all(credentials_path.parent().unwrap()).unwrap();
        let original = b"{\"sentinel\":\"byte-identical\"}\n";
        fs::write(&credentials_path, original).unwrap();
        exchange_oidc(
            &client,
            &apps.url(),
            &request_url,
            "runtime-bearer",
            DEFAULT_OIDC_AUDIENCE,
            "company",
            "prod",
        )
        .expect("exchange with credential file");
        assert_eq!(fs::read(&credentials_path).unwrap(), original);
        actions_request.assert();
        exchange.assert();
    }
}
