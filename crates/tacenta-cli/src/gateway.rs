//! A thin client for `tacenta-gateway`'s key-management API.
//!
//! Unlike the four TCP services `try` talks to, the gateway is plain
//! HTTPS/JSON (decision record 0046), reached at `{host}/v1/...` in
//! production — the front proxy routes `/v1/*` to the gateway on the same domain, so
//! there is no port to know. The same gateway publishes the service document
//! `try` and `chat` discover the four services from (decision 0090),
//! which is why every command resolves the gateway's base URL the same way.
//! Every key-management call re-authenticates with the tenant's email and
//! password (`lib.rs`'s own module doc: "there is no tenant session yet").

use serde::{Deserialize, Serialize};

/// The gateway's base URL, the one place the environment is read for it:
/// `TACENTA_GATEWAY_URL` verbatim if set (local dev), otherwise
/// `https://{TACENTA_HOST}`,
/// default `tacenta.com`. Setting both is refused rather than resolved by
/// precedence: one of them would be silently ignored, and the one ignored
/// would be the one typed last. Resolved once per command, then threaded
/// through explicitly rather than read again from inside `post`, so tests can
/// point the same request functions at a real local server without touching
/// process environment.
pub fn resolve_base_url() -> Result<String, String> {
    let url = std::env::var("TACENTA_GATEWAY_URL").ok();
    let host = std::env::var("TACENTA_HOST").ok();
    match (url, host) {
        (Some(u), Some(h)) => Err(format!(
            "both TACENTA_GATEWAY_URL ({u}) and TACENTA_HOST ({h}) are set; unset one"
        )),
        (Some(u), None) => Ok(u.trim_end_matches('/').to_owned()),
        (None, host) => Ok(format!(
            "https://{}",
            host.unwrap_or_else(|| "tacenta.com".to_owned())
        )),
    }
}

#[derive(Serialize)]
struct CreateKeyReq<'a> {
    email: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
}

#[derive(Serialize)]
struct KeyAuthReq<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RevokeKeyReq<'a> {
    email: &'a str,
    password: &'a str,
    prefix: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct KeyCreated {
    pub api_key: String,
    pub key_prefix: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyList {
    pub keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
pub struct KeyEntry {
    pub prefix: String,
    pub label: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct KeyRevoked {
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
}

/// Map a coarse gateway error reason to a short, user-facing message. Mirrors
/// `friendly()`'s treatment of `tacenta_client::Error` below in `main.rs`: no
/// raw status codes or JSON at the user.
fn friendly_reason(reason: &str) -> String {
    match reason {
        "invalid_credentials" => "wrong email or password".to_owned(),
        "rate_limited" => "too many attempts — wait a moment and try again".to_owned(),
        "server_error" => "the server had a problem. try again shortly".to_owned(),
        other => other.replace('_', " "),
    }
}

/// Send `body` to `path` and decode a `200`/`201` JSON response as `T`;
/// anything else is turned into a friendly error from the response's coarse
/// `{"error": "..."}` reason, or a plain transport error if the request never
/// reached the server.
async fn post<Req: Serialize, Res: for<'de> Deserialize<'de>>(
    base: &str,
    path: &str,
    body: &Req,
) -> Result<Res, String> {
    let url = format!("{base}{path}");
    let res = reqwest::Client::new()
        .post(&url)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("could not reach {url}: {e}"))?;

    if res.status().is_success() {
        res.json::<Res>()
            .await
            .map_err(|e| format!("unexpected response from {url}: {e}"))
    } else {
        let status = res.status();
        match res.json::<ErrorBody>().await {
            Ok(body) => Err(friendly_reason(&body.error)),
            Err(_) => Err(format!("{url} returned {status}")),
        }
    }
}

pub async fn create_key(
    base: &str,
    email: &str,
    password: &str,
    label: Option<&str>,
) -> Result<KeyCreated, String> {
    post(
        base,
        "/v1/tenants/keys/create",
        &CreateKeyReq {
            email,
            password,
            label,
        },
    )
    .await
}

pub async fn list_keys(base: &str, email: &str, password: &str) -> Result<KeyList, String> {
    post(
        base,
        "/v1/tenants/keys/list",
        &KeyAuthReq { email, password },
    )
    .await
}

pub async fn revoke_key(
    base: &str,
    email: &str,
    password: &str,
    prefix: &str,
) -> Result<KeyRevoked, String> {
    post(
        base,
        "/v1/tenants/keys/revoke",
        &RevokeKeyReq {
            email,
            password,
            prefix,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use tacenta_accounts::{AccountStore, Accounts};
    use tacenta_gateway::GatewayState;

    /// Start a real gateway on an ephemeral loopback port and return its base
    /// URL. A real listener rather than an in-process `tower::oneshot`, since
    /// this module's whole job is a real HTTP round trip through `reqwest`.
    async fn spawn_gateway() -> String {
        let state = GatewayState::new(Arc::new(AccountStore::memory(Accounts::new())));
        let app = tacenta_gateway::app(state, &[]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// The gateway writes the service document and the client reads it: the
    /// two structs live in different crates, so this is the check that they
    /// agree on the wire (decision 0090).
    #[tokio::test]
    async fn the_client_reads_the_gateways_service_document() {
        let base = spawn_gateway().await;
        let tenant = tacenta_client::Tacenta::connect_via(
            "tct_test",
            &format!("{base}/.well-known/tacenta"),
            &tacenta_client::ClientTls::web_pki(),
        )
        .await
        .unwrap();
        assert!(
            !tenant.is_tls(),
            "the default document is a plaintext loopback server"
        );
        assert_eq!(tenant.server_name(), None);
        assert_eq!(
            tenant.endpoints().accounts,
            "127.0.0.1:4722".parse().unwrap()
        );
        assert_eq!(
            tenant.endpoints().provisioning,
            "127.0.0.1:4723".parse().unwrap()
        );
    }

    #[tokio::test]
    async fn creates_lists_and_revokes_a_key() {
        let base = spawn_gateway().await;
        let client = reqwest::Client::new();
        let signup = client
            .post(format!("{base}/v1/tenants"))
            .json(&serde_json::json!({
                "username": "acme",
                "email": "admin@acme.example",
                "password": "correct horse",
            }))
            .send()
            .await
            .unwrap();
        assert!(signup.status().is_success());

        let created = create_key(&base, "admin@acme.example", "correct horse", Some("ci"))
            .await
            .unwrap();
        assert!(created.api_key.starts_with("tct_"));
        assert!(!created.key_prefix.is_empty());

        let listed = list_keys(&base, "admin@acme.example", "correct horse")
            .await
            .unwrap();
        assert_eq!(listed.keys.len(), 2, "the signup key plus the new one");
        assert!(listed.keys.iter().any(|k| k.prefix == created.key_prefix));

        let revoked = revoke_key(
            &base,
            "admin@acme.example",
            "correct horse",
            &created.key_prefix,
        )
        .await
        .unwrap();
        assert!(revoked.revoked);

        let listed = list_keys(&base, "admin@acme.example", "correct horse")
            .await
            .unwrap();
        assert_eq!(listed.keys.len(), 1, "the revoked key is gone");
    }

    #[tokio::test]
    async fn a_wrong_password_is_a_friendly_error() {
        let base = spawn_gateway().await;
        let client = reqwest::Client::new();
        client
            .post(format!("{base}/v1/tenants"))
            .json(&serde_json::json!({
                "username": "acme",
                "email": "admin@acme.example",
                "password": "correct horse",
            }))
            .send()
            .await
            .unwrap();

        let err = list_keys(&base, "admin@acme.example", "wrong")
            .await
            .unwrap_err();
        assert_eq!(err, "wrong email or password");
    }
}
