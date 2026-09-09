//! The echo bot — a first-class reference agent.
//!
//! An [`EchoBot`] is an ordinary [`Client`] that receives messages and sends
//! each straight back to its sender. It exists for three reasons, none of
//! them an afterthought:
//!
//! - **A live end-to-end proof.** Anyone with a client can message the bot
//!   and watch the same bytes come back, exercising the whole stack —
//!   directory lookup, session establishment, encrypt, relay, decrypt — in
//!   one round trip.
//! - **The canonical agent.** It is the smallest complete agent identity: it
//!   connects, holds a durable identity, and acts on messages.
//! - **A persistent peer.** It keeps its identity across restarts
//!   ([`connect_with_identity`](EchoBot::connect_with_identity)), so a user
//!   who has messaged and verified the bot still has the same bound key after
//!   the bot restarts — the first real consumer of client identity
//!   persistence (decision record 0031).
//!
//! ```no_run
//! # async fn f() -> tacenta_client::Result<()> {
//! use tacenta_echo::EchoBot;
//! use tacenta_client::Config;
//! let mut bot = EchoBot::connect(&Config {
//!     directory: "127.0.0.1:4720".parse().unwrap(),
//!     relay: "127.0.0.1:4721".parse().unwrap(),
//!     user: "+echo".into(),
//!     device: 1,
//! })
//! .await?;
//! bot.serve().await
//! # }
//! ```

use tacenta_client::{AccountConfig, Client, ClientTls, Config, DefaultClient, DeviceAddr, Result};

/// An echo bot: a client that sends every message it receives back to whoever
/// sent it.
pub struct EchoBot {
    client: Client,
}

impl EchoBot {
    /// Connect a bot with a fresh identity — first-run enrolment. Save
    /// [`export_identity`](EchoBot::export_identity) and use
    /// [`connect_with_identity`](EchoBot::connect_with_identity) on later runs
    /// so the bot keeps the same address and bound key.
    pub async fn connect(config: &Config) -> Result<EchoBot> {
        Ok(EchoBot {
            client: DefaultClient::connect(config).await?,
        })
    }

    /// Connect a bot under a saved identity, so it keeps the same address and
    /// bound key across restarts and peers see no key-fingerprint change.
    pub async fn connect_with_identity(config: &Config, identity: &[u8]) -> Result<EchoBot> {
        Ok(EchoBot {
            client: DefaultClient::connect_with_identity(config, identity).await?,
        })
    }

    /// Sign in and provision the bot as an account user, so it runs under a
    /// tenant handle (e.g. `acme/echo`) and other users in the tenant can find
    /// it by name and add it as a contact. The account (a user named `echo`,
    /// say) must already exist; see [`DefaultClient::sign_up`].
    pub async fn sign_in(config: &AccountConfig) -> Result<EchoBot> {
        Ok(EchoBot {
            client: DefaultClient::sign_in(config).await?,
        })
    }

    /// Like [`sign_in`](EchoBot::sign_in), but over TLS to a server presenting
    /// `server_name` — the bot's path when the server serves its TCP services
    /// over TLS.
    pub async fn sign_in_tls(
        config: &AccountConfig,
        server_name: &str,
        tls: &ClientTls,
    ) -> Result<EchoBot> {
        Ok(EchoBot {
            client: DefaultClient::sign_in_tls(config, server_name, tls).await?,
        })
    }

    /// Sign in and provision the bot under a saved device identity, keeping its
    /// bound key across restarts (the account sibling of
    /// [`connect_with_identity`](EchoBot::connect_with_identity)).
    pub async fn sign_in_with_identity(config: &AccountConfig, identity: &[u8]) -> Result<EchoBot> {
        Ok(EchoBot {
            client: Client::sign_in_with_identity(config, identity).await?,
        })
    }

    /// The bot's address — where peers send to reach it.
    pub fn address(&self) -> &DeviceAddr {
        self.client.address()
    }

    /// The bot's identity secret, to persist so it can reconnect under the
    /// same identity via
    /// [`connect_with_identity`](EchoBot::connect_with_identity). Carries a
    /// private key; store it as a secret.
    pub fn export_identity(&self) -> Vec<u8> {
        self.client.export_identity()
    }

    /// The bot's full resumable state — identity *and* live sessions — to
    /// persist so it can restart mid-conversation via
    /// [`connect_with_state`](EchoBot::connect_with_state) without dropping
    /// messages a peer sent while it was down (decision record 0051). Carries
    /// session secrets and a private key; store it as a secret.
    pub async fn export_state(&self) -> Result<Vec<u8>> {
        self.client.export_state().await
    }

    /// Connect a bot from a saved [`export_state`](EchoBot::export_state)
    /// blob, resuming its sessions so a restart loses no in-flight messages.
    pub async fn connect_with_state(config: &Config, state: &[u8]) -> Result<EchoBot> {
        Ok(EchoBot {
            client: DefaultClient::connect_with_state(config, state).await?,
        })
    }

    /// Sign in a bot from a saved [`export_state`](EchoBot::export_state)
    /// blob over TLS (the account/hosted path), resuming its sessions.
    pub async fn sign_in_with_state_tls(
        config: &AccountConfig,
        server_name: &str,
        tls: &ClientTls,
        state: &[u8],
    ) -> Result<EchoBot> {
        Ok(EchoBot {
            client: DefaultClient::sign_in_with_state_tls(config, server_name, tls, state).await?,
        })
    }

    /// Wait for the next batch of mail, echo each message back to its sender,
    /// and return how many were echoed. One step of [`serve`](EchoBot::serve),
    /// exposed so a caller (or a test) can drive the bot one batch at a time.
    pub async fn serve_once(&mut self) -> Result<usize> {
        let messages = self.client.receive().await?;
        let echoed = messages.len();
        for message in messages {
            self.client.send(&message.from, &message.plaintext).await?;
        }
        Ok(echoed)
    }

    /// Echo forever, one batch at a time. The client reconnects with
    /// bounded backoff when its connection drops and drains any backlog
    /// that queued in the meantime, so the bot rides out a server restart
    /// on its own; this returns only when reconnection has given up.
    pub async fn serve(&mut self) -> Result<()> {
        loop {
            self.serve_once().await?;
        }
    }
}
