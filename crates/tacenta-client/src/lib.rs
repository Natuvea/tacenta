//! The high-level Tacenta client.
//!
//! One [`Client`] wraps everything a caller would otherwise orchestrate by
//! hand — an identity and its provider session store, a directory connection, an
//! authenticated relay connection, and per-peer sessions — behind
//! [`connect`](Client::connect), [`send`](Client::send), and
//! [`receive`](Client::receive) (or [`inbound`](Client::inbound), the same
//! one message at a time). This is the surface the platform bindings
//! (UniFFI / wasm) export.
//!
//! An app starts one layer up, at the tenant handle (decision 0090):
//! [`Tacenta::connect`] takes an API key and a server name, fetches the
//! server's service document, and hands out signed-in clients through
//! [`Tacenta::sign_up`] and [`Tacenta::sign_in`], so no app carries a host or
//! a port. The [`Config`]-based constructors below are the layer under that:
//! explicit addresses, for a test or a deployment that already knows them.
//!
//! ```no_run
//! # async fn f() -> Result<(), tacenta_client::Error> {
//! use tacenta_client::Tacenta;
//! let tenant = Tacenta::connect("tct_your_api_key").await?;
//! tenant.sign_up("alice", "correct horse").await?;
//! let mut alice = tenant.sign_in("alice", "correct horse").await?;
//! let to_bob = alice.find("bob").await?.expect("bob signed up");
//! alice.send(&to_bob.address, b"hello").await?;
//! # Ok(()) }
//! ```
//!
//! With explicit addresses:
//!
//! ```no_run
//! # async fn f() -> Result<(), tacenta_client::Error> {
//! use tacenta_client::{Config, DefaultClient, DeviceAddr};
//! let mut alice = DefaultClient::connect(&Config {
//!     directory: "127.0.0.1:4720".parse().unwrap(),
//!     relay: "127.0.0.1:4721".parse().unwrap(),
//!     user: "+alice".into(),
//!     device: 1,
//! })
//! .await?;
//! alice.send(&DeviceAddr::new("+bob", 1), b"hello").await?;
//! for message in alice.receive().await? {
//!     println!("from {}: {:?}", message.from.user, message.plaintext);
//! }
//! # Ok(()) }
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use rand::TryRngCore as _;
// Of the imports here, only `DefaultProvider` names a provider, and only as the
// default type parameter -- so a caller writing `Client` gets open-tacenta's
// provider. Nothing else in this file names a provider's concrete types, which
// is what makes it a client of the seam rather than of any one provider.
use tacenta_core::crypto::{Address, CryptoProvider, DefaultProvider};
use tacenta_core::persist::{SealError, seal, unseal};
use tacenta_relay::{Request, Response, decode_response, encode_request};
use tacenta_transport::{Connection, DirConnection};
use tacenta_wire::{Envelope, Kind};

mod secure_store;
pub use secure_store::{SecureStore, SecureStoreError};
mod dial;
use dial::Dialer;
pub use dial::{ByteStream, Connecting, Connector};
mod tenant;
pub use tacenta_discovery::{ServiceDocument, Tls, WELL_KNOWN_PATH};
pub use tenant::{Endpoints, Tacenta};

pub use tacenta_accounts::{AccountResponse, SignupReason};
pub use tacenta_directory::DirResponse;
pub use tacenta_relay::DeviceAddr;
pub use tacenta_transport::{ClientTls, ProvisionOutcome};

/// Where to reach a Tacenta server, and who to connect as.
#[derive(Clone, Debug)]
pub struct Config {
    /// The directory service address.
    pub directory: SocketAddr,
    /// The relay server address.
    pub relay: SocketAddr,
    /// This client's user identifier.
    pub user: String,
    /// This client's device number.
    pub device: u8,
}

/// Where to reach a server's account endpoints, plus the credentials to sign
/// in with. Used by the account flow ([`Client::sign_in`]) — sign in, then
/// provision this device under the account's handle — in contrast to
/// [`Config`], which registers a device directly under a raw handle (the
/// pre-account path).
#[derive(Clone)]
pub struct AccountConfig {
    /// The directory service address (peer lookups).
    pub directory: SocketAddr,
    /// The relay server address.
    pub relay: SocketAddr,
    /// The account service address (sign in).
    pub accounts: SocketAddr,
    /// The provisioning service address (bind this device).
    pub provisioning: SocketAddr,
    /// The tenant API key that scopes the account operations.
    pub api_key: String,
    /// The user's username (their per-tenant handle).
    pub identifier: String,
    /// The user's password.
    pub password: String,
    /// This client's device number.
    pub device: u8,
}

/// Redacts the two secrets: a config in a log line or a crash breadcrumb
/// must not carry the password or the API key.
impl std::fmt::Debug for AccountConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountConfig")
            .field("directory", &self.directory)
            .field("relay", &self.relay)
            .field("accounts", &self.accounts)
            .field("provisioning", &self.provisioning)
            .field("api_key", &"<redacted>")
            .field("identifier", &self.identifier)
            .field("password", &"<redacted>")
            .field("device", &self.device)
            .finish()
    }
}

/// The most bytes one `send` accepts: the relay's per-message envelope
/// limit less room for the envelope's own header and the ciphertext's
/// overhead. Larger is refused as [`ErrorKind::InvalidArgument`] before any
/// ratchet step, on every head.
pub const MAX_MESSAGE_BYTES: usize = tacenta_relay::MAX_ENVELOPE_BYTES - 1024;

/// The signal a client pings when mail may be waiting; see
/// [`Client::mail`]. Cheap to clone and hold apart from the client.
#[derive(Clone)]
pub struct MailSignal(Arc<tokio::sync::Notify>);

impl MailSignal {
    /// Wait until the relay has pushed since the last wait (or one permit
    /// was stored by a push that landed earlier), or a connection ended.
    pub async fn wait(&self) {
        self.0.notified().await;
    }
}

/// What the last sign-in or connect found, read with
/// [`restore_outcome`](Client::restore_outcome): whether the sessions a
/// restored state carried are in use, or were discarded because the state
/// was older than one already seen. The same three values on every head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestoreOutcome {
    /// No sessions were restored: a fresh identity, or one restored from
    /// an identity alone.
    Fresh,
    /// The state's sessions resumed as they were.
    Resumed,
    /// The state was older than one already seen (a rollback, caught by
    /// the secure store's counter or by the directory), so its sessions
    /// were discarded and the identity kept: conversations re-establish on
    /// next contact. Show it to the user; keep the blob.
    SessionsDiscarded,
}

impl RestoreOutcome {
    /// The outcome's name as the heads that carry a string spell it:
    /// `"fresh"`, `"resumed"`, `"sessionsDiscarded"`.
    pub fn as_str(self) -> &'static str {
        match self {
            RestoreOutcome::Fresh => "fresh",
            RestoreOutcome::Resumed => "resumed",
            RestoreOutcome::SessionsDiscarded => "sessionsDiscarded",
        }
    }
}

/// A decrypted inbound message and the device that sent it.
#[derive(Clone, Debug)]
pub struct Received {
    pub from: DeviceAddr,
    pub plaintext: Vec<u8>,
}

/// A resolved contact: another user's addressable handle. Produced by
/// [`Client::find`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// The addressable device — the handle (e.g. `acme/bob`) and device number.
    pub address: DeviceAddr,
}

impl Contact {
    /// The contact's handle, e.g. `acme/bob`.
    pub fn handle(&self) -> &str {
        &self.address.user
    }
}

/// A client-local contact list. It lives on the device and is **never sent to
/// the server**, so the server never learns a user's contact graph — the
/// metadata-privacy choice for an end-to-end-encrypted messenger. Serialize
/// with [`to_bytes`](Contacts::to_bytes) to persist it across restarts; a
/// user's contacts do not sync across their devices without doing that
/// deliberately.
#[derive(Clone, Debug, Default)]
pub struct Contacts {
    entries: Vec<Contact>,
}

impl Contacts {
    /// An empty contact list.
    pub fn new() -> Contacts {
        Contacts::default()
    }

    /// Add a contact, ignoring a duplicate (by address).
    pub fn add(&mut self, contact: Contact) {
        if !self.entries.iter().any(|c| c.address == contact.address) {
            self.entries.push(contact);
        }
    }

    /// Remove every contact with this handle.
    pub fn remove(&mut self, handle: &str) {
        self.entries.retain(|c| c.address.user != handle);
    }

    /// The contact with this handle, if any.
    pub fn get(&self, handle: &str) -> Option<&Contact> {
        self.entries.iter().find(|c| c.address.user == handle)
    }

    /// Every contact.
    pub fn all(&self) -> &[Contact] {
        &self.entries
    }

    /// Serialize the list to bytes, to persist on the device.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for contact in &self.entries {
            let handle = contact.address.user.as_bytes();
            out.extend_from_slice(&(handle.len() as u32).to_be_bytes());
            out.extend_from_slice(handle);
            out.extend_from_slice(&contact.address.device.to_be_bytes());
        }
        out
    }

    /// Reconstruct a list from [`to_bytes`](Contacts::to_bytes); `None` on any
    /// malformation.
    pub fn from_bytes(bytes: &[u8]) -> Option<Contacts> {
        let mut rest = bytes;
        let count = take_u32(&mut rest)?;
        // Never sized from the bytes: a rewritten count would ask for the
        // world before a byte was checked.
        let mut entries = Vec::new();
        for _ in 0..count {
            let len = take_u32(&mut rest)? as usize;
            let (handle, r) = rest.split_at_checked(len)?;
            rest = r;
            let user = String::from_utf8(handle.to_vec()).ok()?;
            let device = take_u32(&mut rest)?;
            entries.push(Contact {
                address: DeviceAddr::new(user, device),
            });
        }
        rest.is_empty().then_some(Contacts { entries })
    }
}

/// Read a big-endian u32 from the front of `bytes`, advancing it.
fn take_u32(bytes: &mut &[u8]) -> Option<u32> {
    let (head, rest) = bytes.split_at_checked(4)?;
    *bytes = rest;
    Some(u32::from_be_bytes(head.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(handle: &str, device: u32) -> Contact {
        Contact {
            address: DeviceAddr::new(handle, device),
        }
    }

    #[test]
    fn contacts_dedup_remove_and_round_trip() {
        let mut contacts = Contacts::new();
        contacts.add(contact("acme/bob", 1));
        contacts.add(contact("acme/bob", 1)); // duplicate: ignored
        contacts.add(contact("acme/carol", 2));
        assert_eq!(contacts.all().len(), 2);
        assert_eq!(contacts.get("acme/bob"), Some(&contact("acme/bob", 1)));
        assert_eq!(contacts.get("acme/nobody"), None);

        // Round-trip through the serialized form.
        let restored = Contacts::from_bytes(&contacts.to_bytes()).unwrap();
        assert_eq!(restored.all(), contacts.all());

        contacts.remove("acme/bob");
        assert_eq!(contacts.all().len(), 1);
        assert!(contacts.get("acme/bob").is_none());
    }

    /// The session-state split parser is hand-rolled and reached with attacker-
    /// influenced bytes on restore; no byte string may panic it. `split_state`
    /// is private, so this lives in the crate rather than the fuzz integration
    /// test.
    #[test]
    fn a_blob_without_a_provider_restores_as_legacy() {
        // What every blob written before the provider was recorded is, because
        // nothing else could have written one.
        let identity = [0xaa_u8; 36];
        let sessions = [0xbb_u8; 8];
        let mut blob = (identity.len() as u32).to_be_bytes().to_vec();
        blob.extend_from_slice(&identity);
        blob.extend_from_slice(&sessions);

        let split = split_state(&blob).expect("legacy blob parses");
        assert_eq!(split.provider, SessionProvider::Legacy);
        assert_eq!(split.identity, identity);
        assert_eq!(split.sessions, sessions);
        assert_eq!(split.prekeys, None, "a legacy blob carries no prekeys");
    }

    #[test]
    fn a_tagged_blob_round_trips_either_provider() {
        for provider in [SessionProvider::Legacy, SessionProvider::OpenTacenta] {
            let identity = [0xcc_u8; 36];
            let sessions = [0xdd_u8; 4];
            let mut blob = vec![STATE_TAGGED, STATE_VERSION_2, provider.to_byte()];
            blob.extend_from_slice(&(identity.len() as u32).to_be_bytes());
            blob.extend_from_slice(&identity);
            blob.extend_from_slice(&sessions);

            let split = split_state(&blob).expect("tagged blob parses");
            assert_eq!(split.provider, provider);
            assert_eq!(split.identity, identity);
            assert_eq!(split.sessions, sessions);
            assert_eq!(split.prekeys, None, "a v2 blob carries no prekeys");
        }
    }

    #[test]
    fn a_v3_blob_carries_a_framed_sessions_and_a_prekeys_section() {
        let identity = [0xce_u8; 36];
        let sessions = [0xdf_u8; 5];
        let prekeys = [0xa1_u8; 9];
        let mut blob = vec![
            STATE_TAGGED,
            STATE_VERSION_3,
            SessionProvider::OpenTacenta.to_byte(),
        ];
        put_lp(&mut blob, &identity);
        put_lp(&mut blob, &sessions);
        put_lp(&mut blob, &prekeys);

        let split = split_state(&blob).expect("v3 blob parses");
        assert_eq!(split.provider, SessionProvider::OpenTacenta);
        assert_eq!(split.identity, identity);
        assert_eq!(split.sessions, sessions);
        assert_eq!(
            split.prekeys,
            Some(&prekeys[..]),
            "v3 carries the prekeys section"
        );

        // Trailing bytes after the prekeys section are refused, so a v3 blob is
        // exactly its three framed parts and nothing smuggled after them.
        blob.push(0x00);
        assert!(split_state(&blob).is_err(), "trailing bytes are refused");
    }

    #[test]
    fn the_two_shapes_cannot_be_confused() {
        // A legacy blob starts with the high byte of a u32 identity length. An
        // identity is a registration id and a serialized key, so that length is
        // far below 2^24 and the byte is zero. The tag is 0xff, so no legacy
        // blob can be read as tagged and no tagged blob as legacy.
        assert_ne!(STATE_TAGGED, 0x00);
        let identity = [0x11_u8; 36];
        let mut legacy = (identity.len() as u32).to_be_bytes().to_vec();
        legacy.extend_from_slice(&identity);
        assert_eq!(legacy[0], 0x00);
    }

    #[test]
    fn an_unknown_version_or_provider_is_refused() {
        let body = {
            let identity = [0x22_u8; 36];
            let mut b = (identity.len() as u32).to_be_bytes().to_vec();
            b.extend_from_slice(&identity);
            b
        };
        let mut bad_version = vec![STATE_TAGGED, 0x09, SessionProvider::Legacy.to_byte()];
        bad_version.extend_from_slice(&body);
        assert!(split_state(&bad_version).is_err());

        let mut bad_provider = vec![STATE_TAGGED, STATE_VERSION_2, 0x7f];
        bad_provider.extend_from_slice(&body);
        assert!(split_state(&bad_provider).is_err());
    }

    #[test]
    fn split_state_is_panic_free() {
        let _ = split_state(&[]);
        for a in 0u16..=255 {
            let _ = split_state(&[a as u8]);
            for b in 0u16..=255 {
                let _ = split_state(&[a as u8, b as u8]);
            }
        }
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        };
        for _ in 0..50_000 {
            let len = (next() as usize) % 128;
            let input: Vec<u8> = (0..len).map(|_| next()).collect();
            let _ = split_state(&input);
        }
    }

    struct FixedKeyStore {
        key: [u8; 32],
        counter: std::sync::atomic::AtomicU64,
    }
    impl FixedKeyStore {
        fn new(key: [u8; 32]) -> Self {
            Self {
                key,
                counter: std::sync::atomic::AtomicU64::new(0),
            }
        }
    }
    impl SecureStore for FixedKeyStore {
        fn wrap_key(&self) -> std::result::Result<[u8; 32], SecureStoreError> {
            Ok(self.key)
        }
        fn rollback_counter(&self) -> std::result::Result<u64, SecureStoreError> {
            Ok(self.counter.load(std::sync::atomic::Ordering::SeqCst))
        }
        fn bump_rollback_counter(&self) -> std::result::Result<u64, SecureStoreError> {
            Ok(self
                .counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1)
        }
    }

    /// The sealed (v5) and unsealed (v4) formats do not cross-parse, which is
    /// what makes a downgrade attack a non-starter: an attacker cannot strip the
    /// seal off a v5 blob and feed the remainder to the unsealed parser as a
    /// forged-generation v4 blob, nor route a v4 blob through the sealed path.
    #[test]
    fn sealed_and_unsealed_formats_do_not_cross_parse() {
        let store = FixedKeyStore::new([0x5a; 32]);
        let key = store.wrap_key().unwrap();

        // A minimal v3 body to seal.
        let body = {
            let mut b = vec![
                STATE_TAGGED,
                STATE_VERSION_3,
                SessionProvider::Legacy.to_byte(),
            ];
            put_lp(&mut b, &[0x11; 36]); // identity
            put_lp(&mut b, &[]); // sessions
            put_lp(&mut b, &[]); // prekeys
            b
        };
        // The sealed body is the v3 body followed by the 8-byte rollback counter.
        let mut inner = body.clone();
        inner.extend_from_slice(&0u64.to_be_bytes());
        let mut sealed = vec![STATE_TAGGED, STATE_VERSION_5];
        sealed.extend_from_slice(&seal(&key, 7, &inner));

        // The sealed path opens it, recovers the authenticated generation, and
        // strips the counter back off to hand the v3 body to the parser.
        let opened = open_sealed(&store, &sealed).unwrap();
        assert_eq!(opened.generation, 7);
        assert_eq!(opened.body, body);
        assert!(!opened.stale, "counter 0 against a store at 0 is fresh");
        assert!(opened.bound.is_none(), "a v5 blob binds no address");

        // A v6 blob leads with the address it was sealed for, and refuses
        // another; the body and counter follow as in v5.
        let mut bound = Vec::new();
        put_lp(&mut bound, b"acme/bob");
        bound.extend_from_slice(&1u32.to_be_bytes());
        bound.extend_from_slice(&inner);
        let mut sealed6 = vec![STATE_TAGGED, STATE_VERSION_6];
        sealed6.extend_from_slice(&seal(&key, 7, &bound));
        let opened = open_sealed(&store, &sealed6).unwrap();
        assert_eq!(opened.body, body);
        assert_eq!(opened.bound, Some(DeviceAddr::new("acme/bob", 1)));
        assert!(
            opened
                .expect_address(&DeviceAddr::new("acme/bob", 1))
                .is_ok()
        );
        assert!(opened.expect_user("bob", 1).is_ok());
        assert!(matches!(
            opened.expect_address(&DeviceAddr::new("acme/carol", 1)),
            Err(Error::StateMismatch { .. })
        ));
        assert!(matches!(
            opened.expect_user("bob", 2),
            Err(Error::StateMismatch { .. })
        ));
        assert!(matches!(
            opened.expect_user("carol", 1),
            Err(Error::StateMismatch { .. })
        ));

        // The *unsealed* parser refuses a v5 blob rather than misreading it.
        assert!(
            split_state(&sealed).is_err(),
            "v5 must not parse as unsealed"
        );

        // And the sealed path refuses a v4 (unsealed) blob.
        let mut v4 = body.clone();
        v4[1] = STATE_VERSION_4;
        v4.extend_from_slice(&7u64.to_be_bytes());
        assert!(
            open_sealed(&store, &v4).is_err(),
            "v4 must not open as sealed"
        );
    }

    /// The authenticated generation cannot be forged: altering it in the sealed
    /// bytes makes the restore fail closed (the crate-level counterpart of the
    /// end-to-end `a_forged_sealed_generation_is_refused`).
    #[test]
    fn a_forged_generation_in_a_sealed_blob_is_refused() {
        let store = FixedKeyStore::new([0x5a; 32]);
        let key = store.wrap_key().unwrap();
        let body = vec![
            STATE_TAGGED,
            STATE_VERSION_3,
            SessionProvider::Legacy.to_byte(),
        ];
        let mut sealed = vec![STATE_TAGGED, STATE_VERSION_5];
        sealed.extend_from_slice(&seal(&key, 1, &body));

        // Forge the generation (bytes 3..11: after TAGGED, V5, SEAL_VERSION).
        sealed[3..11].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(
            open_sealed(&store, &sealed),
            Err(Error::SecureStore(_))
        ));
    }
}

/// What can go wrong talking to a Tacenta server. [`Error::kind`] is the
/// contract an app branches on; the variants carry the detail, including
/// the server's own reply where there was one, and may grow (the enum is
/// non-exhaustive).
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A network or transport error.
    Io(std::io::Error),
    /// The relay refused a send, returning this outcome.
    Relay(RelayRefusal),
    /// The caller's own input was wrong: a device number the protocol cannot
    /// carry, a message over the size limit, a call the client's shape does
    /// not support. Fix the call, not the network.
    InvalidArgument(&'static str),
    /// The directory refused an operation, returning this outcome.
    Directory(DirResponse),
    /// The account service refused an operation (a refused signup or
    /// sign-in), returning this outcome.
    Account(AccountResponse),
    /// Provisioning was refused (bad session, failed possession, or the
    /// handle is bound to a different key), returning this outcome.
    Provision(ProvisionOutcome),
    /// A cryptographic operation failed.
    Crypto(String),
    /// The server sent an unexpected or malformed response.
    Protocol(&'static str),
    /// The persisted-state authenticator was refused, or the secure-storage key
    /// behind it was unavailable (decision 0078, anchor B). A refused
    /// authenticator on a restore means the state file was altered — including
    /// the deliberate forgery the rollback finding is about, which is now caught rather than
    /// resumed.
    SecureStore(String),
    /// The platform's secure store could not be reached: a Keychain before
    /// first unlock, a Keystore that needs the user. Nothing was refused;
    /// retry after unlock, and keep the blob.
    StoreUnavailable(String),
    /// A sealed state that belongs to another user or device was offered
    /// for this one, and refused before its identity could be registered
    /// under an address it was never bound to.
    StateMismatch {
        /// The address the state was sealed for.
        state: DeviceAddr,
        /// The address it was offered to.
        client: DeviceAddr,
    },
    /// The server's service document could not be fetched or read, so the
    /// tenant handle does not know where the services are (decision 0090).
    Discovery(String),
}

/// A secure store's failure as the client reports it: a store that is
/// not reachable is its own kind, so an app can wait for the unlock
/// rather than treat it as tampering.
fn store_err(e: SecureStoreError) -> Error {
    match e {
        SecureStoreError::Unavailable(reason) => Error::StoreUnavailable(reason),
        SecureStoreError::Backend(reason) => Error::SecureStore(reason),
    }
}

/// Why the relay refused a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefusal {
    /// The message is over the relay's per-message size limit. Permanent:
    /// a smaller message, not a retry.
    TooLarge,
    /// The recipient's queue is at its count or byte budget. Transient:
    /// retry after it drains.
    QueueFull,
    /// The recipient's device is not registered.
    UnknownRecipient,
}

/// What an app can branch on: the kind of an [`Error`], the same set on
/// every head (decision 0090). The message
/// carries the detail; the kind is the contract. Non-exhaustive: a kind may
/// be added, so match with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The network or the transport failed, including a reconnect that ran
    /// out of patience. Retry later.
    Network,
    /// The server's service document could not be fetched or read, so the
    /// handle does not know where the services are.
    Discovery,
    /// The API key selects no tenant.
    UnknownTenant,
    /// The username is already taken in this tenant.
    UsernameTaken,
    /// The username is not one the server accepts.
    InvalidUsername,
    /// The password is too weak.
    WeakPassword,
    /// A sign-up was refused for another reason: registration is closed,
    /// the handle is reserved, or (for a tenant) the email is taken or
    /// invalid.
    SignUpRefused,
    /// The credentials were refused, or the session they opened has expired.
    /// Coarse by design: it does not say whether the account exists.
    SignInRefused,
    /// The address is bound to a different device identity than the one
    /// presented (trust on first use). Resume from the saved state that
    /// holds the bound identity, or use another device number.
    IdentityMismatch,
    /// The address is not registered: the recipient's device is gone, or
    /// never was.
    NotFound,
    /// The server asked for a slower pace: too many failed sign-ins, or the
    /// recipient's queue is full. Back off and retry.
    RateLimited,
    /// The server could not process the request; nothing was applied. Retry.
    ServerFailure,
    /// The persisted state was refused: altered, older than the last send,
    /// or its authenticator did not verify.
    State,
    /// The platform's secure store could not be reached (a Keychain before
    /// first unlock, a Keystore that needs the user). Retry after unlock;
    /// keep the blob.
    StoreUnavailable,
    /// The caller's own input was wrong: a malformed address, a message
    /// over the size limit. Fix the call, not the network.
    InvalidArgument,
    /// A protocol or cryptographic failure, or an unexpected server reply:
    /// a bug on one side or the other, worth reporting.
    Internal,
}

impl ErrorKind {
    /// The kind's name as the heads that carry a string spell it (the
    /// TypeScript `kind`, and the manifest's `typescript` column):
    /// `"network"`, `"signInRefused"`, ...
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Network => "network",
            ErrorKind::Discovery => "discovery",
            ErrorKind::UnknownTenant => "unknownTenant",
            ErrorKind::UsernameTaken => "usernameTaken",
            ErrorKind::InvalidUsername => "invalidUsername",
            ErrorKind::WeakPassword => "weakPassword",
            ErrorKind::SignUpRefused => "signUpRefused",
            ErrorKind::SignInRefused => "signInRefused",
            ErrorKind::IdentityMismatch => "identityMismatch",
            ErrorKind::NotFound => "notFound",
            ErrorKind::RateLimited => "rateLimited",
            ErrorKind::ServerFailure => "serverFailure",
            ErrorKind::State => "state",
            ErrorKind::StoreUnavailable => "storeUnavailable",
            ErrorKind::InvalidArgument => "invalidArgument",
            ErrorKind::Internal => "internal",
        }
    }
}

impl Error {
    /// The kind of this error, for an app to branch on.
    pub fn kind(&self) -> ErrorKind {
        match self {
            // The relay refused the identity itself (rotated away, or never
            // bound): not the network's fault, and not fixed by retrying.
            Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                ErrorKind::IdentityMismatch
            }
            Error::Io(_) => ErrorKind::Network,
            Error::InvalidArgument(_) => ErrorKind::InvalidArgument,
            Error::Discovery(_) => ErrorKind::Discovery,
            Error::Relay(RelayRefusal::TooLarge) => ErrorKind::InvalidArgument,
            Error::Relay(RelayRefusal::QueueFull) => ErrorKind::RateLimited,
            Error::Relay(RelayRefusal::UnknownRecipient) => ErrorKind::NotFound,
            Error::Account(response) => match response {
                AccountResponse::UnknownTenant => ErrorKind::UnknownTenant,
                AccountResponse::SignupRefused { reason } => match reason {
                    SignupReason::UsernameTaken => ErrorKind::UsernameTaken,
                    SignupReason::InvalidUsername => ErrorKind::InvalidUsername,
                    SignupReason::WeakPassword => ErrorKind::WeakPassword,
                    SignupReason::EmailTaken | SignupReason::InvalidEmail => {
                        ErrorKind::SignUpRefused
                    }
                },
                AccountResponse::SignInRefused => ErrorKind::SignInRefused,
                AccountResponse::RateLimited => ErrorKind::RateLimited,
                AccountResponse::ServerError => ErrorKind::ServerFailure,
                _ => ErrorKind::Internal,
            },
            Error::Directory(response) => match response {
                DirResponse::Rejected
                | DirResponse::DepositRejected
                | DirResponse::Unauthorized => ErrorKind::IdentityMismatch,
                DirResponse::NotFound | DirResponse::Unregistered => ErrorKind::NotFound,
                DirResponse::RateLimited => ErrorKind::RateLimited,
                DirResponse::RegistrationClosed | DirResponse::ReservedHandle => {
                    ErrorKind::SignUpRefused
                }
                DirResponse::RolledBack => ErrorKind::State,
                _ => ErrorKind::Internal,
            },
            Error::Provision(outcome) => match outcome {
                ProvisionOutcome::Rejected => ErrorKind::IdentityMismatch,
                ProvisionOutcome::BadSession => ErrorKind::SignInRefused,
                ProvisionOutcome::ServerError => ErrorKind::ServerFailure,
                _ => ErrorKind::Internal,
            },
            Error::SecureStore(_) => ErrorKind::State,
            Error::StoreUnavailable(_) => ErrorKind::StoreUnavailable,
            Error::StateMismatch { .. } => ErrorKind::IdentityMismatch,
            Error::Crypto(_) | Error::Protocol(_) => ErrorKind::Internal,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "transport error: {e}"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::Relay(RelayRefusal::TooLarge) => {
                write!(f, "message exceeds the relay's per-message size limit")
            }
            Error::Relay(RelayRefusal::QueueFull) => {
                write!(f, "recipient's queue is full; retry after it drains")
            }
            Error::Relay(RelayRefusal::UnknownRecipient) => {
                write!(f, "recipient is not registered")
            }
            Error::Directory(o) => write!(f, "directory refused the request: {o:?}"),
            Error::Account(o) => write!(f, "account service refused the request: {o:?}"),
            Error::Provision(o) => write!(f, "provisioning refused: {o:?}"),
            Error::Crypto(e) => write!(f, "crypto error: {e}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::SecureStore(e) => write!(f, "persisted-state authentication error: {e}"),
            Error::StoreUnavailable(e) => write!(f, "secure storage is not available: {e}"),
            Error::StateMismatch { state, client } => write!(
                f,
                "the sealed state belongs to {}/{}, not {}/{}",
                state.user, state.device, client.user, client.device
            ),
            Error::Discovery(e) => write!(f, "service discovery failed: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::Io(e)
    }
}

/// A convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

fn crypto(e: impl std::fmt::Debug) -> Error {
    Error::Crypto(format!("{e:?}"))
}

/// The crypto-layer address for a routing address (device numbers are u8 at
/// the crypto layer; the relay carries them as u32).
///
/// `Address` rather than a provider's own address type: this client is
/// written against the provider seam, so it must not name a provider's types.
fn peer_address(addr: &DeviceAddr) -> Result<Address> {
    let device =
        u8::try_from(addr.device).map_err(|_| Error::InvalidArgument("device id out of range"))?;
    Ok(Address::new(&addr.user, device))
}

/// The routing address for a crypto-layer peer address (the inverse of
/// [`peer_address`]).
fn device_addr(peer: &Address) -> DeviceAddr {
    DeviceAddr::new(peer.user.clone(), u32::from(peer.device))
}

// The provider a session was established under is a property of `P`, so the
// tag is `SessionProvider::of::<P>()` rather than a constant: a constant
// would write the wrong tag into a blob held by a client running anything
// else, in the field whose only job is to say which provider's session a
// blob holds.

/// Which implementation established the sessions in a state blob.
///
/// A session is bound to the provider that established it: keys are derived
/// under provider-specific labels, so a session tagged with a different
/// provider is unreadable. A client restoring state has to know which it is
/// holding before it can decide whether to continue the session or drop it
/// and establish again. That is what this records.
///
/// It lives in the state envelope rather than inside a provider's own session
/// blob, because the question it answers is which blob to hand to which
/// provider.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionProvider {
    /// The tag written by state blobs before the provider tag existed; the
    /// default a pre-tag blob restores as.
    Legacy,
    /// tacenta-core, consumed as `open-tacenta`.
    OpenTacenta,
}

impl SessionProvider {
    /// The byte this provider is written as in the state envelope.
    pub fn to_byte(self) -> u8 {
        match self {
            SessionProvider::Legacy => 0x01,
            SessionProvider::OpenTacenta => 0x02,
        }
    }

    /// Which provider `P` is.
    ///
    /// Keyed off `CryptoProvider::NAME`, which is the only thing the seam
    /// exposes about a provider's identity. An unrecognised name is a provider
    /// this envelope has no byte for, and saying so is better than picking one:
    /// a wrong tag here makes a client continue a session it cannot read.
    fn of<P: CryptoProvider>() -> SessionProvider {
        match P::NAME {
            "open-tacenta" => SessionProvider::OpenTacenta,
            other => panic!("no state-envelope tag for crypto provider {other:?}"),
        }
    }

    fn from_byte(b: u8) -> Option<SessionProvider> {
        match b {
            0x01 => Some(SessionProvider::Legacy),
            0x02 => Some(SessionProvider::OpenTacenta),
            _ => None,
        }
    }
}

/// Marks a state blob that carries a version and a provider.
///
/// A blob written before this existed begins with the high byte of a `u32`
/// identity length. An identity is a registration id and a serialized key, so
/// that length is far below 2^24 and the byte is always zero. `0xff` therefore
/// cannot be the start of an older blob, which is what makes the two
/// distinguishable without guessing.
const STATE_TAGGED: u8 = 0xff;

/// The v2 version byte: identity and sessions, no prekeys. No longer
/// written; still read.
const STATE_VERSION_2: u8 = 0x02;

/// The v3 version byte: identity, sessions **and the published prekey store**,
/// so a restored device can decrypt a first-contact message a new peer sent to
/// a published one-time prekey while it was offline. v2's tail-encoded sessions
/// cannot carry a section after them, so v3 length-frames the sessions and
/// appends a prekeys section.
const STATE_VERSION_3: u8 = 0x03;

/// The v4 version byte: v3 plus a trailing `u64` **persisted-state generation**,
/// the anti-rollback counter of decision 0078. Carried so a restore knows which
/// generation to present to the directory; a directory that has since witnessed
/// a higher one reports the restore as a rollback.
const STATE_VERSION_4: u8 = 0x04;

/// The v5 marker: a **sealed** state (decision 0078, anchor B). The two bytes
/// `STATE_TAGGED, STATE_VERSION_5` are followed by a `tacenta_core::persist`
/// seal whose authenticated payload is a v3 body and whose bound counter is the
/// persisted-state generation. Unlike v4 — which appends the generation as an
/// unauthenticated plaintext `u64` a file-rewriter can forge — the generation
/// here lives *inside* the authenticator, so it cannot be forged without the
/// secure-storage key. This is the sealed body format — the rollback-resistant
/// one, which refuses a forged state and, via the per-send `SecureStore`
/// counter, any state older than the latest send (closing the rollback gap
/// against a file-rewriter given a rollback-resistant store, 0078); v4 remains
/// for the unsealed path, which makes no rollback claim. v6 below is what a
/// sealed export writes; v5 is still read.
const STATE_VERSION_5: u8 = 0x05;

/// The v6 marker: v5 with **the address the state was sealed for** under
/// the authenticator, ahead of the body: `lp(user) || device (u32 BE) ||
/// v3 body || counter`. A restore for another user or device is refused
/// before that identity is registered under the wrong address, where
/// trust-on-first-use would have made it permanent. Written by every sealed
/// export; v5 is still read, unbound.
const STATE_VERSION_6: u8 = 0x06;

/// The parts of an [`export_state`](Client::export_state) blob. `prekeys` is
/// `None` for a v2 or legacy blob that never carried them; `Some` (possibly
/// empty) for v3 and v4. `generation` is 0 for anything before v4.
struct SplitState<'a> {
    provider: SessionProvider,
    identity: &'a [u8],
    sessions: &'a [u8],
    prekeys: Option<&'a [u8]>,
    generation: u64,
}

/// A big-endian `u32` length prefix, then the block.
fn put_lp(out: &mut Vec<u8>, block: &[u8]) {
    out.extend_from_slice(&(block.len() as u32).to_be_bytes());
    out.extend_from_slice(block);
}

/// Read a `u32`-length-prefixed block, returning it and the rest. `None` on any
/// truncation — this runs over untrusted bytes and must not panic.
fn take_lp(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = b.split_at_checked(4)?;
    let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
    rest.split_at_checked(len)
}

/// Split an [`export_state`](Client::export_state) blob into its parts.
///
/// Three shapes are accepted, and accepting the older two is the point — a new
/// client must restore a state an older one wrote. A legacy blob (no tag)
/// restores as [`SessionProvider::Legacy`], which is what it is: nothing else
/// could have written one. A v3 blob written by a newer client cannot be read
/// here only if this *is* the newer client; an *older* client meeting a v3 blob
/// fails closed with "unknown state blob version" rather than restoring it
/// wrong.
///
/// Panic-free over arbitrary bytes: every field is bounds-checked, never
/// indexed.
fn split_state(state: &[u8]) -> Result<SplitState<'_>> {
    let trunc = || Error::Protocol("state blob truncated");
    match state.split_first() {
        Some((&STATE_TAGGED, rest)) => {
            let (&version, rest) = rest.split_first().ok_or_else(trunc)?;
            let (&tag, rest) = rest.split_first().ok_or_else(trunc)?;
            let provider = SessionProvider::from_byte(tag)
                .ok_or(Error::Protocol("unknown session provider"))?;
            match version {
                STATE_VERSION_2 => {
                    let (identity, sessions) = take_lp(rest).ok_or_else(trunc)?;
                    Ok(SplitState {
                        provider,
                        identity,
                        sessions,
                        prekeys: None,
                        generation: 0,
                    })
                }
                STATE_VERSION_3 => {
                    let (identity, rest) = take_lp(rest).ok_or_else(trunc)?;
                    let (sessions, rest) = take_lp(rest).ok_or_else(trunc)?;
                    let (prekeys, rest) = take_lp(rest).ok_or_else(trunc)?;
                    if !rest.is_empty() {
                        return Err(Error::Protocol("state blob has trailing bytes"));
                    }
                    Ok(SplitState {
                        provider,
                        identity,
                        sessions,
                        prekeys: Some(prekeys),
                        generation: 0,
                    })
                }
                STATE_VERSION_4 => {
                    let (identity, rest) = take_lp(rest).ok_or_else(trunc)?;
                    let (sessions, rest) = take_lp(rest).ok_or_else(trunc)?;
                    let (prekeys, rest) = take_lp(rest).ok_or_else(trunc)?;
                    let (gen_bytes, rest) = rest.split_at_checked(8).ok_or_else(trunc)?;
                    if !rest.is_empty() {
                        return Err(Error::Protocol("state blob has trailing bytes"));
                    }
                    Ok(SplitState {
                        provider,
                        identity,
                        sessions,
                        prekeys: Some(prekeys),
                        generation: u64::from_be_bytes(gen_bytes.try_into().expect("8 bytes")),
                    })
                }
                _ => Err(Error::Protocol("unknown state blob version")),
            }
        }
        // No tag: a pre-provider blob. Identity length-prefixed, sessions the
        // tail, no prekeys.
        _ => {
            let (identity, sessions) = take_lp(state).ok_or_else(trunc)?;
            Ok(SplitState {
                provider: SessionProvider::Legacy,
                identity,
                sessions,
                prekeys: None,
                generation: 0,
            })
        }
    }
}

/// Restore a split blob's prekey store into `party` **before it publishes its
/// bundle**.
///
/// The ordering is the whole point, and it is why this is a free function
/// called at the restore sites rather than a method run after connect.
/// `publish_bundle` reuses an existing store rather than minting a fresh one, so
/// importing first means the client republishes the *restored* bundle: the
/// directory and the party agree on one prekey set, the message a new peer
/// queued against it still decrypts, and a first contact made *after* the
/// restore uses that same republished set. Importing after connect would leave
/// the party holding old prekeys while the directory advertised new ones —
/// fixing the queued message by breaking the next one.
///
/// A no-op unless the blob carried a non-empty prekeys section written by this
/// same provider; a cross-provider or v2 blob simply re-establishes on first
/// send, as it did before.
fn restore_prekeys_into<P: CryptoProvider>(party: &mut P, split: &SplitState<'_>) -> Result<()> {
    if split.provider != SessionProvider::of::<P>() {
        return Ok(());
    }
    if let Some(prekeys) = split.prekeys.filter(|p| !p.is_empty()) {
        party.import_prekeys(prekeys).map_err(crypto)?;
    }
    Ok(())
}

/// Verify and open a sealed state blob (decision 0078, anchor B), returning the
/// unsealed v3-shaped body and its **authenticated** generation.
///
/// **A refused authenticator is the rollback forgery being caught, not a soft
/// error.** The attacker the rollback finding is about rewrites the state file to present old
/// sessions under a high generation; without the secure-storage key they cannot
/// produce a matching authenticator, so `unseal` refuses and the restore fails
/// closed rather than resuming the rolled-back state. That is the whole point of
/// sealing, and it is why the sealed restore paths surface this as an error
/// instead of falling back to the unsealed parse.
///
/// Returns the v3 body, the authenticated `state_generation`, and whether the
/// store's rollback counter reports this state as **stale** — a value the store
/// has already moved past, i.e. a same-generation rollback the directory witness
/// cannot see. The caller discards sessions on a stale verdict, exactly as it
/// does on a directory `RolledBack`.
/// A sealed state, opened: the v3 body, its authenticated generation,
/// whether the store's counter reports it stale, and the address it was
/// sealed for (`None` for a v5 blob, written before the address was bound).
struct Opened {
    body: Vec<u8>,
    generation: u64,
    stale: bool,
    bound: Option<DeviceAddr>,
}

impl Opened {
    /// Refuse a state sealed for another address. Exact.
    fn expect_address(&self, client: &DeviceAddr) -> Result<()> {
        match &self.bound {
            Some(state) if state != client => Err(Error::StateMismatch {
                state: state.clone(),
                client: client.clone(),
            }),
            _ => Ok(()),
        }
    }

    /// The same check before a sign-in, when only the username and device
    /// are known and the tenant prefix is not: the bound user must be that
    /// username, bare or under a tenant. The exact check follows sign-in.
    fn expect_user(&self, identifier: &str, device: u32) -> Result<()> {
        match &self.bound {
            Some(state)
                if state.device != device
                    || !(state.user == identifier
                        || state.user.ends_with(&format!("/{identifier}"))) =>
            {
                Err(Error::StateMismatch {
                    state: state.clone(),
                    client: DeviceAddr::new(identifier, device),
                })
            }
            _ => Ok(()),
        }
    }
}

fn open_sealed(store: &dyn SecureStore, state: &[u8]) -> Result<Opened> {
    let rest = match state.split_first() {
        Some((&STATE_TAGGED, rest)) => rest,
        _ => return Err(Error::SecureStore("not a sealed state blob".into())),
    };
    let (&version, sealed) = rest
        .split_first()
        .ok_or(Error::Protocol("state blob truncated"))?;
    if version != STATE_VERSION_5 && version != STATE_VERSION_6 {
        return Err(Error::SecureStore("not a sealed state blob".into()));
    }
    let key = zeroize::Zeroizing::new(store.wrap_key().map_err(store_err)?);
    let opened = unseal(&key, sealed).map_err(|e| match e {
        SealError::BadAuthenticator => Error::SecureStore(
            "state authenticator does not match: the file was altered or the key is wrong".into(),
        ),
        SealError::TooShort => Error::SecureStore("sealed state is truncated".into()),
        SealError::UnknownVersion => Error::SecureStore("sealed state envelope version".into()),
    })?;
    // The sealed body is `v3 body || rollback counter (8 bytes)`; both are under
    // the authenticator, so the counter cannot be edited without breaking it.
    let split_at = opened
        .payload
        .len()
        .checked_sub(8)
        .ok_or(Error::SecureStore(
            "sealed state missing its rollback counter".into(),
        ))?;
    let (mut body, counter_bytes) = opened.payload.split_at(split_at);
    let counter = u64::from_be_bytes(counter_bytes.try_into().expect("8 bytes"));
    // v6 leads with the address the state was sealed for.
    let bound = if version == STATE_VERSION_6 {
        let truncated = || Error::SecureStore("sealed state missing its address".into());
        let (len, rest) = body.split_at_checked(4).ok_or_else(truncated)?;
        let len = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
        let (user, rest) = rest.split_at_checked(len).ok_or_else(truncated)?;
        let (device, rest) = rest.split_at_checked(4).ok_or_else(truncated)?;
        let user = std::str::from_utf8(user)
            .map_err(|_| truncated())?
            .to_owned();
        body = rest;
        Some(DeviceAddr::new(
            user,
            u32::from_be_bytes(device.try_into().expect("4 bytes")),
        ))
    } else {
        None
    };
    let highest = store.rollback_counter().map_err(store_err)?;
    // Older than the newest state this device sealed: a same-generation rollback.
    // Equal is fresh — restoring the latest sealed state is ordinary recovery.
    let stale = counter < highest;
    Ok(Opened {
        body: body.to_vec(),
        generation: opened.generation,
        stale,
        bound,
    })
}

/// Where a client dials its services — retained so the connections can be
/// re-established after a drop without asking the caller to reconfigure.
/// (`Endpoints` without qualification is the SDK's public type, in `tenant`.)
struct Dialed {
    directory: SocketAddr,
    relay: SocketAddr,
    dialer: Dialer,
}

/// The client this build establishes sessions with.
///
/// **This alias is where the product's provider choice lives.** `Client` on its
/// own defaults to the same
/// thing, but Rust does not apply a default type parameter when inferring an
/// associated function call, so `Client::connect(..)` cannot tell which
/// provider it is for. Callers write `DefaultClient::connect(..)` instead.
///
/// Naming it here rather than making callers write the provider at every call
/// site is what makes the provider choice one edit rather than a sweep: a
/// caller says "the default", not which provider it is.
///
/// **The client names `crypto::DefaultProvider` rather than a concrete type,
/// so the provider is chosen in one place.** A client signing under one
/// provider and a server verifying under another would fail every
/// provisioning attempt at its possession check: two halves of one deployment
/// have to move together, which `CryptoProvider::verify_challenge` says in
/// its own documentation, and routing both through `DefaultProvider` is what
/// keeps them together.
pub type DefaultClient = Client<DefaultProvider>;

/// A connected client: an identity, a directory connection, an
/// authenticated relay connection, and the peers it has open sessions with.
///
/// Generic over the crypto provider, defaulting to `DefaultProvider` so that
/// every caller keeps working by writing `Client` and nothing else.
///
/// **The default is the point, and so is the parameter.** A client that held
/// a concrete provider type would make any provider change a whole-binary
/// change; a client generic over the seam lets sessions tagged with a
/// different provider be recognised and drained rather than misread.
pub struct Client<P: CryptoProvider = DefaultProvider> {
    party: P,
    directory: DirConnection,
    relay: Connection,
    /// Pinged by every relay connection this client makes (across
    /// reconnects) on a push and when the connection ends; what
    /// [`mail`](Client::mail) hands out.
    mail: Arc<tokio::sync::Notify>,
    me: DeviceAddr,
    sessions: HashSet<DeviceAddr>,
    endpoints: Dialed,
    /// Which implementation established this client's sessions. Recorded so a
    /// restored blob says what it holds rather than leaving a caller to assume.
    session_provider: SessionProvider,
    /// This client's persisted-state generation, the *coarse* anti-rollback
    /// counter of decision 0078. Advances on a session-affecting event (a new
    /// session), travels in the exported blob, and is presented to the directory
    /// by [`checkpoint`](Client::checkpoint). Not every message moves it — that
    /// is decision 2's trade.
    state_generation: u64,
    /// The secure-storage store, once [`attach_secure_store`](Client::attach_secure_store)
    /// (or a sealed restore) has provided it. When present, **rollback protection
    /// is on**: every send and every ratchet-advancing receive commits a
    /// monotonic counter to it (the fine-grained freshness marker that closes the
    /// per-send window), and a sealed export binds that counter's
    /// current value. When absent, the client behaves as before — no per-send
    /// commits, and only the unsealed / coarse paths are available.
    secure_store: Option<Arc<dyn SecureStore + Send + Sync>>,
    /// What the constructor found; see [`RestoreOutcome`].
    restore: RestoreOutcome,
    /// The highest rollback counter this client has seen from its store,
    /// so a bump that does not advance past it (a store that was reset or
    /// replaced under the client) is refused rather than trusted. Zero
    /// until a store is attached.
    counter_seen: std::sync::atomic::AtomicU64,
}

impl<P: CryptoProvider> Client<P> {
    /// Generate a fresh identity, publish it to the directory, and
    /// authenticate to the relay — leaving a client ready to send and
    /// receive. This is first-run enrolment: the identity is new every call,
    /// so re-running it for an address that is already bound to a different
    /// key is refused by trust-on-first-use. To keep an identity across
    /// restarts, save [`export_identity`](Client::export_identity) and
    /// reconnect with [`connect_with_identity`](Client::connect_with_identity).
    pub async fn connect(config: &Config) -> Result<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let party = P::generate(&config.user, config.device, &mut rng).map_err(crypto)?;
        Self::connect_with_party(config, party, &Dialer::tcp(None)).await
    }

    /// Like [`connect`](Client::connect), but over TLS to a server presenting
    /// `server_name` (e.g. the hosted `tacenta.com`). `tls` decides which
    /// certificate to trust — [`ClientTls::web_pki`] for a public CA.
    pub async fn connect_tls(config: &Config, server_name: &str, tls: &ClientTls) -> Result<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let party = P::generate(&config.user, config.device, &mut rng).map_err(crypto)?;
        Self::connect_with_party(config, party, &Dialer::tcp(Some((server_name, tls)))).await
    }

    /// Reconnect under a previously saved identity (from
    /// [`export_identity`](Client::export_identity)): the client presents the
    /// same identity key, so the directory refreshes the existing binding
    /// rather than rejecting a new key for the address, and peers see no
    /// safety-number change. The session and prekey store starts empty —
    /// prekeys are re-published and peer sessions re-establish on next use.
    pub async fn connect_with_identity(config: &Config, identity: &[u8]) -> Result<Self> {
        let party = P::from_identity(&config.user, config.device, identity).map_err(crypto)?;
        Self::connect_with_party(config, party, &Dialer::tcp(None)).await
    }

    /// Reconnect under a full saved state (from
    /// [`export_state`](Client::export_state)): the same identity *and* the
    /// live ratchet sessions, so open conversations resume mid-ratchet — a
    /// message a peer sent while this device was down still decrypts. The
    /// stronger sibling of
    /// [`connect_with_identity`](Client::connect_with_identity), which keeps
    /// only the identity and re-establishes sessions from scratch.
    pub async fn connect_with_state(config: &Config, state: &[u8]) -> Result<Self> {
        let split = split_state(state)?;
        let mut party =
            P::from_identity(&config.user, config.device, split.identity).map_err(crypto)?;
        restore_prekeys_into(&mut party, &split)?;
        let mut client = Self::connect_with_party(config, party, &Dialer::tcp(None)).await?;
        client
            .restore_sessions(split.provider, split.sessions)
            .await?;
        client.restore = RestoreOutcome::Resumed;
        client.state_generation = split.generation;
        // Anchor A (0078) is deliberately NOT auto-invoked here. Its detection
        // is defeatable by a file-rewriter, so this unsealed default path
        // makes no rollback claim and adds no exposure; `checkpoint` is public
        // for a deployment that opts into detection-only. The real control is
        // anchor B (an authenticated generation plus a per-send `SecureStore`
        // counter) — built, and living on the *sealed* path
        // (`connect_with_state_sealed` and siblings), not here.
        Ok(client)
    }

    /// Like [`connect_with_state`](Client::connect_with_state), but over TLS to
    /// a server presenting `server_name`.
    pub async fn connect_with_state_tls(
        config: &Config,
        server_name: &str,
        tls: &ClientTls,
        state: &[u8],
    ) -> Result<Self> {
        let split = split_state(state)?;
        let mut party =
            P::from_identity(&config.user, config.device, split.identity).map_err(crypto)?;
        restore_prekeys_into(&mut party, &split)?;
        let mut client =
            Self::connect_with_party(config, party, &Dialer::tcp(Some((server_name, tls)))).await?;
        client
            .restore_sessions(split.provider, split.sessions)
            .await?;
        client.restore = RestoreOutcome::Resumed;
        client.state_generation = split.generation;
        // Anchor A (0078) is deliberately NOT auto-invoked here. Its detection
        // is defeatable by a file-rewriter, so this unsealed default path
        // makes no rollback claim and adds no exposure; `checkpoint` is public
        // for a deployment that opts into detection-only. The real control is
        // anchor B (an authenticated generation plus a per-send `SecureStore`
        // counter) — built, and living on the *sealed* path
        // (`connect_with_state_sealed` and siblings), not here.
        Ok(client)
    }

    /// Reconnect under a **sealed** full state (from
    /// [`export_state_sealed`](Client::export_state_sealed)) — decision 0078's
    /// anchor B, the rollback-resistant restore path. Attaches `store` (per-send
    /// commits resume), refuses a forged state, and catches a state older than
    /// the latest send via the counter — closing the rollback gap against a file-rewriter
    /// given a rollback-resistant store.
    ///
    /// Two things happen that the unsealed
    /// [`connect_with_state`](Client::connect_with_state) does not do. First,
    /// the state's authenticator is verified under a key from `store`; a state a
    /// file-rewriter forged (old sessions, high generation) has no matching
    /// authenticator and is **refused** here rather than resumed, which is the
    /// forged-generation gap closed. Second, because the generation that survives that check
    /// is authenticated, presenting it to the directory (`checkpoint`) is a real
    /// freshness control: a genuine *older* sealed state — a legitimate backup
    /// restore, or an attacker replaying an untouched old file — authenticates
    /// but is caught as a rollback, and its sessions are discarded (decision 3).
    ///
    /// A directory that is unreachable does not fail the connect: the client
    /// resumes optimistically and the witness runs on the next reachable
    /// checkpoint (decision 3a).
    pub async fn connect_with_state_sealed(
        config: &Config,
        state: &[u8],
        store: Arc<dyn SecureStore + Send + Sync>,
    ) -> Result<Self> {
        let opened = open_sealed(&*store, state)?;
        opened.expect_address(&DeviceAddr::new(
            config.user.clone(),
            u32::from(config.device),
        ))?;
        let split = split_state(&opened.body)?;
        let mut party =
            P::from_identity(&config.user, config.device, split.identity).map_err(crypto)?;
        restore_prekeys_into(&mut party, &split)?;
        let mut client = Self::connect_with_party(config, party, &Dialer::tcp(None)).await?;
        client
            .restore_sessions(split.provider, split.sessions)
            .await?;
        client.restore = RestoreOutcome::Resumed;
        client.state_generation = opened.generation;
        // Hold the store for the restored client's life: per-send commits are on
        // from here, so a future rollback is caught at send granularity.
        client.attach_secure_store(store)?;
        // Same-generation / per-send rollback caught locally by the counter,
        // independently of (and before) the directory witness. `checkpoint` then
        // discards on a coarse rollback; a network error resumes optimistically
        // (3a), so it is swallowed.
        if opened.stale {
            client.discard_sessions();
        }
        let _ = client.checkpoint().await;
        Ok(client)
    }

    /// Like [`connect_with_state_sealed`](Client::connect_with_state_sealed),
    /// but over TLS to a server presenting `server_name`.
    pub async fn connect_with_state_sealed_tls(
        config: &Config,
        server_name: &str,
        tls: &ClientTls,
        state: &[u8],
        store: Arc<dyn SecureStore + Send + Sync>,
    ) -> Result<Self> {
        let opened = open_sealed(&*store, state)?;
        opened.expect_address(&DeviceAddr::new(
            config.user.clone(),
            u32::from(config.device),
        ))?;
        let split = split_state(&opened.body)?;
        let mut party =
            P::from_identity(&config.user, config.device, split.identity).map_err(crypto)?;
        restore_prekeys_into(&mut party, &split)?;
        let mut client =
            Self::connect_with_party(config, party, &Dialer::tcp(Some((server_name, tls)))).await?;
        client
            .restore_sessions(split.provider, split.sessions)
            .await?;
        client.restore = RestoreOutcome::Resumed;
        client.state_generation = opened.generation;
        // Hold the store for the restored client's life (per-send commits on),
        // then act on any rollback the counter caught, before the witness.
        client.attach_secure_store(store)?;
        if opened.stale {
            client.discard_sessions();
        }
        let _ = client.checkpoint().await;
        Ok(client)
    }

    /// Restore serialized sessions into the party's store and rebuild this
    /// client's record of who it has an open session with.
    ///
    /// Sessions tagged with a different provider are dropped rather than
    /// restored. A session is bound to the provider that established it, so
    /// such a session cannot be carried across, and anything that appeared to
    /// would be a bug worth more than the convenience. The conversation re-establishes
    /// on the next send, which is what a peer reinstalling already does.
    async fn restore_sessions(&mut self, provider: SessionProvider, sessions: &[u8]) -> Result<()> {
        if provider != SessionProvider::of::<P>() {
            return Ok(());
        }
        let restored = self.party.import_sessions(sessions).await.map_err(crypto)?;
        for peer in &restored {
            self.sessions.insert(device_addr(peer));
        }
        Ok(())
    }

    /// Offer the directory a batch of one-time bundles, best-effort.
    ///
    /// See the call site for why a failure here is not a connection failure.
    async fn deposit_prekeys(party: &mut P, directory: &mut DirConnection, me: &DeviceAddr) {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let Ok(batch) = party.publish_one_time_batch(&mut rng).await else {
            return;
        };
        if batch.is_empty() {
            return;
        }
        let identity = party.identity_key();
        let _ = directory
            .deposit_prekeys(me, identity, batch, |ch| {
                party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
            })
            .await;
    }

    /// Publish `party`'s bundle to the directory and authenticate it to the
    /// relay. Shared by [`connect`](Client::connect) (fresh identity) and
    /// [`connect_with_identity`](Client::connect_with_identity) (saved one).
    async fn connect_with_party(config: &Config, mut party: P, dialer: &Dialer) -> Result<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let me = DeviceAddr::new(config.user.clone(), u32::from(config.device));

        // Publish identity + prekey bundle to the directory.
        let bundle_bytes = party.publish_bundle(&mut rng).await.map_err(crypto)?;
        let identity = party.identity_key();
        let mut directory = dialer.directory(config.directory).await?;
        let outcome = directory
            .register(&me, identity, bundle_bytes, |ch| {
                party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
            })
            .await?;
        if !matches!(outcome, DirResponse::Registered | DirResponse::Refreshed) {
            return Err(Error::Directory(outcome));
        }

        // Stock the one-time bundle pool the directory dispenses from
        // (decision 0074). Registration replaces the pool, so this has to
        // follow it rather than precede it.
        //
        // **Not fatal if it fails, and that is a deliberate asymmetry.**
        // Without a pool the directory serves the multi-use bundle to
        // everyone, which is sound -- the signed prekey and the KEM
        // last-resort key are multi-use by design -- and costs only the extra
        // forward secrecy a one-time key would have added. Refusing to
        // connect over it would trade a working session for a stronger one
        // that is not available, which is the wrong way round. A provider
        // with no one-time prekeys returns an empty batch and skips the round
        // trip entirely.
        Self::deposit_prekeys(&mut party, &mut directory, &me).await;

        // Authenticate to the relay; it verifies against the directory.
        let sign = |ch: &[u8]| party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err());
        let mail = Arc::new(tokio::sync::Notify::new());
        let relay = dialer.relay(config.relay, &me, sign, mail.clone()).await?;

        Ok(Self {
            party,
            directory,
            relay,
            mail,
            me,
            sessions: HashSet::new(),
            session_provider: SessionProvider::of::<P>(),
            state_generation: 0,
            secure_store: None,
            restore: RestoreOutcome::Fresh,
            counter_seen: std::sync::atomic::AtomicU64::new(0),
            endpoints: Dialed {
                directory: config.directory,
                relay: config.relay,
                dialer: dialer.clone(),
            },
        })
    }

    /// This client's own address.
    pub fn address(&self) -> &DeviceAddr {
        &self.me
    }

    /// Serialize this client's identity secret so it can be persisted and
    /// reused across restarts via
    /// [`connect_with_identity`](Client::connect_with_identity). The bytes
    /// carry a private key — store them as a secret, at rest as carefully as
    /// any other key material.
    pub fn export_identity(&self) -> Vec<u8> {
        self.party.export_identity()
    }

    /// Serialize this client's full resumable state — its identity, its live
    /// ratchet sessions with every peer it has an open conversation with, **and
    /// its published prekey store** — so a process restart resumes conversations
    /// mid-ratchet instead of re-establishing them, and can still decrypt a
    /// *first-contact* message a new peer sent while this device was down.
    /// Re-establishing loses any message a peer sent while this device was down;
    /// persisting the sessions keeps live conversations decryptable, and
    /// persisting the prekeys keeps first contact decryptable — a message a new
    /// peer sent to a published one-time prekey is encrypted to that prekey, and
    /// its private half lives only in the prekey store. Restore with
    /// [`connect_with_state`](Client::connect_with_state) or
    /// [`sign_in_with_state`](Client::sign_in_with_state).
    ///
    /// The bytes carry the identity private key, session secrets and prekey
    /// private halves — store them as a secret, encrypted at rest. Supersedes
    /// [`export_identity`](Client::export_identity), which keeps only the
    /// identity.
    pub async fn export_state(&self) -> Result<Vec<u8>> {
        // A v3-shaped body, then the generation appended as a plaintext `u64`.
        // That plaintext tail is precisely what a file-rewriter forges,
        // which is why this path makes no rollback claim; `export_state_sealed`
        // binds the same generation inside an authenticator instead.
        let mut out = self.export_body_v3().await?;
        out[1] = STATE_VERSION_4;
        out.extend_from_slice(&self.state_generation.to_be_bytes());
        Ok(out)
    }

    /// Build the v3-shaped state body — `STATE_TAGGED, STATE_VERSION_3,
    /// provider`, then length-prefixed identity, sessions and prekeys.
    ///
    /// Shared by [`export_state`](Client::export_state) (which overwrites the
    /// version byte to v4 and appends a plaintext generation) and
    /// [`export_state_sealed`](Client::export_state_sealed) (which seals this
    /// body under a secure-storage key). Keeping one builder means the two paths
    /// cannot drift in what they carry.
    async fn export_body_v3(&self) -> Result<Vec<u8>> {
        let peers: Vec<Address> = self
            .sessions
            .iter()
            .filter_map(|addr| peer_address(addr).ok())
            .collect();
        let identity = self.party.export_identity();
        let sessions = self.party.export_sessions(&peers).await.map_err(crypto)?;
        // Empty when `publish_bundle` was never called; the section is still
        // written so the format is uniform, and an empty one is skipped on
        // restore.
        let prekeys = self.party.export_prekeys().unwrap_or_default();
        let mut out = vec![
            STATE_TAGGED,
            STATE_VERSION_3,
            self.session_provider.to_byte(),
        ];
        put_lp(&mut out, &identity);
        put_lp(&mut out, &sessions);
        put_lp(&mut out, &prekeys);
        Ok(out)
    }

    /// Export a **sealed** full state — decision 0078's anchor B, the
    /// rollback-resistant path: against an attacker who can rewrite the state
    /// file it refuses a forged generation and, via the per-send store counter,
    /// any state older than the latest send — closing the rollback gap against a
    /// file-rewriter given a rollback-resistant store.
    ///
    /// The bytes carry the same identity, sessions and prekeys as
    /// [`export_state`](Client::export_state), but the persisted-state
    /// generation is bound *inside* an authenticator keyed by the attached
    /// [`SecureStore`] rather than appended in plaintext, and the store's
    /// **rollback counter** is bound alongside it. An attacker who rewrites the
    /// file cannot forge either without the secure-storage key. Restore with
    /// [`connect_with_state_sealed`](Client::connect_with_state_sealed) or
    /// [`sign_in_with_state_sealed`](Client::sign_in_with_state_sealed).
    ///
    /// **Requires a store attached** ([`attach_secure_store`](Client::attach_secure_store),
    /// or a sealed restore, which attaches it). The counter it binds is the
    /// *current* value — send and receive advance it, so it already reflects this
    /// state's ratchet position; export does not bump it. That is what makes a
    /// restore of a state older than the latest send caught, not just an older
    /// *export* (the per-send window).
    ///
    /// The seal authenticates but does **not** encrypt: the bytes carry secrets
    /// and must be stored encrypted at rest. What the seal adds is freshness — the
    /// property the rollback finding is about — not confidentiality.
    pub async fn export_state_sealed(&self) -> Result<Vec<u8>> {
        let store = self.secure_store.as_ref().ok_or_else(|| {
            Error::SecureStore(
                "no secure store attached; call attach_secure_store before exporting sealed state"
                    .into(),
            )
        })?;
        let key = zeroize::Zeroizing::new(store.wrap_key().map_err(store_err)?);
        // Bind the counter's *current* value — send/receive advanced it, so it
        // already reflects this state's ratchet position. Reading, not bumping,
        // is what closes the per-send window: a restore of any state older than
        // the latest send presents a counter below the store's high-water mark.
        let counter = store.rollback_counter().map_err(store_err)?;
        let mut payload = Vec::new();
        put_lp(&mut payload, self.me.user.as_bytes());
        payload.extend_from_slice(&self.me.device.to_be_bytes());
        payload.extend_from_slice(&self.export_body_v3().await?);
        payload.extend_from_slice(&counter.to_be_bytes());
        let sealed = seal(&key, self.state_generation, &payload);
        let mut out = Vec::with_capacity(2 + sealed.len());
        out.push(STATE_TAGGED);
        out.push(STATE_VERSION_6);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Present this client's persisted-state generation to the directory
    /// (decision 0078), and act on a rollback.
    ///
    /// The directory advances its per-device anchor and reports whether the
    /// state is current (`Fresh`) or older than one it has already witnessed
    /// (`RolledBack`). On a rollback the sessions are discarded and the identity
    /// kept (decision 3): the ratchets an attacker rewound are not resumed, so
    /// they re-establish fresh on the next message and the attacker gets a
    /// client that has forgotten the chain keys it wanted replayed.
    ///
    /// **Opt-in, and detection-only.** This is 0078's anchor A. It is *not*
    /// invoked automatically on any shipping path, because the generation it
    /// presents is unauthenticated in the state file and a file-rewriter forges
    /// it — so calling it defends only against a
    /// legitimate backup restore or a naive whole-file replay, not against the
    /// file-rewriting attacker, and it exposes the anchor-poisoning DoS.
    /// A deployment that wants that limited detection calls it after connecting,
    /// after activity, and on a schedule; the real control waits for anchor B
    /// (an authenticated generation under a secure-storage key). Returns the
    /// directory's verdict; a network error is surfaced, the rollback is not an
    /// error.
    pub async fn checkpoint(&mut self) -> Result<DirResponse> {
        let generation = self.state_generation;
        // Disjoint field borrows: the witness borrows `directory`, the closure
        // borrows `party`.
        let party = &self.party;
        let response = self
            .directory
            .witness(&self.me, generation, |ch| {
                party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
            })
            .await?;
        if matches!(response, DirResponse::RolledBack) {
            self.discard_sessions();
        }
        Ok(response)
    }

    /// Discard every session while keeping the identity — decision 0078's
    /// decision 3. The single action taken on a detected rollback, whether the
    /// directory witness ([`checkpoint`](Client::checkpoint)) caught a coarse
    /// cross-generation one or the secure-storage counter caught a
    /// same-generation one on a sealed restore.
    fn discard_sessions(&mut self) {
        self.party.clear_sessions();
        self.sessions.clear();
        self.restore = RestoreOutcome::SessionsDiscarded;
    }

    /// What the constructor found: whether restored sessions are in use or
    /// were discarded as a rollback. Read it after any sign-in or connect;
    /// a rollback the directory catches later (`checkpoint`) moves it too.
    pub fn restore_outcome(&self) -> RestoreOutcome {
        self.restore
    }

    /// Turn on **per-send rollback protection** (decision 0078, closing the
    /// per-send window): hold `store` for the client's life so every send and
    /// every ratchet-advancing receive commits the freshness counter to it, and
    /// a sealed export binds that counter's current value.
    ///
    /// Call this once, before sending, on a freshly [`connect`](Client::connect)ed
    /// or [`sign_in`](Client::sign_in)ed client; a sealed restore
    /// ([`connect_with_state_sealed`](Client::connect_with_state_sealed)) attaches
    /// the store itself. Attaching the same store the platform holds for
    /// [`export_state_sealed`](Client::export_state_sealed) is what makes the
    /// counter monotone across restarts.
    ///
    /// One store per client: a second attach is refused as
    /// [`Error::InvalidArgument`], since re-rooting the counter mid-life
    /// would let a state older than the last send pass. The store's
    /// current counter is read on attach and every later bump must exceed
    /// it, so a store reset underneath the client fails the next send.
    pub fn attach_secure_store(&mut self, store: Arc<dyn SecureStore + Send + Sync>) -> Result<()> {
        if self.secure_store.is_some() {
            return Err(Error::InvalidArgument(
                "a secure store is already attached; a client takes one store for its life",
            ));
        }
        let seen = store.rollback_counter().map_err(store_err)?;
        self.counter_seen
            .store(seen, std::sync::atomic::Ordering::SeqCst);
        self.secure_store = Some(store);
        Ok(())
    }

    /// Commit one ratchet advance to the secure-storage counter, if a store is
    /// attached. Called on every send and every ratchet-advancing receive: it is
    /// the fine-grained freshness marker that closes the per-send window a
    /// per-export counter left open.
    ///
    /// **Fails the operation on a secure-storage error, deliberately.** If the
    /// advance cannot be recorded, a later restore could not tell that the
    /// ratchet had moved, so the safe choice is to refuse the send/receive rather
    /// than proceed with an un-recorded advance. A client that cannot tolerate
    /// that dependency should not attach a store (and gets no rollback claim).
    fn commit_ratchet_advance(&self) -> Result<()> {
        if let Some(store) = &self.secure_store {
            let advanced = store.bump_rollback_counter().map_err(store_err)?;
            let seen = self.counter_seen.load(std::sync::atomic::Ordering::SeqCst);
            // Monotone or nothing: a counter that did not move past what
            // this client has seen is a store reset or replaced under it,
            // and a send recorded against it would be unprotected.
            if advanced <= seen {
                return Err(Error::SecureStore(format!(
                    "the secure store's rollback counter did not advance ({advanced} after {seen})"
                )));
            }
            self.counter_seen
                .store(advanced, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }

    /// Whether this client currently holds an open session with `peer` — a
    /// conversation it can resume without a fresh handshake. Goes to `false`
    /// for every peer after a rollback [`checkpoint`](Client::checkpoint)
    /// discards the sessions.
    pub fn has_open_session(&self, peer: &DeviceAddr) -> bool {
        self.sessions.contains(peer)
    }

    /// Re-establish the directory and relay connections, re-authenticating
    /// with this client's identity. Sessions live in memory and survive, so
    /// conversations continue where they left off. [`send`](Client::send) and
    /// [`receive`](Client::receive) call this themselves (with bounded
    /// backoff) when they find the connection gone; it is public for a caller
    /// that wants to reconnect eagerly.
    pub async fn reconnect(&mut self) -> Result<()> {
        let dialer = &self.endpoints.dialer;
        let directory = dialer.directory(self.endpoints.directory).await?;
        let party = &self.party;
        let sign = |ch: &[u8]| party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err());
        let relay = dialer
            .relay(self.endpoints.relay, &self.me, sign, self.mail.clone())
            .await?;
        self.directory = directory;
        self.relay = relay;
        Ok(())
    }

    /// [`reconnect`](Client::reconnect) with bounded patience: an immediate
    /// attempt, then 1s/2s/4s/8s backoff — enough to ride out a server
    /// restart, bounded so a dead server surfaces as an error, not a hang.
    async fn reconnect_with_patience(&mut self) -> Result<()> {
        let mut delay = std::time::Duration::from_secs(1);
        let mut outcome = self.reconnect().await;
        for _ in 0..4 {
            if outcome.is_ok() {
                break;
            }
            // Half to one-and-a-half times the step: a fleet cut off by one
            // restart does not come back in lockstep.
            let jitter: u8 = rand::Rng::random(&mut rand::rngs::OsRng.unwrap_err());
            sleep(delay.mul_f64(0.5 + f64::from(jitter) / 255.0)).await;
            delay *= 2;
            outcome = self.reconnect().await;
        }
        outcome
    }

    /// Fetch and decode `to`'s published prekey bundle from the directory.
    /// A peer's published bundle, as bytes.
    ///
    /// Bytes rather than a decoded bundle: the seam takes a serialized bundle,
    /// so decoding it here would mean naming a provider's type to hand it
    /// straight back. Whether the bytes are a bundle at all is the provider's
    /// question, and it answers it in `establish_session`.
    async fn fetch_bundle(&mut self, to: &DeviceAddr) -> Result<Vec<u8>> {
        let DirResponse::Found { bundle, .. } = self.directory.lookup(to).await? else {
            return Err(Error::Relay(RelayRefusal::UnknownRecipient));
        };
        Ok(bundle)
    }

    /// Encrypt and send `message` to `to`, opening a session (via a
    /// directory lookup of the recipient's bundle) on first contact.
    ///
    /// If the connection is found dead, a bounded reconnect runs and the
    /// same ciphertext is retried once — the retry re-sends, it does not
    /// re-encrypt, so the ratchet advances exactly once per call. In the
    /// rare case where the first attempt landed before the connection
    /// died, the duplicate is dropped by the recipient (a replayed
    /// ciphertext cannot decrypt twice).
    pub async fn send(&mut self, to: &DeviceAddr, message: &[u8]) -> Result<()> {
        // Before any ratchet step or store commit: a message the relay would
        // refuse is the caller's mistake, and costs nothing here.
        if message.len() > MAX_MESSAGE_BYTES {
            return Err(Error::InvalidArgument(
                "message exceeds the relay's per-message size limit",
            ));
        }
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let peer = peer_address(to)?;
        if !self.sessions.contains(to) {
            let peer_bundle = match self.fetch_bundle(to).await {
                Err(Error::Io(_)) => {
                    self.reconnect_with_patience().await?;
                    self.fetch_bundle(to).await?
                }
                other => other?,
            };
            self.party
                .establish_session(&peer, &peer_bundle, &mut rng)
                .await
                .map_err(crypto)?;
            if self.sessions.insert(to.clone()) {
                // A new session is a session-affecting event (0078, decision 2).
                self.state_generation += 1;
            }
        }
        let framed = self
            .party
            .encrypt(&peer, message, &mut rng)
            .await
            .map_err(crypto)?;
        // The sending ratchet advanced; record it in secure storage before the
        // message goes out, so a restore of any state older than this send is
        // caught (the per-send window). No-op unless a store is attached.
        self.commit_ratchet_advance()?;
        let request = encode_request(&Request::Send {
            to: to.clone(),
            envelope: Envelope {
                kind: Kind::Dm,
                payload: framed,
            },
        });
        let resp = match self.relay.request(&request).await {
            Err(_) => {
                self.reconnect_with_patience().await?;
                self.relay.request(&request).await?
            }
            Ok(resp) => resp,
        };
        match decode_response(&resp) {
            Some(Response::Ok) => Ok(()),
            // Permanent: the message is over the relay's per-message size limit
            // Distinct from backpressure so a caller does not retry it.
            Some(Response::TooLarge) => Err(Error::Relay(RelayRefusal::TooLarge)),
            // Transient: the recipient's queue is at its count or byte budget.
            Some(Response::QueueFull) => Err(Error::Relay(RelayRefusal::QueueFull)),
            Some(Response::UnknownRecipient) => Err(Error::Relay(RelayRefusal::UnknownRecipient)),
            _ => Err(Error::Protocol("send was not accepted")),
        }
    }

    /// Wait for the next non-empty batch of mail, decrypting and
    /// acknowledging every pending message and returning each with its
    /// sender. Because the relay attributes messages, this works even for a
    /// first-contact message from a peer this client has never talked to.
    ///
    /// The relay is polled *before* waiting, so everything queued while this
    /// client was offline is drained immediately — a reconnecting client
    /// gets its backlog without waiting for the next push. If the connection
    /// is found dead, a bounded reconnect (immediate, then 1s/2s/4s/8s) runs
    /// before giving up.
    ///
    /// A message that cannot be decrypted — a replayed ciphertext, a corrupt
    /// envelope — is acknowledged past and dropped rather than returned:
    /// retrying it can never succeed, and refusing to advance would wedge
    /// the queue behind one poison message forever.
    pub async fn receive(&mut self) -> Result<Vec<Received>> {
        loop {
            let batch = self.drain().await?;
            if !batch.is_empty() {
                return Ok(batch);
            }
            // Nothing pending: wait for the server's push, then poll again.
            // The wait is on the mail signal rather than the connection, so
            // a head that holds this client behind a lock can do the same
            // wait without the lock (see [`mail`](Client::mail)); a dead
            // connection pings the signal too, and the next poll reconnects.
            self.mail.notified().await;
        }
    }

    /// The signal that says mail may be waiting: pinged on every push from
    /// the relay, across reconnects, and when a connection ends. A caller
    /// that shares this client behind a lock waits on this outside the lock
    /// and then calls [`drain`](Client::drain), so another task can `send`
    /// meanwhile; [`receive`](Client::receive) is that loop for a caller
    /// holding the client itself. The signal keeps one permit, so a push
    /// that lands between a poll and the wait is not missed.
    pub fn mail(&self) -> MailSignal {
        MailSignal(self.mail.clone())
    }

    /// Inbound messages as a stream, one at a time in the order the relay
    /// delivered them: [`receive`](Client::receive) flattened, for a caller
    /// that wants each message as it arrives rather than batches. The
    /// stream borrows the client while it is polled, so a task that also
    /// sends keeps the client behind a lock and does what the FFI and
    /// browser heads do: wait on [`mail`](Client::mail) outside the lock
    /// and [`drain`](Client::drain) inside it. An error is yielded once
    /// and ends the stream; calling again starts another. The stream is
    /// not `Unpin`: pin it (`std::pin::pin!`) before calling `next`.
    pub fn inbound(&mut self) -> impl futures_util::Stream<Item = Result<Received>> + '_ {
        futures_util::stream::try_unfold(
            (self, std::collections::VecDeque::new()),
            |(client, mut buffered)| async move {
                loop {
                    if let Some(message) = buffered.pop_front() {
                        return Ok(Some((message, (client, buffered))));
                    }
                    buffered.extend(client.receive().await?);
                }
            },
        )
    }

    /// A single non-blocking poll: whatever is queued for this device right now,
    /// or an empty batch if nothing is pending. Unlike [`receive`](Self::receive)
    /// it never waits for the server's push — the caller drives the cadence.
    ///
    /// This exists for a loop that must also do something else between checks
    /// for mail (read the keyboard, redraw a UI): `receive` would park in its
    /// wait and starve that work, and cancelling `receive` on a timer is unsafe
    /// because the poll it wraps is a socket round trip that must not be torn
    /// mid-response. `drain` returns promptly either way, so the caller decides
    /// when to poll again.
    pub async fn drain(&mut self) -> Result<Vec<Received>> {
        match self.poll_batch().await {
            Ok(batch) => Ok(batch),
            Err(Error::Io(_)) => {
                self.reconnect_with_patience().await?;
                self.poll_batch().await
            }
            Err(e) => Err(e),
        }
    }

    /// One poll: fetch whatever the relay holds for this device, decrypt
    /// what decrypts, acknowledge everything fetched. Empty if nothing was
    /// pending (or the whole batch was poison).
    async fn poll_batch(&mut self) -> Result<Vec<Received>> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let poll = encode_request(&Request::Poll {
            device: self.me.clone(),
        });
        let Some(Response::Delivered { from, messages }) =
            decode_response(&self.relay.request(&poll).await?)
        else {
            return Err(Error::Protocol("expected a delivery"));
        };

        let mut received = Vec::with_capacity(messages.len());
        for message in &messages {
            let Ok(peer) = peer_address(&message.from) else {
                continue;
            };
            let Ok(plaintext) = self
                .party
                .decrypt(&peer, &message.envelope.payload, &mut rng)
                .await
            else {
                continue;
            };
            if self.sessions.insert(message.from.clone()) {
                // First contact from a new peer establishes a session — a
                // session-affecting event (0078, decision 2).
                self.state_generation += 1;
            }
            received.push(Received {
                from: message.from.clone(),
                plaintext,
            });
        }

        // The receiving ratchet advanced for each decrypted message. Commit that
        // to the counter — **best-effort, unlike send**: the messages are already
        // decrypted, so failing here would lose them. The send path (where a
        // rewound ratchet would reuse keys) is the fail-closed guarantee; a secure-storage
        // failure during receive leaves only a narrow receive-side replay window.
        if !received.is_empty() {
            let _ = self.commit_ratchet_advance();
        }

        if !messages.is_empty() {
            let ack = encode_request(&Request::Ack {
                device: self.me.clone(),
                up_to: from + messages.len() as u64,
            });
            match decode_response(&self.relay.request(&ack).await?) {
                Some(Response::Acked { accepted: true }) => {}
                _ => return Err(Error::Protocol("acknowledgement was not accepted")),
            }
        }
        Ok(received)
    }

    /// Re-key this client's identity: generate a fresh identity, rotate the
    /// directory binding to it — authorized by the current key (decision
    /// record 0024) — and adopt it.
    ///
    /// Rotation invalidates existing peer sessions: the new identity has an
    /// empty store, so the next [`send`](Client::send) to each peer opens a
    /// fresh session, and a peer who verified the old key sees a
    /// safety-number change. The live relay connection, authenticated under
    /// the old key when the client connected, stays valid for its lifetime.
    pub async fn rotate(&mut self) -> Result<()> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let device =
            u8::try_from(self.me.device).map_err(|_| Error::Protocol("device id out of range"))?;
        let mut next = P::generate(&self.me.user, device, &mut rng).map_err(crypto)?;
        let new_bundle = next.publish_bundle(&mut rng).await.map_err(crypto)?;
        let new_identity = next.identity_key();

        // Possession is proved by the new key; the change is authorized by
        // the currently bound key. Disjoint borrows: the directory (mut), the
        // address, and the current key are separate fields of `self`.
        let current = &self.party;
        let outcome = self
            .directory
            .rotate(
                &self.me,
                new_identity,
                new_bundle,
                |ch| next.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
                |stmt| current.sign_challenge(stmt, &mut rand::rngs::OsRng.unwrap_err()),
            )
            .await?;
        if outcome != DirResponse::Rotated {
            return Err(Error::Directory(outcome));
        }
        self.party = next;
        self.sessions.clear();
        Ok(())
    }

    /// The delivered-to-all watermark across `devices`: how many messages the
    /// relay has confirmed delivered to *every* one of them (decision record
    /// 0026) — the minimum of their per-device delivered counts. Every
    /// address must belong to this client's user; the relay refuses a query
    /// that spans another user's devices.
    pub async fn delivered_watermark(&mut self, devices: &[DeviceAddr]) -> Result<u64> {
        let request = encode_request(&Request::Delivered {
            devices: devices.to_vec(),
        });
        match decode_response(&self.relay.request(&request).await?) {
            Some(Response::DeliveredCount { count }) => Ok(count),
            _ => Err(Error::Protocol("expected a delivered count")),
        }
    }

    /// Resolve `username` within this client's own tenant to a [`Contact`], or
    /// `None` if no such user is registered. The username is combined with the
    /// client's tenant — read from its own handle `"<tenant>/<user>"` — so it
    /// finds users in the same tenant; exact resolution only, no enumeration.
    /// Errs if this client is not operating under a tenant handle (the
    /// pre-account path). Resolves the primary device (device 1); multi-device
    /// resolution is later work.
    pub async fn find(&mut self, username: &str) -> Result<Option<Contact>> {
        let tenant = self
            .me
            .user
            .split_once('/')
            .map(|(tenant, _)| tenant)
            .ok_or(Error::InvalidArgument(
                "client is not under a tenant handle",
            ))?;
        let address = DeviceAddr::new(format!("{tenant}/{username}"), 1);
        match self.directory.lookup(&address).await? {
            DirResponse::Found { .. } => Ok(Some(Contact { address })),
            DirResponse::NotFound => Ok(None),
            other => Err(Error::Directory(other)),
        }
    }

    /// Sign up a new user under a tenant. A control-plane action: it creates
    /// the account but does not connect — call [`sign_in`](Client::sign_in)
    /// afterwards for a connected client. `api_key` scopes it to the tenant.
    pub async fn sign_up(
        accounts: SocketAddr,
        api_key: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        Self::sign_up_trusting(accounts, &Dialer::tcp(None), api_key, username, password).await
    }

    /// Like [`sign_up`](Client::sign_up), but over TLS to a server presenting
    /// `server_name` (the hosted path).
    pub async fn sign_up_tls(
        accounts: SocketAddr,
        server_name: &str,
        tls: &ClientTls,
        api_key: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        Self::sign_up_trusting(
            accounts,
            &Dialer::tcp(Some((server_name, tls))),
            api_key,
            username,
            password,
        )
        .await
    }

    /// [`sign_up`](Client::sign_up) and [`sign_up_tls`](Client::sign_up_tls)
    /// in one: `trust` is `None` for plaintext, or the server name and the
    /// trust to check its certificate against. The tenant handle calls this.
    pub(crate) async fn sign_up_trusting(
        accounts: SocketAddr,
        dialer: &Dialer,
        api_key: &str,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let mut conn = dialer.accounts(accounts).await?;
        match conn.sign_up_user(api_key, username, password).await? {
            AccountResponse::UserCreated { .. } => Ok(()),
            // A success-shaped reply where a refusal was expected carries
            // things (a token, a key) that must not reach an error string.
            AccountResponse::TenantCreated { .. } | AccountResponse::SignedIn { .. } => {
                Err(Error::Protocol("unexpected account response"))
            }
            other => Err(Error::Account(other)),
        }
    }

    /// Sign in and provision a fresh device identity, returning a client that
    /// sends and receives under the account's handle (e.g. `acme/alice`).
    ///
    /// Save [`export_identity`](Client::export_identity) and reconnect with
    /// [`sign_in_with_identity`](Client::sign_in_with_identity) on later runs,
    /// so the device keeps the same key: re-provisioning a *new* key for an
    /// already-bound handle is refused by trust-on-first-use.
    pub async fn sign_in(config: &AccountConfig) -> Result<Self> {
        Self::sign_in_trusting(config, &Dialer::tcp(None)).await
    }

    /// Like [`sign_in`](Client::sign_in), but over TLS to a server presenting
    /// `server_name` (the hosted path). `tls` decides the trust —
    /// [`ClientTls::web_pki`] for a public CA such as Let's Encrypt.
    pub async fn sign_in_tls(
        config: &AccountConfig,
        server_name: &str,
        tls: &ClientTls,
    ) -> Result<Self> {
        Self::sign_in_trusting(config, &Dialer::tcp(Some((server_name, tls)))).await
    }

    /// [`sign_in`](Client::sign_in) and [`sign_in_tls`](Client::sign_in_tls)
    /// in one, keyed on `trust`.
    pub(crate) async fn sign_in_trusting(config: &AccountConfig, dialer: &Dialer) -> Result<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let party = P::generate(&config.identifier, config.device, &mut rng).map_err(crypto)?;
        Self::sign_in_with_party(config, party, dialer).await
    }

    /// Sign in and provision under a saved device identity (from
    /// [`export_identity`](Client::export_identity)), keeping the same bound
    /// key across restarts.
    pub async fn sign_in_with_identity(config: &AccountConfig, identity: &[u8]) -> Result<Self> {
        let party =
            P::from_identity(&config.identifier, config.device, identity).map_err(crypto)?;
        Self::sign_in_with_party(config, party, &Dialer::tcp(None)).await
    }

    /// Sign in under a full saved state (from
    /// [`export_state`](Client::export_state)): the same device identity *and*
    /// its live ratchet sessions, so conversations resume mid-ratchet across a
    /// process restart. The account-path sibling of
    /// [`connect_with_state`](Client::connect_with_state).
    pub async fn sign_in_with_state(config: &AccountConfig, state: &[u8]) -> Result<Self> {
        Self::sign_in_with_state_trusting(config, &Dialer::tcp(None), state).await
    }

    /// Like [`sign_in_with_state`](Client::sign_in_with_state), but over TLS to
    /// a server presenting `server_name` (the hosted path).
    pub async fn sign_in_with_state_tls(
        config: &AccountConfig,
        server_name: &str,
        tls: &ClientTls,
        state: &[u8],
    ) -> Result<Self> {
        Self::sign_in_with_state_trusting(config, &Dialer::tcp(Some((server_name, tls))), state)
            .await
    }

    /// [`sign_in_with_state`](Client::sign_in_with_state) and its TLS sibling
    /// in one, keyed on `trust`.
    pub(crate) async fn sign_in_with_state_trusting(
        config: &AccountConfig,
        dialer: &Dialer,
        state: &[u8],
    ) -> Result<Self> {
        let split = split_state(state)?;
        let mut party =
            P::from_identity(&config.identifier, config.device, split.identity).map_err(crypto)?;
        restore_prekeys_into(&mut party, &split)?;
        let mut client = Self::sign_in_with_party(config, party, dialer).await?;
        client
            .restore_sessions(split.provider, split.sessions)
            .await?;
        client.restore = RestoreOutcome::Resumed;
        client.state_generation = split.generation;
        // Anchor A (0078) is deliberately NOT auto-invoked here. Its detection
        // is defeatable by a file-rewriter, so this unsealed default path
        // makes no rollback claim and adds no exposure; `checkpoint` is public
        // for a deployment that opts into detection-only. The real control is
        // anchor B (an authenticated generation plus a per-send `SecureStore`
        // counter) — built, and living on the *sealed* path
        // (`connect_with_state_sealed` and siblings), not here.
        Ok(client)
    }

    /// Sign in under a **sealed** full state (from
    /// [`export_state_sealed`](Client::export_state_sealed)) — the account-path
    /// sibling of
    /// [`connect_with_state_sealed`](Client::connect_with_state_sealed), and the
    /// rollback-resistant sign-in path (decision 0078, anchor B). Attaches
    /// `store`; a forged state is refused, any state older than the latest send
    /// is caught by the store counter, and the generation is witnessed to the
    /// directory — closing the rollback gap against a file-rewriter given a
    /// rollback-resistant store.
    pub async fn sign_in_with_state_sealed(
        config: &AccountConfig,
        state: &[u8],
        store: Arc<dyn SecureStore + Send + Sync>,
    ) -> Result<Self> {
        Self::sign_in_with_state_sealed_trusting(config, &Dialer::tcp(None), state, store).await
    }

    /// Like [`sign_in_with_state_sealed`](Client::sign_in_with_state_sealed),
    /// but over TLS to a server presenting `server_name` (the hosted path).
    pub async fn sign_in_with_state_sealed_tls(
        config: &AccountConfig,
        server_name: &str,
        tls: &ClientTls,
        state: &[u8],
        store: Arc<dyn SecureStore + Send + Sync>,
    ) -> Result<Self> {
        Self::sign_in_with_state_sealed_trusting(
            config,
            &Dialer::tcp(Some((server_name, tls))),
            state,
            store,
        )
        .await
    }

    /// [`sign_in_with_state_sealed`](Client::sign_in_with_state_sealed) and
    /// its TLS sibling in one, keyed on the dialer. The tenant handle calls
    /// this.
    pub(crate) async fn sign_in_with_state_sealed_trusting(
        config: &AccountConfig,
        dialer: &Dialer,
        state: &[u8],
        store: Arc<dyn SecureStore + Send + Sync>,
    ) -> Result<Self> {
        let opened = open_sealed(&*store, state)?;
        // Before sign-in only the username and device are known; the exact
        // address (with its tenant) is checked once the server has said it.
        opened.expect_user(&config.identifier, u32::from(config.device))?;
        let split = split_state(&opened.body)?;
        let mut party =
            P::from_identity(&config.identifier, config.device, split.identity).map_err(crypto)?;
        restore_prekeys_into(&mut party, &split)?;
        let mut client = Self::sign_in_with_party(config, party, dialer).await?;
        opened.expect_address(&client.me)?;
        client
            .restore_sessions(split.provider, split.sessions)
            .await?;
        client.restore = RestoreOutcome::Resumed;
        client.state_generation = opened.generation;
        // Hold the store for the restored client's life (per-send commits
        // on), then act on any rollback the counter caught, before the
        // witness: the order is load-bearing.
        client.attach_secure_store(store)?;
        if opened.stale {
            client.discard_sessions();
        }
        let _ = client.checkpoint().await;
        Ok(client)
    }

    /// Sign in for a session token, provision `party`'s identity into the
    /// directory under the account's handle, then connect the directory and
    /// authenticate to the relay as that handle. Shared by
    /// [`sign_in`](Client::sign_in) and
    /// [`sign_in_with_identity`](Client::sign_in_with_identity).
    async fn sign_in_with_party(
        config: &AccountConfig,
        mut party: P,
        dialer: &Dialer,
    ) -> Result<Self> {
        let mut rng = rand::rngs::OsRng.unwrap_err();

        // Sign in for a session token.
        let mut accounts = dialer.accounts(config.accounts).await?;
        let token = match accounts
            .sign_in(&config.api_key, &config.identifier, &config.password)
            .await?
        {
            AccountResponse::SignedIn { token, .. } => token,
            AccountResponse::TenantCreated { .. } | AccountResponse::UserCreated { .. } => {
                return Err(Error::Protocol("unexpected account response"));
            }
            other => return Err(Error::Account(other)),
        };

        // Provision this device's identity under the account handle.
        let bundle_bytes = party.publish_bundle(&mut rng).await.map_err(crypto)?;
        let identity = party.identity_key();
        let mut provisioning = dialer.provisioning(config.provisioning).await?;
        let handle = match provisioning
            .provision(
                &token,
                u32::from(config.device),
                identity,
                bundle_bytes,
                |ch| party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
            )
            .await?
        {
            ProvisionOutcome::Provisioned { handle } => handle,
            other => return Err(Error::Provision(other)),
        };
        let me = DeviceAddr::new(handle, u32::from(config.device));

        // Connect the directory (peer lookups) and authenticate to the relay
        // as the provisioned handle.
        let directory = dialer.directory(config.directory).await?;
        let sign = |ch: &[u8]| party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err());
        let mail = Arc::new(tokio::sync::Notify::new());
        let relay = dialer.relay(config.relay, &me, sign, mail.clone()).await?;

        Ok(Self {
            party,
            directory,
            relay,
            mail,
            me,
            sessions: HashSet::new(),
            session_provider: SessionProvider::of::<P>(),
            state_generation: 0,
            secure_store: None,
            restore: RestoreOutcome::Fresh,
            counter_seen: std::sync::atomic::AtomicU64::new(0),
            endpoints: Dialed {
                directory: config.directory,
                relay: config.relay,
                dialer: dialer.clone(),
            },
        })
    }
}

/// Sleep on the runtime this target has: tokio's timer natively, the
/// browser's in wasm.
async fn sleep(d: std::time::Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(d).await;
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::sleep(d).await;
}
