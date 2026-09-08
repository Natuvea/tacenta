//! Wire protocol for the account service — the request/response types a
//! client and server exchange to sign up and sign in, and their byte
//! encoding. The shape mirrors the directory protocol: a one-byte tag then
//! length-prefixed fields, hand-encoded (no serde), decoding to `None` on any
//! malformation.
//!
//! These requests carry **plaintext passwords and API keys**. The transport
//! is expected to be TLS in any real deployment (the account server has a TLS
//! serve path, as the directory does); the server hashes the password with
//! argon2id on arrival and never stores it. Client-side password hashing
//! (SRP / OPAQUE, so the server never sees the password) is a future option,
//! not this baseline.

use crate::SignupError;

/// A client's request to the account service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountRequest {
    /// Create a new tenant with a unique username, email, and password.
    SignUpTenant {
        username: String,
        email: String,
        password: String,
    },
    /// Create a user within the tenant selected by `api_key`. Users sign up
    /// with a username and password only — no email (only tenants have one).
    SignUpUser {
        api_key: String,
        username: String,
        password: String,
    },
    /// Sign in a user within the tenant selected by `api_key`, by username plus
    /// password.
    SignIn {
        api_key: String,
        identifier: String,
        password: String,
    },
}

/// The account service's response.
#[derive(Clone, PartialEq, Eq)]
pub enum AccountResponse {
    /// A tenant was created; carries its id and its one-time API key.
    TenantCreated { tenant_id: String, api_key: String },
    /// A user was created; carries the user's handle (username).
    UserCreated { username: String },
    /// A sign-in succeeded; carries the resolved handle and a session token
    /// the client presents to authorise later account actions.
    SignedIn { username: String, token: String },
    /// A signup was refused, with a coarse reason.
    SignupRefused { reason: SignupReason },
    /// A sign-in was refused. Coarse by design: it does not say whether the
    /// account exists.
    SignInRefused,
    /// The API key did not select a known tenant.
    UnknownTenant,
    /// The server could not process the request (a backend failure). Transient;
    /// the request was not applied.
    ServerError,
    /// Too many recent failed sign-ins for this identifier, so the credential
    /// check was refused without running. Not an existence oracle: the
    /// counter keys unknown identifiers too (see `ratelimit`). Back off.
    RateLimited,
}

/// Redacts the API key and the session token: a reply in a log line or an
/// error string must not carry either.
impl std::fmt::Debug for AccountResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountResponse::TenantCreated { tenant_id, .. } => f
                .debug_struct("TenantCreated")
                .field("tenant_id", tenant_id)
                .field("api_key", &"<redacted>")
                .finish(),
            AccountResponse::UserCreated { username } => f
                .debug_struct("UserCreated")
                .field("username", username)
                .finish(),
            AccountResponse::SignedIn { username, .. } => f
                .debug_struct("SignedIn")
                .field("username", username)
                .field("token", &"<redacted>")
                .finish(),
            AccountResponse::SignupRefused { reason } => f
                .debug_struct("SignupRefused")
                .field("reason", reason)
                .finish(),
            AccountResponse::SignInRefused => f.write_str("SignInRefused"),
            AccountResponse::UnknownTenant => f.write_str("UnknownTenant"),
            AccountResponse::ServerError => f.write_str("ServerError"),
            AccountResponse::RateLimited => f.write_str("RateLimited"),
        }
    }
}

/// The coarse, wire-serialisable reason a signup was refused. Mirrors the
/// field-level [`SignupError`] variants; `UnknownTenant` is not here because
/// the protocol surfaces it as its own response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignupReason {
    UsernameTaken,
    EmailTaken,
    InvalidUsername,
    InvalidEmail,
    WeakPassword,
}

impl SignupError {
    /// The wire reason for this error, or `None` for `UnknownTenant` (which
    /// the protocol surfaces as [`AccountResponse::UnknownTenant`]).
    pub fn reason(&self) -> Option<SignupReason> {
        match self {
            SignupError::UsernameTaken => Some(SignupReason::UsernameTaken),
            SignupError::EmailTaken => Some(SignupReason::EmailTaken),
            SignupError::InvalidUsername => Some(SignupReason::InvalidUsername),
            SignupError::InvalidEmail => Some(SignupReason::InvalidEmail),
            SignupError::WeakPassword => Some(SignupReason::WeakPassword),
            SignupError::UnknownTenant => None,
        }
    }
}

pub(crate) fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

pub(crate) fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_be_bytes(head.try_into().ok()?), rest))
}

pub(crate) fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}

pub(crate) fn take_u64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, rest) = bytes.split_at_checked(8)?;
    Some((u64::from_be_bytes(head.try_into().ok()?), rest))
}

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, u32::try_from(s.len()).expect("field fits u32"));
    out.extend_from_slice(s.as_bytes());
}

pub(crate) fn take_str(bytes: &[u8]) -> Option<(String, &[u8])> {
    let (len, rest) = take_u32(bytes)?;
    let (s, rest) = rest.split_at_checked(len as usize)?;
    Some((String::from_utf8(s.to_vec()).ok()?, rest))
}

/// Encode a request. Tags: 1 = SignUpTenant, 2 = SignUpUser, 3 = SignIn.
pub fn encode_account_request(request: &AccountRequest) -> Vec<u8> {
    let mut out = Vec::new();
    match request {
        AccountRequest::SignUpTenant {
            username,
            email,
            password,
        } => {
            out.push(1);
            put_str(&mut out, username);
            put_str(&mut out, email);
            put_str(&mut out, password);
        }
        AccountRequest::SignUpUser {
            api_key,
            username,
            password,
        } => {
            out.push(2);
            put_str(&mut out, api_key);
            put_str(&mut out, username);
            put_str(&mut out, password);
        }
        AccountRequest::SignIn {
            api_key,
            identifier,
            password,
        } => {
            out.push(3);
            put_str(&mut out, api_key);
            put_str(&mut out, identifier);
            put_str(&mut out, password);
        }
    }
    out
}

/// Decode a request; `None` on any malformation.
pub fn decode_account_request(bytes: &[u8]) -> Option<AccountRequest> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => {
            let (username, rest) = take_str(rest)?;
            let (email, rest) = take_str(rest)?;
            let (password, rest) = take_str(rest)?;
            rest.is_empty().then_some(AccountRequest::SignUpTenant {
                username,
                email,
                password,
            })
        }
        2 => {
            let (api_key, rest) = take_str(rest)?;
            let (username, rest) = take_str(rest)?;
            let (password, rest) = take_str(rest)?;
            rest.is_empty().then_some(AccountRequest::SignUpUser {
                api_key,
                username,
                password,
            })
        }
        3 => {
            let (api_key, rest) = take_str(rest)?;
            let (identifier, rest) = take_str(rest)?;
            let (password, rest) = take_str(rest)?;
            rest.is_empty().then_some(AccountRequest::SignIn {
                api_key,
                identifier,
                password,
            })
        }
        _ => None,
    }
}

/// Encode a response. Tags: 1 = TenantCreated, 2 = UserCreated, 3 = SignedIn,
/// 4 = SignupRefused, 5 = SignInRefused, 6 = UnknownTenant, 7 = ServerError,
/// 8 = RateLimited.
pub fn encode_account_response(response: &AccountResponse) -> Vec<u8> {
    let mut out = Vec::new();
    match response {
        AccountResponse::TenantCreated { tenant_id, api_key } => {
            out.push(1);
            put_str(&mut out, tenant_id);
            put_str(&mut out, api_key);
        }
        AccountResponse::UserCreated { username } => {
            out.push(2);
            put_str(&mut out, username);
        }
        AccountResponse::SignedIn { username, token } => {
            out.push(3);
            put_str(&mut out, username);
            put_str(&mut out, token);
        }
        AccountResponse::SignupRefused { reason } => {
            out.push(4);
            out.push(reason_tag(*reason));
        }
        AccountResponse::SignInRefused => out.push(5),
        AccountResponse::UnknownTenant => out.push(6),
        AccountResponse::ServerError => out.push(7),
        AccountResponse::RateLimited => out.push(8),
    }
    out
}

/// Decode a response; `None` on any malformation.
pub fn decode_account_response(bytes: &[u8]) -> Option<AccountResponse> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => {
            let (tenant_id, rest) = take_str(rest)?;
            let (api_key, rest) = take_str(rest)?;
            rest.is_empty()
                .then_some(AccountResponse::TenantCreated { tenant_id, api_key })
        }
        2 => {
            let (username, rest) = take_str(rest)?;
            rest.is_empty()
                .then_some(AccountResponse::UserCreated { username })
        }
        3 => {
            let (username, rest) = take_str(rest)?;
            let (token, rest) = take_str(rest)?;
            rest.is_empty()
                .then_some(AccountResponse::SignedIn { username, token })
        }
        4 => {
            let (&code, rest) = rest.split_first()?;
            rest.is_empty()
                .then(|| tag_reason(code))
                .flatten()
                .map(|reason| AccountResponse::SignupRefused { reason })
        }
        5 => rest.is_empty().then_some(AccountResponse::SignInRefused),
        6 => rest.is_empty().then_some(AccountResponse::UnknownTenant),
        7 => rest.is_empty().then_some(AccountResponse::ServerError),
        8 => rest.is_empty().then_some(AccountResponse::RateLimited),
        _ => None,
    }
}

fn reason_tag(reason: SignupReason) -> u8 {
    match reason {
        SignupReason::UsernameTaken => 1,
        SignupReason::EmailTaken => 2,
        SignupReason::InvalidUsername => 3,
        SignupReason::InvalidEmail => 4,
        SignupReason::WeakPassword => 5,
    }
}

fn tag_reason(tag: u8) -> Option<SignupReason> {
    match tag {
        1 => Some(SignupReason::UsernameTaken),
        2 => Some(SignupReason::EmailTaken),
        3 => Some(SignupReason::InvalidUsername),
        4 => Some(SignupReason::InvalidEmail),
        5 => Some(SignupReason::WeakPassword),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_round_trips(request: AccountRequest) {
        assert_eq!(
            decode_account_request(&encode_account_request(&request)),
            Some(request),
        );
    }

    fn response_round_trips(response: AccountResponse) {
        assert_eq!(
            decode_account_response(&encode_account_response(&response)),
            Some(response),
        );
    }

    #[test]
    fn requests_round_trip() {
        request_round_trips(AccountRequest::SignUpTenant {
            username: "acme".into(),
            email: "a@acme.example".into(),
            password: "correct horse".into(),
        });
        request_round_trips(AccountRequest::SignUpUser {
            api_key: "tct_abc".into(),
            username: "alice".into(),
            password: "hunter2!!".into(),
        });
        request_round_trips(AccountRequest::SignIn {
            api_key: "tct_abc".into(),
            identifier: "alice".into(),
            password: "hunter2!!".into(),
        });
    }

    #[test]
    fn responses_round_trip() {
        response_round_trips(AccountResponse::TenantCreated {
            tenant_id: "ten_1".into(),
            api_key: "tct_abc".into(),
        });
        response_round_trips(AccountResponse::UserCreated {
            username: "alice".into(),
        });
        response_round_trips(AccountResponse::SignedIn {
            username: "alice".into(),
            token: "ses_abc".into(),
        });
        response_round_trips(AccountResponse::SignupRefused {
            reason: SignupReason::EmailTaken,
        });
        response_round_trips(AccountResponse::SignInRefused);
        response_round_trips(AccountResponse::UnknownTenant);
        response_round_trips(AccountResponse::ServerError);
        response_round_trips(AccountResponse::RateLimited);
    }

    #[test]
    fn garbage_decodes_to_none() {
        assert_eq!(decode_account_request(&[]), None);
        assert_eq!(decode_account_request(&[9, 0, 0, 0, 0]), None);
        assert_eq!(decode_account_response(&[]), None);
        assert_eq!(
            decode_account_response(&[4, 99]),
            None,
            "unknown reason tag"
        );
        // A trailing byte past a complete message is a malformation.
        let mut extra = encode_account_response(&AccountResponse::SignInRefused);
        extra.push(0);
        assert_eq!(decode_account_response(&extra), None);
    }
}

#[cfg(test)]
mod redaction {
    use super::*;

    #[test]
    fn debug_output_redacts_the_secrets() {
        let created = format!(
            "{:?}",
            AccountResponse::TenantCreated {
                tenant_id: "t1".into(),
                api_key: "tct_secret".into()
            }
        );
        assert!(!created.contains("tct_secret"), "{created}");
        assert!(created.contains("<redacted>"));
        let signed = format!(
            "{:?}",
            AccountResponse::SignedIn {
                username: "alice".into(),
                token: "session-token".into()
            }
        );
        assert!(!signed.contains("session-token"), "{signed}");
    }
}
