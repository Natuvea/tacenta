//! `Error::kind()` is the contract every head branches on (decision 0090): each server outcome the client can meet
//! lands in the kind an app would expect.

use tacenta_client::{DeviceAddr, DirResponse, Error, ErrorKind, ProvisionOutcome, RelayRefusal};

#[test]
fn server_outcomes_land_in_the_kind_an_app_expects() {
    let cases: Vec<(Error, ErrorKind)> = vec![
        (
            Error::Io(std::io::Error::other("socket closed")),
            ErrorKind::Network,
        ),
        (Error::Discovery("no document".into()), ErrorKind::Discovery),
        (
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "authentication rejected",
            )),
            ErrorKind::IdentityMismatch,
        ),
        (
            Error::InvalidArgument("device id out of range"),
            ErrorKind::InvalidArgument,
        ),
        (
            Error::Relay(RelayRefusal::UnknownRecipient),
            ErrorKind::NotFound,
        ),
        (
            Error::Relay(RelayRefusal::QueueFull),
            ErrorKind::RateLimited,
        ),
        (
            Error::Relay(RelayRefusal::TooLarge),
            ErrorKind::InvalidArgument,
        ),
        (
            Error::Directory(DirResponse::Rejected),
            ErrorKind::IdentityMismatch,
        ),
        (Error::Directory(DirResponse::NotFound), ErrorKind::NotFound),
        (
            Error::Directory(DirResponse::RateLimited),
            ErrorKind::RateLimited,
        ),
        (
            Error::Directory(DirResponse::RegistrationClosed),
            ErrorKind::SignUpRefused,
        ),
        (Error::Directory(DirResponse::RolledBack), ErrorKind::State),
        (
            Error::Directory(DirResponse::PossessionFailed),
            ErrorKind::Internal,
        ),
        (
            Error::Provision(ProvisionOutcome::Rejected),
            ErrorKind::IdentityMismatch,
        ),
        (
            Error::Provision(ProvisionOutcome::BadSession),
            ErrorKind::SignInRefused,
        ),
        (
            Error::Provision(ProvisionOutcome::ServerError),
            ErrorKind::ServerFailure,
        ),
        (Error::SecureStore("altered".into()), ErrorKind::State),
        (
            Error::StoreUnavailable("locked".into()),
            ErrorKind::StoreUnavailable,
        ),
        (
            Error::StateMismatch {
                state: DeviceAddr::new("acme/bob", 1),
                client: DeviceAddr::new("acme/carol", 1),
            },
            ErrorKind::IdentityMismatch,
        ),
        (Error::Crypto("bad key".into()), ErrorKind::Internal),
        (Error::Protocol("short frame"), ErrorKind::Internal),
    ];
    for (error, kind) in cases {
        assert_eq!(error.kind(), kind, "{error}");
    }
}

#[test]
fn account_refusals_are_distinguishable() {
    use tacenta_accounts::{AccountResponse, SignupReason};
    for (reason, kind) in [
        (SignupReason::UsernameTaken, ErrorKind::UsernameTaken),
        (SignupReason::InvalidUsername, ErrorKind::InvalidUsername),
        (SignupReason::WeakPassword, ErrorKind::WeakPassword),
        (SignupReason::EmailTaken, ErrorKind::SignUpRefused),
        (SignupReason::InvalidEmail, ErrorKind::SignUpRefused),
    ] {
        assert_eq!(
            Error::Account(AccountResponse::SignupRefused { reason }).kind(),
            kind
        );
    }
    assert_eq!(
        Error::Account(AccountResponse::RateLimited).kind(),
        ErrorKind::RateLimited
    );
    assert_eq!(
        Error::Account(AccountResponse::UnknownTenant).kind(),
        ErrorKind::UnknownTenant
    );
    assert_eq!(
        Error::Account(AccountResponse::SignInRefused).kind(),
        ErrorKind::SignInRefused
    );
    assert_eq!(
        Error::Account(AccountResponse::ServerError).kind(),
        ErrorKind::ServerFailure
    );
}

#[test]
fn every_kind_has_the_name_the_other_heads_use() {
    // Spot checks; the surface test compares the whole table to the manifest.
    assert_eq!(ErrorKind::SignInRefused.as_str(), "signInRefused");
    assert_eq!(ErrorKind::InvalidArgument.as_str(), "invalidArgument");
}

#[test]
fn the_account_config_prints_no_secret() {
    let config = tacenta_client::AccountConfig {
        directory: "127.0.0.1:4720".parse().unwrap(),
        relay: "127.0.0.1:4721".parse().unwrap(),
        accounts: "127.0.0.1:4722".parse().unwrap(),
        provisioning: "127.0.0.1:4723".parse().unwrap(),
        api_key: "tct_secret".into(),
        identifier: "alice".into(),
        password: "hunter2!!".into(),
        device: 1,
    };
    let shown = format!("{config:?}");
    assert!(!shown.contains("tct_secret"), "{shown}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains("alice"));
}
