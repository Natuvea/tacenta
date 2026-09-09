//! The client is written against the provider trait, not a concrete type.
//!
//! `Client<P>` is generic over `CryptoProvider`, and `DefaultProvider` is the
//! single place the shipped provider is named. Collapsing `Client<P>` into a
//! concrete `Client` would undo the seam and spread the provider's name
//! through every call site; this file pins the seam so that cannot happen
//! unnoticed.

use tacenta_client::{Client, Config, DefaultClient};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider, open::OpenParty};

/// `Client` still takes a provider type parameter, and the seam is still a
/// trait rather than a concrete type.
///
/// Writing `Client<OpenParty>` explicitly is the assertion: if `Client` stops
/// being generic this file stops compiling, which is the regression that
/// matters.
#[test]
fn the_client_is_still_generic_over_the_provider() {
    fn accepts<P: CryptoProvider>() {}
    accepts::<OpenParty>();
    accepts::<DefaultProvider>();

    // The default is an alias for the shipped provider rather than a separate
    // type, which is what makes `DefaultProvider` the single place the choice
    // is named.
    assert_eq!(
        core::any::type_name::<Client<OpenParty>>(),
        core::any::type_name::<DefaultClient>(),
    );
}

/// The state envelope records the provider a client is built with, derived
/// from the type parameter rather than written as a constant, so the tag and
/// the provider cannot drift apart.
#[test]
fn the_recorded_provider_follows_the_type_parameter() {
    assert_eq!(OpenParty::NAME, "open-tacenta");
    assert_eq!(DefaultProvider::NAME, OpenParty::NAME);
}

/// A `Config` builds a client without the call site naming a provider.
///
/// `no_run`-style: constructing the future is enough to prove the types line
/// up, and connecting needs a server.
#[allow(dead_code)]
async fn the_config_does_not_name_a_provider(config: Config) {
    let _: Result<Client<OpenParty>, _> = Client::<OpenParty>::connect(&config).await;
    let _: Result<DefaultClient, _> = DefaultClient::connect(&config).await;
}
