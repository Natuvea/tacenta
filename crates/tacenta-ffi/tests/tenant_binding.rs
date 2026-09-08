//! The binding drives the tenant handle as a Swift or Kotlin caller would
//! (decision 0090): connect through a service document, sign users up
//! and in, message by handle, resume from state, and take the WebSocket
//! carriage. All blocking, no async on the caller's side, and no host or
//! port below the document.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tacenta_accounts::{AccountResponse, AccountStore, Accounts};
use tacenta_discovery::{ServiceDocument, Tls};
use tacenta_ffi::{ClientError, Tenant};
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::AccountConnection;

/// A server, a gateway publishing its document (with the carriage), and a
/// tenant. Returns the document URL and the API key.
fn stack(rt: &tokio::runtime::Runtime) -> (String, String) {
    rt.block_on(async {
        let server = Server::bind(&ServerConfig {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            directory_port: 0,
            relay_port: 0,
            accounts_port: 0,
            provisioning_port: 0,
            database_url: None,
            data_dir: None,
            tls: None,
            snapshot_interval: None,
            relay_max_total_bytes: None,
            registration_max_per_hour: None,
            registration_policy: None,
            max_connections: None,
        })
        .await
        .unwrap();
        let ports = [
            server.directory_addr().unwrap().port(),
            server.relay_addr().unwrap().port(),
            server.accounts_addr().unwrap().port(),
            server.provisioning_addr().unwrap().port(),
        ];
        let accounts = server.accounts_addr().unwrap();
        tokio::spawn(server.serve());

        let mut admin = AccountConnection::connect(accounts).await.unwrap();
        let AccountResponse::TenantCreated { api_key, .. } = admin
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .await
            .unwrap()
        else {
            panic!("expected a tenant");
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let doc = ServiceDocument::on("127.0.0.1", "127.0.0.1", ports, Tls::None)
            .with_ws(&format!("ws://127.0.0.1:{port}/v1/ws"));
        let state = tacenta_gateway::GatewayState::with_service(
            Arc::new(AccountStore::memory(Accounts::new())),
            doc,
        )
        .unwrap();
        tokio::spawn(async move {
            axum::serve(listener, tacenta_gateway::app(state, &[]))
                .await
                .unwrap();
        });
        (
            format!("http://127.0.0.1:{port}/.well-known/tacenta"),
            api_key,
        )
    })
}

#[test]
fn the_binding_drives_the_tenant_handle() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (document_url, api_key) = stack(&rt);
    rt.block_on(drive(document_url, api_key));
}

async fn drive(document_url: String, api_key: String) {
    let tenant = Tenant::connect_via(api_key.clone(), document_url.clone())
        .await
        .unwrap();
    assert!(!tenant.is_websocket());
    tenant
        .sign_up("alice".into(), "hunter2!!".into())
        .await
        .unwrap();
    tenant
        .sign_up("bob".into(), "hunter2!!".into())
        .await
        .unwrap();
    let alice = tenant
        .sign_in("alice".into(), "hunter2!!".into(), 1)
        .await
        .unwrap();
    let bob = tenant
        .sign_in("bob".into(), "hunter2!!".into(), 1)
        .await
        .unwrap();
    assert_eq!(alice.address().user, "acme/alice");
    let refused = tenant
        .sign_in("alice".into(), "wrong".into(), 1)
        .await
        .err()
        .expect("a wrong password is refused");
    assert!(
        matches!(refused, ClientError::SignInRefused { .. }),
        "{refused:?}"
    );

    let to_bob = alice.find("bob".into()).await.unwrap().unwrap().address;
    let nobody = tacenta_ffi::Address {
        user: "acme/nobody".into(),
        device: 1,
    };
    let unregistered = alice
        .send(nobody, b"to no one".to_vec())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(unregistered, ClientError::NotFound { .. }),
        "{unregistered:?}"
    );
    let taken = tenant
        .sign_up("alice".into(), "hunter2!!".into())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(taken, ClientError::UsernameTaken { .. }),
        "{taken:?}"
    );
    alice
        .send(to_bob.clone(), b"north dock".to_vec())
        .await
        .unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"north dock");

    // A receive the caller abandons (a cancelled task on the foreign side)
    // loses nothing: the wait carries on, and the batch it lands is what
    // the next receive returns.
    let abandoned =
        tokio::time::timeout(std::time::Duration::from_millis(200), alice.receive()).await;
    assert!(
        abandoned.is_err(),
        "nothing was waiting, so the receive should still be pending"
    );
    bob.send(alice.address(), b"after the cancel".to_vec())
        .await
        .unwrap();
    let batch = alice.receive().await.unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].plaintext, b"after the cancel");

    // A receive left pending does not hold the client: a send goes through
    // meanwhile, and the pending receive gets the reply it provokes.
    let waiting = {
        let alice = alice.clone();
        tokio::spawn(async move { alice.receive().await })
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        alice.send(to_bob.clone(), b"while receiving".to_vec()),
    )
    .await
    .expect("the send went through while the receive was pending")
    .unwrap();
    assert_eq!(
        bob.receive().await.unwrap()[0].plaintext,
        b"while receiving"
    );
    bob.send(alice.address(), b"to the pending receive".to_vec())
        .await
        .unwrap();
    let got = waiting.await.unwrap().unwrap();
    assert_eq!(got[0].plaintext, b"to the pending receive");

    // The stream form: the same receive underneath, one message at a time,
    // across however many batches the relay makes of them.
    bob.send(alice.address(), b"one".to_vec()).await.unwrap();
    bob.send(alice.address(), b"two".to_vec()).await.unwrap();
    let inbound = alice.clone().inbound();
    assert_eq!(inbound.next().await.unwrap().plaintext, b"one");
    assert_eq!(inbound.next().await.unwrap().plaintext, b"two");
    // Nothing queued: `next` waits for mail, and a send from another task
    // goes through meanwhile, as `receive` does.
    let waiting = {
        let inbound = inbound.clone();
        tokio::spawn(async move { inbound.next().await })
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        alice.send(to_bob.clone(), b"still sending".to_vec()),
    )
    .await
    .expect("the send went through while next was pending")
    .unwrap();
    assert_eq!(bob.receive().await.unwrap()[0].plaintext, b"still sending");
    bob.send(alice.address(), b"three".to_vec()).await.unwrap();
    assert_eq!(waiting.await.unwrap().unwrap().plaintext, b"three");
    drop(inbound);

    // Resume from state through the handle; the session continues, and the
    // dropped client's connections went with it rather than lingering.
    let state = alice.export_state().await.unwrap();
    drop(alice);
    let again = tenant
        .sign_in_with_state("alice".into(), "hunter2!!".into(), state, 1)
        .await
        .unwrap();
    bob.send(again.address(), b"welcome back".to_vec())
        .await
        .unwrap();
    assert_eq!(again.receive().await.unwrap()[0].plaintext, b"welcome back");
    assert_eq!(
        again.restore_outcome().await.unwrap(),
        tacenta_ffi::RestoreOutcome::Resumed
    );
    assert_eq!(
        bob.restore_outcome().await.unwrap(),
        tacenta_ffi::RestoreOutcome::Fresh
    );

    // The same tenant over the carriage: a browser's path, from a native head.
    let carried = tenant.websocket().unwrap();
    assert!(carried.is_websocket());
    carried
        .sign_up("carol".into(), "hunter2!!".into())
        .await
        .unwrap();
    let carol = carried
        .sign_in("carol".into(), "hunter2!!".into(), 1)
        .await
        .unwrap();
    let to_carol = bob.find("carol".into()).await.unwrap().unwrap().address;
    bob.send(to_carol, b"over the wire".to_vec()).await.unwrap();
    assert_eq!(
        carol.receive().await.unwrap()[0].plaintext,
        b"over the wire"
    );
}

#[test]
fn a_document_that_cannot_be_fetched_is_a_readable_error() {
    let err = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(Tenant::connect_via(
            "tct_x".into(),
            "http://127.0.0.1:1/.well-known/tacenta".into(),
        ))
        .err()
        .expect("nothing listens on port 1");
    assert!(
        err.to_string().contains("service discovery failed"),
        "{err}"
    );
    assert!(matches!(err, ClientError::Discovery { .. }), "{err:?}");
}
