//! Server composition for hosted inventory statements.
//!
//! The caller is responsible for account-session authorization and proof of
//! possession before it reaches this service. This narrow layer commits the
//! lifecycle transition, then signs exactly the resulting state, and only while
//! that state is still the account's current one.
//!
//! **A retry** reaches the account store's idempotency record and gets the
//! original committed result. If the account has not moved since, that result is
//! signed again (a new signature over the same statement). If it has, the
//! service returns [`InventoryServiceError::Superseded`] and signs nothing: a
//! fresh signature over an old generation would attest to devices that have
//! since been revoked.
//!
//! **Durability is the store backend's.** The Postgres backend has committed
//! the mutation before this service signs. The in-memory backend has not made it
//! durable at all until the server writes an account snapshot (on graceful
//! shutdown, and on `snapshot_interval` only if one is configured), so a crash
//! after signing can lose a mutation whose statement was already issued.

use std::sync::Arc;

use tacenta_accounts::{AccountStore, StoreError, TenantId};
use tacenta_core::crypto::groups::inventory::DeviceBinding;

use crate::inventory_issuer::InventoryIssuer;

/// Failure while turning a committed account lifecycle result into a hosted
/// inventory statement.
#[derive(Debug)]
pub enum InventoryServiceError {
    Store(StoreError),
    MissingHandle,
    Signing,
    /// The mutation is committed, or an earlier attempt with the same retry key
    /// committed it, but the account has since moved past that state, so the
    /// service refuses to sign it. The generations tell the caller how far.
    Superseded {
        committed_generation: u64,
        current_generation: u64,
    },
}

impl std::fmt::Display for InventoryServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "inventory store failure: {error}"),
            Self::MissingHandle => f.write_str("inventory account has no directory handle"),
            Self::Signing => f.write_str("inventory statement could not be signed"),
            Self::Superseded {
                committed_generation,
                current_generation,
            } => write!(
                f,
                "inventory generation {committed_generation} is superseded by \
                 generation {current_generation}; it is not signed again"
            ),
        }
    }
}

impl std::error::Error for InventoryServiceError {}

/// Commits account device lifecycle state before signing the corresponding
/// canonical hosted inventory statement.
pub struct HostedInventoryService {
    accounts: Arc<AccountStore>,
    issuer: InventoryIssuer,
}

impl HostedInventoryService {
    pub fn new(accounts: Arc<AccountStore>, issuer: InventoryIssuer) -> Self {
        Self { accounts, issuer }
    }

    pub fn issuer_public_key(&self) -> [u8; 32] {
        self.issuer.public_key()
    }

    pub async fn link_device_binding(
        &self,
        tenant: &TenantId,
        username: &str,
        predecessor_generation: u64,
        idempotency_key: [u8; 32],
        binding: DeviceBinding,
    ) -> Result<Vec<u8>, InventoryServiceError> {
        let inventory = self
            .accounts
            .link_device_binding(
                tenant,
                username,
                predecessor_generation,
                idempotency_key,
                binding,
            )
            .await
            .map_err(InventoryServiceError::Store)?;
        self.issue(tenant, username, inventory).await
    }

    async fn issue(
        &self,
        tenant: &TenantId,
        username: &str,
        inventory: tacenta_accounts::DeviceInventory,
    ) -> Result<Vec<u8>, InventoryServiceError> {
        // A retry returns the result of the first attempt, which may be old.
        // Sign only what is still current. The account may move again between
        // this read and the signature; that is inherent, and the statement's
        // generation is what a verifier orders by.
        let current = self
            .accounts
            .device_inventory(tenant, username)
            .await
            .map_err(InventoryServiceError::Store)?
            .ok_or(InventoryServiceError::MissingHandle)?;
        if current != inventory {
            return Err(InventoryServiceError::Superseded {
                committed_generation: inventory.generation,
                current_generation: current.generation,
            });
        }
        let handle = self
            .accounts
            .handle(tenant, username)
            .await
            .map_err(InventoryServiceError::Store)?
            .ok_or(InventoryServiceError::MissingHandle)?;
        self.issuer
            .issue(handle, inventory)
            .map_err(|_| InventoryServiceError::Signing)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::HostedInventoryService;
    use crate::inventory_issuer::InventoryIssuer;
    use tacenta_accounts::{AccountStore, Accounts};
    use tacenta_core::crypto::groups::inventory::{
        DeviceBinding, GROUP_EPOCH_V1, InventoryStatement,
    };

    #[tokio::test]
    async fn committed_link_is_what_the_issuer_signs() {
        let mut accounts = Accounts::new();
        let (tenant, _) = accounts
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        accounts
            .sign_up_user(&tenant.id, "alice", "hunter2!!")
            .unwrap();
        let service = HostedInventoryService::new(
            Arc::new(AccountStore::memory(accounts)),
            InventoryIssuer::from_secret(7, [9; 32]),
        );
        let binding = DeviceBinding {
            device_id: 1,
            identity_public_key: [3; 32],
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        };
        let statement = service
            .link_device_binding(&tenant.id, "alice", 0, [1; 32], binding.clone())
            .await
            .unwrap();
        let decoded =
            InventoryStatement::decode_signed(&statement, &service.issuer_public_key()).unwrap();
        assert_eq!(decoded.account_handle, "acme/alice");
        assert_eq!(decoded.inventory_generation, 1);
        assert_eq!(decoded.active, vec![binding]);
    }
}

#[cfg(test)]
mod retry_and_scope_tests {
    use std::sync::Arc;

    use super::{HostedInventoryService, InventoryServiceError};
    use crate::inventory_issuer::InventoryIssuer;
    use tacenta_accounts::{AccountStore, Accounts, InventoryError, StoreError, TenantId};
    use tacenta_core::crypto::groups::inventory::{
        DeviceBinding, GROUP_EPOCH_V1, InventoryStatement,
    };

    fn b(device_id: u32, key: u8) -> DeviceBinding {
        DeviceBinding {
            device_id,
            identity_public_key: [key; 32],
            capabilities: GROUP_EPOCH_V1,
            replacement_predecessor: None,
        }
    }

    fn fixture() -> (Arc<AccountStore>, HostedInventoryService, TenantId) {
        let mut accounts = Accounts::new();
        let (tenant, _) = accounts
            .sign_up_tenant("acme", "admin@acme.example", "correct horse")
            .unwrap();
        accounts
            .sign_up_user(&tenant.id, "alice", "hunter2!!")
            .unwrap();
        accounts
            .sign_up_user(&tenant.id, "bob", "hunter2!!")
            .unwrap();
        let store = Arc::new(AccountStore::memory(accounts));
        let service =
            HostedInventoryService::new(store.clone(), InventoryIssuer::from_secret(7, [9; 32]));
        (store, service, tenant.id)
    }

    fn decode(service: &HostedInventoryService, bytes: &[u8]) -> InventoryStatement {
        InventoryStatement::decode_signed(bytes, &service.issuer_public_key()).unwrap()
    }

    /// An immediate retry, while the account is still at the result's
    /// generation, is signed again over that same state. The signatures need
    /// not be byte-identical; the statements they carry are.
    #[tokio::test]
    async fn an_immediate_retry_is_signed_over_the_same_committed_state() {
        let (_, service, t) = fixture();
        let s1 = service
            .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .await
            .unwrap();
        let s2 = service
            .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .await
            .unwrap();
        let (d1, d2) = (decode(&service, &s1), decode(&service, &s2));
        assert_eq!((d1.inventory_generation, &d1.active), (1, &vec![b(1, 1)]));
        assert_eq!(d1, d2);
    }

    #[tokio::test]
    async fn a_changed_retry_and_a_stale_predecessor_are_typed_refusals() {
        let (_, service, t) = fixture();
        service
            .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .await
            .unwrap();
        assert!(matches!(
            service
                .link_device_binding(&t, "alice", 0, [1; 32], b(2, 2))
                .await,
            Err(InventoryServiceError::Store(StoreError::Inventory(
                InventoryError::IdempotencyConflict
            )))
        ));
        assert!(matches!(
            service
                .link_device_binding(&t, "alice", 0, [2; 32], b(2, 2))
                .await,
            Err(InventoryServiceError::Store(StoreError::Inventory(
                InventoryError::PredecessorMismatch
            )))
        ));
    }

    #[tokio::test]
    async fn statements_are_bound_to_their_own_account_and_issuer() {
        let (_, service, t) = fixture();
        let alice = service
            .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .await
            .unwrap();
        // The same key and body on another account is a fresh mutation there.
        let bob = service
            .link_device_binding(&t, "bob", 0, [1; 32], b(1, 1))
            .await
            .unwrap();
        assert_eq!(decode(&service, &alice).account_handle, "acme/alice");
        assert_eq!(decode(&service, &bob).account_handle, "acme/bob");
        assert!(matches!(
            service
                .link_device_binding(&t, "mallory", 0, [1; 32], b(1, 1))
                .await,
            Err(InventoryServiceError::Store(StoreError::Inventory(
                InventoryError::UnknownUser
            )))
        ));
        let other = InventoryIssuer::from_secret(8, [10; 32]);
        assert!(InventoryStatement::decode_signed(&alice, &other.public_key()).is_err());
    }

    /// A retry that arrives after the account has moved on names a generation
    /// that is no longer current. The service must not sign it: a fresh
    /// signature over the old state would attest that a since-revoked device is
    /// active. The retry is refused with the two generations, and the account
    /// is untouched.
    #[tokio::test]
    async fn a_retry_after_the_account_moved_on_is_refused_not_signed() {
        let (store, service, t) = fixture();
        service
            .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .await
            .unwrap();
        store
            .revoke_device_binding(&t, "alice", 1, [2; 32], b(1, 1))
            .await
            .unwrap();
        let retry = service
            .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .await;
        assert!(
            matches!(
                retry,
                Err(InventoryServiceError::Superseded {
                    committed_generation: 1,
                    current_generation: 2,
                })
            ),
            "got {retry:?}"
        );
        let now = store.device_inventory(&t, "alice").await.unwrap().unwrap();
        assert_eq!(now.generation, 2);
        assert!(now.active.is_empty());
    }
}
