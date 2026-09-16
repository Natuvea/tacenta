//! Server composition for durable hosted inventory statements.
//!
//! The caller is responsible for account-session authorization and proof of
//! possession before it reaches this service. This narrow layer commits the
//! lifecycle transition, then signs exactly the resulting durable state. A
//! retry reaches the account store's idempotency record and is signed from the
//! same committed inventory generation.

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
}

impl std::fmt::Display for InventoryServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "inventory store failure: {error}"),
            Self::MissingHandle => f.write_str("inventory account has no directory handle"),
            Self::Signing => f.write_str("inventory statement could not be signed"),
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
