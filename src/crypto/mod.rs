use crate::core::{GhostChatError, Result, SessionConfig};
use openmls::prelude::*;
use openmls_basic_credential::{BasicCredential, CredentialWithKey, SignatureKeyPair};
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// Wrapper around the MLS cryptographic operations.
/// This layer separates the core application logic from the openmls library.
pub struct CryptoManager {
    pub provider: OpenMlsRustCrypto,
    pub storage: MemoryStorage,
    pub config: SessionConfig,
}

impl CryptoManager {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            storage: MemoryStorage::default(),
            config,
        }
    }

    /// Verification that we can instantiate a basic group with the chosen ciphersuite.
    /// This is a health check for the openmls integration.
    pub fn verify_integration(&self) -> Result<()> {
        let signature_key_pair =
            SignatureKeyPair::new(self.config.ciphersuite.signature_algorithm())
                .map_err(|e| GhostChatError::CryptoError(e.to_string()))?;

        let identity = rand::random::<[u8; 32]>().to_vec();
        let credential = BasicCredential::new(identity);

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_key_pair.public().into(),
        };

        // Attempt to create an MLS group to verify ciphersuite and provider integration
        let _mls_group = MlsGroup::new(
            &self.provider,
            &signature_key_pair,
            &MlsGroupCreateConfig::default(),
            credential_with_key,
        )
        .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(())
    }

    /// This interface will be used to implement the periodic epoch advance.
    /// The actual implementation will call MlsGroup::self_update.
    pub fn advance_epoch(&self, _group: &mut MlsGroup) -> Result<()> {
        // Placeholder for the self_update call to be implemented in the messaging layer.
        Ok(())
    }
}

// MlsGroupInterface trait is no longer needed since CryptoManager
// directly interacts with MlsGroup; removing for simplicity.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_manager_new_initializes_providers() {
        let config = SessionConfig::default();
        let crypto_manager = CryptoManager::new(config.clone());
        assert_eq!(crypto_manager.config.ciphersuite, config.ciphersuite);
    }

    #[test]
    fn crypto_manager_verify_integration_succeeds() {
        let config = SessionConfig::default();
        let crypto_manager = CryptoManager::new(config);
        assert!(crypto_manager.verify_integration().is_ok());
    }
}
