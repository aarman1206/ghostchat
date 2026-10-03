use crate::core::{GhostChatError, Result, SessionConfig};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use zeroize::Zeroize;

/// Wrapper around the MLS cryptographic operations.
/// This layer separates the core application logic from the openmls library.
pub struct CryptoManager {
    pub provider: OpenMlsRustCrypto,
    pub config: SessionConfig,
}

impl Drop for CryptoManager {
    fn drop(&mut self) {
        self.clear_storage();
    }
}

impl CryptoManager {
    /// Best-effort erasure of serialized key/state copies owned by the memory
    /// provider. This is not a guarantee about OpenMLS temporaries or OS swap.
    fn clear_storage(&self) {
        let mut values = match self.provider.storage().values.write() {
            Ok(values) => values,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (mut key, mut value) in values.drain() {
            key.zeroize();
            value.zeroize();
        }
    }

    pub fn new(config: SessionConfig) -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
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
            &MlsGroupCreateConfig::builder()
                .ciphersuite(self.config.ciphersuite)
                .build(),
            credential_with_key,
        )
        .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(())
    }
}

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

    #[test]
    fn memory_provider_copies_are_cleared_at_teardown() {
        let manager = CryptoManager::new(SessionConfig::default());
        manager.verify_integration().unwrap();
        assert!(!manager.provider.storage().values.read().unwrap().is_empty());
        manager.clear_storage();
        assert!(manager.provider.storage().values.read().unwrap().is_empty());
    }
}
