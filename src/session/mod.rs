//! Session management for GhostChat MLS groups.
//!
//! This module provides functions for creating MLS groups, joining participants,
//! sending/receiving application messages, and advancing epochs.
//!
use crate::{
    core::{GhostChatError, Result, SessionConfig},
    crypto::CryptoManager,
    identity::EphemeralIdentity,
    protocol::{self, Envelope, Message, RoomConfig},
};
use openmls::prelude::*;
use openmls_basic_credential::{BasicCredential, CredentialWithKey};
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// Manages an MLS group session.
///
/// Handles group creation, member joins, message exchange, and epoch advancement.
pub struct SessionManager {
    /// The underlying MLS group.
    pub group: openmls::group::MlsGroup,
    /// The crypto manager for cryptographic operations.
    pub crypto_manager: CryptoManager,
    /// The session configuration.
    pub config: SessionConfig,
    /// The identity of the session creator/manager.
    pub creator_identity: EphemeralIdentity,
}

impl SessionManager {
    /// Create a new MLS group with the given identity.
    ///
    /// This initializes a new MLS group with the creator as the first member.
    /// The creator's identity is stored in `creator_identity` and the MLS group
    /// is set up with the configured ciphersuite and participant limit.
    pub fn create_group(
        crypto_manager: CryptoManager,
        identity: EphemeralIdentity,
    ) -> Result<Self> {
        let group = openmls::group::MlsGroup::new(
            &crypto_manager.provider,
            &identity.signer,
            &openmls::group::MlsGroupCreateConfig::default(),
            identity.credential_with_key,
        )
        .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(Self {
            group,
            crypto_manager,
            config: SessionConfig::default(),
            creator_identity: identity,
        })
    }

    /// Add a new member to the group using their KeyPackage.
    pub fn add_member(
        &mut self,
        key_package: openmls::key_packages::KeyPackage,
    ) -> Result<(
        protocol::MlsMessageOut,
        protocol::MlsMessageOut,
        Option<protocol::GroupInfo>,
    )> {
        let (commit, welcome, group_info) = self
            .group
            .add_members(
                &self.crypto_manager.provider,
                &self.crypto_manager.provider.signer(),
                &[key_package],
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok((
            protocol::MlsMessageOut::from(commit),
            protocol::MlsMessageOut::from(welcome),
            group_info.map(|g| protocol::GroupInfo::from(g)),
        ))
    }

    /// Advance the MLS epoch via self-update.
    pub fn advance_epoch(&mut self) -> Result<protocol::MlsMessageOut> {
        let bundle = self
            .group
            .self_update(
                &self.crypto_manager.provider,
                &self.crypto_manager.provider.signer(),
                openmls::group::LeafNodeParameters::default(),
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(protocol::MlsMessageOut::from(bundle.commit))
    }

    /// Send an application message to the group.
    pub fn send_message(&mut self, message: &[u8]) -> Result<protocol::MlsMessageOut> {
        let mls_message = self
            .group
            .create_message(
                &self.crypto_manager.provider,
                &self.crypto_manager.provider.signer(),
                message,
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(protocol::MlsMessageOut::from(mls_message))
    }

    /// Process an incoming MLS message.
    pub fn receive_message(
        &mut self,
        message: openmls::framing::MlsMessageIn,
    ) -> Result<protocol::ProcessedMessage> {
        let processed_message = self
            .group
            .process_message(&self.crypto_manager.provider, message)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(protocol::ProcessedMessage::from(processed_message))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::Ciphersuite;

    fn default_ciphersuite() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    }

    #[test]
    fn test_create_group() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());
        let identity = EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
            .expect("identity generation should succeed");

        let mut session = SessionManager::create_group(crypto_manager, identity)
            .expect("group creation should succeed");

        assert_eq!(session.group.members().count(), 1);
    }

    #[test]
    fn test_join_group() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());
        let creator_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
                .expect("identity generation should succeed");

        let mut session = SessionManager::create_group(crypto_manager, creator_identity)
            .expect("group creation should succeed");

        let joiner_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &session.crypto_manager.provider)
                .expect("identity generation should succeed");

        let key_package = openmls::key_packages::KeyPackage::builder()
            .build(
                default_ciphersuite(),
                &session.crypto_manager.provider,
                &joiner_identity.signer,
                joiner_identity.credential_with_key,
            )
            .expect("key package creation should succeed");

        let (commit, welcome, _) = session
            .add_member(key_package)
            .expect("adding member should succeed");

        assert_eq!(session.group.members().count(), 2);
    }

    #[test]
    fn test_message_round_trip() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());
        let creator_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
                .expect("identity generation should succeed");

        let mut session = SessionManager::create_group(crypto_manager, creator_identity)
            .expect("group creation should succeed");

        let message = b"Hello, GhostChat!";
        let mls_message = session
            .send_message(message)
            .expect("message creation should succeed");

        let processed_message = session
            .receive_message(mls_message.into())
            .expect("message processing should succeed");

        assert_eq!(
            processed_message.content().into_bytes(),
            message,
            "received message should match sent message"
        );
    }

    #[test]
    fn test_epoch_advancement() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());
        let creator_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
                .expect("identity generation should succeed");

        let mut session = SessionManager::create_group(crypto_manager, creator_identity)
            .expect("group creation should succeed");

        let initial_epoch = session.group.epoch();
        session
            .advance_epoch()
            .expect("epoch advancement should succeed");

        assert_eq!(session.group.epoch(), initial_epoch + 1);
    }
}
