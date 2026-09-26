//! Session management for GhostChat MLS groups.
//!
//! This module provides functions for creating MLS groups, joining participants,
//! sending/receiving application messages, and advancing epochs.

use crate::{
    core::{GhostChatError, Result, SessionConfig},
    crypto::CryptoManager,
    identity::EphemeralIdentity,
};

use openmls::{
    framing::{MlsMessageIn, MlsMessageOut, ProcessedMessage},
    prelude::*,
    treesync::LeafNodeParameters,
};

/// Manages an MLS group session.
///
/// Handles group creation, member joins, message exchange, and epoch advancement.
pub struct SessionManager {
    /// The underlying MLS group.
    pub group: MlsGroup,

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
    /// The configured ciphersuite is explicitly applied to the MLS group.
    pub fn create_group(
        crypto_manager: CryptoManager,
        identity: EphemeralIdentity,
    ) -> Result<Self> {
        let config = crypto_manager.config.clone();

        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(config.ciphersuite)
            .build();

        let group = MlsGroup::new(
            &crypto_manager.provider,
            &identity.signer,
            &group_config,
            identity.credential_with_key.clone(),
        )
        .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(Self {
            group,
            crypto_manager,
            config,
            creator_identity: identity,
        })
    }

    /// Add a new member to the group using their KeyPackage.
    ///
    /// Returns the commit, welcome, and optional GroupInfo as serialized
    /// OpenMLS message objects.
    pub fn add_member(
        &mut self,
        key_package: KeyPackage,
    ) -> Result<(MlsMessageOut, MlsMessageOut, Option<MlsMessageOut>)> {
        if self.group.members().count() >= self.config.max_participants {
            return Err(GhostChatError::Internal(
                "maximum participant limit reached".to_string(),
            ));
        }

        let (commit, welcome, group_info) = self
            .group
            .add_members(
                &self.crypto_manager.provider,
                &self.creator_identity.signer,
                &[key_package],
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        self.group
            .merge_pending_commit(&self.crypto_manager.provider)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok((commit, welcome, group_info.map(MlsMessageOut::from)))
    }

    /// Advance the MLS epoch via a self-update.
    pub fn advance_epoch(&mut self) -> Result<MlsMessageOut> {
        let (commit, _welcome, _group_info) = self
            .group
            .self_update(
                &self.crypto_manager.provider,
                &self.creator_identity.signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?
            .into_contents();

        self.group
            .merge_pending_commit(&self.crypto_manager.provider)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(commit)
    }

    /// Send an encrypted MLS application message to the group.
    pub fn send_message(&mut self, message: &[u8]) -> Result<MlsMessageOut> {
        let mls_message = self
            .group
            .create_message(
                &self.crypto_manager.provider,
                &self.creator_identity.signer,
                message,
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(mls_message)
    }

    /// Process an incoming serialized MLS message.
    ///
    /// MlsMessageIn must first be converted into a ProtocolMessage before
    /// being passed to the OpenMLS group.
    pub fn receive_message(&mut self, message: MlsMessageIn) -> Result<ProcessedMessage> {
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        let processed_message = self
            .group
            .process_message(&self.crypto_manager.provider, protocol_message)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(processed_message)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use openmls::prelude::tls_codec::Deserialize;
    use openmls::prelude::Ciphersuite;

    fn default_ciphersuite() -> Ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    }

    #[test]
    fn test_create_group() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());

        let identity = EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
            .expect("identity generation should succeed");

        let session = SessionManager::create_group(crypto_manager, identity)
            .expect("group creation should succeed");

        assert_eq!(session.group.members().count(), 1);
        assert_eq!(session.group.ciphersuite(), default_ciphersuite());
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

        let key_package_bundle = KeyPackage::builder()
            .build(
                default_ciphersuite(),
                &session.crypto_manager.provider,
                &joiner_identity.signer,
                joiner_identity.credential_with_key,
            )
            .expect("key package creation should succeed");

        let key_package = key_package_bundle.key_package().clone();

        let (_commit, _welcome, _group_info) = session
            .add_member(key_package)
            .expect("adding member should succeed");

        assert_eq!(session.group.members().count(), 2);
    }

    #[test]
    fn test_three_party_limit_rejects_fourth_member() {
        let alice_crypto = CryptoManager::new(SessionConfig::default());
        let alice_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &alice_crypto.provider)
                .expect("Alice identity generation should succeed");

        let mut alice = SessionManager::create_group(alice_crypto, alice_identity)
            .expect("Alice group creation should succeed");

        let bob_crypto = CryptoManager::new(SessionConfig::default());
        let bob_identity = EphemeralIdentity::generate(default_ciphersuite(), &bob_crypto.provider)
            .expect("Bob identity generation should succeed");

        let bob_key_package = KeyPackage::builder()
            .build(
                default_ciphersuite(),
                &bob_crypto.provider,
                &bob_identity.signer,
                bob_identity.credential_with_key.clone(),
            )
            .expect("Bob key package creation should succeed");

        let charlie_crypto = CryptoManager::new(SessionConfig::default());
        let charlie_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &charlie_crypto.provider)
                .expect("Charlie identity generation should succeed");

        let charlie_key_package = KeyPackage::builder()
            .build(
                default_ciphersuite(),
                &charlie_crypto.provider,
                &charlie_identity.signer,
                charlie_identity.credential_with_key.clone(),
            )
            .expect("Charlie key package creation should succeed");

        let dave_crypto = CryptoManager::new(SessionConfig::default());
        let dave_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &dave_crypto.provider)
                .expect("Dave identity generation should succeed");

        let dave_key_package = KeyPackage::builder()
            .build(
                default_ciphersuite(),
                &dave_crypto.provider,
                &dave_identity.signer,
                dave_identity.credential_with_key.clone(),
            )
            .expect("Dave key package creation should succeed");

        // Alice starts as the only participant.
        assert_eq!(alice.group.members().count(), 1);

        // Add Bob: 2 participants.
        alice
            .add_member(bob_key_package.key_package().clone())
            .expect("Alice should be able to add Bob");

        assert_eq!(alice.group.members().count(), 2);

        // Add Charlie: 3 participants, the configured maximum.
        alice
            .add_member(charlie_key_package.key_package().clone())
            .expect("Alice should be able to add Charlie");

        assert_eq!(alice.group.members().count(), 3);
        assert_eq!(alice.config.max_participants, 3);

        // Adding a fourth participant must be rejected before MLS
        // membership is modified.
        let result = alice.add_member(dave_key_package.key_package().clone());

        assert!(matches!(
            result,
            Err(GhostChatError::Internal(message))
                if message.contains("maximum participant limit")
        ));

        assert_eq!(alice.group.members().count(), 3);
    }

    #[test]
    fn test_two_party_message_exchange() {
        // Alice owns the initial group.
        let alice_crypto = CryptoManager::new(SessionConfig::default());

        let alice_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &alice_crypto.provider)
                .expect("Alice identity generation should succeed");

        let mut alice = SessionManager::create_group(alice_crypto, alice_identity)
            .expect("Alice group creation should succeed");

        // Bob has completely separate cryptographic state.
        let bob_crypto = CryptoManager::new(SessionConfig::default());

        let bob_identity = EphemeralIdentity::generate(default_ciphersuite(), &bob_crypto.provider)
            .expect("Bob identity generation should succeed");

        let bob_key_package = KeyPackage::builder()
            .build(
                default_ciphersuite(),
                &bob_crypto.provider,
                &bob_identity.signer,
                bob_identity.credential_with_key.clone(),
            )
            .expect("Bob key package creation should succeed");

        // Alice adds Bob and commits the membership change locally.
        let (_commit, welcome, _group_info) = alice
            .add_member(bob_key_package.key_package().clone())
            .expect("Alice should be able to add Bob");

        assert_eq!(alice.group.members().count(), 2);

        // Convert Alice's wire-format Welcome into the Welcome object.
        let welcome_bytes = welcome
            .to_bytes()
            .expect("Welcome serialization should succeed");

        let welcome_message = MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice())
            .expect("Bob should be able to deserialize the Welcome");

        let welcome = match welcome_message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("MLS message should contain a Welcome"),
        };

        // Bob joins using Alice's Welcome and current ratchet tree.
        let ratchet_tree = alice.group.export_ratchet_tree();

        let mut bob_group = StagedWelcome::new_from_welcome(
            &bob_crypto.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            Some(ratchet_tree.into()),
        )
        .expect("Bob should be able to process Alice's Welcome")
        .into_group(&bob_crypto.provider)
        .expect("Bob should be able to create the MLS group");

        assert_eq!(bob_group.members().count(), 2);
        assert_eq!(
            alice.group.export_ratchet_tree(),
            bob_group.export_ratchet_tree()
        );

        // Alice encrypts an application message.
        let plaintext = b"Hello, Bob!";

        let ciphertext = alice
            .send_message(plaintext)
            .expect("Alice should be able to create an application message");

        // Convert Alice's ciphertext into the ProtocolMessage expected by Bob.
        let ciphertext_bytes = ciphertext
            .to_bytes()
            .expect("ciphertext serialization should succeed");

        let incoming = MlsMessageIn::tls_deserialize_exact(ciphertext_bytes.as_slice())
            .expect("Bob should be able to deserialize the MLS message");

        let incoming = incoming
            .try_into_protocol_message()
            .expect("MLS message should convert to a protocol message");

        let processed = bob_group
            .process_message(&bob_crypto.provider, incoming)
            .expect("Bob should be able to decrypt Alice's message");

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                assert_eq!(message.into_bytes(), plaintext);
            }
            other => {
                panic!("expected application message, got {other:?}");
            }
        }
    }

    #[test]
    fn test_message_creation() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());

        let identity = EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
            .expect("identity generation should succeed");

        let mut session = SessionManager::create_group(crypto_manager, identity)
            .expect("group creation should succeed");

        let message = b"Hello, GhostChat!";

        let mls_message = session
            .send_message(message)
            .expect("message creation should succeed");

        assert!(!mls_message.to_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_epoch_advancement() {
        let crypto_manager = CryptoManager::new(SessionConfig::default());

        let identity = EphemeralIdentity::generate(default_ciphersuite(), &crypto_manager.provider)
            .expect("identity generation should succeed");

        let mut session = SessionManager::create_group(crypto_manager, identity)
            .expect("group creation should succeed");

        let initial_epoch = session.group.epoch();

        session
            .advance_epoch()
            .expect("epoch advancement should succeed");

        assert_eq!(session.group.epoch().as_u64(), initial_epoch.as_u64() + 1);
    }
}
