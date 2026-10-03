//! Session management for GhostChat MLS groups.
//!
//! This module provides functions for creating MLS groups, joining participants,
//! sending/receiving application messages, and advancing epochs.

use crate::{
    core::{GhostChatError, Result, SessionConfig},
    crypto::CryptoManager,
    identity::EphemeralIdentity,
    protocol::{Envelope, Message},
};

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::{
    framing::{
        MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessage, ProcessedMessageContent,
    },
    prelude::{Sender, *},
    treesync::{LeafNodeParameters, RatchetTreeIn},
};

pub mod local;
pub mod network;
pub use local::{ChatMessage, LocalRoom, ParticipantSnapshot, RoomSnapshot};
pub use network::{NetworkRoom, NetworkUiEvent, TorInvitation};

/// Lifecycle state of a local MLS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Closed,
}

/// Safe application-level events produced after processing a protocol envelope.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Application {
        plaintext: Vec<u8>,
        epoch: u64,
        sender: Option<crate::core::ParticipantId>,
    },
    CommitApplied {
        previous_epoch: u64,
        epoch: u64,
    },
    Shutdown {
        reason: String,
    },
}

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

    closed: bool,
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
        validate_config(&config)?;

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
            closed: false,
        })
    }

    /// Create a complete fresh session, including its ephemeral identity and
    /// actual OpenMLS group.
    pub fn create(config: SessionConfig) -> Result<Self> {
        validate_config(&config)?;
        let crypto_manager = CryptoManager::new(config.clone());
        let identity = EphemeralIdentity::generate(config.ciphersuite, &crypto_manager.provider)?;
        Self::create_group(crypto_manager, identity)
    }

    /// Bind the MLS group id to the random room id carried by the invitation.
    pub fn create_for_room(config: SessionConfig, room_id: &[u8; 16]) -> Result<Self> {
        validate_config(&config)?;
        let crypto_manager = CryptoManager::new(config.clone());
        let identity = EphemeralIdentity::generate(config.ciphersuite, &crypto_manager.provider)?;
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(config.ciphersuite)
            .build();
        let group = MlsGroup::new_with_group_id(
            &crypto_manager.provider,
            &identity.signer,
            &group_config,
            GroupId::from_slice(room_id),
            identity.credential_with_key.clone(),
        )
        .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        Ok(Self {
            group,
            crypto_manager,
            config,
            creator_identity: identity,
            closed: false,
        })
    }

    /// Join an existing group from a protocol Welcome envelope.
    pub fn join_from_welcome(
        crypto_manager: CryptoManager,
        identity: EphemeralIdentity,
        envelope: Envelope,
    ) -> Result<Self> {
        Self::join_verified(crypto_manager, identity, envelope, None)
    }

    /// Pin the MLS Welcome signer and group id to the invitation, independently
    /// of Tor's endpoint authentication.
    pub fn join_verified(
        crypto_manager: CryptoManager,
        identity: EphemeralIdentity,
        envelope: Envelope,
        expected: Option<(&crate::core::ParticipantId, &[u8; 16])>,
    ) -> Result<Self> {
        validate_config(&crypto_manager.config)?;
        let (welcome_bytes, tree_bytes) = match envelope.message {
            Message::MlsWelcome {
                welcome,
                ratchet_tree,
            } => (welcome, ratchet_tree),
            _ => {
                return Err(GhostChatError::ProtocolError(
                    "expected an MLS Welcome envelope".to_string(),
                ));
            }
        };

        let welcome_message = MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice())
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        let welcome = match welcome_message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => {
                return Err(GhostChatError::ProtocolError(
                    "MLS Welcome envelope did not contain a Welcome message".to_string(),
                ));
            }
        };
        if welcome.ciphersuite() != crypto_manager.config.ciphersuite {
            return Err(GhostChatError::ProtocolError(
                "Welcome ciphersuite does not match configuration".into(),
            ));
        }

        let ratchet_tree = RatchetTreeIn::tls_deserialize_exact(tree_bytes.as_slice())
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        let join_config = MlsGroupJoinConfig::builder().build();
        let staged = StagedWelcome::new_from_welcome(
            &crypto_manager.provider,
            &join_config,
            welcome,
            Some(ratchet_tree),
        )
        .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        if staged.members().count() > crypto_manager.config.max_participants.min(3) {
            return Err(GhostChatError::ParticipantLimitReached);
        }
        if let Some((owner, _)) = expected {
            let signer = staged
                .welcome_sender()
                .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
            if &crate::core::ParticipantId::from_public_key(signer.signature_key().as_slice())
                != owner
            {
                return Err(GhostChatError::ProtocolError(
                    "Welcome signer does not match invitation".into(),
                ));
            }
        }
        if let Some((_, room_id)) = expected {
            if staged.group_context().group_id().as_slice() != room_id {
                return Err(GhostChatError::ProtocolError(
                    "Welcome group does not match invitation".into(),
                ));
            }
        }
        let group = staged
            .into_group(&crypto_manager.provider)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        if let Some((_, room_id)) = expected {
            if group.group_id().as_slice() != room_id
                || group.ciphersuite() != crypto_manager.config.ciphersuite
            {
                return Err(GhostChatError::ProtocolError(
                    "Welcome group does not match invitation".into(),
                ));
            }
        }

        Ok(Self {
            config: crypto_manager.config.clone(),
            group,
            crypto_manager,
            creator_identity: identity,
            closed: false,
        })
    }

    pub fn state(&self) -> SessionState {
        if self.closed {
            SessionState::Closed
        } else {
            SessionState::Active
        }
    }

    pub fn is_active(&self) -> bool {
        !self.closed
    }

    pub fn participant_id(&self) -> crate::core::ParticipantId {
        self.creator_identity.participant_id()
    }

    pub fn public_key(&self) -> &[u8] {
        self.creator_identity.public_key()
    }

    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    pub fn member_count(&self) -> usize {
        self.group.members().count()
    }

    pub fn key_package(&self) -> Result<KeyPackage> {
        self.creator_identity
            .key_package(self.config.ciphersuite, &self.crypto_manager.provider)
    }

    pub fn export_ratchet_tree_bytes(&self) -> Result<Vec<u8>> {
        self.group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))
    }

    /// Add a new member to the group using their KeyPackage.
    ///
    /// Returns the commit, welcome, and optional GroupInfo as serialized
    /// OpenMLS message objects.
    pub fn add_member(
        &mut self,
        key_package: KeyPackage,
    ) -> Result<(MlsMessageOut, MlsMessageOut, Option<MlsMessageOut>)> {
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }
        if self.group.members().count() >= self.config.max_participants.min(3) {
            return Err(GhostChatError::ParticipantLimitReached);
        }

        let (commit, welcome, group_info) = self
            .group
            .add_members(
                &self.crypto_manager.provider,
                &self.creator_identity.signer,
                &[key_package],
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        if let Err(error) = self
            .group
            .merge_pending_commit(&self.crypto_manager.provider)
        {
            self.closed = true;
            return Err(GhostChatError::MlsError(error.to_string()));
        }

        Ok((commit, welcome, group_info.map(MlsMessageOut::from)))
    }

    /// Remove a member identified by the public signing key-derived
    /// `ParticipantId`. The removal is an authenticated MLS commit and the
    /// caller is responsible for distributing the returned commit envelope.
    pub fn remove_member(
        &mut self,
        participant_id: &crate::core::ParticipantId,
    ) -> Result<MlsMessageOut> {
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }
        let member = self
            .group
            .members()
            .find(|member| {
                crate::core::ParticipantId::from_public_key(&member.signature_key)
                    == *participant_id
            })
            .ok_or_else(|| {
                GhostChatError::ProtocolError("participant is not an MLS group member".to_string())
            })?;
        if member.index == self.group.own_leaf_index() {
            return Err(GhostChatError::ProtocolError(
                "the local participant cannot remove itself".to_string(),
            ));
        }
        let (commit, _welcome, _group_info) = self
            .group
            .remove_members(
                &self.crypto_manager.provider,
                &self.creator_identity.signer,
                &[member.index],
            )
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        self.group
            .merge_pending_commit(&self.crypto_manager.provider)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        Ok(commit)
    }

    /// Advance the MLS epoch via a self-update.
    pub fn advance_epoch(&mut self) -> Result<MlsMessageOut> {
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }
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
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }
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
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        let processed_message = self
            .group
            .process_message(&self.crypto_manager.provider, protocol_message)
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;

        Ok(processed_message)
    }

    /// Encrypt an application message and wrap the MLS bytes in the protocol
    /// envelope. The returned envelope is still unencoded until a transport
    /// calls `Envelope::encode`.
    pub fn send_application(&mut self, message: &[u8]) -> Result<Envelope> {
        let mls_message = self.send_message(message)?;
        let bytes = mls_message
            .to_bytes()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        Ok(Envelope::mls_application(bytes))
    }

    /// Process an encoded protocol envelope and return only safe application
    /// events. Commit messages are validated by OpenMLS before being merged.
    pub fn receive_envelope_bytes(&mut self, bytes: &[u8]) -> Result<SessionEvent> {
        let envelope =
            Envelope::decode(bytes).map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;
        self.receive_envelope(envelope)
    }

    pub fn receive_envelope(&mut self, envelope: Envelope) -> Result<SessionEvent> {
        self.receive_authorized(envelope, None)
    }

    /// A network room uses an owner-only commit policy to prevent competing
    /// commits. Verify the actual MLS sender before merging any staged commit.
    pub fn receive_authorized(
        &mut self,
        envelope: Envelope,
        commit_author: Option<&crate::core::ParticipantId>,
    ) -> Result<SessionEvent> {
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }

        match envelope.message {
            Message::MlsApplication {
                application_message,
            } => {
                let message = MlsMessageIn::tls_deserialize_exact(application_message.as_slice())
                    .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
                let processed = self.receive_message(message)?;
                let epoch = processed.epoch().as_u64();
                let sender = self.participant_id_for_sender(processed.sender());
                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(message) => {
                        Ok(SessionEvent::Application {
                            plaintext: message.into_bytes(),
                            epoch,
                            sender,
                        })
                    }
                    ProcessedMessageContent::OwnPrivateMessage => Err(
                        GhostChatError::ProtocolError("received own private message".to_string()),
                    ),
                    _ => Err(GhostChatError::ProtocolError(
                        "MLS application envelope did not contain an application message"
                            .to_string(),
                    )),
                }
            }
            Message::MlsHandshake { mls_message } => {
                let message = MlsMessageIn::tls_deserialize_exact(mls_message.as_slice())
                    .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
                let processed = self.receive_message(message)?;
                if let Some(author) = commit_author {
                    if self.participant_id_for_sender(processed.sender()).as_ref() != Some(author) {
                        return Err(GhostChatError::ProtocolError(
                            "unauthorized MLS commit author".into(),
                        ));
                    }
                }
                let previous_epoch = self.epoch();
                match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        // OpenMLS authenticates and validates the proposals. Apply
                        // GhostChat's stricter room capacity policy before merge.
                        let member_count = self
                            .member_count()
                            .saturating_sub(staged_commit.remove_proposals().count())
                            .saturating_add(staged_commit.add_proposals().count());
                        if member_count > self.config.max_participants.min(3) {
                            return Err(GhostChatError::ParticipantLimitReached);
                        }
                        self.group
                            .merge_staged_commit(&self.crypto_manager.provider, *staged_commit)
                            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
                        self.closed = !self.group.is_active();
                        Ok(SessionEvent::CommitApplied {
                            previous_epoch,
                            epoch: self.epoch(),
                        })
                    }
                    ProcessedMessageContent::OwnPendingCommit => {
                        self.group
                            .merge_pending_commit(&self.crypto_manager.provider)
                            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
                        Ok(SessionEvent::CommitApplied {
                            previous_epoch,
                            epoch: self.epoch(),
                        })
                    }
                    ProcessedMessageContent::ProposalMessage(_)
                    | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                        Err(GhostChatError::ProtocolError(
                            "standalone MLS proposals require an application authorization policy"
                                .to_string(),
                        ))
                    }
                    _ => Err(GhostChatError::ProtocolError(
                        "MLS handshake envelope did not contain a commit".to_string(),
                    )),
                }
            }
            Message::Shutdown { reason } => {
                if commit_author.is_some() {
                    return Err(GhostChatError::ProtocolError(
                        "network shutdown must be an authenticated MLS application".into(),
                    ));
                }
                self.closed = true;
                Ok(SessionEvent::Shutdown { reason })
            }
            Message::RoomIntro { .. }
            | Message::JoinRequest { .. }
            | Message::PeerReady
            | Message::ParticipantEvent { .. }
            | Message::MlsWelcome { .. }
            | Message::Error { .. } => Err(GhostChatError::ProtocolError(
                "message type is not valid for an active MLS session".to_string(),
            )),
        }
    }

    pub fn shutdown(&mut self, reason: impl Into<String>) -> Result<Envelope> {
        if self.closed {
            return Err(GhostChatError::SessionClosed);
        }
        self.closed = true;
        Ok(Envelope::shutdown(reason))
    }

    fn participant_id_for_sender(&self, sender: &Sender) -> Option<crate::core::ParticipantId> {
        let Sender::Member(index) = sender else {
            return None;
        };
        self.group
            .members()
            .find(|member| member.index == *index)
            .map(|member| crate::core::ParticipantId::from_public_key(&member.signature_key))
    }
}

fn validate_config(config: &SessionConfig) -> Result<()> {
    if !(1..=3).contains(&config.max_participants) {
        return Err(GhostChatError::ProtocolError(
            "GhostChat supports between one and three participants".into(),
        ));
    }
    Ok(())
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
                joiner_identity.credential_with_key.clone(),
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
            Err(GhostChatError::ParticipantLimitReached)
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

    #[test]
    fn replayed_application_and_old_epoch_messages_are_rejected() {
        let alice_crypto = CryptoManager::new(SessionConfig::default());
        let alice_identity =
            EphemeralIdentity::generate(default_ciphersuite(), &alice_crypto.provider)
                .expect("Alice identity generation should succeed");
        let mut alice = SessionManager::create_group(alice_crypto, alice_identity)
            .expect("Alice group creation should succeed");

        let bob_crypto = CryptoManager::new(SessionConfig::default());
        let bob_identity = EphemeralIdentity::generate(default_ciphersuite(), &bob_crypto.provider)
            .expect("Bob identity generation should succeed");
        let bob_key_package = bob_identity
            .key_package(default_ciphersuite(), &bob_crypto.provider)
            .expect("Bob KeyPackage should be created");
        let (_commit, welcome, _group_info) = alice
            .add_member(bob_key_package)
            .expect("Alice should add Bob");
        let welcome = Envelope::mls_welcome(
            welcome.to_bytes().expect("Welcome should serialize"),
            alice
                .export_ratchet_tree_bytes()
                .expect("ratchet tree should serialize"),
        );
        let mut bob = SessionManager::join_from_welcome(bob_crypto, bob_identity, welcome)
            .expect("Bob should join the group");

        let application = alice
            .send_application(b"one-time")
            .expect("application should encrypt");
        assert!(matches!(
            bob.receive_envelope(application.clone()),
            Ok(SessionEvent::Application { .. })
        ));
        assert!(bob.receive_envelope(application).is_err());

        let old_epoch_application = alice
            .send_application(b"old epoch")
            .expect("old epoch application should encrypt");
        let commit = alice
            .advance_epoch()
            .expect("Alice should advance the epoch");
        let commit = Envelope::mls_handshake(commit.to_bytes().expect("commit should serialize"));
        assert!(matches!(
            bob.receive_envelope(commit),
            Ok(SessionEvent::CommitApplied { .. })
        ));
        assert!(bob.receive_envelope(old_epoch_application).is_err());

        let malformed_commit = Envelope::mls_handshake(vec![0xff, 0x00, 0xff]);
        assert!(bob.receive_envelope(malformed_commit).is_err());
    }

    #[test]
    fn hard_capacity_rejection_happens_before_received_commit_merge() {
        let mut alice = SessionManager::create(SessionConfig::default()).unwrap();
        let mut joiners = Vec::new();
        for _ in 0..3 {
            let crypto = CryptoManager::new(SessionConfig::default());
            let identity =
                EphemeralIdentity::generate(default_ciphersuite(), &crypto.provider).unwrap();
            let key_package = identity
                .key_package(default_ciphersuite(), &crypto.provider)
                .unwrap();
            joiners.push((crypto, identity, key_package));
        }
        let (crypto, identity, key_package) = joiners.remove(0);
        let (_, welcome, _) = alice.add_member(key_package).unwrap();
        let mut bob = SessionManager::join_from_welcome(
            crypto,
            identity,
            Envelope::mls_welcome(
                welcome.to_bytes().unwrap(),
                alice.export_ratchet_tree_bytes().unwrap(),
            ),
        )
        .unwrap();
        let (_, _, charlie_key_package) = joiners.remove(0);
        let (commit, _, _) = alice.add_member(charlie_key_package).unwrap();
        bob.receive_envelope(Envelope::mls_handshake(commit.to_bytes().unwrap()))
            .unwrap();
        let (_, _, fourth_key_package) = joiners.remove(0);
        alice.config.max_participants = 100;
        assert!(matches!(
            alice.add_member(fourth_key_package.clone()),
            Err(GhostChatError::ParticipantLimitReached)
        ));
        // A malicious owner can bypass the public SessionManager guard. The
        // receiver still refuses this real authenticated OpenMLS Add commit.
        let (commit, _, _) = alice
            .group
            .add_members(
                &alice.crypto_manager.provider,
                &alice.creator_identity.signer,
                &[fourth_key_package],
            )
            .unwrap();
        alice
            .group
            .merge_pending_commit(&alice.crypto_manager.provider)
            .unwrap();
        let epoch = bob.epoch();
        let owner = alice.participant_id();
        assert!(matches!(
            bob.receive_authorized(
                Envelope::mls_handshake(commit.to_bytes().unwrap()),
                Some(&owner)
            ),
            Err(GhostChatError::ParticipantLimitReached)
        ));
        assert_eq!(bob.epoch(), epoch);
        assert_eq!(bob.member_count(), 3);
        assert!(bob.is_active());
    }

    #[test]
    fn invalid_capacity_config_and_network_legacy_shutdown_are_rejected() {
        for limit in [0, 4, usize::MAX] {
            let config = SessionConfig {
                max_participants: limit,
                ..SessionConfig::default()
            };
            assert!(SessionManager::create(config.clone()).is_err());
            assert!(SessionManager::create_for_room(config, &[0; 16]).is_err());
        }
        let mut session = SessionManager::create(SessionConfig::default()).unwrap();
        let owner = session.participant_id();
        assert!(session
            .receive_authorized(Envelope::shutdown("untrusted"), Some(&owner))
            .is_err());
        assert!(session.is_active());
        // Preserve the explicitly local session shutdown API for LocalRoom.
        assert!(matches!(
            session.receive_envelope(Envelope::shutdown("local")),
            Ok(SessionEvent::Shutdown { .. })
        ));
    }
}
