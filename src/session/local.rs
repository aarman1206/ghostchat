//! A deterministic three-party room built on the real MLS/session APIs.
//!
//! `LocalRoom` is a development transport adapter, not a network service. It
//! keeps independent OpenMLS providers and groups for each participant, moves
//! only encoded protocol bytes through `InMemoryTransport`, and therefore
//! exercises the same boundaries a future network/Tor adapter must use.

use std::collections::BTreeMap;

use rand::random;
use serde::Serialize;
use zeroize::Zeroize;

use crate::{
    core::{GhostChatError, ParticipantId, Result, SessionConfig},
    crypto::CryptoManager,
    identity::EphemeralIdentity,
    protocol::{Envelope, Message, RoomConfig},
    session::{SessionEvent, SessionManager},
    transport::{InMemoryTransport, Transport},
};

#[derive(Clone, Debug, Serialize)]
pub struct ParticipantSnapshot {
    pub id: String,
    pub display_name: String,
    pub state: String,
    pub is_self: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatMessage {
    pub id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub body: String,
    pub timestamp: String,
    pub mine: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RoomSnapshot {
    pub session_id: String,
    pub room_name: String,
    pub invite_code: String,
    pub owner_id: String,
    pub state: String,
    pub epoch: u64,
    pub participants: Vec<ParticipantSnapshot>,
    pub messages: Vec<ChatMessage>,
    pub transport: String,
    pub tor_state: String,
    pub connection_state: String,
    pub encryption_active: bool,
}

struct ParticipantSession {
    display_name: String,
    session: SessionManager,
}

struct PendingJoin {
    display_name: String,
    crypto_manager: CryptoManager,
    identity: EphemeralIdentity,
}

pub struct LocalRoom {
    room_id: [u8; 16],
    invite_code: String,
    room_name: String,
    config: SessionConfig,
    invite: Envelope,
    creator_id: ParticipantId,
    participants: BTreeMap<ParticipantId, ParticipantSession>,
    pending_joins: BTreeMap<ParticipantId, PendingJoin>,
    transport: InMemoryTransport,
    messages: Vec<ChatMessage>,
    next_message_id: u64,
    closed: bool,
}

impl LocalRoom {
    pub fn create(
        config: SessionConfig,
        room_name: Option<String>,
        display_name: &str,
    ) -> Result<Self> {
        let display_name = normalise_name(display_name)?;
        let room_name = room_name
            .unwrap_or_else(|| "GhostChat room".to_string())
            .trim()
            .to_string();
        let room_name = if room_name.is_empty() {
            "GhostChat room".to_string()
        } else {
            room_name
        };

        let crypto_manager = CryptoManager::new(config.clone());
        let identity = EphemeralIdentity::generate(config.ciphersuite, &crypto_manager.provider)?;
        let session = SessionManager::create_group(crypto_manager, identity)?;
        let creator_id = session.participant_id();
        let room_id = random::<[u8; 16]>();
        let invite = Envelope::room_intro(
            room_id,
            session.public_key().to_vec(),
            room_config(&config)?,
        );
        let invite_code = invite
            .encode()
            .map(|bytes| hex_encode(&bytes))
            .map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;

        let mut transport = InMemoryTransport::default();
        transport.register(creator_id.clone())?;

        let mut participants = BTreeMap::new();
        participants.insert(
            creator_id.clone(),
            ParticipantSession {
                display_name,
                session,
            },
        );

        Ok(Self {
            room_id,
            invite_code,
            room_name,
            config,
            invite,
            creator_id,
            participants,
            pending_joins: BTreeMap::new(),
            transport,
            messages: Vec::new(),
            next_message_id: 1,
            closed: false,
        })
    }

    pub fn creator_id(&self) -> ParticipantId {
        self.creator_id.clone()
    }

    pub fn invite_code(&self) -> &str {
        &self.invite_code
    }

    pub fn session_id(&self) -> String {
        hex_encode(&self.room_id)
    }

    pub fn invite_envelope(&self) -> &Envelope {
        &self.invite
    }

    pub fn room_name(&self) -> &str {
        &self.room_name
    }

    pub fn validate_invite_code(&self, code: &str) -> Result<()> {
        if code.trim() != self.invite_code {
            return Err(GhostChatError::ProtocolError(
                "invite code does not match this room".to_string(),
            ));
        }
        let bytes = hex_decode(code.trim())?;
        let envelope =
            Envelope::decode(&bytes).map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;
        let expected_config = room_config(&self.config)?;
        let expected_creator_identity = self
            .participants
            .get(&self.creator_id)
            .map(|participant| participant.session.public_key().to_vec())
            .unwrap_or_default();
        match envelope.message {
            Message::RoomIntro {
                room_id,
                creator_identity: intro_creator_identity,
                config,
            } if room_id == self.room_id
                && intro_creator_identity == expected_creator_identity
                && config == expected_config =>
            {
                Ok(())
            }
            _ => Err(GhostChatError::ProtocolError(
                "invite code is not a valid room introduction".to_string(),
            )),
        }
    }

    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    pub fn is_active(&self) -> bool {
        !self.closed
    }

    pub fn epoch(&self) -> Result<u64> {
        self.ensure_active()?;
        self.participants
            .get(&self.creator_id)
            .map(|participant| participant.session.epoch())
            .ok_or_else(|| GhostChatError::Internal("room creator is missing".to_string()))
    }

    /// Add a local development participant through a real MLS Welcome flow.
    pub fn add_participant(&mut self, display_name: &str) -> Result<ParticipantId> {
        self.ensure_active()?;
        let display_name = normalise_name(display_name)?;
        if self.participants.len() + self.pending_joins.len() >= self.config.max_participants {
            return Err(GhostChatError::ParticipantLimitReached);
        }

        let crypto_manager = CryptoManager::new(self.config.clone());
        let identity =
            EphemeralIdentity::generate(self.config.ciphersuite, &crypto_manager.provider)?;
        let participant_id = identity.participant_id();
        let key_package =
            identity.key_package(self.config.ciphersuite, &crypto_manager.provider)?;
        self.transport.register(participant_id.clone())?;

        let pending = PendingJoin {
            display_name,
            crypto_manager,
            identity,
        };

        let (commit, welcome, tree_bytes) = {
            let creator = self
                .participants
                .get_mut(&self.creator_id)
                .ok_or_else(|| GhostChatError::Internal("room creator is missing".to_string()))?;
            let (commit, welcome, _) = match creator.session.add_member(key_package) {
                Ok(artifacts) => artifacts,
                Err(error) => {
                    let _ = self.transport.unregister(&participant_id);
                    return Err(error);
                }
            };
            let tree_bytes = creator.session.export_ratchet_tree_bytes()?;
            (commit, welcome, tree_bytes)
        };

        let commit_bytes = commit
            .to_bytes()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        let commit_envelope = Envelope::mls_handshake(commit_bytes);
        let welcome_envelope = Envelope::mls_welcome(welcome_bytes, tree_bytes);
        let commit_wire = commit_envelope
            .encode()
            .map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;
        let welcome_wire = welcome_envelope
            .encode()
            .map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;

        self.pending_joins.insert(participant_id.clone(), pending);
        let existing_ids: Vec<ParticipantId> = self.participants.keys().cloned().collect();
        for existing_id in existing_ids {
            if existing_id != self.creator_id {
                self.transport
                    .send(&self.creator_id, &existing_id, &commit_wire)?;
            }
        }
        self.transport
            .send(&self.creator_id, &participant_id, &welcome_wire)?;

        self.drain_transport()?;
        if self.pending_joins.contains_key(&participant_id) {
            return Err(GhostChatError::Internal(
                "join Welcome was not delivered".to_string(),
            ));
        }
        Ok(participant_id)
    }

    pub fn snapshot(&self, current_id: &ParticipantId) -> Result<RoomSnapshot> {
        let epoch = self.epoch()?;
        if !self.participants.contains_key(current_id) {
            return Err(GhostChatError::Internal(
                "current participant is not in the room".to_string(),
            ));
        }

        let participants = self
            .participants
            .iter()
            .map(|(id, participant)| ParticipantSnapshot {
                id: id.to_string(),
                display_name: participant.display_name.clone(),
                state: "online".to_string(),
                is_self: id == current_id,
            })
            .collect();

        let messages = self
            .messages
            .iter()
            .cloned()
            .map(|mut message| {
                message.mine = message.sender_id == current_id.as_str();
                message
            })
            .collect();

        Ok(RoomSnapshot {
            session_id: self.session_id(),
            room_name: self.room_name.clone(),
            invite_code: self.invite_code.clone(),
            owner_id: self.creator_id.to_string(),
            state: if self.closed {
                "closed".to_string()
            } else {
                "active".to_string()
            },
            epoch,
            participants,
            messages,
            transport: "in-memory".to_string(),
            tor_state: "not-applicable".to_string(),
            connection_state: if self.closed {
                "closed".to_string()
            } else {
                "connected".to_string()
            },
            encryption_active: !self.closed,
        })
    }

    /// Encrypt and deliver a message to every other local participant. Each
    /// recipient must successfully decrypt the bytes before the message is
    /// added to the runtime-only history.
    pub fn send_message(&mut self, sender_id: &ParticipantId, body: &str) -> Result<ChatMessage> {
        self.ensure_active()?;
        let body = validate_body(body)?;
        let envelope = self
            .participants
            .get_mut(sender_id)
            .ok_or_else(|| GhostChatError::Internal("sender is not in the room".to_string()))?
            .session
            .send_application(body.as_bytes())?;
        let wire = envelope
            .encode()
            .map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;
        let recipients: Vec<ParticipantId> = self
            .participants
            .keys()
            .filter(|id| *id != sender_id)
            .cloned()
            .collect();
        for recipient in &recipients {
            self.transport.send(sender_id, recipient, &wire)?;
        }

        let events = self.drain_transport()?;
        let mut delivered = 0usize;
        for (_, event) in events {
            if let SessionEvent::Application { plaintext, .. } = event {
                if plaintext != body.as_bytes() {
                    return Err(GhostChatError::CryptoError(
                        "recipient decrypted a different application message".to_string(),
                    ));
                }
                delivered += 1;
            }
        }
        if delivered != recipients.len() {
            return Err(GhostChatError::Internal(format!(
                "message delivered to {delivered} of {} participants",
                recipients.len()
            )));
        }

        let sender_name = self
            .participants
            .get(sender_id)
            .map(|participant| participant.display_name.clone())
            .ok_or_else(|| GhostChatError::Internal("sender disappeared".to_string()))?;
        let message = ChatMessage {
            id: format!("message-{}", self.next_message_id),
            sender_id: sender_id.to_string(),
            sender_name,
            body,
            timestamp: String::new(),
            mine: true,
        };
        self.next_message_id = self.next_message_id.saturating_add(1);
        self.messages.push(message.clone());
        if self.messages.len() > 500 {
            self.messages.remove(0).body.zeroize();
        }
        Ok(message)
    }

    /// Advance the creator's MLS epoch and deliver the authenticated commit to
    /// every other participant before returning the new real epoch number.
    pub fn advance_epoch(&mut self) -> Result<u64> {
        self.ensure_active()?;
        let commit = self
            .participants
            .get_mut(&self.creator_id)
            .ok_or_else(|| GhostChatError::Internal("room creator is missing".to_string()))?
            .session
            .advance_epoch()?;
        let commit_bytes = commit
            .to_bytes()
            .map_err(|e| GhostChatError::MlsError(e.to_string()))?;
        let envelope = Envelope::mls_handshake(commit_bytes);
        let wire = envelope
            .encode()
            .map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;
        let recipients: Vec<ParticipantId> = self
            .participants
            .keys()
            .filter(|id| *id != &self.creator_id)
            .cloned()
            .collect();
        for recipient in &recipients {
            self.transport.send(&self.creator_id, recipient, &wire)?;
        }
        for (_, event) in self.drain_transport()? {
            if !matches!(event, SessionEvent::CommitApplied { .. }) {
                return Err(GhostChatError::ProtocolError(
                    "epoch commit did not produce a commit event".to_string(),
                ));
            }
        }

        let epoch = self.epoch()?;
        if self
            .participants
            .values()
            .any(|participant| participant.session.epoch() != epoch)
        {
            return Err(GhostChatError::Internal(
                "participants are not synchronized after epoch update".to_string(),
            ));
        }
        Ok(epoch)
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.ensure_active()?;
        self.closed = true;
        self.pending_joins.clear();
        self.participants.clear();
        self.transport.clear();
        self.messages
            .iter_mut()
            .for_each(|message| message.body.zeroize());
        self.messages.clear();
        self.invite_code.zeroize();
        self.room_name.zeroize();
        Ok(())
    }

    fn drain_transport(&mut self) -> Result<Vec<(ParticipantId, SessionEvent)>> {
        let endpoints: Vec<ParticipantId> = self.transport.endpoints().cloned().collect();
        let mut events = Vec::new();
        for endpoint in endpoints {
            while let Some(frame) = self.transport.receive(&endpoint)? {
                let envelope = Envelope::decode(&frame.bytes)
                    .map_err(|e| GhostChatError::ProtocolError(e.to_string()))?;
                if let Some(pending) = self.pending_joins.remove(&endpoint) {
                    let PendingJoin {
                        display_name,
                        crypto_manager,
                        identity,
                    } = pending;
                    let session =
                        SessionManager::join_from_welcome(crypto_manager, identity, envelope)?;
                    self.participants.insert(
                        endpoint.clone(),
                        ParticipantSession {
                            display_name,
                            session,
                        },
                    );
                } else {
                    let participant = self.participants.get_mut(&endpoint).ok_or_else(|| {
                        GhostChatError::TransportError(format!(
                            "transport delivered to unknown participant: {endpoint}"
                        ))
                    })?;
                    let event = participant.session.receive_envelope(envelope)?;
                    events.push((endpoint.clone(), event));
                }
            }
        }
        Ok(events)
    }

    fn ensure_active(&self) -> Result<()> {
        if self.closed {
            Err(GhostChatError::SessionClosed)
        } else {
            Ok(())
        }
    }
}

fn room_config(config: &SessionConfig) -> Result<RoomConfig> {
    Ok(RoomConfig {
        max_participants: u8::try_from(config.max_participants).map_err(|_| {
            GhostChatError::Internal("participant limit does not fit protocol field".to_string())
        })?,
        epoch_update_interval_secs: u32::try_from(config.epoch_update_interval_secs).map_err(
            |_| GhostChatError::Internal("epoch interval does not fit protocol field".to_string()),
        )?,
        ciphersuite: u16::from(config.ciphersuite),
    })
}

fn normalise_name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(GhostChatError::Internal(
            "display name must not be empty".to_string(),
        ));
    }
    if value.chars().count() > 32 {
        return Err(GhostChatError::Internal(
            "display name must be 32 characters or fewer".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn validate_body(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(GhostChatError::Internal(
            "message must not be empty".to_string(),
        ));
    }
    if value.chars().count() > 4_000 {
        return Err(GhostChatError::Internal(
            "message must be 4,000 characters or fewer".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(GhostChatError::ProtocolError(
            "invite code has invalid hex length".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let high = hex_nibble(raw[index]).ok_or_else(|| {
            GhostChatError::ProtocolError("invite code has invalid hex".to_string())
        })?;
        let low = hex_nibble(raw[index + 1]).ok_or_else(|| {
            GhostChatError::ProtocolError("invite code has invalid hex".to_string())
        })?;
        bytes.push((high << 4) | low);
        index += 2;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_room_runs_three_party_encrypted_lifecycle() {
        let mut room =
            LocalRoom::create(SessionConfig::default(), Some("Test room".into()), "Alice")
                .expect("room should be created");
        let alice = room.creator_id();
        let invite = room.snapshot(&alice).unwrap().invite_code;
        room.validate_invite_code(&invite)
            .expect("room introduction should validate");
        assert!(room.validate_invite_code("00").is_err());
        let bob = room.add_participant("Bob").expect("Bob should join");
        let charlie = room
            .add_participant("Charlie")
            .expect("Charlie should join");
        assert_eq!(room.participant_count(), 3);
        assert_eq!(room.snapshot(&alice).unwrap().epoch, 2);

        room.send_message(&alice, "hello everyone")
            .expect("Alice message should decrypt for both recipients");
        room.send_message(&bob, "hello Alice")
            .expect("Bob message should decrypt for all recipients");
        room.send_message(&charlie, "hello back").unwrap();
        assert_eq!(room.snapshot(&alice).unwrap().messages.len(), 3);

        for _ in 0..3 {
            room.advance_epoch().expect("epoch should advance");
        }
        let epoch = room.epoch().expect("epoch should be readable");
        assert_eq!(epoch, 5);
        room.send_message(&charlie, "message after epoch update")
            .expect("post-update message should decrypt");
    }

    #[test]
    fn malformed_wire_and_outsider_ciphertext_are_rejected() {
        let mut alice = SessionManager::create(SessionConfig::default()).unwrap();
        assert!(alice.receive_envelope_bytes(&[0xFF, 0x00, 0xFF]).is_err());

        let mut outsider = SessionManager::create(SessionConfig::default()).unwrap();
        let encrypted = alice.send_application(b"room secret").unwrap();
        assert!(outsider.receive_envelope(encrypted).is_err());
    }

    #[test]
    fn local_room_rejects_fourth_participant_and_can_be_recreated() {
        let mut room = LocalRoom::create(SessionConfig::default(), None, "Alice").unwrap();
        room.add_participant("Bob").unwrap();
        room.add_participant("Charlie").unwrap();
        assert!(matches!(
            room.add_participant("Dave"),
            Err(GhostChatError::ParticipantLimitReached)
        ));
        room.shutdown().unwrap();
        assert!(matches!(
            room.add_participant("Eve"),
            Err(GhostChatError::SessionClosed)
        ));

        let recreated = LocalRoom::create(SessionConfig::default(), None, "New Alice");
        assert!(recreated.is_ok());
    }

    #[test]
    fn local_development_history_is_bounded_and_cleared() {
        let mut room = LocalRoom::create(SessionConfig::default(), None, "Alice").unwrap();
        let alice = room.creator_id();
        for index in 0..501 {
            room.send_message(&alice, &format!("message {index}"))
                .unwrap();
        }
        let snapshot = room.snapshot(&alice).unwrap();
        assert_eq!(snapshot.messages.len(), 500);
        assert_eq!(snapshot.messages[0].body, "message 1");
        room.shutdown().unwrap();
        assert!(room.messages.is_empty());
        assert!(room.invite_code.is_empty());
    }
}
