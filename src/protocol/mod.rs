//! Transport-independent GhostChat application protocol.
//!
//! This module defines a minimal, versioned wire/message envelope for GhostChat
//! that carries MLS messages as opaque payloads. The transport layer treats all
//! MLS ciphertext/messages as opaque byte arrays.
//!
//! Design goals:
//! - Transport-independent (no Tor, no networking assumptions)
//! - MLS messages remain opaque payloads
//! - Explicit protocol versioning and message-type identification
//! - Length/framing validation with malformed/oversized rejection
//! - No plaintext chat content in the envelope

use serde::{Deserialize, Serialize};
use std::fmt;

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowed message size (1 MB).
/// This prevents memory exhaustion from oversized payloads.
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// GhostChat protocol message types.
/// Each variant carries an opaque payload that the transport layer does not inspect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// Room/session introduction or handshake metadata.
    /// Sent by the room creator to initiate a new room.
    RoomIntro {
        /// Random room identifier (16 bytes).
        room_id: [u8; 16],
        /// Room creator's ephemeral public key (Ed25519, 32 bytes).
        creator_identity: Vec<u8>,
        /// Room configuration (max participants, epoch interval, etc.).
        config: RoomConfig,
    },

    /// MLS proposal or commit message.
    /// Carries an `MlsMessageOut` as an opaque byte array.
    MlsHandshake {
        /// The raw MLS message bytes.
        mls_message: Vec<u8>,
    },

    /// MLS Welcome message for joining a group.
    /// Carries a `Welcome` as an opaque byte array.
    MlsWelcome {
        /// The raw Welcome message bytes.
        welcome: Vec<u8>,
    },

    /// MLS application message (encrypted chat content).
    /// Carries an application message as an opaque byte array.
    MlsApplication {
        /// The raw application message bytes.
        application_message: Vec<u8>,
    },

    /// Protocol error.
    Error {
        /// Human-readable error code.
        code: ErrorCode,
        /// Optional human-readable description.
        description: String,
    },

    /// Clean session/room shutdown.
    Shutdown {
        /// Optional reason for shutdown.
        reason: String,
    },
}

/// GhostChat room configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomConfig {
    /// Maximum number of participants (hard limit: 3).
    pub max_participants: u8,
    /// Seconds between periodic MLS self_update commits.
    pub epoch_update_interval_secs: u32,
    /// Ciphersuite identifier.
    pub ciphersuite: u16,
}

impl Default for RoomConfig {
    fn default() -> Self {
        Self {
            max_participants: 3,
            epoch_update_interval_secs: 300,
            ciphersuite: 0x0001, // MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        }
    }
}

/// GhostChat protocol error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ErrorCode {
    /// Generic/unknown error.
    Unknown = 0,
    /// Malformed message (decode failed).
    MalformedMessage = 1,
    /// Unsupported protocol version.
    UnsupportedVersion = 2,
    /// Message exceeds maximum allowed size.
    OversizedPayload = 3,
    /// Message type not supported.
    UnsupportedMessageType = 4,
    /// Invalid room state for this operation.
    InvalidRoomState = 5,
    /// Authentication/authorization failure.
    AuthenticationFailed = 6,
    /// Room is full.
    RoomFull = 7,
    /// Participant not found.
    ParticipantNotFound = 8,
    /// Internal protocol error.
    InternalError = 255,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Encoded protocol message with version and length framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version.
    pub version: u8,
    /// The message payload.
    pub message: Message,
}

impl Envelope {
    /// Create a new envelope with the current protocol version.
    pub fn new(message: Message) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }

    /// Serialize the envelope to bytes (bincode).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let bytes =
            bincode::serialize(self).map_err(|e| EncodeError::Serialization(e.to_string()))?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(EncodeError::OversizedPayload);
        }
        Ok(bytes)
    }

    /// Deserialize an envelope from bytes (bincode).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(DecodeError::OversizedPayload);
        }
        let envelope: Envelope =
            bincode::deserialize(bytes).map_err(|e| DecodeError::Deserialization(e.to_string()))?;
        if envelope.version != PROTOCOL_VERSION {
            return Err(DecodeError::UnsupportedVersion(envelope.version));
        }
        Ok(envelope)
    }
}

/// Envelope encoding errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    Serialization(String),
    OversizedPayload,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::Serialization(e) => write!(f, "serialization error: {}", e),
            EncodeError::OversizedPayload => write!(f, "payload exceeds maximum size"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Envelope decoding errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Deserialization(String),
    UnsupportedVersion(u8),
    OversizedPayload,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Deserialization(e) => write!(f, "deserialization error: {}", e),
            DecodeError::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {}", v),
            DecodeError::OversizedPayload => write!(f, "payload exceeds maximum size"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_mls_message() -> Vec<u8> {
        vec![0x01, 0x02, 0x03, 0x04]
    }

    fn dummy_welcome() -> Vec<u8> {
        vec![0x05, 0x06, 0x07, 0x08]
    }

    fn dummy_app_message() -> Vec<u8> {
        vec![0x09, 0x0A, 0x0B, 0x0C]
    }

    #[test]
    fn encode_decode_room_intro() {
        let msg = Message::RoomIntro {
            room_id: [1u8; 16],
            creator_identity: vec![1, 2, 3, 4],
            config: RoomConfig::default(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn encode_decode_mls_handshake() {
        let msg = Message::MlsHandshake {
            mls_message: dummy_mls_message(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn encode_decode_mls_welcome() {
        let msg = Message::MlsWelcome {
            welcome: dummy_welcome(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn encode_decode_mls_application() {
        let msg = Message::MlsApplication {
            application_message: dummy_app_message(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn encode_decode_error() {
        let msg = Message::Error {
            code: ErrorCode::MalformedMessage,
            description: "test error".to_string(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn encode_decode_shutdown() {
        let msg = Message::Shutdown {
            reason: "session ended".to_string(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn reject_oversized_payload() {
        let large_payload = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let msg = Message::MlsHandshake {
            mls_message: large_payload,
        };
        let envelope = Envelope::new(msg);
        let result = envelope.encode();
        assert!(matches!(result, Err(EncodeError::OversizedPayload)));
    }

    #[test]
    fn reject_oversized_decode() {
        let large_payload = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let msg = Message::MlsHandshake {
            mls_message: large_payload,
        };
        let envelope = Envelope::new(msg);
        // Manually serialize a too-large envelope (bypassing encode check)
        let bytes = bincode::serialize(&envelope).unwrap();
        let result = Envelope::decode(&bytes);
        assert!(matches!(result, Err(DecodeError::OversizedPayload)));
    }

    #[test]
    fn reject_unsupported_version() {
        let msg = Message::RoomIntro {
            room_id: [1u8; 16],
            creator_identity: vec![1, 2, 3, 4],
            config: RoomConfig::default(),
        };
        let mut envelope = Envelope::new(msg);
        envelope.version = PROTOCOL_VERSION + 1;
        let bytes = envelope.encode().expect("encoding should succeed");
        let result = Envelope::decode(&bytes);
        assert!(matches!(result, Err(DecodeError::UnsupportedVersion(_))));
    }

    #[test]
    fn reject_malformed_input() {
        let garbage = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = Envelope::decode(&garbage);
        assert!(matches!(result, Err(DecodeError::Deserialization(_))));
    }

    #[test]
    fn mls_ciphertext_remains_opaque() {
        // The transport layer should never be able to inspect MLS ciphertext.
        // This test verifies that Message::MlsApplication payload is treated as opaque bytes.
        let plaintext = b"Hello, World!";
        let msg = Message::MlsApplication {
            application_message: plaintext.to_vec(),
        };
        let envelope = Envelope::new(msg);
        let encoded = envelope.encode().expect("encoding should succeed");

        // The encoded envelope contains the plaintext as-is in the payload field.
        // In a real deployment, this would be the MLS-encrypted ciphertext.
        // The protocol layer does not inspect or modify the payload.
        let decoded = Envelope::decode(&encoded).expect("decoding should succeed");
        if let Message::MlsApplication {
            application_message,
        } = &decoded.message
        {
            assert_eq!(application_message, plaintext);
        } else {
            panic!("wrong message type");
        }
    }
}
