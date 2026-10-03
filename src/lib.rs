pub mod core;
pub mod crypto;
pub mod identity;
pub mod protocol;
pub mod session;
pub mod transport;

// The library root provides only the high-level manager.
pub use crate::core::ParticipantId;
pub use crate::core::{GhostChatError, Result, SessionConfig};
pub use crate::crypto::CryptoManager;
pub use crate::protocol::{Envelope, Message, RoomConfig};
pub use crate::session::{
    ChatMessage, LocalRoom, NetworkRoom, NetworkUiEvent, ParticipantSnapshot, RoomSnapshot,
    TorInvitation,
};
pub use crate::transport::{
    InMemoryHub, InMemoryStreamTransport, InMemoryTransport, StreamEvent, StreamTransport,
    TorConfig, TorDaemon, TorTransport, Transport, TransportFrame,
};
