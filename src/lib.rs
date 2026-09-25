pub mod core;
pub mod crypto;
pub mod identity;
pub mod protocol;
pub mod session;

// The library root provides only the high-level manager.
pub use crate::core::{GhostChatError, Result, SessionConfig};
pub use crate::crypto::CryptoManager;
pub use crate::protocol::Envelope;
