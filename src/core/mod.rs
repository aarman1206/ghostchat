use openmls::prelude::Ciphersuite;
use thiserror::Error;

/// All error variants that GhostChat surfaces to callers.
///
/// Individual openmls operations return operation-specific error types
/// (e.g. `NewGroupError`, `SelfUpdateError`). Those are converted to
/// `GhostChatError::MlsError(String)` at each call site with `.map_err`.
///
/// No blanket `From<openmls::Error>` is registered because `openmls` has
/// no single top-level `Error` type — VERIFIED FROM LOCAL SOURCE:
/// openmls-0.9.0/src/error.rs exports `LibraryError` and `ErrorString`
/// only; there is no `pub enum Error` at the crate root.
#[derive(Debug, Error)]
pub enum GhostChatError {
    /// Wraps any openmls operation error as a display string.
    #[error("MLS error: {0}")]
    MlsError(String),

    /// Wraps storage provider errors.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Wraps failures from the cryptographic layer.
    #[error("Cryptography error: {0}")]
    CryptoError(String),

    /// Catches-all for internal invariant violations.
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, GhostChatError>;

/// Runtime configuration for a GhostChat session.
///
/// All fields have documented defaults matching the architecture decisions.
/// Nothing here touches the network, Tor, or UI.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// MLS ciphersuite in use.
    ///
    /// Decision: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
    /// — does not require hardware AES-NI, tested on all target platforms.
    /// VERIFIED FROM LOCAL SOURCE: present in openmls-0.9.0 prelude.rs.
    pub ciphersuite: Ciphersuite,

    /// Recommended interval, in seconds, for the runtime to trigger
    /// periodic MLS `self_update` commits (epoch advance).
    ///
    /// Default: 300 (5 minutes). The core library does not run a scheduler;
    /// the hosting runtime is responsible for invoking `SessionManager::advance_epoch`.
    /// This provides epoch-level forward secrecy with a bounded compromise
    /// window. It is NOT per-message forward secrecy.
    pub epoch_update_interval_secs: u64,

    /// Maximum number of participants per room (hard limit: 3).
    pub max_participants: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            epoch_update_interval_secs: 300,
            max_participants: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_correct_ciphersuite() {
        let cfg = SessionConfig::default();
        assert_eq!(
            cfg.ciphersuite,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        );
    }

    #[test]
    fn default_config_epoch_interval_is_5_minutes() {
        let cfg = SessionConfig::default();
        assert_eq!(cfg.epoch_update_interval_secs, 300);
    }

    #[test]
    fn default_config_max_participants_is_3() {
        let cfg = SessionConfig::default();
        assert_eq!(cfg.max_participants, 3);
    }

    #[test]
    fn ghostchat_error_display() {
        let e = GhostChatError::MlsError("test".to_string());
        assert!(e.to_string().contains("test"));
    }
}
