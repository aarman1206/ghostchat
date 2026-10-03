//! Transport-independent byte delivery primitives.
//!
//! The transport never decodes `Envelope` values and never sees plaintext.
//! `InMemoryTransport` is deliberately local and deterministic: it exists to
//! exercise the same wire boundary that the network Tor adapter uses
//! use without claiming to provide network anonymity.

use std::collections::{BTreeMap, VecDeque};

use crate::core::{GhostChatError, ParticipantId, Result};

pub mod framing;
pub mod stream;
pub mod tor;

pub use framing::{FrameCodec, FrameError, FrameStream, FramedStream, DEFAULT_MAX_FRAME_SIZE};
pub use stream::{
    InMemoryHub, InMemoryStreamTransport, StreamEvent, StreamTransport, TorTransport,
};
pub use tor::{
    OnionServiceConfig, TorConfig, TorDaemon, TorError, TorOnionService, TorResult, TorStream,
};

pub type WireBytes = Vec<u8>;

const MAX_LOCAL_ENDPOINTS: usize = 8;
const MAX_LOCAL_QUEUE_FRAMES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportFrame {
    pub from: ParticipantId,
    pub to: ParticipantId,
    pub bytes: WireBytes,
}

/// A byte-only transport boundary between session management and delivery.
pub trait Transport {
    fn register(&mut self, endpoint: ParticipantId) -> Result<()>;
    fn unregister(&mut self, endpoint: &ParticipantId) -> Result<()>;
    fn send(&mut self, from: &ParticipantId, to: &ParticipantId, bytes: &[u8]) -> Result<()>;
    fn receive(&mut self, recipient: &ParticipantId) -> Result<Option<TransportFrame>>;
}

/// Deterministic FIFO transport for local development and integration tests.
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    queues: BTreeMap<ParticipantId, VecDeque<TransportFrame>>,
}

impl InMemoryTransport {
    pub fn endpoints(&self) -> impl Iterator<Item = &ParticipantId> {
        self.queues.keys()
    }

    pub fn clear(&mut self) {
        self.queues.clear();
    }

    fn ensure_endpoint(&self, endpoint: &ParticipantId) -> Result<()> {
        if self.queues.contains_key(endpoint) {
            Ok(())
        } else {
            Err(GhostChatError::TransportError(format!(
                "unknown transport endpoint: {endpoint}"
            )))
        }
    }
}

impl Transport for InMemoryTransport {
    fn register(&mut self, endpoint: ParticipantId) -> Result<()> {
        if self.queues.contains_key(&endpoint) {
            return Err(GhostChatError::TransportError(format!(
                "transport endpoint already registered: {endpoint}"
            )));
        }
        if self.queues.len() >= MAX_LOCAL_ENDPOINTS {
            return Err(GhostChatError::TransportError(
                "local endpoint limit reached".into(),
            ));
        }
        self.queues.insert(endpoint, VecDeque::new());
        Ok(())
    }

    fn unregister(&mut self, endpoint: &ParticipantId) -> Result<()> {
        self.queues.remove(endpoint).map(|_| ()).ok_or_else(|| {
            GhostChatError::TransportError(format!(
                "cannot unregister unknown transport endpoint: {endpoint}"
            ))
        })
    }

    fn send(&mut self, from: &ParticipantId, to: &ParticipantId, bytes: &[u8]) -> Result<()> {
        self.ensure_endpoint(from)?;
        self.ensure_endpoint(to)?;
        if bytes.is_empty() || bytes.len() > DEFAULT_MAX_FRAME_SIZE {
            return Err(GhostChatError::TransportError(
                "invalid or oversized local frame".into(),
            ));
        }
        let queue = self.queues.get_mut(to).expect("endpoint was checked above");
        if queue.len() >= MAX_LOCAL_QUEUE_FRAMES {
            return Err(GhostChatError::TransportError(
                "local output queue is full".into(),
            ));
        }
        queue.push_back(TransportFrame {
            from: from.clone(),
            to: to.clone(),
            bytes: bytes.to_vec(),
        });
        Ok(())
    }

    fn receive(&mut self, recipient: &ParticipantId) -> Result<Option<TransportFrame>> {
        self.ensure_endpoint(recipient)?;
        Ok(self
            .queues
            .get_mut(recipient)
            .expect("endpoint was checked above")
            .pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ParticipantId {
        ParticipantId::from_public_key(&[byte; 32])
    }

    #[test]
    fn transport_preserves_bytes_and_fifo_order() {
        let alice = id(1);
        let bob = id(2);
        let mut transport = InMemoryTransport::default();
        transport.register(alice.clone()).unwrap();
        transport.register(bob.clone()).unwrap();

        transport.send(&alice, &bob, &[1, 2]).unwrap();
        transport.send(&alice, &bob, &[3, 4]).unwrap();

        assert_eq!(transport.receive(&bob).unwrap().unwrap().bytes, vec![1, 2]);
        assert_eq!(transport.receive(&bob).unwrap().unwrap().bytes, vec![3, 4]);
        assert!(transport.receive(&bob).unwrap().is_none());
    }

    #[test]
    fn transport_rejects_unknown_endpoints_and_duplicate_registration() {
        let alice = id(1);
        let bob = id(2);
        let mut transport = InMemoryTransport::default();
        transport.register(alice.clone()).unwrap();
        assert!(transport.register(alice.clone()).is_err());
        assert!(transport.send(&alice, &bob, b"no").is_err());
        assert!(transport.receive(&bob).is_err());
    }

    #[test]
    fn local_transport_bounds_frames_queues_and_endpoints() {
        let mut transport = InMemoryTransport::default();
        for byte in 0..MAX_LOCAL_ENDPOINTS {
            transport.register(id(byte as u8)).unwrap();
        }
        assert!(transport.register(id(20)).is_err());
        assert!(transport.send(&id(0), &id(1), &[]).is_err());
        assert!(transport
            .send(&id(0), &id(1), &vec![0; DEFAULT_MAX_FRAME_SIZE + 1])
            .is_err());
        for _ in 0..MAX_LOCAL_QUEUE_FRAMES {
            transport.send(&id(0), &id(1), &[1]).unwrap();
        }
        assert!(transport.send(&id(0), &id(1), &[2]).is_err());
        transport.receive(&id(1)).unwrap();
        transport.send(&id(0), &id(1), &[2]).unwrap();
    }
}
