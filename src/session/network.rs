//! Tor-backed GhostChat rooms.
//!
//! The session layer consumes a byte-only [`StreamTransport`]. Tor and its
//! onion service are below that boundary; the transport never decodes an
//! [`Envelope`] and never sees application plaintext. The room owner is an
//! MLS member and forwards only authenticated, encoded protocol envelopes to
//! the other members.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bincode::Options;
use ed25519_dalek::{Signature, VerifyingKey};
use openmls::framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut};
use openmls::prelude::{tls_codec::Deserialize, OpenMlsProvider, ProtocolVersion};
use openmls_traits::signatures::Signer;
use rand::random;
use serde::{Deserialize as SerdeDeserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::core::{GhostChatError, ParticipantId, Result, SessionConfig};
use crate::crypto::CryptoManager;
use crate::identity::EphemeralIdentity;
use crate::protocol::{Envelope, ErrorCode, Message, RoomConfig, MAX_MESSAGE_SIZE};
use crate::session::{
    ChatMessage, ParticipantSnapshot, RoomSnapshot, SessionEvent, SessionManager,
};
use crate::transport::{StreamEvent, StreamTransport, TorConfig, TorTransport};

const INVITATION_VERSION: u8 = 1;
const JOIN_TOKEN_BYTES: usize = 32;
const INVITATION_MAX_BYTES: usize = 8 * 1024;
const MAX_POLL_EVENTS: usize = 128;
const MAX_UNJOINED_CONNECTIONS: usize = 8;
const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Post-join control and chat values are themselves MLS application
/// plaintext. Outer envelopes carry only opaque MLS ciphertext.
#[derive(Clone, Serialize, SerdeDeserialize)]
enum Payload {
    Chat(String),
    Ready,
    Names(Vec<(ParticipantId, String)>),
    Shutdown,
    Leave,
    ReadyAccepted,
    ReadyRetry,
}

#[derive(Clone, Serialize, SerdeDeserialize)]
pub struct TorInvitation {
    pub version: u8,
    pub onion_address: String,
    pub virtual_port: u16,
    pub room_intro: Vec<u8>,
    pub join_token: Vec<u8>,
    /// Ed25519 signature by the creator over all other invitation fields.
    pub creator_signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedInvitation<'a> {
    version: u8,
    onion_address: &'a str,
    virtual_port: u16,
    room_intro: &'a [u8],
    join_token: &'a [u8],
}

impl TorInvitation {
    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"GhostChat invitation v1\0".to_vec();
        bytes.extend(
            crate::protocol::wire_options(INVITATION_MAX_BYTES as u64)
                .serialize(&UnsignedInvitation {
                    version: self.version,
                    onion_address: &self.onion_address,
                    virtual_port: self.virtual_port,
                    room_intro: &self.room_intro,
                    join_token: &self.join_token,
                })
                .map_err(|error| GhostChatError::ProtocolError(error.to_string()))?,
        );
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        if self.version != INVITATION_VERSION {
            return Err(GhostChatError::ProtocolError(
                "unsupported Tor invitation version".to_string(),
            ));
        }
        validate_onion_address(&self.onion_address)?;
        if self.virtual_port == 0 || self.join_token.len() != JOIN_TOKEN_BYTES {
            return Err(GhostChatError::ProtocolError(
                "invitation contains invalid Tor routing material".to_string(),
            ));
        }
        if self.room_intro.len() > MAX_MESSAGE_SIZE || self.creator_signature.len() != 64 {
            return Err(GhostChatError::ProtocolError(
                "invitation contains oversized or malformed authentication data".to_string(),
            ));
        }
        let (_, creator_identity, _) = parse_room_intro(self)?;
        let public_key: [u8; 32] = creator_identity.as_slice().try_into().map_err(|_| {
            GhostChatError::ProtocolError("creator identity has an invalid length".to_string())
        })?;
        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
            GhostChatError::ProtocolError("creator identity is not a valid Ed25519 key".to_string())
        })?;
        let signature = Signature::from_slice(&self.creator_signature).map_err(|_| {
            GhostChatError::ProtocolError("invitation signature has an invalid length".to_string())
        })?;
        let unsigned_bytes = Zeroizing::new(self.unsigned_bytes()?);
        verifying_key
            .verify_strict(&unsigned_bytes, &signature)
            .map_err(|_| {
                GhostChatError::ProtocolError("invitation authentication failed".to_string())
            })
    }

    pub fn encode_code(&self) -> Result<String> {
        self.validate()?;
        let bytes = Zeroizing::new(
            crate::protocol::wire_options(INVITATION_MAX_BYTES as u64)
                .serialize(self)
                .map_err(|error| GhostChatError::ProtocolError(error.to_string()))?,
        );
        if bytes.len() > INVITATION_MAX_BYTES {
            return Err(GhostChatError::ProtocolError(
                "invitation is too large".to_string(),
            ));
        }
        Ok(hex_encode(&bytes))
    }

    pub fn decode_code(code: &str) -> Result<Self> {
        let code = code.trim();
        if code.is_empty() || code.len() > INVITATION_MAX_BYTES.saturating_mul(2) {
            return Err(GhostChatError::ProtocolError(
                "invitation code is empty or too large".to_string(),
            ));
        }
        let bytes = Zeroizing::new(hex_decode(code)?);
        if bytes.len() > INVITATION_MAX_BYTES {
            return Err(GhostChatError::ProtocolError(
                "invitation is too large".to_string(),
            ));
        }
        let invitation: Self = crate::protocol::wire_options(INVITATION_MAX_BYTES as u64)
            .deserialize(&bytes)
            .map_err(|error| GhostChatError::ProtocolError(error.to_string()))?;
        invitation.validate()?;
        Ok(invitation)
    }

    fn signed(
        onion_address: String,
        virtual_port: u16,
        room_intro: Vec<u8>,
        join_token: Vec<u8>,
        signer: &EphemeralIdentity,
    ) -> Result<Self> {
        let mut invitation = Self {
            version: INVITATION_VERSION,
            onion_address,
            virtual_port,
            room_intro,
            join_token,
            creator_signature: Vec::new(),
        };
        let unsigned_bytes = Zeroizing::new(invitation.unsigned_bytes()?);
        invitation.creator_signature = signer
            .signer
            .sign(&unsigned_bytes)
            .map_err(|error| GhostChatError::CryptoError(format!("{error:?}")))?;
        invitation.validate()?;
        Ok(invitation)
    }
}

impl Drop for TorInvitation {
    fn drop(&mut self) {
        self.join_token.zeroize();
    }
}

#[derive(Clone, Debug)]
pub enum NetworkUiEvent {
    Message(ChatMessage),
    Participant(ParticipantSnapshot),
    State(RoomSnapshot),
    Error(String),
}

struct Peer {
    display_name: String,
    connection_id: u64,
}

struct PendingPeer {
    participant_id: ParticipantId,
    display_name: String,
    connection_id: u64,
    deadline: Instant,
    welcome_epoch: u64,
}

struct JoinMaterial {
    crypto_manager: CryptoManager,
    identity: EphemeralIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkRole {
    Creator,
    Joiner,
}

struct NetworkRoomInner {
    config: SessionConfig,
    role: NetworkRole,
    transport: Box<dyn StreamTransport>,
    session: Option<SessionManager>,
    join_material: Option<JoinMaterial>,
    self_id: ParticipantId,
    creator_id: ParticipantId,
    room_id: [u8; 16],
    room_name: String,
    join_token: Vec<u8>,
    invitation_code: String,
    peers: BTreeMap<ParticipantId, Peer>,
    pending: BTreeMap<ParticipantId, PendingPeer>,
    unjoined: BTreeMap<u64, Instant>,
    join_deadline: Option<Instant>,
    welcome_received: bool,
    ready_sent: bool,
    ready: bool,
    participant_names: BTreeMap<ParticipantId, String>,
    messages: Vec<ChatMessage>,
    next_message_id: u64,
    closed: bool,
}

#[derive(Clone)]
pub struct NetworkRoom {
    inner: Arc<Mutex<NetworkRoomInner>>,
}

impl NetworkRoom {
    pub fn create(
        config: SessionConfig,
        room_name: Option<String>,
        display_name: &str,
    ) -> Result<Self> {
        let tor = TorConfig::from_env().map_err(transport_error)?;
        Self::create_with_tor(config, tor, room_name, display_name)
    }

    pub fn create_with_tor(
        config: SessionConfig,
        tor: TorConfig,
        room_name: Option<String>,
        display_name: &str,
    ) -> Result<Self> {
        Self::create_with_transport(config, room_name, display_name, || {
            let (transport, address, port) = TorTransport::host(tor).map_err(transport_error)?;
            Ok((Box::new(transport), address, port))
        })
    }

    fn create_with_transport(
        config: SessionConfig,
        room_name: Option<String>,
        display_name: &str,
        host: impl FnOnce() -> Result<(Box<dyn StreamTransport>, String, u16)>,
    ) -> Result<Self> {
        validate_session_config(&config)?;
        let display_name = normalise_name(display_name)?;
        let room_name = normalise_room_name(room_name);
        let room_id = random::<[u8; 16]>();
        let session = SessionManager::create_for_room(config.clone(), &room_id)?;
        let self_id = session.participant_id();
        let creator_id = self_id.clone();
        let intro = Envelope::room_intro(
            room_id,
            session.public_key().to_vec(),
            room_config(&config)?,
        );
        let room_intro = intro
            .encode()
            .map_err(|error| GhostChatError::ProtocolError(error.to_string()))?;
        // Validate all local room material before creating an onion service.
        let (transport, onion_address, virtual_port) = host()?;
        let join_token = random::<[u8; JOIN_TOKEN_BYTES]>().to_vec();
        let invitation = TorInvitation::signed(
            onion_address,
            virtual_port,
            room_intro,
            join_token.clone(),
            &session.creator_identity,
        )?;
        let invitation_code = invitation.encode_code()?;
        let mut participant_names = BTreeMap::new();
        participant_names.insert(self_id.clone(), display_name);
        Ok(Self {
            inner: Arc::new(Mutex::new(NetworkRoomInner {
                config,
                role: NetworkRole::Creator,
                transport,
                session: Some(session),
                join_material: None,
                self_id,
                creator_id,
                room_id,
                room_name,
                join_token,
                invitation_code,
                peers: BTreeMap::new(),
                pending: BTreeMap::new(),
                unjoined: BTreeMap::new(),
                join_deadline: None,
                welcome_received: true,
                ready_sent: false,
                ready: true,
                participant_names,
                messages: Vec::new(),
                next_message_id: 1,
                closed: false,
            })),
        })
    }

    pub fn join(invitation_code: &str, config: SessionConfig, display_name: &str) -> Result<Self> {
        let invitation = TorInvitation::decode_code(invitation_code)?;
        let tor = TorConfig::from_env().map_err(transport_error)?;
        Self::join_with_tor(invitation, config, tor, display_name)
    }

    pub fn join_with_tor(
        invitation: TorInvitation,
        config: SessionConfig,
        tor: TorConfig,
        display_name: &str,
    ) -> Result<Self> {
        Self::join_with_transport(
            invitation,
            config,
            display_name,
            Instant::now(),
            |host, port| {
                TorTransport::connect(tor, host, port)
                    .map(|transport| Box::new(transport) as Box<dyn StreamTransport>)
                    .map_err(transport_error)
            },
        )
    }

    fn join_with_transport(
        invitation: TorInvitation,
        config: SessionConfig,
        display_name: &str,
        now: Instant,
        connect: impl FnOnce(&str, u16) -> Result<Box<dyn StreamTransport>>,
    ) -> Result<Self> {
        invitation.validate()?;
        let (room_id, creator_public_key, room_config_wire) = parse_room_intro(&invitation)?;
        let config = room_config_for_join(config, &room_config_wire)?;
        let display_name = normalise_name(display_name)?;
        let invitation_code = invitation.encode_code()?;
        let crypto_manager = CryptoManager::new(config.clone());
        let identity = EphemeralIdentity::generate(config.ciphersuite, &crypto_manager.provider)?;
        let key_package = identity.key_package(config.ciphersuite, &crypto_manager.provider)?;
        let key_package_bytes = MlsMessageOut::from(key_package)
            .to_bytes()
            .map_err(|error| GhostChatError::MlsError(error.to_string()))?;
        let join_token = invitation.join_token.clone();
        let join_request =
            Envelope::join_request(join_token.clone(), display_name.clone(), key_package_bytes);
        let mut transport = connect(&invitation.onion_address, invitation.virtual_port)?;
        if let Err(error) = send_wire_transport(&mut *transport, 0, &join_request) {
            transport.shutdown();
            return Err(error);
        }

        let self_id = identity.participant_id();
        let creator_id = ParticipantId::from_public_key(&creator_public_key);
        let mut participant_names = BTreeMap::new();
        participant_names.insert(self_id.clone(), display_name);
        participant_names.insert(creator_id.clone(), "Room creator".to_string());
        let mut peers = BTreeMap::new();
        peers.insert(
            creator_id.clone(),
            Peer {
                display_name: "Room creator".to_string(),
                connection_id: 0,
            },
        );
        Ok(Self {
            inner: Arc::new(Mutex::new(NetworkRoomInner {
                config,
                role: NetworkRole::Joiner,
                transport,
                session: None,
                join_material: Some(JoinMaterial {
                    crypto_manager,
                    identity,
                }),
                self_id,
                creator_id,
                room_id,
                room_name: "GhostChat room".to_string(),
                join_token,
                invitation_code,
                peers,
                pending: BTreeMap::new(),
                unjoined: BTreeMap::new(),
                join_deadline: Some(now + JOIN_TIMEOUT),
                welcome_received: false,
                ready_sent: false,
                ready: false,
                participant_names,
                messages: Vec::new(),
                next_message_id: 1,
                closed: false,
            })),
        })
    }

    pub fn invite_code(&self) -> Result<String> {
        let inner = self.lock()?;
        ensure_open(&inner)?;
        Ok(inner.invitation_code.clone())
    }

    pub fn session_id(&self) -> Result<String> {
        Ok(hex_encode(&self.lock()?.room_id))
    }

    pub fn creator_id(&self) -> Result<ParticipantId> {
        Ok(self.lock()?.creator_id.clone())
    }

    pub fn is_creator(&self) -> Result<bool> {
        Ok(self.lock()?.role == NetworkRole::Creator)
    }

    pub fn poll(&self) -> Result<Vec<NetworkUiEvent>> {
        self.poll_at(Instant::now())
    }

    fn poll_at(&self, now: Instant) -> Result<Vec<NetworkUiEvent>> {
        let mut inner = self.lock()?;
        let mut events = Vec::new();
        if inner.closed {
            return Ok(events);
        }
        let mut processed_event = false;
        expire_connections(&mut inner, now, &mut events)?;
        for _ in 0..MAX_POLL_EVENTS {
            if inner.closed {
                break;
            }
            let event = match inner.transport.receive() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => {
                    close_room(&mut inner);
                    return Err(error);
                }
            };
            processed_event = true;
            if let Err(error) = handle_stream_event(&mut inner, event, now, &mut events) {
                events.push(NetworkUiEvent::Error(error.to_string()));
            }
        }
        if let Err(error) = send_ready_if_needed(&mut inner) {
            close_room(&mut inner);
            return Err(error);
        }
        if processed_event || !events.is_empty() {
            events.push(NetworkUiEvent::State(snapshot_locked(&inner)?));
        }
        Ok(events)
    }

    pub fn snapshot(&self) -> Result<RoomSnapshot> {
        let inner = self.lock()?;
        snapshot_locked(&inner)
    }

    pub fn send_message(&self, body: &str) -> Result<ChatMessage> {
        let mut inner = self.lock()?;
        ensure_open(&inner)?;
        if !inner.ready {
            return Err(GhostChatError::ProtocolError(
                "waiting for room creator to confirm MLS readiness".into(),
            ));
        }
        let body = validate_body(body)?;
        let payload = Zeroizing::new(encode_payload(&Payload::Chat(body.clone()))?);
        let envelope = inner
            .session
            .as_mut()
            .ok_or_else(|| GhostChatError::Internal("waiting for MLS Welcome".to_string()))?
            .send_application(&payload)?;
        if let Err(error) = send_from_local(&mut inner, &envelope) {
            close_room(&mut inner);
            return Err(error);
        }
        let sender_id = inner.self_id.clone();
        let message = make_chat_message(&mut inner, &sender_id, body);
        inner.messages.push(message.clone());
        if inner.messages.len() > 500 {
            clear_message(&mut inner.messages.remove(0));
        }
        Ok(message)
    }

    pub fn advance_epoch(&self) -> Result<u64> {
        let mut inner = self.lock()?;
        ensure_open(&inner)?;
        if inner.role != NetworkRole::Creator {
            return Err(GhostChatError::ProtocolError(
                "only the room owner can advance the MLS epoch".to_string(),
            ));
        }
        if !inner.pending.is_empty() {
            return Err(GhostChatError::ProtocolError(
                "cannot advance the MLS epoch while a participant is joining".to_string(),
            ));
        }
        let result = inner
            .session
            .as_mut()
            .ok_or(GhostChatError::SessionClosed)?
            .advance_epoch();
        let commit = match result {
            Ok(commit) => commit,
            Err(error) => {
                close_room(&mut inner);
                return Err(error);
            }
        };
        let bytes = match commit.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                close_room(&mut inner);
                return Err(GhostChatError::MlsError(error.to_string()));
            }
        };
        let envelope = Envelope::mls_handshake(bytes);
        broadcast(&mut inner, &envelope, None)?;
        broadcast_pending(&mut inner, &envelope, None)?;
        inner
            .session
            .as_ref()
            .map(SessionManager::epoch)
            .ok_or(GhostChatError::SessionClosed)
    }

    pub fn remove_participant(&self, participant_id: &str) -> Result<()> {
        let participant_id = ParticipantId::parse(participant_id).ok_or_else(|| {
            GhostChatError::ProtocolError("participant identifier is invalid".to_string())
        })?;
        let mut inner = self.lock()?;
        ensure_open(&inner)?;
        if inner.role != NetworkRole::Creator {
            return Err(GhostChatError::ProtocolError(
                "only the room owner can remove a participant".to_string(),
            ));
        }
        let connection_id = inner
            .peers
            .get(&participant_id)
            .map(|peer| peer.connection_id)
            .or_else(|| {
                inner
                    .pending
                    .get(&participant_id)
                    .map(|peer| peer.connection_id)
            })
            .ok_or_else(|| {
                GhostChatError::ProtocolError("participant is not connected".to_string())
            })?;
        disconnect_connection(&mut inner, connection_id, &mut Vec::new())
    }

    pub fn shutdown(&self) -> Result<()> {
        let mut inner = self.lock()?;
        if inner.closed {
            return Ok(());
        }
        let control = if inner.role == NetworkRole::Creator {
            Payload::Shutdown
        } else {
            Payload::Leave
        };
        if inner.session.is_some() {
            // Encrypt once for the group, including peers awaiting confirmation.
            if let Ok(bytes) = encode_payload(&control) {
                if let Ok(envelope) = inner.session.as_mut().unwrap().send_application(&bytes) {
                    for connection_id in member_connections(&inner, true, None) {
                        let _ = send_wire(&mut inner, connection_id, &envelope);
                    }
                }
            }
        }
        // Do not tear down the socket until a leave/shutdown ciphertext has
        // passed through the writer. The transport still closes the stream
        // immediately afterward, so this remains bounded.
        let _ = inner.transport.flush();
        close_room(&mut inner);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, NetworkRoomInner>> {
        self.inner
            .lock()
            .map_err(|_| GhostChatError::TransportError("network room lock poisoned".to_string()))
    }
}

impl Drop for NetworkRoomInner {
    fn drop(&mut self) {
        // Arc's last-owner destruction is atomic, unlike a strong_count check
        // on each handle. This also runs after simultaneous handle drops.
        close_room(self);
    }
}

fn clear_message(message: &mut ChatMessage) {
    message.body.zeroize();
    message.sender_name.zeroize();
}

fn close_room(inner: &mut NetworkRoomInner) {
    if inner.closed {
        return;
    }
    inner.closed = true;
    inner.ready = false;
    inner.welcome_received = false;
    inner.ready_sent = false;
    inner.transport.shutdown();
    inner.join_deadline = None;
    inner.unjoined.clear();
    for peer in inner.peers.values_mut() {
        peer.display_name.zeroize();
    }
    for peer in inner.pending.values_mut() {
        peer.display_name.zeroize();
    }
    inner.peers.clear();
    inner.pending.clear();
    inner
        .participant_names
        .values_mut()
        .for_each(Zeroize::zeroize);
    inner.participant_names.clear();
    inner.messages.iter_mut().for_each(clear_message);
    inner.messages.clear();
    inner.join_token.zeroize();
    inner.invitation_code.zeroize();
    inner.room_name.zeroize();
    // Drops our owned OpenMLS/provider/identity state. Upstream allocations and
    // copies already returned to callers are not a secure-erasure guarantee.
    inner.session = None;
    inner.join_material = None;
}

fn send_wire_transport<T: StreamTransport + ?Sized>(
    transport: &mut T,
    connection_id: u64,
    envelope: &Envelope,
) -> Result<()> {
    let bytes = Zeroizing::new(
        envelope
            .encode()
            .map_err(|error| GhostChatError::ProtocolError(error.to_string()))?,
    );
    transport.send(connection_id, &bytes)
}

fn send_wire(inner: &mut NetworkRoomInner, connection_id: u64, envelope: &Envelope) -> Result<()> {
    send_wire_transport(&mut *inner.transport, connection_id, envelope)
}

fn encode_payload(payload: &Payload) -> Result<Vec<u8>> {
    crate::protocol::wire_options(MAX_MESSAGE_SIZE as u64)
        .serialize(payload)
        .map_err(|error| GhostChatError::ProtocolError(error.to_string()))
}

fn decode_payload(bytes: &[u8]) -> Result<Payload> {
    crate::protocol::wire_options(MAX_MESSAGE_SIZE as u64)
        .deserialize(bytes)
        .map_err(|error| GhostChatError::ProtocolError(error.to_string()))
}

fn send_control(inner: &mut NetworkRoomInner, connection_id: u64, payload: &Payload) -> Result<()> {
    let bytes = Zeroizing::new(encode_payload(payload)?);
    let envelope = inner
        .session
        .as_mut()
        .ok_or(GhostChatError::SessionClosed)?
        .send_application(&bytes)?;
    send_wire(inner, connection_id, &envelope)
}

fn send_ready_if_needed(inner: &mut NetworkRoomInner) -> Result<()> {
    if inner.role != NetworkRole::Joiner
        || inner.closed
        || !inner.welcome_received
        || inner.ready
        || inner.ready_sent
        || inner.session.is_none()
    {
        return Ok(());
    }
    let connection_id = inner
        .peers
        .get(&inner.creator_id)
        .map(|peer| peer.connection_id)
        .ok_or_else(|| GhostChatError::TransportError("creator connection is missing".into()))?;
    send_control(inner, connection_id, &Payload::Ready)?;
    inner.ready_sent = true;
    Ok(())
}

fn send_from_local(inner: &mut NetworkRoomInner, envelope: &Envelope) -> Result<()> {
    if inner.role == NetworkRole::Creator {
        broadcast(inner, envelope, None)
    } else {
        let connection_id = inner
            .peers
            .get(&inner.creator_id)
            .map(|peer| peer.connection_id)
            .ok_or_else(|| {
                GhostChatError::TransportError("creator connection is missing".to_string())
            })?;
        send_wire(inner, connection_id, envelope)
    }
}

fn broadcast(
    inner: &mut NetworkRoomInner,
    envelope: &Envelope,
    except_connection_id: Option<u64>,
) -> Result<()> {
    let connection_ids: Vec<u64> = inner
        .peers
        .values()
        .filter(|peer| Some(peer.connection_id) != except_connection_id)
        .map(|peer| peer.connection_id)
        .collect();
    let mut first_error = None;
    for connection_id in connection_ids {
        if let Err(error) = send_wire(inner, connection_id, envelope) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    if let Some(error) = first_error {
        // A partially delivered epoch change cannot be rolled back on the
        // remote MLS groups. Close the room rather than retain split state.
        close_room(inner);
        Err(error)
    } else {
        Ok(())
    }
}

fn member_connections(
    inner: &NetworkRoomInner,
    include_pending: bool,
    except_connection_id: Option<u64>,
) -> Vec<u64> {
    let mut ids: Vec<u64> = inner
        .peers
        .values()
        .map(|peer| peer.connection_id)
        .collect();
    if include_pending {
        ids.extend(inner.pending.values().map(|peer| peer.connection_id));
    }
    ids.sort_unstable();
    ids.dedup();
    ids.retain(|id| Some(*id) != except_connection_id);
    ids
}

fn broadcast_pending(
    inner: &mut NetworkRoomInner,
    envelope: &Envelope,
    except_connection_id: Option<u64>,
) -> Result<()> {
    let connection_ids: Vec<u64> = inner
        .pending
        .values()
        .filter(|peer| Some(peer.connection_id) != except_connection_id)
        .map(|peer| peer.connection_id)
        .collect();
    let mut first_error = None;
    for connection_id in connection_ids {
        if let Err(error) = send_wire(inner, connection_id, envelope) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    if let Some(error) = first_error {
        close_room(inner);
        Err(error)
    } else {
        Ok(())
    }
}

fn broadcast_names(inner: &mut NetworkRoomInner) -> Result<()> {
    let names = current_names(inner);
    validate_names(inner, &names)?;
    // Refresh the complete metadata snapshot for confirmed peers. Pending
    // members receive commits and must authenticate Ready at the new epoch.
    for connection_id in member_connections(inner, false, None) {
        send_control(inner, connection_id, &Payload::Names(names.clone()))?;
    }
    Ok(())
}

fn current_member_ids(inner: &NetworkRoomInner) -> Vec<ParticipantId> {
    inner
        .session
        .as_ref()
        .map(|session| {
            session
                .group
                .members()
                .map(|member| ParticipantId::from_public_key(&member.signature_key))
                .collect()
        })
        .unwrap_or_default()
}

fn current_names(inner: &NetworkRoomInner) -> Vec<(ParticipantId, String)> {
    let members = current_member_ids(inner);
    members
        .into_iter()
        .filter_map(|participant_id| {
            inner
                .participant_names
                .get(&participant_id)
                .cloned()
                .map(|name| (participant_id, name))
        })
        .collect()
}

fn validate_names(inner: &NetworkRoomInner, names: &[(ParticipantId, String)]) -> Result<()> {
    if names.len() > inner.config.max_participants.min(3) {
        return Err(GhostChatError::ProtocolError(
            "participant metadata exceeds the room limit".to_string(),
        ));
    }
    let member_ids: std::collections::BTreeSet<_> = current_member_ids(inner).into_iter().collect();
    let name_ids: std::collections::BTreeSet<_> = names.iter().map(|(id, _)| id.clone()).collect();
    if !name_ids.is_subset(&member_ids) || name_ids.len() != names.len() {
        return Err(GhostChatError::ProtocolError(
            "participant metadata must name unique current members".into(),
        ));
    }
    for (participant_id, name) in names {
        if !member_ids.contains(participant_id) {
            return Err(GhostChatError::ProtocolError(
                "participant metadata names a non-member".to_string(),
            ));
        }
        normalise_name(name)?;
    }
    Ok(())
}

fn rollback_join(inner: &mut NetworkRoomInner, participant_id: &ParticipantId) -> Result<()> {
    inner.pending.remove(participant_id);
    inner.participant_names.remove(participant_id);
    let Some(session) = inner.session.as_mut() else {
        return Ok(());
    };
    let commit = session.remove_member(participant_id)?;
    let envelope = Envelope::mls_handshake(
        commit
            .to_bytes()
            .map_err(|error| GhostChatError::MlsError(error.to_string()))?,
    );
    broadcast(inner, &envelope, None)
}

fn expire_connections(
    inner: &mut NetworkRoomInner,
    now: Instant,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    if inner.role == NetworkRole::Joiner {
        if inner.join_deadline.is_some_and(|deadline| now >= deadline) {
            close_room(inner);
            ui_events.push(NetworkUiEvent::Error("join timed out".to_string()));
        }
        return Ok(());
    }
    let expired_unjoined: Vec<u64> = inner
        .unjoined
        .iter()
        .filter(|(_, deadline)| now >= **deadline)
        .map(|(connection_id, _)| *connection_id)
        .collect();
    for connection_id in expired_unjoined {
        inner.unjoined.remove(&connection_id);
        inner.transport.disconnect(connection_id);
    }
    let expired_pending: Vec<u64> = inner
        .pending
        .values()
        .filter(|peer| now >= peer.deadline)
        .map(|peer| peer.connection_id)
        .collect();
    for connection_id in expired_pending {
        disconnect_connection(inner, connection_id, ui_events)?;
        ui_events.push(NetworkUiEvent::Error("participant join timed out".into()));
        if inner.closed {
            break;
        }
    }
    Ok(())
}

fn send_error(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    code: ErrorCode,
    _description: &str,
) {
    let description = error_description(code);
    let envelope = Envelope::new(Message::Error {
        code,
        description: description.to_string(),
    });
    let _ = send_wire(inner, connection_id, &envelope);
}

fn error_description(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::MalformedMessage => "The peer sent a malformed message.",
        ErrorCode::UnsupportedVersion => "The peer uses an unsupported protocol version.",
        ErrorCode::OversizedPayload => "The peer sent an oversized payload.",
        ErrorCode::UnsupportedMessageType => "The peer sent an unsupported message type.",
        ErrorCode::InvalidRoomState => "The room is not ready for that operation.",
        ErrorCode::AuthenticationFailed => "Peer authentication failed.",
        ErrorCode::RoomFull => "The room is full.",
        ErrorCode::ParticipantNotFound => "The participant was not found.",
        ErrorCode::Unknown | ErrorCode::InternalError => "The peer request could not be completed.",
    }
}

fn handle_stream_event(
    inner: &mut NetworkRoomInner,
    event: StreamEvent,
    now: Instant,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    ensure_open(inner)?;
    match event {
        StreamEvent::Connected { connection_id } => {
            if inner.role == NetworkRole::Creator {
                if inner.unjoined.len() >= MAX_UNJOINED_CONNECTIONS {
                    inner.transport.disconnect(connection_id);
                    return Err(GhostChatError::ParticipantLimitReached);
                }
                inner
                    .unjoined
                    .entry(connection_id)
                    .or_insert(now + JOIN_TIMEOUT);
            }
            Ok(())
        }
        StreamEvent::Frame {
            connection_id,
            bytes,
        } => {
            let envelope = match Envelope::decode(&bytes) {
                Ok(envelope) => envelope,
                Err(error) => {
                    send_error(
                        inner,
                        connection_id,
                        ErrorCode::MalformedMessage,
                        "invalid protocol envelope",
                    );
                    disconnect_connection(inner, connection_id, ui_events)?;
                    return Err(GhostChatError::ProtocolError(error.to_string()));
                }
            };
            let result = handle_frame(inner, connection_id, envelope, now, ui_events);
            if result.is_err() {
                disconnect_connection(inner, connection_id, ui_events)?;
            }
            result
        }
        StreamEvent::Closed { connection_id } => {
            disconnect_connection(inner, connection_id, ui_events)
        }
    }
}

fn handle_frame(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    envelope: Envelope,
    now: Instant,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    ensure_open(inner)?;
    let active = inner
        .peers
        .iter()
        .find(|(_, peer)| peer.connection_id == connection_id)
        .map(|(participant_id, _)| participant_id.clone());
    let pending = inner
        .pending
        .iter()
        .find(|(_, peer)| peer.connection_id == connection_id)
        .map(|(participant_id, _)| participant_id.clone());

    if let Some(participant_id) = active {
        return if inner.role == NetworkRole::Creator {
            handle_creator_peer_frame(inner, connection_id, participant_id, envelope, ui_events)
        } else {
            if connection_id != 0 {
                inner.transport.disconnect(connection_id);
                close_room(inner);
                return Err(GhostChatError::ProtocolError(
                    "joiner received a frame on an unexpected connection".to_string(),
                ));
            }
            handle_joiner_peer_frame(inner, connection_id, envelope, now, ui_events)
        };
    }
    if pending.is_some() {
        if matches!(envelope.message, Message::MlsApplication { .. }) {
            return handle_pending_ready(inner, connection_id, envelope, ui_events);
        }
        send_error(
            inner,
            connection_id,
            ErrorCode::InvalidRoomState,
            "join is not ready",
        );
        let _ = disconnect_connection(inner, connection_id, ui_events);
        return Err(GhostChatError::ProtocolError(
            "pending peer sent an unexpected message".to_string(),
        ));
    }

    if inner.role == NetworkRole::Creator {
        if !inner.unjoined.contains_key(&connection_id) {
            inner.transport.disconnect(connection_id);
            return Err(GhostChatError::ProtocolError(
                "unregistered connection".into(),
            ));
        }
        if let Message::JoinRequest {
            token,
            display_name,
            key_package,
        } = envelope.message
        {
            inner.unjoined.remove(&connection_id);
            return handle_join_request(
                inner,
                connection_id,
                token,
                display_name,
                key_package,
                now,
                ui_events,
            );
        }
    }
    send_error(
        inner,
        connection_id,
        ErrorCode::InvalidRoomState,
        "unexpected first message",
    );
    inner.transport.disconnect(connection_id);
    Err(GhostChatError::ProtocolError(
        "unexpected first message on Tor connection".to_string(),
    ))
}

fn handle_join_request(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    token: Vec<u8>,
    display_name: String,
    key_package_bytes: Vec<u8>,
    now: Instant,
    _ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    if !constant_time_eq(&token, &inner.join_token) {
        send_error(
            inner,
            connection_id,
            ErrorCode::AuthenticationFailed,
            "invitation authentication failed",
        );
        inner.transport.disconnect(connection_id);
        return Err(GhostChatError::ProtocolError(
            "join invitation authentication failed".to_string(),
        ));
    }
    let display_name = match normalise_name(&display_name) {
        Ok(name) => name,
        Err(error) => {
            send_error(
                inner,
                connection_id,
                ErrorCode::MalformedMessage,
                "invalid display name",
            );
            inner.transport.disconnect(connection_id);
            return Err(error);
        }
    };
    if !inner.pending.is_empty() {
        send_error(
            inner,
            connection_id,
            ErrorCode::InvalidRoomState,
            "another participant is joining",
        );
        inner.transport.disconnect(connection_id);
        return Err(GhostChatError::ProtocolError(
            "another participant is already joining".to_string(),
        ));
    }
    let session = inner
        .session
        .as_ref()
        .ok_or(GhostChatError::SessionClosed)?;
    if session.member_count() >= inner.config.max_participants.min(3) {
        send_error(inner, connection_id, ErrorCode::RoomFull, "room is full");
        inner.transport.disconnect(connection_id);
        return Err(GhostChatError::ParticipantLimitReached);
    }
    let key_package_message =
        match MlsMessageIn::tls_deserialize_exact(key_package_bytes.as_slice()) {
            Ok(message) => message,
            Err(error) => {
                send_error(
                    inner,
                    connection_id,
                    ErrorCode::MalformedMessage,
                    "invalid KeyPackage",
                );
                inner.transport.disconnect(connection_id);
                return Err(GhostChatError::MlsError(error.to_string()));
            }
        };
    let key_package = match key_package_message.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package
            .validate(
                session.crypto_manager.provider.crypto(),
                ProtocolVersion::Mls10,
            )
            .map_err(|error| {
                send_error(
                    inner,
                    connection_id,
                    ErrorCode::AuthenticationFailed,
                    "invalid KeyPackage",
                );
                inner.transport.disconnect(connection_id);
                GhostChatError::MlsError(error.to_string())
            })?,
        _ => {
            send_error(
                inner,
                connection_id,
                ErrorCode::MalformedMessage,
                "join request did not contain a KeyPackage",
            );
            inner.transport.disconnect(connection_id);
            return Err(GhostChatError::ProtocolError(
                "join request did not contain a KeyPackage".to_string(),
            ));
        }
    };
    if key_package.ciphersuite() != inner.config.ciphersuite {
        send_error(
            inner,
            connection_id,
            ErrorCode::AuthenticationFailed,
            "KeyPackage ciphersuite does not match the room",
        );
        inner.transport.disconnect(connection_id);
        return Err(GhostChatError::ProtocolError(
            "KeyPackage ciphersuite does not match room".to_string(),
        ));
    }
    let participant_id =
        ParticipantId::from_public_key(key_package.leaf_node().signature_key().as_slice());
    if participant_id == inner.self_id
        || inner.peers.contains_key(&participant_id)
        || inner.pending.contains_key(&participant_id)
    {
        send_error(
            inner,
            connection_id,
            ErrorCode::AuthenticationFailed,
            "participant is already present",
        );
        inner.transport.disconnect(connection_id);
        return Err(GhostChatError::ProtocolError(
            "participant is already present".to_string(),
        ));
    }
    let (commit, welcome) = {
        let session = inner
            .session
            .as_mut()
            .ok_or(GhostChatError::SessionClosed)?;
        let result = session.add_member(key_package);
        let (commit, welcome, _) = match result {
            Ok(artifacts) => artifacts,
            Err(error) => {
                if !session.is_active() {
                    close_room(inner);
                }
                return Err(error);
            }
        };
        (commit, welcome)
    };
    let tree_bytes = match inner
        .session
        .as_ref()
        .ok_or(GhostChatError::SessionClosed)?
        .export_ratchet_tree_bytes()
    {
        Ok(bytes) => bytes,
        Err(error) => {
            close_room(inner);
            return Err(error);
        }
    };
    let commit_bytes = match commit.to_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            close_room(inner);
            return Err(GhostChatError::MlsError(error.to_string()));
        }
    };
    let welcome_bytes = match welcome.to_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            close_room(inner);
            return Err(GhostChatError::MlsError(error.to_string()));
        }
    };
    let commit_envelope = Envelope::mls_handshake(commit_bytes);
    let welcome_envelope = Envelope::mls_welcome(welcome_bytes, tree_bytes);
    inner.pending.insert(
        participant_id.clone(),
        PendingPeer {
            participant_id: participant_id.clone(),
            display_name,
            connection_id,
            deadline: now + JOIN_TIMEOUT,
            welcome_epoch: inner
                .session
                .as_ref()
                .ok_or(GhostChatError::SessionClosed)?
                .epoch(),
        },
    );
    if let Err(error) = broadcast(inner, &commit_envelope, None) {
        let rollback = rollback_join(inner, &participant_id);
        inner.transport.disconnect(connection_id);
        if rollback.is_err() {
            close_room(inner);
        }
        return Err(error);
    }
    if let Err(error) = send_wire(inner, connection_id, &welcome_envelope) {
        let rollback = rollback_join(inner, &participant_id);
        inner.transport.disconnect(connection_id);
        if rollback.is_err() {
            close_room(inner);
        }
        return Err(error);
    }
    Ok(())
}

fn handle_pending_ready(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    envelope: Envelope,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    let participant_id = inner
        .pending
        .iter()
        .find(|(_, peer)| peer.connection_id == connection_id)
        .map(|(participant_id, _)| participant_id.clone())
        .ok_or_else(|| GhostChatError::ProtocolError("unknown pending peer".to_string()))?;
    let welcome_epoch = inner.pending[&participant_id].welcome_epoch;
    let current_epoch = inner
        .session
        .as_ref()
        .ok_or(GhostChatError::SessionClosed)?
        .epoch();
    if let Message::MlsApplication {
        application_message,
    } = &envelope.message
    {
        let message = MlsMessageIn::tls_deserialize_exact(application_message.as_slice())
            .map_err(|error| GhostChatError::MlsError(error.to_string()))?
            .try_into_protocol_message()
            .map_err(|error| GhostChatError::MlsError(error.to_string()))?;
        if message.content_type() != openmls::framing::ContentType::Application {
            return Err(GhostChatError::ProtocolError(
                "expected MLS application readiness".into(),
            ));
        }
        // A removal commit may cross an in-flight Ready. Do not accept an old
        // ciphertext as readiness or move any MLS state. The pending peer will
        // send a fresh Ready after processing the authenticated commit. Its
        // original deadline remains in force; future/malformed messages fail.
        if message.epoch().as_u64() >= welcome_epoch && message.epoch().as_u64() < current_epoch {
            send_control(inner, connection_id, &Payload::ReadyRetry)?;
            return Ok(());
        }
    }
    let event = inner
        .session
        .as_mut()
        .ok_or(GhostChatError::SessionClosed)?
        .receive_envelope(envelope)?;
    let (sender, payload) = application_payload(event)?;
    if sender != participant_id || !matches!(payload, Payload::Ready) {
        let _ = disconnect_connection(inner, connection_id, ui_events);
        return Err(GhostChatError::ProtocolError(
            "pending peer did not authenticate its MLS readiness".to_string(),
        ));
    }
    promote_pending_peer(inner, connection_id, ui_events)
}

fn promote_pending_peer(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    let participant_id = inner
        .pending
        .iter()
        .find(|(_, peer)| peer.connection_id == connection_id)
        .map(|(participant_id, _)| participant_id.clone())
        .ok_or_else(|| GhostChatError::ProtocolError("unknown pending peer".to_string()))?;
    let pending = inner
        .pending
        .remove(&participant_id)
        .ok_or_else(|| GhostChatError::ProtocolError("pending peer disappeared".to_string()))?;
    inner
        .participant_names
        .insert(pending.participant_id.clone(), pending.display_name.clone());
    inner.peers.insert(
        pending.participant_id.clone(),
        Peer {
            display_name: pending.display_name,
            connection_id: pending.connection_id,
        },
    );
    let names = current_names(inner);
    if let Err(error) = validate_names(inner, &names) {
        inner.peers.remove(&participant_id);
        let rollback = rollback_join(inner, &participant_id);
        if rollback.is_err() {
            close_room(inner);
        }
        return Err(error);
    }
    if let Err(error) = send_control(inner, connection_id, &Payload::Names(names.clone())) {
        inner.peers.remove(&participant_id);
        let rollback = rollback_join(inner, &participant_id);
        inner.transport.disconnect(connection_id);
        if rollback.is_err() {
            close_room(inner);
        }
        return Err(error);
    }
    if let Err(error) = send_control(inner, connection_id, &Payload::ReadyAccepted) {
        disconnect_connection(inner, connection_id, ui_events)?;
        return Err(error);
    }
    let peer_ids: Vec<u64> = inner
        .peers
        .values()
        .filter(|peer| peer.connection_id != connection_id)
        .map(|peer| peer.connection_id)
        .collect();
    for peer_id in peer_ids {
        if let Err(error) = send_control(inner, peer_id, &Payload::Names(names.clone())) {
            disconnect_connection(inner, peer_id, ui_events)?;
            return Err(error);
        }
    }
    if let Some(peer) = inner.peers.get(&participant_id) {
        ui_events.push(NetworkUiEvent::Participant(ParticipantSnapshot {
            id: participant_id.to_string(),
            display_name: peer.display_name.clone(),
            state: "online".to_string(),
            is_self: false,
        }));
    }
    Ok(())
}

fn handle_creator_peer_frame(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    participant_id: ParticipantId,
    envelope: Envelope,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    match envelope.message {
        Message::MlsApplication { .. } => {
            let event = inner
                .session
                .as_mut()
                .ok_or(GhostChatError::SessionClosed)?
                .receive_envelope(envelope.clone())?;
            let (sender, payload) = application_payload(event)?;
            if sender != participant_id {
                inner.transport.disconnect(connection_id);
                return Err(GhostChatError::ProtocolError(
                    "MLS sender does not match the connected participant".to_string(),
                ));
            }
            match payload {
                Payload::Chat(body) => {
                    let body = validate_body(&body)?;
                    broadcast(inner, &envelope, Some(connection_id))?;
                    let message = make_chat_message(inner, &sender, body);
                    inner.messages.push(message.clone());
                    if inner.messages.len() > 500 {
                        clear_message(&mut inner.messages.remove(0));
                    }
                    ui_events.push(NetworkUiEvent::Message(message));
                    Ok(())
                }
                Payload::Leave => disconnect_connection(inner, connection_id, ui_events),
                Payload::Ready => {
                    send_control(inner, connection_id, &Payload::Names(current_names(inner)))?;
                    send_control(inner, connection_id, &Payload::ReadyAccepted)
                }
                Payload::Shutdown
                | Payload::Names(_)
                | Payload::ReadyAccepted
                | Payload::ReadyRetry => Err(GhostChatError::ProtocolError(
                    "unauthorized peer control message".into(),
                )),
            }
        }
        Message::MlsHandshake { .. } => {
            send_error(
                inner,
                connection_id,
                ErrorCode::UnsupportedMessageType,
                "only the room owner may create commits",
            );
            disconnect_connection(inner, connection_id, ui_events)?;
            Err(GhostChatError::ProtocolError(
                "only the room owner may create MLS commits".to_string(),
            ))
        }
        Message::Shutdown { .. } | Message::ParticipantEvent { .. } => Err(
            GhostChatError::ProtocolError("legacy control message rejected".into()),
        ),
        _ => {
            send_error(
                inner,
                connection_id,
                ErrorCode::InvalidRoomState,
                "invalid room message",
            );
            inner.transport.disconnect(connection_id);
            Err(GhostChatError::ProtocolError(
                "participant sent an invalid room message".to_string(),
            ))
        }
    }
}

fn handle_joiner_peer_frame(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    envelope: Envelope,
    now: Instant,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    match envelope.message {
        Message::MlsWelcome { .. } => {
            if inner.session.is_some() {
                return Err(GhostChatError::ProtocolError(
                    "duplicate MLS Welcome".to_string(),
                ));
            }
            let material = inner
                .join_material
                .take()
                .ok_or_else(|| GhostChatError::Internal("join material is missing".to_string()))?;
            let session = match SessionManager::join_verified(
                material.crypto_manager,
                material.identity,
                envelope,
                Some((&inner.creator_id, &inner.room_id)),
            ) {
                Ok(session) => session,
                Err(error) => {
                    close_room(inner);
                    return Err(error);
                }
            };
            inner.session = Some(session);
            inner.welcome_received = true;
            inner.ready_sent = false;
            inner.join_deadline = Some(now + JOIN_TIMEOUT);
            Ok(())
        }
        Message::MlsApplication { .. } => {
            let event = inner
                .session
                .as_mut()
                .ok_or_else(|| GhostChatError::Internal("waiting for MLS Welcome".to_string()))?
                .receive_envelope(envelope)?;
            apply_session_event(inner, event, ui_events)
        }
        Message::MlsHandshake { .. } => {
            let event = inner
                .session
                .as_mut()
                .ok_or_else(|| GhostChatError::Internal("waiting for MLS Welcome".to_string()))?
                .receive_authorized(envelope, Some(&inner.creator_id))?;
            if !matches!(event, SessionEvent::CommitApplied { .. }) {
                return Err(GhostChatError::ProtocolError(
                    "invalid MLS handshake".to_string(),
                ));
            }
            if !inner
                .session
                .as_ref()
                .is_some_and(SessionManager::is_active)
            {
                close_room(inner);
            } else {
                let members = current_member_ids(inner);
                inner.participant_names.retain(|id, name| {
                    if members.contains(id) {
                        true
                    } else {
                        name.zeroize();
                        false
                    }
                });
                if !members.contains(&inner.creator_id) {
                    close_room(inner);
                    return Err(GhostChatError::ProtocolError(
                        "room creator was removed".into(),
                    ));
                }
                if !inner.ready {
                    inner.ready_sent = false;
                }
            }
            Ok(())
        }
        Message::Error { code, .. } => {
            if inner.session.is_some() {
                return Err(GhostChatError::ProtocolError(
                    "outer error after MLS Welcome".into(),
                ));
            }
            ui_events.push(NetworkUiEvent::Error(error_description(code).to_string()));
            close_room(inner);
            Ok(())
        }
        Message::Shutdown { .. } | Message::ParticipantEvent { .. } => {
            inner.transport.disconnect(connection_id);
            close_room(inner);
            Err(GhostChatError::ProtocolError(
                "legacy control message rejected".to_string(),
            ))
        }
        _ => {
            inner.transport.disconnect(connection_id);
            close_room(inner);
            Err(GhostChatError::ProtocolError(
                "creator sent an invalid room message".to_string(),
            ))
        }
    }
}

fn apply_session_event(
    inner: &mut NetworkRoomInner,
    event: SessionEvent,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    ensure_open(inner)?;
    match event {
        SessionEvent::Application {
            mut plaintext,
            sender,
            ..
        } => {
            let decoded = decode_payload(&plaintext);
            plaintext.zeroize();
            let sender_id = sender.ok_or_else(|| {
                GhostChatError::ProtocolError("MLS application sender is unavailable".to_string())
            })?;
            if sender_id == inner.self_id {
                return Err(GhostChatError::ProtocolError(
                    "received a replay of the local application message".to_string(),
                ));
            }
            let payload = decoded?;
            if !inner.ready
                && !matches!(
                    &payload,
                    Payload::Names(_)
                        | Payload::Shutdown
                        | Payload::ReadyAccepted
                        | Payload::ReadyRetry
                )
            {
                return Err(GhostChatError::ProtocolError(
                    "joiner is waiting for creator confirmation".to_string(),
                ));
            }
            match payload {
                Payload::Chat(body) => {
                    let message = make_chat_message(inner, &sender_id, validate_body(&body)?);
                    inner.messages.push(message.clone());
                    if inner.messages.len() > 500 {
                        clear_message(&mut inner.messages.remove(0));
                    }
                    ui_events.push(NetworkUiEvent::Message(message));
                    Ok(())
                }
                Payload::Names(names) => {
                    if sender_id != inner.creator_id {
                        return Err(GhostChatError::ProtocolError(
                            "only the room creator may publish participant metadata".to_string(),
                        ));
                    }
                    validate_names(inner, &names)?;
                    inner
                        .participant_names
                        .values_mut()
                        .for_each(Zeroize::zeroize);
                    inner.participant_names.clear();
                    for (participant_id, name) in names {
                        inner
                            .participant_names
                            .insert(participant_id, normalise_name(&name)?);
                    }
                    Ok(())
                }
                Payload::ReadyAccepted => {
                    if sender_id != inner.creator_id
                        || (!inner.ready_sent && !inner.ready)
                        || !inner.participant_names.contains_key(&inner.self_id)
                        || !inner.participant_names.contains_key(&inner.creator_id)
                    {
                        return Err(GhostChatError::ProtocolError(
                            "invalid readiness confirmation".into(),
                        ));
                    }
                    inner.ready = true;
                    inner.join_deadline = None;
                    Ok(())
                }
                Payload::ReadyRetry => {
                    if sender_id != inner.creator_id {
                        return Err(GhostChatError::ProtocolError(
                            "invalid readiness retry".into(),
                        ));
                    }
                    if !inner.ready {
                        inner.ready_sent = false;
                    }
                    Ok(())
                }
                Payload::Shutdown => {
                    if sender_id != inner.creator_id {
                        return Err(GhostChatError::ProtocolError(
                            "only the room creator may end the room".to_string(),
                        ));
                    }
                    close_room(inner);
                    ui_events.push(NetworkUiEvent::Error(
                        "room creator ended the session".to_string(),
                    ));
                    Ok(())
                }
                Payload::Leave | Payload::Ready => Err(GhostChatError::ProtocolError(
                    "invalid MLS control message".to_string(),
                )),
            }
        }
        SessionEvent::CommitApplied { .. } => Ok(()),
        SessionEvent::Shutdown { .. } => Err(GhostChatError::ProtocolError(
            "legacy shutdown is not valid on a network room".into(),
        )),
    }
}

fn application_payload(event: SessionEvent) -> Result<(ParticipantId, Payload)> {
    match event {
        SessionEvent::Application {
            mut plaintext,
            sender,
            ..
        } => {
            let decoded = decode_payload(&plaintext);
            plaintext.zeroize();
            let sender = sender.ok_or_else(|| {
                GhostChatError::ProtocolError("MLS application sender is unavailable".to_string())
            })?;
            Ok((sender, decoded?))
        }
        _ => Err(GhostChatError::ProtocolError(
            "expected an MLS application control message".to_string(),
        )),
    }
}

fn disconnect_connection(
    inner: &mut NetworkRoomInner,
    connection_id: u64,
    ui_events: &mut Vec<NetworkUiEvent>,
) -> Result<()> {
    inner.unjoined.remove(&connection_id);
    if inner.role == NetworkRole::Joiner {
        if connection_id == 0 {
            close_room(inner);
        }
        return Ok(());
    }
    inner.transport.disconnect(connection_id);
    let pending_id = inner
        .pending
        .iter()
        .find(|(_, peer)| peer.connection_id == connection_id)
        .map(|(participant_id, _)| participant_id.clone());
    if let Some(participant_id) = pending_id {
        inner.pending.remove(&participant_id);
        inner.participant_names.remove(&participant_id);
        inner.transport.disconnect(connection_id);
        if let Err(error) = remove_member_and_broadcast(inner, &participant_id) {
            close_room(inner);
            return Err(error);
        }
        return Ok(());
    }
    let active_id = inner
        .peers
        .iter()
        .find(|(_, peer)| peer.connection_id == connection_id)
        .map(|(participant_id, _)| participant_id.clone());
    if let Some(participant_id) = active_id {
        inner.peers.remove(&participant_id);
        inner.participant_names.remove(&participant_id);
        inner.transport.disconnect(connection_id);
        if let Err(error) = remove_member_and_broadcast(inner, &participant_id) {
            close_room(inner);
            return Err(error);
        }
        ui_events.push(NetworkUiEvent::Participant(ParticipantSnapshot {
            id: participant_id.to_string(),
            display_name: "Participant".to_string(),
            state: "offline".to_string(),
            is_self: false,
        }));
    }
    Ok(())
}

fn remove_member_and_broadcast(
    inner: &mut NetworkRoomInner,
    participant_id: &ParticipantId,
) -> Result<()> {
    let Some(session) = inner.session.as_mut() else {
        return Ok(());
    };
    let commit = session.remove_member(participant_id)?;
    let envelope = Envelope::mls_handshake(
        commit
            .to_bytes()
            .map_err(|error| GhostChatError::MlsError(error.to_string()))?,
    );
    broadcast(inner, &envelope, None)?;
    broadcast_pending(inner, &envelope, None)?;
    broadcast_names(inner)
}

fn snapshot_locked(inner: &NetworkRoomInner) -> Result<RoomSnapshot> {
    let epoch = inner.session.as_ref().map_or(0, SessionManager::epoch);
    let mut participants = Vec::new();
    if let Some(session) = &inner.session {
        for member in session.group.members() {
            let participant_id = ParticipantId::from_public_key(&member.signature_key);
            let display_name = inner
                .participant_names
                .get(&participant_id)
                .cloned()
                .unwrap_or_else(|| "Anonymous".to_string());
            let state = if participant_id == inner.self_id
                || inner.participant_names.contains_key(&participant_id)
            {
                if participant_id == inner.self_id && !inner.ready {
                    "joining"
                } else {
                    "online"
                }
            } else {
                "joining"
            };
            participants.push(ParticipantSnapshot {
                id: participant_id.to_string(),
                display_name,
                state: state.to_string(),
                is_self: participant_id == inner.self_id,
            });
        }
    } else if !inner.closed {
        participants.push(ParticipantSnapshot {
            id: inner.self_id.to_string(),
            display_name: inner
                .participant_names
                .get(&inner.self_id)
                .cloned()
                .unwrap_or_else(|| "You".to_string()),
            state: "joining".to_string(),
            is_self: true,
        });
        participants.push(ParticipantSnapshot {
            id: inner.creator_id.to_string(),
            display_name: inner
                .participant_names
                .get(&inner.creator_id)
                .cloned()
                .unwrap_or_else(|| "Room creator".to_string()),
            state: "online".to_string(),
            is_self: false,
        });
    }
    for (participant_id, pending) in &inner.pending {
        if !participants
            .iter()
            .any(|participant| participant.id == participant_id.as_str())
        {
            participants.push(ParticipantSnapshot {
                id: participant_id.to_string(),
                display_name: pending.display_name.clone(),
                state: "joining".to_string(),
                is_self: false,
            });
        }
    }
    participants.sort_by(|left, right| left.id.cmp(&right.id));
    let messages = inner
        .messages
        .iter()
        .cloned()
        .map(|mut message| {
            message.mine = message.sender_id == inner.self_id.as_str();
            message
        })
        .collect();
    let (state, connection_state, encryption_active) = if inner.closed {
        ("closed", "closed", false)
    } else if !inner.ready {
        ("connecting", "connecting", false)
    } else {
        ("active", "connected", true)
    };
    Ok(RoomSnapshot {
        session_id: hex_encode(&inner.room_id),
        room_name: inner.room_name.clone(),
        invite_code: inner.invitation_code.clone(),
        owner_id: inner.creator_id.to_string(),
        state: state.to_string(),
        epoch,
        participants,
        messages,
        transport: "tor".to_string(),
        tor_state: if inner.closed {
            "closed".to_string()
        } else {
            "connected".to_string()
        },
        connection_state: connection_state.to_string(),
        encryption_active,
    })
}

fn make_chat_message(
    inner: &mut NetworkRoomInner,
    sender_id: &ParticipantId,
    body: String,
) -> ChatMessage {
    let sender_name = inner
        .participant_names
        .get(sender_id)
        .cloned()
        .unwrap_or_else(|| "Anonymous".to_string());
    let message = ChatMessage {
        id: format!("message-{}", inner.next_message_id),
        sender_id: sender_id.to_string(),
        sender_name,
        body,
        timestamp: String::new(),
        mine: sender_id == &inner.self_id,
    };
    inner.next_message_id = inner.next_message_id.saturating_add(1);
    message
}

fn parse_room_intro(invitation: &TorInvitation) -> Result<([u8; 16], Vec<u8>, RoomConfig)> {
    let envelope = Envelope::decode(&invitation.room_intro)
        .map_err(|error| GhostChatError::ProtocolError(error.to_string()))?;
    match envelope.message {
        Message::RoomIntro {
            room_id,
            creator_identity,
            config,
        } => {
            if creator_identity.len() != 32
                || config.max_participants == 0
                || config.max_participants > 3
                || config.epoch_update_interval_secs == 0
                || config.ciphersuite != u16::from(SessionConfig::default().ciphersuite)
            {
                return Err(GhostChatError::ProtocolError(
                    "room introduction is invalid".to_string(),
                ));
            }
            Ok((room_id, creator_identity, config))
        }
        _ => Err(GhostChatError::ProtocolError(
            "invitation does not contain a room introduction".to_string(),
        )),
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

fn room_config_for_join(mut local: SessionConfig, remote: &RoomConfig) -> Result<SessionConfig> {
    validate_session_config(&local)?;
    if remote.ciphersuite != u16::from(local.ciphersuite) {
        return Err(GhostChatError::ProtocolError(
            "invitation ciphersuite does not match local configuration".to_string(),
        ));
    }
    if remote.max_participants == 0 || remote.max_participants > 3 {
        return Err(GhostChatError::ProtocolError(
            "invitation participant limit is invalid".to_string(),
        ));
    }
    local.max_participants = usize::from(remote.max_participants);
    local.epoch_update_interval_secs = u64::from(remote.epoch_update_interval_secs);
    validate_session_config(&local)?;
    Ok(local)
}

fn validate_session_config(config: &SessionConfig) -> Result<()> {
    if config.max_participants == 0 || config.max_participants > 3 {
        return Err(GhostChatError::Internal(
            "GhostChat supports between one and three participants".to_string(),
        ));
    }
    if config.ciphersuite != SessionConfig::default().ciphersuite {
        return Err(GhostChatError::ProtocolError(
            "unsupported room ciphersuite".into(),
        ));
    }
    if config.epoch_update_interval_secs == 0
        || u32::try_from(config.epoch_update_interval_secs).is_err()
    {
        return Err(GhostChatError::Internal(
            "epoch interval does not fit protocol field".to_string(),
        ));
    }
    Ok(())
}

fn normalise_room_name(value: Option<String>) -> String {
    let value = value.unwrap_or_else(|| "GhostChat room".to_string());
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 64 {
        "GhostChat room".to_string()
    } else {
        value.to_string()
    }
}

fn normalise_name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 32 || value.chars().any(char::is_control) {
        return Err(GhostChatError::Internal(
            "display name must be 1-32 non-control characters".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn validate_body(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 4_000 || value.chars().any(char::is_control) {
        return Err(GhostChatError::Internal(
            "message must be 1-4,000 non-control characters".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn ensure_open(inner: &NetworkRoomInner) -> Result<()> {
    if inner.closed {
        Err(GhostChatError::SessionClosed)
    } else {
        Ok(())
    }
}

fn validate_onion_address(address: &str) -> Result<()> {
    crate::transport::tor::validate_onion_host(address).map_err(transport_error)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

fn transport_error(error: impl std::fmt::Display) -> GhostChatError {
    GhostChatError::TransportError(error.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(GhostChatError::ProtocolError(
            "invitation code has invalid hex length".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().as_chunks::<2>().0 {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            GhostChatError::ProtocolError("invitation code has invalid hex".to_string())
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            GhostChatError::ProtocolError("invitation code has invalid hex".to_string())
        })?;
        bytes.push((high << 4) | low);
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
    use crate::transport::{InMemoryHub, InMemoryStreamTransport};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn new_creator() -> (NetworkRoom, InMemoryHub) {
        let (transport, hub) = InMemoryStreamTransport::hub();
        let room = NetworkRoom::create_with_transport(
            SessionConfig::default(),
            Some("test room".to_string()),
            "Alice",
            move || {
                Ok((
                    Box::new(transport) as Box<dyn StreamTransport>,
                    crate::transport::tor::test_onion_host(),
                    80,
                ))
            },
        )
        .expect("creator should be created");
        (room, hub)
    }

    fn begin_join(
        creator: &NetworkRoom,
        hub: &InMemoryHub,
        name: &str,
        now: Instant,
    ) -> NetworkRoom {
        let invitation = TorInvitation::decode_code(
            &creator
                .invite_code()
                .expect("creator invitation should exist"),
        )
        .expect("creator invitation should decode");
        let transport = hub.connect().expect("client should connect");
        NetworkRoom::join_with_transport(
            invitation,
            SessionConfig::default(),
            name,
            now,
            move |_host, _port| Ok(Box::new(transport) as Box<dyn StreamTransport>),
        )
        .expect("joiner should be created")
    }

    fn complete_join(creator: &NetworkRoom, joiner: &NetworkRoom, now: Instant) {
        creator
            .poll_at(now)
            .expect("creator should process join request");
        joiner.poll_at(now).expect("joiner should process Welcome");
        creator.poll_at(now).expect("creator should process Ready");
        joiner.poll_at(now).expect("joiner should process Names");
        assert_eq!(
            joiner
                .snapshot()
                .expect("joiner snapshot should work")
                .state,
            "active"
        );
    }

    fn only_connection(creator: &NetworkRoom) -> u64 {
        creator
            .lock()
            .unwrap()
            .peers
            .values()
            .next()
            .unwrap()
            .connection_id
    }

    fn assert_cleanly_closed(room: &NetworkRoom) {
        let inner = room.lock().unwrap();
        assert!(inner.closed);
        assert!(!inner.ready);
        assert!(inner.session.is_none());
        assert!(inner.join_material.is_none());
        assert!(inner.join_deadline.is_none());
        assert!(inner.peers.is_empty());
        assert!(inner.pending.is_empty());
        assert!(inner.unjoined.is_empty());
        assert!(inner.participant_names.is_empty());
        assert!(inner.messages.is_empty());
        assert!(inner.invitation_code.is_empty());
        assert!(inner.join_token.is_empty());
        let snapshot = snapshot_locked(&inner).unwrap();
        assert_eq!(snapshot.state, "closed");
        assert!(snapshot.invite_code.is_empty());
        assert!(snapshot.participants.is_empty());
        assert!(snapshot.messages.is_empty());
        drop(inner);
        assert!(room.invite_code().is_err());
        assert!(room.send_message("after close").is_err());
        assert!(room.poll().unwrap().is_empty());
        room.shutdown().unwrap();
    }

    struct ObservedTransport {
        transport: InMemoryStreamTransport,
        shutdowns: Arc<AtomicUsize>,
        fail_send: Option<usize>,
        sends: usize,
    }

    impl StreamTransport for ObservedTransport {
        fn send(&mut self, connection_id: u64, bytes: &[u8]) -> Result<()> {
            self.sends += 1;
            if self.fail_send == Some(self.sends) {
                return Err(GhostChatError::TransportError(
                    "injected send failure".into(),
                ));
            }
            self.transport.send(connection_id, bytes)
        }

        fn flush(&mut self) -> Result<()> {
            self.transport.flush()
        }
        fn receive(&mut self) -> Result<Option<StreamEvent>> {
            self.transport.receive()
        }
        fn disconnect(&mut self, connection_id: u64) {
            self.transport.disconnect(connection_id);
        }
        fn shutdown(&mut self) {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            self.transport.shutdown();
        }
    }

    fn observed_creator(fail_send: Option<usize>) -> (NetworkRoom, InMemoryHub, Arc<AtomicUsize>) {
        let (transport, hub) = InMemoryStreamTransport::hub();
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let observed = ObservedTransport {
            transport,
            shutdowns: shutdowns.clone(),
            fail_send,
            sends: 0,
        };
        let room = NetworkRoom::create_with_transport(
            SessionConfig::default(),
            None,
            "Alice",
            move || {
                Ok((
                    Box::new(observed),
                    crate::transport::tor::test_onion_host(),
                    80,
                ))
            },
        )
        .unwrap();
        (room, hub, shutdowns)
    }

    #[test]
    fn signed_invitation_round_trips_and_rejects_tampering() {
        let config = SessionConfig::default();
        let session = SessionManager::create(config.clone()).expect("session should be created");
        let intro = Envelope::room_intro(
            [7; 16],
            session.public_key().to_vec(),
            room_config(&config).expect("room config should encode"),
        );
        let invitation = TorInvitation::signed(
            crate::transport::tor::test_onion_host(),
            80,
            intro.encode().expect("intro should encode"),
            vec![9; JOIN_TOKEN_BYTES],
            &session.creator_identity,
        )
        .expect("invitation should be signed");
        let code = invitation.encode_code().expect("invitation should encode");
        let decoded = TorInvitation::decode_code(&code).expect("invitation should decode");
        assert_eq!(decoded.join_token, vec![9; JOIN_TOKEN_BYTES]);
        let mut tampered = decoded;
        tampered.join_token[0] ^= 1;
        assert!(tampered.encode_code().is_err());
    }

    #[test]
    fn invitation_rejects_non_v3_onion_addresses() {
        assert!(validate_onion_address("127.0.0.1.onion").is_err());
        assert!(validate_onion_address(&crate::transport::tor::test_onion_host()).is_ok());
    }

    #[test]
    fn invitations_reject_malformed_oversized_trailing_and_bad_config_material() {
        let config = SessionConfig::default();
        let session = SessionManager::create(config.clone()).expect("session should be created");
        let intro = Envelope::room_intro(
            [8; 16],
            session.public_key().to_vec(),
            room_config(&config).expect("room config should encode"),
        );
        let invitation = TorInvitation::signed(
            crate::transport::tor::test_onion_host(),
            80,
            intro.encode().expect("intro should encode"),
            vec![3; JOIN_TOKEN_BYTES],
            &session.creator_identity,
        )
        .expect("invitation should be signed");
        let code = invitation.encode_code().expect("invitation should encode");
        assert!(TorInvitation::decode_code("zz").is_err());
        assert!(TorInvitation::decode_code("00").is_err());
        assert!(TorInvitation::decode_code(&"ab".repeat(INVITATION_MAX_BYTES + 1)).is_err());
        let mut trailing = hex_decode(&code).expect("code should be hex");
        trailing.push(0);
        assert!(TorInvitation::decode_code(&hex_encode(&trailing)).is_err());

        let mut bad_token = invitation.clone();
        bad_token.join_token = vec![0; JOIN_TOKEN_BYTES - 1];
        assert!(bad_token.encode_code().is_err());
        let mut bad_intro = invitation.clone();
        bad_intro.room_intro = vec![0; MAX_MESSAGE_SIZE + 1];
        assert!(bad_intro.encode_code().is_err());

        let bad_config = RoomConfig {
            max_participants: 4,
            ..room_config(&config).expect("room config should encode")
        };
        assert!(TorInvitation::signed(
            crate::transport::tor::test_onion_host(),
            80,
            Envelope::room_intro([9; 16], session.public_key().to_vec(), bad_config)
                .encode()
                .expect("intro should encode"),
            vec![3; JOIN_TOKEN_BYTES],
            &session.creator_identity,
        )
        .is_err());
        for byte in 0..=u8::MAX {
            let malformed = format!("{byte:02x}00");
            assert!(TorInvitation::decode_code(&malformed).is_err());
        }
    }

    #[test]
    fn network_room_supports_three_members_rejects_fourth_and_authenticates_controls() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let charlie = begin_join(&creator, &hub, "Charlie", now);
        complete_join(&creator, &charlie, now);
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            3
        );

        let fourth = begin_join(&creator, &hub, "Dave", now);
        let events = creator
            .poll_at(now)
            .expect("creator should reject fourth join");
        assert!(events.iter().all(
            |event| !matches!(event, NetworkUiEvent::Error(message) if message.contains("Dave"))
        ));
        let fourth_events = fourth
            .poll_at(now)
            .expect("fourth join should receive rejection");
        assert!(fourth_events
            .iter()
            .any(|event| matches!(event, NetworkUiEvent::Error(_))));
        assert_eq!(
            creator.snapshot().expect("snapshot should work").state,
            "active"
        );

        {
            let mut bob_inner = bob.lock().expect("bob lock should work");
            send_control(&mut bob_inner, 0, &Payload::Shutdown)
                .expect("authenticated control should be sent");
        }
        creator
            .poll_at(now)
            .expect("creator should process peer control");
        charlie
            .poll_at(now)
            .expect("remaining peer should process removal");
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            2
        );
        assert_eq!(
            creator.snapshot().expect("snapshot should work").state,
            "active"
        );

        let rejoin = begin_join(&creator, &hub, "Fresh", now);
        complete_join(&creator, &rejoin, now);
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            3
        );
    }

    #[test]
    fn network_room_serializes_joins_expires_stalls_and_delivers_removal_commits() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);

        let stalled = begin_join(&creator, &hub, "Stalled", now);
        let competing = begin_join(&creator, &hub, "Competing", now);
        creator
            .poll_at(now)
            .expect("creator should process one join and reject one");
        let competing_events = competing.poll_at(now).expect("competing join should stop");
        assert!(competing_events
            .iter()
            .any(|event| matches!(event, NetworkUiEvent::Error(_))));
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            3
        );

        let expired = now + JOIN_TIMEOUT + Duration::from_secs(1);
        creator
            .poll_at(expired)
            .expect("stalled join should expire deterministically");
        bob.poll_at(expired)
            .expect("Bob should receive removal commit");
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            2
        );

        let fresh = begin_join(&creator, &hub, "Fresh", expired);
        complete_join(&creator, &fresh, expired);
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            3
        );
        let _ = stalled.poll_at(expired);
    }

    #[test]
    fn pending_member_catches_up_after_peer_disconnect_and_creator_close_is_terminal() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let pending = begin_join(&creator, &hub, "Pending", now);
        creator
            .poll_at(now)
            .expect("creator should stage pending join");

        // The pending peer has a Welcome queued but has not confirmed. The
        // active peer disappears before confirmation; its removal commit must
        // reach the pending MLS group before Ready is accepted.
        {
            let mut bob_inner = bob.lock().expect("bob lock should work");
            bob_inner.transport.shutdown();
        }
        creator
            .poll_at(now)
            .expect("creator should remove abruptly closed peer");
        pending
            .poll_at(now)
            .expect("pending peer should process Welcome and removal commit");
        creator
            .poll_at(now)
            .expect("creator should accept current-epoch Ready");
        pending
            .poll_at(now)
            .expect("pending peer should receive Names confirmation");
        assert_eq!(
            creator
                .snapshot()
                .expect("snapshot should work")
                .participants
                .len(),
            2
        );
        assert_eq!(
            pending.snapshot().expect("snapshot should work").state,
            "active"
        );

        // A creator-side transport close is terminal and idempotent for the
        // joiner; polling again must not process queued events.
        {
            let mut creator_inner = creator.lock().expect("creator lock should work");
            creator_inner.transport.shutdown();
        }
        pending
            .poll_at(now)
            .expect("joiner should observe creator close");
        assert_eq!(
            pending.snapshot().expect("snapshot should work").state,
            "closed"
        );
        assert!(pending
            .poll_at(now)
            .expect("closed poll should be inert")
            .is_empty());
    }

    #[test]
    fn network_room_rejects_duplicate_welcome_replay_and_future_mls_messages() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);

        // A Welcome is only valid before the first Welcome. Even malformed
        // duplicate bytes must terminate the active joiner rather than being
        // parsed as an unauthenticated control.
        {
            let mut creator_inner = creator.lock().expect("creator lock should work");
            let connection_id = creator_inner
                .peers
                .values()
                .next()
                .expect("Bob should be connected")
                .connection_id;
            send_wire(
                &mut creator_inner,
                connection_id,
                &Envelope::mls_welcome(vec![0], vec![0]),
            )
            .expect("duplicate Welcome should be queued");
        }
        bob.poll_at(now)
            .expect("duplicate Welcome should be rejected");
        assert_eq!(
            bob.snapshot().expect("snapshot should work").state,
            "closed"
        );
        creator
            .poll_at(now)
            .expect("creator should remove closed peer");

        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);

        // Deliver a valid application from the old epoch after a commit. MLS
        // owns replay/stale-epoch rejection; the network layer only tears down
        // the bound connection after OpenMLS rejects it.
        let old_application = {
            let mut creator_inner = creator.lock().expect("creator lock should work");
            creator_inner
                .session
                .as_mut()
                .expect("creator session should exist")
                .send_application(b"stale")
                .expect("application should encrypt")
        };
        creator
            .advance_epoch()
            .expect("creator should advance the epoch");
        {
            let mut creator_inner = creator.lock().expect("creator lock should work");
            let connection_id = creator_inner
                .peers
                .values()
                .next()
                .expect("Bob should be connected")
                .connection_id;
            send_wire(&mut creator_inner, connection_id, &old_application)
                .expect("stale application should be queued");
        }
        bob.poll_at(now)
            .expect("stale application should be rejected");
        assert_eq!(
            bob.snapshot().expect("snapshot should work").state,
            "closed"
        );
        creator
            .poll_at(now)
            .expect("creator should remove stale peer");

        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);

        // Skip the first authenticated commit and send a later one: OpenMLS
        // rejects a future epoch, proving the network does not manufacture a
        // local ratchet or accept out-of-order ciphertext.
        {
            let mut creator_inner = creator.lock().expect("creator lock should work");
            let future = {
                let session = creator_inner
                    .session
                    .as_mut()
                    .expect("creator session should exist");
                let _first = session.advance_epoch().expect("first commit should work");
                session.advance_epoch().expect("future commit should work")
            };
            let connection_id = creator_inner
                .peers
                .values()
                .next()
                .expect("Bob should be connected")
                .connection_id;
            let envelope =
                Envelope::mls_handshake(future.to_bytes().expect("future commit should serialize"));
            send_wire(&mut creator_inner, connection_id, &envelope)
                .expect("future commit should be queued");
        }
        bob.poll_at(now).expect("future commit should be rejected");
        assert_eq!(
            bob.snapshot().expect("snapshot should work").state,
            "closed"
        );
    }

    #[test]
    fn three_member_chat_ready_confirmation_and_authenticated_shutdown() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        assert_eq!(creator.snapshot().unwrap().participants.len(), 1);
        let bob = begin_join(&creator, &hub, "Bob", now);
        creator.poll_at(now).unwrap();
        bob.poll_at(now).unwrap();
        // Receiving a valid Welcome proves membership, but the owner still
        // has to acknowledge Ready before the UI can send or show active.
        assert_eq!(bob.snapshot().unwrap().state, "connecting");
        assert!(!bob.snapshot().unwrap().encryption_active);
        assert!(bob.send_message("too soon").is_err());
        creator.poll_at(now).unwrap();
        bob.poll_at(now).unwrap();
        assert_eq!(creator.snapshot().unwrap().participants.len(), 2);
        let charlie = begin_join(&creator, &hub, "Charlie", now);
        complete_join(&creator, &charlie, now);
        bob.poll_at(now).unwrap();
        assert_eq!(creator.snapshot().unwrap().participants.len(), 3);
        for room in [&creator, &bob, &charlie] {
            assert_eq!(room.snapshot().unwrap().participants.len(), 3);
            assert_eq!(room.snapshot().unwrap().state, "active");
            assert_eq!(
                room.snapshot().unwrap().epoch,
                creator.snapshot().unwrap().epoch
            );
        }
        creator.send_message("owner chat").unwrap();
        bob.poll_at(now).unwrap();
        charlie.poll_at(now).unwrap();
        bob.send_message("peer chat").unwrap();
        creator.poll_at(now).unwrap();
        charlie.poll_at(now).unwrap();
        assert_eq!(creator.snapshot().unwrap().messages.len(), 2);
        assert_eq!(charlie.snapshot().unwrap().messages.len(), 2);
        assert_eq!(charlie.snapshot().unwrap().messages[1].sender_name, "Bob");
        creator.shutdown().unwrap();
        bob.poll_at(now).unwrap();
        charlie.poll_at(now).unwrap();
        for room in [&creator, &bob, &charlie] {
            assert_cleanly_closed(room);
        }
    }

    #[test]
    fn outer_controls_are_rejected_and_outer_error_text_is_never_reflected() {
        let now = Instant::now();
        for legacy in [
            Envelope::shutdown("untrusted shutdown label"),
            Envelope::new(Message::ParticipantEvent {
                participant_id: ParticipantId::from_public_key(&[0; 32]).to_string(),
                display_name: "spoofed".into(),
                joined: true,
            }),
            Envelope::new(Message::PeerReady),
        ] {
            let (creator, hub) = new_creator();
            let bob = begin_join(&creator, &hub, "Bob", now);
            complete_join(&creator, &bob, now);
            let connection_id = only_connection(&creator);
            send_wire(&mut creator.lock().unwrap(), connection_id, &legacy).unwrap();
            let events = bob.poll_at(now).unwrap();
            assert!(events
                .iter()
                .any(|event| matches!(event, NetworkUiEvent::Error(_))));
            assert!(!events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value.contains("untrusted shutdown label"))));
            assert_cleanly_closed(&bob);
        }

        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        let error = Envelope::new(Message::Error {
            code: ErrorCode::AuthenticationFailed,
            description: "attacker supplied UI instructions".into(),
        });
        // Before Welcome only the error code is usable; its display text is a
        // local static mapping. Do not let the creator process the JoinRequest.
        send_wire(&mut creator.lock().unwrap(), 1, &error).unwrap();
        let events = bob.poll_at(now).unwrap();
        assert!(events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value == "Peer authentication failed.")));
        assert!(!events.iter().any(
            |event| matches!(event, NetworkUiEvent::Error(value) if value.contains("attacker"))
        ));
        assert_cleanly_closed(&bob);
    }

    #[test]
    fn all_creator_received_applications_are_bound_to_the_connection() {
        let now = Instant::now();
        for payload in [
            Payload::Leave,
            Payload::Shutdown,
            Payload::Names(Vec::new()),
            Payload::Ready,
        ] {
            let (creator, hub) = new_creator();
            let bob = begin_join(&creator, &hub, "Bob", now);
            complete_join(&creator, &bob, now);
            let charlie = begin_join(&creator, &hub, "Charlie", now);
            complete_join(&creator, &charlie, now);
            bob.poll_at(now).unwrap();
            let charlie_id = charlie.lock().unwrap().self_id.clone();
            let bob_id = bob.lock().unwrap().self_id.clone();
            let ciphertext = charlie
                .lock()
                .unwrap()
                .session
                .as_mut()
                .unwrap()
                .send_application(&encode_payload(&payload).unwrap())
                .unwrap();
            // Re-route Charlie's genuine ciphertext over Bob's connection.
            // It must not remove or rename Charlie or shut down the room.
            send_wire(&mut bob.lock().unwrap(), 0, &ciphertext).unwrap();
            let events = creator.poll_at(now).unwrap();
            assert!(events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value.contains("MLS sender does not match"))));
            let inner = creator.lock().unwrap();
            assert!(!inner.closed);
            assert!(inner.peers.contains_key(&charlie_id));
            assert!(!inner.peers.contains_key(&bob_id));
            assert_eq!(inner.session.as_ref().unwrap().member_count(), 2);
        }
    }

    #[test]
    fn names_are_owner_only_unique_bounded_current_member_snapshots() {
        let now = Instant::now();
        for case in 0..5 {
            let (creator, hub) = new_creator();
            let bob = begin_join(&creator, &hub, "Bob", now);
            complete_join(&creator, &bob, now);
            let malicious_peer = if case == 4 {
                let charlie = begin_join(&creator, &hub, "Charlie", now);
                complete_join(&creator, &charlie, now);
                bob.poll_at(now).unwrap();
                Some(charlie)
            } else {
                None
            };
            let alice_id = creator.creator_id().unwrap();
            let bob_id = bob.lock().unwrap().self_id.clone();
            let names = match case {
                0 => vec![(ParticipantId::from_public_key(&[2; 32]), "outsider".into())],
                1 => vec![(alice_id.clone(), "Alice".into()); 4],
                2 => vec![
                    (alice_id.clone(), "Alice".into()),
                    (alice_id.clone(), "duplicate".into()),
                ],
                3 => vec![(bob_id.clone(), "control\u{0007}".into())],
                _ => vec![(bob_id.clone(), "forged peer metadata".into())],
            };
            let connection_id = creator.lock().unwrap().peers[&bob_id].connection_id;
            if case == 4 {
                let ciphertext = malicious_peer
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .session
                    .as_mut()
                    .unwrap()
                    .send_application(&encode_payload(&Payload::Names(names)).unwrap())
                    .unwrap();
                // A creator may relay MLS member ciphertext, but only the
                // actual creator's MLS signature authorizes participant names.
                send_wire(&mut creator.lock().unwrap(), connection_id, &ciphertext).unwrap();
            } else {
                send_control(
                    &mut creator.lock().unwrap(),
                    connection_id,
                    &Payload::Names(names),
                )
                .unwrap();
            }
            let events = bob.poll_at(now).unwrap();
            assert!(events
                .iter()
                .any(|event| matches!(event, NetworkUiEvent::Error(_))));
            if case == 4 {
                assert!(events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value.contains("only the room creator"))));
            }
            assert_cleanly_closed(&bob);
        }
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let alice_id = creator.creator_id().unwrap();
        let connection_id = only_connection(&creator);
        // This is a complete snapshot of the known (ready) subset: omitted
        // names disappear, and are not accumulated across repeated updates.
        send_control(
            &mut creator.lock().unwrap(),
            connection_id,
            &Payload::Names(vec![(alice_id.clone(), "Renamed".into())]),
        )
        .unwrap();
        bob.poll_at(now).unwrap();
        let inner = bob.lock().unwrap();
        assert_eq!(inner.participant_names.len(), 1);
        assert_eq!(inner.participant_names[&alice_id], "Renamed");
    }

    #[test]
    fn all_join_phases_and_unknown_connections_have_deterministic_deadlines() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let mut idle = hub.connect().unwrap();
        creator.poll_at(now).unwrap();
        assert_eq!(creator.lock().unwrap().unjoined.len(), 1);
        creator.poll_at(now + JOIN_TIMEOUT).unwrap();
        assert!(creator.lock().unwrap().unjoined.is_empty());
        let mut closed = false;
        while let Some(event) = idle.receive().unwrap() {
            closed |= matches!(event, StreamEvent::Closed { .. });
        }
        assert!(closed);

        let welcome_waiter = begin_join(&creator, &hub, "Welcome timeout", now);
        welcome_waiter.poll_at(now + JOIN_TIMEOUT).unwrap();
        assert_cleanly_closed(&welcome_waiter);
        creator.poll_at(now).unwrap();

        let (creator, hub) = new_creator();
        let confirm_waiter = begin_join(&creator, &hub, "Confirmation timeout", now);
        creator.poll_at(now).unwrap();
        confirm_waiter
            .poll_at(now + Duration::from_secs(1))
            .unwrap();
        assert!(!confirm_waiter.lock().unwrap().ready);
        // This joiner has valid MLS state, but must still discard it when the
        // owner never confirms Ready before the confirmation deadline.
        confirm_waiter
            .poll_at(now + JOIN_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        assert_cleanly_closed(&confirm_waiter);
        creator
            .poll_at(now + JOIN_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        assert_eq!(
            creator
                .lock()
                .unwrap()
                .session
                .as_ref()
                .unwrap()
                .member_count(),
            1
        );
        assert!(creator.lock().unwrap().pending.is_empty());
    }

    #[test]
    fn malformed_key_package_and_wrong_bearer_close_without_leaking_slots() {
        let now = Instant::now();
        for wrong_token in [false, true] {
            let (creator, hub) = new_creator();
            let mut client = hub.connect().unwrap();
            let mut token = creator.lock().unwrap().join_token.clone();
            if wrong_token {
                token[0] ^= 1;
            }
            let envelope = Envelope::join_request(token, "Peer".into(), vec![0xff, 0]);
            send_wire_transport(&mut client, 0, &envelope).unwrap();
            creator.poll_at(now).unwrap();
            assert!(creator.lock().unwrap().pending.is_empty());
            assert!(creator.lock().unwrap().unjoined.is_empty());
            assert_eq!(
                creator
                    .lock()
                    .unwrap()
                    .session
                    .as_ref()
                    .unwrap()
                    .member_count(),
                1
            );
            let mut closed = false;
            while let Some(event) = client.receive().unwrap() {
                closed |= matches!(event, StreamEvent::Closed { .. });
            }
            assert!(closed);
            let fresh = begin_join(&creator, &hub, "Fresh", now);
            complete_join(&creator, &fresh, now);
        }
    }

    #[test]
    fn welcome_send_failure_rolls_back_and_fanout_failure_is_terminal() {
        let now = Instant::now();
        // The very first creator send is Welcome. Its failure must undo the
        // already merged Add instead of retaining an orphaned pending leaf.
        let (creator, hub, _) = observed_creator(Some(1));
        let bob = begin_join(&creator, &hub, "Bob", now);
        creator.poll_at(now).unwrap();
        assert!(creator.lock().unwrap().pending.is_empty());
        assert!(creator.lock().unwrap().peers.is_empty());
        assert_eq!(
            creator
                .lock()
                .unwrap()
                .session
                .as_ref()
                .unwrap()
                .member_count(),
            1
        );
        bob.poll_at(now).unwrap();
        assert_cleanly_closed(&bob);
        let fresh = begin_join(&creator, &hub, "Fresh", now);
        complete_join(&creator, &fresh, now);

        // Welcome, Names and ReadyAccepted are sends 1..3. Send 4 is the Add
        // commit for the next join; a fanout failure closes all state instead
        // of leaving peers on divergent epochs.
        let (creator, hub, shutdowns) = observed_creator(Some(4));
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let pending = begin_join(&creator, &hub, "Pending", now);
        creator.poll_at(now).unwrap();
        assert_cleanly_closed(&creator);
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        bob.poll_at(now).unwrap();
        pending.poll_at(now).unwrap();
        assert_cleanly_closed(&bob);
        assert_cleanly_closed(&pending);
    }

    #[test]
    fn simultaneous_last_handle_drops_close_the_inner_transport_once() {
        let (room, hub, shutdowns) = observed_creator(None);
        let mut client = hub.connect().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let room2 = room.clone();
        let barrier1 = barrier.clone();
        let first = std::thread::spawn(move || {
            barrier1.wait();
            drop(room);
        });
        let barrier2 = barrier.clone();
        let second = std::thread::spawn(move || {
            barrier2.wait();
            drop(room2);
        });
        barrier.wait();
        first.join().unwrap();
        second.join().unwrap();
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        let mut closed = false;
        while let Some(event) = client.receive().unwrap() {
            closed |= matches!(event, StreamEvent::Closed { .. });
        }
        assert!(closed);
    }

    #[test]
    fn pending_ready_crossing_a_removal_retries_authentically_at_the_new_epoch() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let pending = begin_join(&creator, &hub, "Pending", now);
        creator.poll_at(now).unwrap();
        let bob_id = bob.lock().unwrap().self_id.to_string();
        creator.remove_participant(&bob_id).unwrap();
        // Process only the queued Welcome, and send Ready before reading the
        // queued removal commit. This deterministically models cross-traffic.
        {
            let mut inner = pending.lock().unwrap();
            let mut saw_welcome = false;
            while let Some(event) = inner.transport.receive().unwrap() {
                saw_welcome |= matches!(&event, StreamEvent::Frame { bytes, .. } if matches!(Envelope::decode(bytes).unwrap().message, Message::MlsWelcome { .. }));
                handle_stream_event(&mut inner, event, now, &mut Vec::new()).unwrap();
                if saw_welcome {
                    break;
                }
            }
            assert!(saw_welcome);
            send_ready_if_needed(&mut inner).unwrap();
        }
        creator.poll_at(now).unwrap();
        assert_eq!(creator.lock().unwrap().pending.len(), 1);
        pending.poll_at(now).unwrap();
        assert!(!pending.lock().unwrap().ready);
        creator.poll_at(now).unwrap();
        pending.poll_at(now).unwrap();
        assert!(pending.lock().unwrap().ready);
        assert!(creator.lock().unwrap().pending.is_empty());
        assert_eq!(
            pending.snapshot().unwrap().epoch,
            creator.snapshot().unwrap().epoch
        );
    }

    #[test]
    fn duplicate_application_commit_and_future_application_are_terminal() {
        let now = Instant::now();
        for case in 0..3 {
            let (creator, hub) = new_creator();
            let bob = begin_join(&creator, &hub, "Bob", now);
            complete_join(&creator, &bob, now);
            let connection_id = only_connection(&creator);
            let mut inner = creator.lock().unwrap();
            let session = inner.session.as_mut().unwrap();
            let envelope = match case {
                0 => session
                    .send_application(&encode_payload(&Payload::Chat("once".into())).unwrap())
                    .unwrap(),
                1 => Envelope::mls_handshake(session.advance_epoch().unwrap().to_bytes().unwrap()),
                _ => {
                    // The commit is deliberately withheld; this ciphertext is
                    // from a future epoch relative to Bob's current group.
                    session.advance_epoch().unwrap();
                    session
                        .send_application(&encode_payload(&Payload::Chat("future".into())).unwrap())
                        .unwrap()
                }
            };
            send_wire(&mut inner, connection_id, &envelope).unwrap();
            if case != 2 {
                send_wire(&mut inner, connection_id, &envelope).unwrap();
            }
            if case == 0 {
                let queued_after_close = inner
                    .session
                    .as_mut()
                    .unwrap()
                    .send_application(
                        &encode_payload(&Payload::Chat("must never be processed".into())).unwrap(),
                    )
                    .unwrap();
                send_wire(&mut inner, connection_id, &queued_after_close).unwrap();
            }
            drop(inner);
            let events = bob.poll_at(now).unwrap();
            assert!(events
                .iter()
                .any(|event| matches!(event, NetworkUiEvent::Error(_))));
            if case == 0 {
                assert_eq!(
                    events
                        .iter()
                        .filter(|event| matches!(event, NetworkUiEvent::Message(_)))
                        .count(),
                    1
                );
            } else {
                assert!(!events
                    .iter()
                    .any(|event| matches!(event, NetworkUiEvent::Message(_))));
            }
            assert_cleanly_closed(&bob);
        }
    }

    #[test]
    fn welcome_is_pinned_to_invitation_creator_group_and_ciphersuite() {
        let now = Instant::now();
        for case in 0..3 {
            let (creator, hub) = new_creator();
            let bob = begin_join(&creator, &hub, "Bob", now);
            creator.poll_at(now).unwrap();
            {
                let mut inner = bob.lock().unwrap();
                match case {
                    0 => inner.creator_id = ParticipantId::from_public_key(&[3; 32]),
                    1 => inner.room_id[0] ^= 1,
                    _ => inner
                        .join_material
                        .as_mut()
                        .unwrap()
                        .crypto_manager
                        .config
                        .ciphersuite =
                        openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                }
            }
            let events = bob.poll_at(now).unwrap();
            assert!(events
                .iter()
                .any(|event| matches!(event, NetworkUiEvent::Error(_))));
            assert_cleanly_closed(&bob);
        }
    }

    #[test]
    fn receiver_enforces_member_cap_on_malicious_owner_commits_and_welcomes() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let charlie = begin_join(&creator, &hub, "Charlie", now);
        complete_join(&creator, &charlie, now);
        bob.poll_at(now).unwrap();
        let fourth = begin_join(&creator, &hub, "Fourth", now);
        let key_package = {
            let inner = fourth.lock().unwrap();
            let material = inner.join_material.as_ref().unwrap();
            material
                .identity
                .key_package(inner.config.ciphersuite, &material.crypto_manager.provider)
                .unwrap()
        };
        // Bypass the owner's SessionManager policy to emulate a malicious room
        // owner. These are real, valid OpenMLS artifacts containing four leaves.
        let (commit, welcome, tree) = {
            let mut inner = creator.lock().unwrap();
            let session = inner.session.as_mut().unwrap();
            let (commit, welcome, _) = session
                .group
                .add_members(
                    &session.crypto_manager.provider,
                    &session.creator_identity.signer,
                    &[key_package],
                )
                .unwrap();
            session
                .group
                .merge_pending_commit(&session.crypto_manager.provider)
                .unwrap();
            (
                Envelope::mls_handshake(commit.to_bytes().unwrap()),
                Envelope::mls_welcome(
                    welcome.to_bytes().unwrap(),
                    session.export_ratchet_tree_bytes().unwrap(),
                ),
                session.member_count(),
            )
        };
        assert_eq!(tree, 4);
        let bob_id = bob.lock().unwrap().self_id.clone();
        let bob_connection = creator.lock().unwrap().peers[&bob_id].connection_id;
        send_wire(&mut creator.lock().unwrap(), bob_connection, &commit).unwrap();
        send_wire(&mut creator.lock().unwrap(), 3, &welcome).unwrap();
        let events = bob.poll_at(now).unwrap();
        assert!(events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value.contains("participant limit"))));
        assert_cleanly_closed(&bob);
        let events = fourth.poll_at(now).unwrap();
        assert!(events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value.contains("participant limit"))));
        assert_cleanly_closed(&fourth);
    }

    #[test]
    fn room_config_and_invitation_are_validated_before_any_transport_factory_call() {
        let config = SessionConfig::default();
        for invalid in [0, 4, usize::MAX] {
            let config = SessionConfig {
                max_participants: invalid,
                ..config.clone()
            };
            assert!(
                NetworkRoom::create_with_transport(config, None, "Alice", || {
                    panic!("invalid config must not create a transport")
                })
                .is_err()
            );
        }
        let (creator, _) = new_creator();
        let good = TorInvitation::decode_code(&creator.invite_code().unwrap()).unwrap();
        let mut tampered = good.clone();
        tampered.join_token[0] ^= 1;
        assert!(NetworkRoom::join_with_transport(
            tampered,
            config.clone(),
            "Bob",
            Instant::now(),
            |_host, _port| { panic!("tampered invitation must not connect") }
        )
        .is_err());
        let invalid_local = SessionConfig {
            max_participants: 4,
            ..config.clone()
        };
        assert!(NetworkRoom::join_with_transport(
            good.clone(),
            invalid_local,
            "Bob",
            Instant::now(),
            |_host, _port| { panic!("invalid local config must not connect") }
        )
        .is_err());
        assert!(NetworkRoom::join_with_transport(
            good,
            config,
            "bad\u{0007}name",
            Instant::now(),
            |_host, _port| { panic!("invalid display name must not connect") }
        )
        .is_err());
    }

    #[test]
    fn invitations_bind_every_field_and_bound_randomized_malformed_input() {
        use rand::{RngCore, SeedableRng};
        let (creator, _) = new_creator();
        let invitation = TorInvitation::decode_code(&creator.invite_code().unwrap()).unwrap();
        for field in 0..6 {
            let mut tampered = invitation.clone();
            match field {
                0 => tampered.version += 1,
                1 => tampered.virtual_port += 1,
                2 => tampered.onion_address.replace_range(..1, "a"),
                3 => {
                    let mut intro = Envelope::decode(&tampered.room_intro).unwrap();
                    if let Message::RoomIntro { room_id, .. } = &mut intro.message {
                        room_id[0] ^= 1;
                    }
                    tampered.room_intro = intro.encode().unwrap();
                }
                4 => tampered.join_token[0] ^= 1,
                _ => tampered.creator_signature[0] ^= 1,
            }
            assert!(tampered.validate().is_err());
        }
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x6768_6f73_7463_6861);
        for len in [
            0,
            1,
            2,
            16,
            32,
            63,
            64,
            127,
            1024,
            INVITATION_MAX_BYTES,
            INVITATION_MAX_BYTES + 1,
        ] {
            for _ in 0..8 {
                let mut bytes = vec![0; len];
                rng.fill_bytes(&mut bytes);
                assert!(TorInvitation::decode_code(&hex_encode(&bytes)).is_err());
            }
        }
        let mut oversized_length = hex_decode(&invitation.encode_code().unwrap()).unwrap();
        // version is one byte; the following fixed-width u64 is onion length.
        oversized_length[1..9].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(TorInvitation::decode_code(&hex_encode(&oversized_length)).is_err());

        let creator_inner = creator.lock().unwrap();
        let signer = &creator_inner.session.as_ref().unwrap().creator_identity;
        let intro = Envelope::decode(&invitation.room_intro).unwrap();
        for case in 0..4 {
            let mut intro = intro.clone();
            if let Message::RoomIntro {
                config,
                creator_identity,
                ..
            } = &mut intro.message
            {
                match case {
                    0 => config.max_participants = 0,
                    1 => config.epoch_update_interval_secs = 0,
                    2 => config.ciphersuite = 0x0001,
                    _ => creator_identity.pop().map(|_| ()).unwrap(),
                }
            }
            assert!(TorInvitation::signed(
                invitation.onion_address.clone(),
                80,
                intro.encode().unwrap(),
                vec![9; JOIN_TOKEN_BYTES],
                signer,
            )
            .is_err());
        }
    }

    #[test]
    fn creator_rejects_invalid_key_package_signatures_and_other_ciphersuites() {
        let now = Instant::now();
        for case in 0..3 {
            let (creator, hub) = new_creator();
            let mut client = hub.connect().unwrap();
            let config = SessionConfig::default();
            let crypto = CryptoManager::new(config.clone());
            let suite = if case == 0 {
                openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            } else {
                config.ciphersuite
            };
            let identity = EphemeralIdentity::generate(suite, &crypto.provider).unwrap();
            let mut key_package =
                MlsMessageOut::from(identity.key_package(suite, &crypto.provider).unwrap())
                    .to_bytes()
                    .unwrap();
            if case == 1 {
                *key_package.last_mut().unwrap() ^= 1;
            }
            if case == 2 {
                key_package = creator
                    .lock()
                    .unwrap()
                    .session
                    .as_mut()
                    .unwrap()
                    .advance_epoch()
                    .unwrap()
                    .to_bytes()
                    .unwrap();
            }
            let token = creator.lock().unwrap().join_token.clone();
            send_wire_transport(
                &mut client,
                0,
                &Envelope::join_request(token, "Invalid peer".into(), key_package),
            )
            .unwrap();
            let events = creator.poll_at(now).unwrap();
            assert!(events
                .iter()
                .any(|event| matches!(event, NetworkUiEvent::Error(_))));
            let inner = creator.lock().unwrap();
            assert!(inner.pending.is_empty());
            assert!(inner.peers.is_empty());
            assert!(inner.unjoined.is_empty());
            assert_eq!(inner.session.as_ref().unwrap().member_count(), 1);
            drop(inner);
            let mut closed = false;
            while let Some(event) = client.receive().unwrap() {
                closed |= matches!(event, StreamEvent::Closed { .. });
            }
            assert!(closed);
        }
    }

    #[test]
    fn forwarded_peer_shutdown_never_acquires_owner_authority() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        complete_join(&creator, &bob, now);
        let charlie = begin_join(&creator, &hub, "Charlie", now);
        complete_join(&creator, &charlie, now);
        bob.poll_at(now).unwrap();
        let bob_id = bob.lock().unwrap().self_id.clone();
        let connection_id = creator.lock().unwrap().peers[&bob_id].connection_id;
        let shutdown = charlie
            .lock()
            .unwrap()
            .session
            .as_mut()
            .unwrap()
            .send_application(&encode_payload(&Payload::Shutdown).unwrap())
            .unwrap();
        send_wire(&mut creator.lock().unwrap(), connection_id, &shutdown).unwrap();
        let events = bob.poll_at(now).unwrap();
        assert!(events.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value.contains("only the room creator"))));
        assert_cleanly_closed(&bob);
        assert_eq!(creator.snapshot().unwrap().state, "active");
        assert_eq!(charlie.snapshot().unwrap().state, "active");
    }

    #[test]
    fn an_old_welcome_cannot_activate_a_fresh_rejoiner() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        creator.poll_at(now).unwrap();
        let old_welcome = {
            let mut inner = bob.lock().unwrap();
            let mut welcome = None;
            while let Some(event) = inner.transport.receive().unwrap() {
                if let StreamEvent::Frame { bytes, .. } = &event {
                    let envelope = Envelope::decode(bytes).unwrap();
                    if matches!(envelope.message, Message::MlsWelcome { .. }) {
                        welcome = Some(envelope);
                    }
                }
                handle_stream_event(&mut inner, event, now, &mut Vec::new()).unwrap();
            }
            send_ready_if_needed(&mut inner).unwrap();
            welcome.unwrap()
        };
        creator.poll_at(now).unwrap();
        bob.poll_at(now).unwrap();
        bob.shutdown().unwrap();
        creator.poll_at(now).unwrap();
        assert_eq!(creator.snapshot().unwrap().participants.len(), 1);
        let fresh = begin_join(&creator, &hub, "Fresh", now);
        // This is an authentic earlier Welcome for a different ephemeral key
        // package. The fresh recipient cannot decrypt it or gain active state.
        send_wire(&mut creator.lock().unwrap(), 2, &old_welcome).unwrap();
        let events = fresh.poll_at(now).unwrap();
        assert!(events
            .iter()
            .any(|event| matches!(event, NetworkUiEvent::Error(_))));
        assert_cleanly_closed(&fresh);
        creator.poll_at(now).unwrap();
        let valid_rejoin = begin_join(&creator, &hub, "Valid rejoin", now);
        complete_join(&creator, &valid_rejoin, now);
    }

    #[test]
    fn two_simultaneous_join_requests_use_one_commit_and_can_retry_to_three_members() {
        let now = Instant::now();
        let (creator, hub) = new_creator();
        let bob = begin_join(&creator, &hub, "Bob", now);
        let charlie = begin_join(&creator, &hub, "Charlie", now);
        creator.poll_at(now).unwrap();
        {
            let inner = creator.lock().unwrap();
            assert_eq!(inner.pending.len(), 1);
            assert_eq!(inner.session.as_ref().unwrap().member_count(), 2);
            assert_eq!(inner.session.as_ref().unwrap().epoch(), 1);
        }
        let rejected = charlie.poll_at(now).unwrap();
        assert!(rejected.iter().any(|event| matches!(event, NetworkUiEvent::Error(value) if value == error_description(ErrorCode::InvalidRoomState))));
        assert_cleanly_closed(&charlie);
        bob.poll_at(now).unwrap();
        creator.poll_at(now).unwrap();
        bob.poll_at(now).unwrap();
        assert_eq!(bob.snapshot().unwrap().state, "active");
        let retry = begin_join(&creator, &hub, "Charlie", now);
        complete_join(&creator, &retry, now);
        bob.poll_at(now).unwrap();
        for room in [&creator, &bob, &retry] {
            assert_eq!(room.snapshot().unwrap().participants.len(), 3);
            assert_eq!(room.snapshot().unwrap().epoch, 2);
            assert_eq!(room.snapshot().unwrap().state, "active");
        }
    }
}
