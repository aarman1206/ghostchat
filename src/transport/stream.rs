//! Byte-only stream transports.
//!
//! The stream layer deliberately knows nothing about GhostChat messages. It
//! accepts opaque bytes, applies a bounded length prefix on network sockets,
//! and returns the same opaque bytes to its caller.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::core::{GhostChatError, Result};

use super::framing::{TimeoutStream, DEFAULT_MAX_FRAME_SIZE};
use super::tor::{OnionServiceConfig, TorConfig, TorDaemon, TorOnionService, TorStream};

/// A lifecycle or data event from a byte stream transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Connected { connection_id: u64 },
    Frame { connection_id: u64, bytes: Vec<u8> },
    Closed { connection_id: u64 },
}

/// A byte-only, connection-oriented transport.
pub trait StreamTransport: Send {
    fn send(&mut self, connection_id: u64, bytes: &[u8]) -> crate::core::Result<()>;
    /// Wait until frames queued before this call have reached the local socket
    /// writer. This is a local write barrier, not an acknowledgement from the
    /// remote peer. Used before sending a leave/shutdown and closing a session.
    fn flush(&mut self) -> crate::core::Result<()>;
    fn receive(&mut self) -> crate::core::Result<Option<StreamEvent>>;
    fn disconnect(&mut self, connection_id: u64);
    fn shutdown(&mut self);
}

const EVENT_QUEUE_CAPACITY: usize = 128;
const SEND_QUEUE_CAPACITY: usize = 32;
const MAX_ACCEPTED_CONNECTIONS: usize = 8;
const MAX_CONNECTION_WORKERS: usize = MAX_ACCEPTED_CONNECTIONS * 2;
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

fn transport_error(message: &'static str) -> GhostChatError {
    GhostChatError::TransportError(message.to_owned())
}

fn transport_error_owned(message: impl Into<String>) -> GhostChatError {
    GhostChatError::TransportError(message.into())
}

fn validate_frame(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > DEFAULT_MAX_FRAME_SIZE {
        return Err(transport_error("invalid or oversized transport frame"));
    }
    Ok(())
}

fn frame_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    validate_frame(bytes)?;
    let mut framed = Vec::with_capacity(bytes.len().saturating_add(4));
    let length = u32::try_from(bytes.len())
        .map_err(|_| transport_error("invalid or oversized transport frame"))?;
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(bytes);
    Ok(framed)
}

/// A Tor-backed byte transport.
pub struct TorTransport {
    inner: Arc<TorTransportInner>,
    events: Receiver<StreamEvent>,
    service: Option<TorOnionService>,
}

struct TorTransportInner {
    shutdown: AtomicBool,
    connections: Mutex<HashMap<u64, Arc<TorConnection>>>,
    events: SyncSender<StreamEvent>,
    accept_handle: Mutex<Option<JoinHandle<()>>>,
    join_handles: Mutex<Vec<JoinHandle<()>>>,
    next_connection_id: AtomicU64,
    live_workers: AtomicUsize,
}

struct TorConnection {
    connection_id: u64,
    socket: Arc<TorStream>,
    outbound: SyncSender<WriterCommand>,
    stop: AtomicBool,
    closed: AtomicBool,
    event_gate: Mutex<()>,
    closed_event_enqueued: AtomicBool,
    closed_event_delivered: AtomicBool,
}

enum WriterCommand {
    Frame(Vec<u8>),
    Flush(SyncSender<io::Result<()>>),
}

struct WorkerSlot(Arc<TorTransportInner>);

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.0.live_workers.fetch_sub(1, Ordering::AcqRel);
    }
}

impl TorTransport {
    /// Create an onion service and return its hostname and virtual port.
    pub fn host(config: TorConfig) -> Result<(Self, String, u16)> {
        let daemon = TorDaemon::connect(config.clone())
            .map_err(|error| transport_error_owned(error.to_string()))?;
        ensure_bootstrapped(&daemon)?;
        let service = TorOnionService::create(&daemon, OnionServiceConfig::default())
            .map_err(|error| transport_error_owned(error.to_string()))?;
        let onion_address = service.onion_address().to_owned();
        let virtual_port = OnionServiceConfig::default().virtual_port;
        let listener = service
            .try_clone_listener()
            .map_err(|error| transport_error_owned(error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| transport_error("could not configure the Tor accept listener"))?;

        let (transport, inner) = Self::empty();
        let accept_inner = Arc::clone(&inner);
        let read_timeout = config.read_timeout;
        let write_timeout = config.write_timeout;
        let accept_handle = thread::Builder::new()
            .name("ghostchat-tor-accept".to_owned())
            .spawn(move || accept_loop(accept_inner, listener, read_timeout, write_timeout))
            .map_err(|_| transport_error("could not start the Tor accept worker"))?;
        register_accept_handle(&inner, accept_handle);

        let mut transport = transport;
        transport.service = Some(service);
        Ok((transport, onion_address, virtual_port))
    }

    /// Connect one outbound stream through Tor's SOCKS listener. The
    /// outbound connection always uses connection id zero.
    pub fn connect(config: TorConfig, host: &str, port: u16) -> Result<Self> {
        let daemon = TorDaemon::connect(config.clone())
            .map_err(|error| transport_error_owned(error.to_string()))?;
        ensure_bootstrapped(&daemon)?;
        let stream = TorStream::connect_with_config(&config, host, port)
            .map_err(|error| transport_error_owned(error.to_string()))?;
        let (transport, inner) = Self::empty();
        if let Err(error) =
            install_connection(&inner, 0, stream, config.read_timeout, config.write_timeout)
        {
            inner.shutdown.store(true, Ordering::SeqCst);
            join_all_workers(&inner);
            return Err(error);
        }
        Ok(transport)
    }

    fn empty() -> (Self, Arc<TorTransportInner>) {
        let (event_sender, events) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let inner = Arc::new(TorTransportInner {
            shutdown: AtomicBool::new(false),
            connections: Mutex::new(HashMap::new()),
            events: event_sender,
            accept_handle: Mutex::new(None),
            join_handles: Mutex::new(Vec::new()),
            next_connection_id: AtomicU64::new(1),
            live_workers: AtomicUsize::new(0),
        });
        (
            Self {
                inner: Arc::clone(&inner),
                events,
                service: None,
            },
            inner,
        )
    }

    fn reap(&self) {
        reap_connections(&self.inner);
        reap_finished_workers(&self.inner);
    }

    fn shutdown_inner(&mut self) {
        if self.inner.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }

        // Closing the authenticated control connection removes the ephemeral
        // service at Tor and avoids waiting on a blocked control command.
        if let Some(mut service) = self.service.take() {
            service.shutdown();
        }
        // The accept worker is joined before connections are closed so it
        // cannot register another reader/writer pair after the worker join
        // pass below has started.
        join_accept_worker(&self.inner);
        close_all_connections(&self.inner);
        join_all_workers(&self.inner);
    }
}

fn ensure_bootstrapped(daemon: &TorDaemon) -> Result<()> {
    let progress = daemon
        .bootstrap_progress()
        .map_err(|error| transport_error_owned(error.to_string()))?;
    if progress < 100 {
        return Err(transport_error_owned(format!(
            "Tor is still bootstrapping ({progress}%)"
        )));
    }
    Ok(())
}

fn flush_connections(
    inner: &Arc<TorTransportInner>,
    connections: Vec<Arc<TorConnection>>,
    deadline: Instant,
) -> Result<()> {
    for connection in connections {
        if connection.closed.load(Ordering::Acquire)
            || connection.stop.load(Ordering::Acquire)
            || inner.shutdown.load(Ordering::Acquire)
        {
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            close_connection(inner, &connection);
            return Err(transport_error("transport flush deadline exceeded"));
        }
        let (ack_sender, ack_receiver) = mpsc::sync_channel(1);
        match connection
            .outbound
            .try_send(WriterCommand::Flush(ack_sender))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                close_connection(inner, &connection);
                return Err(transport_error("transport output queue is full"));
            }
            Err(TrySendError::Disconnected(_)) => {
                close_connection(inner, &connection);
                return Err(transport_error("transport writer is closed"));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match ack_receiver.recv_timeout(remaining) {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                close_connection(inner, &connection);
                return Err(transport_error("transport writer did not flush"));
            }
        }
    }
    Ok(())
}

impl StreamTransport for TorTransport {
    fn send(&mut self, connection_id: u64, bytes: &[u8]) -> Result<()> {
        self.reap();
        let framed = frame_bytes(bytes)?;
        let connection = {
            let connections = self
                .inner
                .connections
                .try_lock()
                .map_err(|_| transport_error("Tor transport state is busy"))?;
            connections.get(&connection_id).cloned()
        }
        .ok_or_else(|| transport_error("unknown or closed transport connection"))?;

        if connection.closed.load(Ordering::Acquire)
            || connection.stop.load(Ordering::Acquire)
            || self.inner.shutdown.load(Ordering::Acquire)
        {
            return Err(transport_error("unknown or closed transport connection"));
        }

        match connection.outbound.try_send(WriterCommand::Frame(framed)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                close_connection(&self.inner, &connection);
                self.reap();
                Err(transport_error("transport output queue is full"))
            }
            Err(TrySendError::Disconnected(_)) => {
                close_connection(&self.inner, &connection);
                self.reap();
                Err(transport_error("transport writer is closed"))
            }
        }
    }

    fn flush(&mut self) -> Result<()> {
        // Flush commands are bounded local write barriers (not remote
        // acknowledgements) and share one aggregate deadline across peers.
        self.reap();
        let deadline = Instant::now() + FLUSH_TIMEOUT;
        let connections: Vec<_> = self
            .inner
            .connections
            .try_lock()
            .map_err(|_| transport_error("Tor transport state is busy"))?
            .values()
            .cloned()
            .collect();
        flush_connections(&self.inner, connections, deadline)
    }

    fn receive(&mut self) -> Result<Option<StreamEvent>> {
        self.reap();
        match self.events.try_recv() {
            Ok(event) => {
                if let StreamEvent::Closed { connection_id } = &event {
                    mark_closed_event_delivered(&self.inner, *connection_id);
                }
                self.reap();
                Ok(Some(event))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                Err(transport_error("transport event queue is closed"))
            }
        }
    }

    fn disconnect(&mut self, connection_id: u64) {
        let connection = match self.inner.connections.lock() {
            Ok(connections) => connections.get(&connection_id).cloned(),
            Err(poisoned) => poisoned.into_inner().get(&connection_id).cloned(),
        };
        if let Some(connection) = connection {
            close_connection(&self.inner, &connection);
        }
        self.reap();
    }

    fn shutdown(&mut self) {
        self.shutdown_inner();
    }
}

fn mark_closed_event_delivered(inner: &Arc<TorTransportInner>, connection_id: u64) {
    let connection = match inner.connections.lock() {
        Ok(connections) => connections.get(&connection_id).cloned(),
        Err(poisoned) => poisoned.into_inner().get(&connection_id).cloned(),
    };
    if let Some(connection) = connection {
        connection
            .closed_event_delivered
            .store(true, Ordering::Release);
    }
}

impl Drop for TorTransport {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

fn register_accept_handle(inner: &Arc<TorTransportInner>, handle: JoinHandle<()>) {
    match inner.accept_handle.lock() {
        Ok(mut slot) => *slot = Some(handle),
        Err(poisoned) => *poisoned.into_inner() = Some(handle),
    }
}

fn register_join_handle(inner: &Arc<TorTransportInner>, handle: JoinHandle<()>) {
    match inner.join_handles.lock() {
        Ok(mut handles) => handles.push(handle),
        Err(poisoned) => poisoned.into_inner().push(handle),
    }
}

fn install_connection(
    inner: &Arc<TorTransportInner>,
    connection_id: u64,
    stream: TorStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<()> {
    if inner.shutdown.load(Ordering::Acquire) {
        let _ = stream.shutdown();
        return Err(transport_error("Tor transport is shut down"));
    }

    let socket = Arc::new(stream);
    let reader_stream = socket
        .try_clone()
        .map_err(|_| transport_error("could not clone the Tor reader socket"))?;
    let writer_stream = socket
        .try_clone()
        .map_err(|_| transport_error("could not clone the Tor writer socket"))?;
    let (outbound, writer_input) = mpsc::sync_channel(SEND_QUEUE_CAPACITY);
    let connection = Arc::new(TorConnection {
        connection_id,
        socket,
        outbound,
        stop: AtomicBool::new(false),
        closed: AtomicBool::new(false),
        event_gate: Mutex::new(()),
        closed_event_enqueued: AtomicBool::new(false),
        closed_event_delivered: AtomicBool::new(false),
    });

    if inner
        .live_workers
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |workers| {
            (workers <= MAX_CONNECTION_WORKERS - 2).then_some(workers + 2)
        })
        .is_err()
    {
        let _ = connection.socket.shutdown();
        return Err(transport_error("transport worker limit reached"));
    }
    let reader_slot = WorkerSlot(Arc::clone(inner));
    let writer_slot = WorkerSlot(Arc::clone(inner));
    {
        let mut connections = match inner.connections.lock() {
            Ok(connections) => connections,
            Err(poisoned) => poisoned.into_inner(),
        };
        if inner.shutdown.load(Ordering::Acquire) {
            let _ = connection.socket.shutdown();
            return Err(transport_error("Tor transport is shut down"));
        }
        if connections.len() >= MAX_ACCEPTED_CONNECTIONS || connections.contains_key(&connection_id)
        {
            let _ = connection.socket.shutdown();
            return Err(transport_error(
                "transport connection limit or duplicate id",
            ));
        }
        connections.insert(connection_id, Arc::clone(&connection));
    }

    if inner
        .events
        .try_send(StreamEvent::Connected { connection_id })
        .is_err()
    {
        close_connection(inner, &connection);
        return Err(transport_error("transport event queue is full"));
    }

    let reader_inner = Arc::clone(inner);
    let reader_connection = Arc::clone(&connection);
    let reader = match thread::Builder::new()
        .name("ghostchat-tor-reader".to_owned())
        .spawn(move || {
            let _slot = reader_slot;
            reader_worker(reader_inner, reader_connection, reader_stream, read_timeout)
        }) {
        Ok(handle) => handle,
        Err(_) => {
            close_connection(inner, &connection);
            return Err(transport_error("could not start the Tor reader worker"));
        }
    };

    let writer_inner = Arc::clone(inner);
    let writer_connection = Arc::clone(&connection);
    let writer = match thread::Builder::new()
        .name("ghostchat-tor-writer".to_owned())
        .spawn(move || {
            let _slot = writer_slot;
            writer_worker(
                writer_inner,
                writer_connection,
                writer_stream,
                writer_input,
                write_timeout,
            )
        }) {
        Ok(handle) => handle,
        Err(_) => {
            close_connection(inner, &connection);
            let _ = reader.join();
            return Err(transport_error("could not start the Tor writer worker"));
        }
    };

    register_join_handle(inner, reader);
    register_join_handle(inner, writer);
    Ok(())
}

fn accept_loop(
    inner: Arc<TorTransportInner>,
    listener: TcpListener,
    read_timeout: Duration,
    write_timeout: Duration,
) {
    while !inner.shutdown.load(Ordering::Acquire) {
        reap_connections(&inner);
        reap_finished_workers(&inner);
        match listener.accept() {
            Ok((stream, _peer)) => {
                let connection_id = match inner.next_connection_id.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |id| id.checked_add(1),
                ) {
                    Ok(id) => id,
                    Err(_) => break,
                };
                let stream = TorStream::from_incoming(stream);
                if stream.set_read_timeout(Some(read_timeout)).is_err()
                    || stream.set_write_timeout(Some(write_timeout)).is_err()
                {
                    let _ = stream.shutdown();
                    continue;
                }
                let _ =
                    install_connection(&inner, connection_id, stream, read_timeout, write_timeout);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(WORKER_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn reader_worker(
    inner: Arc<TorTransportInner>,
    connection: Arc<TorConnection>,
    mut stream: TorStream,
    read_timeout: Duration,
) {
    loop {
        if inner.shutdown.load(Ordering::Acquire) || connection.stop.load(Ordering::Acquire) {
            break;
        }

        match read_frame_once(&mut stream, read_timeout) {
            FrameRead::Frame(bytes) => {
                if !send_frame_event(&inner, &connection, bytes) {
                    break;
                }
            }
            FrameRead::Idle => continue,
            FrameRead::Closed | FrameRead::Invalid => break,
        }
    }
    close_connection(&inner, &connection);
}

fn writer_worker(
    inner: Arc<TorTransportInner>,
    connection: Arc<TorConnection>,
    mut stream: TorStream,
    input: Receiver<WriterCommand>,
    write_timeout: Duration,
) {
    loop {
        if inner.shutdown.load(Ordering::Acquire) || connection.stop.load(Ordering::Acquire) {
            break;
        }
        match input.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(WriterCommand::Frame(frame)) => {
                if write_all_until(&mut stream, &frame, Instant::now() + write_timeout).is_err() {
                    break;
                }
            }
            Ok(WriterCommand::Flush(ack)) => {
                let result = flush_until(&mut stream, Instant::now() + FLUSH_TIMEOUT);
                let failed = result.is_err();
                let _ = ack.send(result);
                if failed {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    close_connection(&inner, &connection);
}

enum FrameRead {
    Frame(Vec<u8>),
    /// A timeout before any byte of a new frame arrived. This is an idle
    /// stream, not a disconnect.
    Idle,
    Closed,
    Invalid,
}

fn read_frame_once<S: Read + TimeoutStream>(stream: &mut S, timeout: Duration) -> FrameRead {
    let mut deadline = Instant::now() + timeout;
    let mut prefix = [0_u8; 4];
    let mut prefix_read = 0;
    while prefix_read < prefix.len() {
        match read_until_deadline(stream, &mut prefix[prefix_read..], deadline) {
            Ok(0) => return FrameRead::Closed,
            Ok(read) => {
                if prefix_read == 0 {
                    deadline = Instant::now() + timeout;
                }
                prefix_read += read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                return if prefix_read == 0 {
                    FrameRead::Idle
                } else {
                    // Never restart a partially read prefix.
                    FrameRead::Closed
                };
            }
            Err(_) => return FrameRead::Closed,
        }
    }

    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > DEFAULT_MAX_FRAME_SIZE {
        return FrameRead::Invalid;
    }

    let mut payload = vec![0_u8; length];
    let mut payload_read = 0;
    while payload_read < payload.len() {
        match read_until_deadline(stream, &mut payload[payload_read..], deadline) {
            Ok(0) => return FrameRead::Closed,
            Ok(read) => payload_read += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                // A partial frame is closed safely rather than retried from
                // its beginning and potentially misframed.
                return FrameRead::Closed;
            }
            Err(_) => return FrameRead::Closed,
        }
    }
    if Instant::now() >= deadline {
        return FrameRead::Closed;
    }
    FrameRead::Frame(payload)
}

fn write_all_until<S: Write + TimeoutStream>(
    stream: &mut S,
    bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "stream frame write deadline exceeded",
            ));
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(&bytes[written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "stream returned zero bytes while writing a frame",
                ));
            }
            Ok(count) if count <= bytes.len() - written => written += count,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream returned more written bytes than requested",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream frame write deadline exceeded",
        ));
    }
    Ok(())
}

fn flush_until<S: Write + TimeoutStream>(stream: &mut S, deadline: Instant) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream flush deadline exceeded",
        ));
    }
    stream.set_write_timeout(Some(remaining))?;
    stream.flush()?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream flush deadline exceeded",
        ));
    }
    Ok(())
}

fn read_until_deadline<S: Read + TimeoutStream>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<usize> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stream frame read deadline exceeded",
        ));
    }
    stream.set_read_timeout(Some(remaining))?;
    stream.read(buffer)
}

fn send_frame_event(
    inner: &Arc<TorTransportInner>,
    connection: &Arc<TorConnection>,
    bytes: Vec<u8>,
) -> bool {
    let _event_gate = match connection.event_gate.lock() {
        Ok(gate) => gate,
        Err(poisoned) => poisoned.into_inner(),
    };
    if connection.closed.load(Ordering::Acquire) {
        return false;
    }
    inner
        .events
        .try_send(StreamEvent::Frame {
            connection_id: connection.connection_id,
            bytes,
        })
        .is_ok()
}

fn close_connection(inner: &Arc<TorTransportInner>, connection: &Arc<TorConnection>) {
    connection.closed.store(true, Ordering::Release);
    connection.stop.store(true, Ordering::Release);
    let _ = connection.socket.shutdown();
    enqueue_closed_event(inner, connection);
}

fn enqueue_closed_event(inner: &Arc<TorTransportInner>, connection: &Arc<TorConnection>) {
    if !connection.closed.load(Ordering::Acquire)
        || connection.closed_event_enqueued.load(Ordering::Acquire)
        || connection.closed_event_delivered.load(Ordering::Acquire)
    {
        return;
    }

    let _event_gate = match connection.event_gate.lock() {
        Ok(gate) => gate,
        Err(poisoned) => poisoned.into_inner(),
    };
    if connection.closed_event_enqueued.load(Ordering::Acquire)
        || connection.closed_event_delivered.load(Ordering::Acquire)
    {
        return;
    }
    if inner
        .events
        .try_send(StreamEvent::Closed {
            connection_id: connection.connection_id,
        })
        .is_ok()
    {
        connection
            .closed_event_enqueued
            .store(true, Ordering::Release);
    }
}

fn close_all_connections(inner: &Arc<TorTransportInner>) {
    let connections: Vec<_> = match inner.connections.lock() {
        Ok(connections) => connections.values().cloned().collect(),
        Err(poisoned) => poisoned.into_inner().values().cloned().collect(),
    };
    for connection in connections {
        close_connection(inner, &connection);
    }
}

fn reap_connections(inner: &Arc<TorTransportInner>) {
    let connections: Vec<_> = match inner.connections.lock() {
        Ok(connections) => connections.values().cloned().collect(),
        Err(poisoned) => poisoned.into_inner().values().cloned().collect(),
    };
    for connection in connections {
        if connection.closed.load(Ordering::Acquire) {
            enqueue_closed_event(inner, &connection);
        }
    }

    match inner.connections.lock() {
        Ok(mut connections) => {
            connections
                .retain(|_, connection| !connection.closed_event_delivered.load(Ordering::Acquire));
        }
        Err(poisoned) => {
            let mut connections = poisoned.into_inner();
            connections
                .retain(|_, connection| !connection.closed_event_delivered.load(Ordering::Acquire));
        }
    }
}

fn reap_finished_workers(inner: &Arc<TorTransportInner>) {
    let Ok(mut handles) = inner.join_handles.try_lock() else {
        return;
    };
    let mut running = Vec::with_capacity(handles.len());
    for handle in handles.drain(..) {
        if handle.is_finished() {
            let _ = handle.join();
        } else {
            running.push(handle);
        }
    }
    *handles = running;
}

fn join_all_workers(inner: &Arc<TorTransportInner>) {
    loop {
        let handles = match inner.join_handles.lock() {
            Ok(mut handles) => std::mem::take(&mut *handles),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        if handles.is_empty() {
            break;
        }
        for handle in handles {
            let _ = handle.join();
        }
    }
}

fn join_accept_worker(inner: &Arc<TorTransportInner>) {
    let handle = match inner.accept_handle.lock() {
        Ok(mut handle) => handle.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}

/// A deterministic in-memory implementation of [`StreamTransport`].
pub struct InMemoryStreamTransport {
    state: Arc<Mutex<MemoryHubState>>,
    role: MemoryRole,
    stopped: bool,
}

/// Factory for deterministic in-memory client transports.
#[derive(Clone)]
pub struct InMemoryHub {
    state: Arc<Mutex<MemoryHubState>>,
}

enum MemoryRole {
    Host,
    Client(u64),
}

struct MemoryClient {
    events: std::collections::VecDeque<StreamEvent>,
    closed: bool,
    client_closed_enqueued: bool,
    client_closed_delivered: bool,
    host_closed_enqueued: bool,
    host_closed_delivered: bool,
}

struct MemoryHubState {
    host_events: std::collections::VecDeque<StreamEvent>,
    clients: HashMap<u64, MemoryClient>,
    next_connection_id: u64,
    stopped: bool,
}

impl InMemoryStreamTransport {
    /// Create a host transport and a hub that can create connected clients.
    pub fn hub() -> (Self, InMemoryHub) {
        let state = Arc::new(Mutex::new(MemoryHubState {
            host_events: std::collections::VecDeque::new(),
            clients: HashMap::new(),
            next_connection_id: 1,
            stopped: false,
        }));
        (
            Self {
                state: Arc::clone(&state),
                role: MemoryRole::Host,
                stopped: false,
            },
            InMemoryHub { state },
        )
    }
}

impl InMemoryHub {
    /// Connect a new client to the host, assigning host-side ids from one.
    pub fn connect(&self) -> Result<InMemoryStreamTransport> {
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| transport_error("in-memory transport state is busy"))?;
        if state.stopped {
            return Err(transport_error("in-memory transport is shut down"));
        }
        retry_memory_closures(&mut state);
        reap_memory_clients(&mut state);
        if state.clients.len() >= MAX_ACCEPTED_CONNECTIONS
            || state.host_events.len() >= EVENT_QUEUE_CAPACITY
        {
            return Err(transport_error("in-memory connection limit reached"));
        }
        let connection_id = state.next_connection_id;
        state.next_connection_id = state
            .next_connection_id
            .checked_add(1)
            .ok_or_else(|| transport_error("in-memory connection id space exhausted"))?;
        state
            .host_events
            .push_back(StreamEvent::Connected { connection_id });
        let mut events = std::collections::VecDeque::new();
        events.push_back(StreamEvent::Connected { connection_id: 0 });
        state.clients.insert(
            connection_id,
            MemoryClient {
                events,
                closed: false,
                client_closed_enqueued: false,
                client_closed_delivered: false,
                host_closed_enqueued: false,
                host_closed_delivered: false,
            },
        );
        Ok(InMemoryStreamTransport {
            state: Arc::clone(&self.state),
            role: MemoryRole::Client(connection_id),
            stopped: false,
        })
    }
}

impl StreamTransport for InMemoryStreamTransport {
    fn send(&mut self, connection_id: u64, bytes: &[u8]) -> Result<()> {
        if self.stopped {
            return Err(transport_error("in-memory transport is shut down"));
        }
        let _ = frame_bytes(bytes)?;
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| transport_error("in-memory transport state is busy"))?;
        match self.role {
            MemoryRole::Host => {
                let closed = state
                    .clients
                    .get(&connection_id)
                    .map(|client| client.closed)
                    .ok_or_else(|| transport_error("unknown or closed transport connection"))?;
                if closed {
                    return Err(transport_error("unknown or closed transport connection"));
                }
                let full = state
                    .clients
                    .get(&connection_id)
                    .map(|client| client.events.len() >= EVENT_QUEUE_CAPACITY)
                    .unwrap_or(true);
                if full {
                    close_memory_client(&mut state, connection_id);
                    return Err(transport_error("in-memory transport output queue is full"));
                }
                state
                    .clients
                    .get_mut(&connection_id)
                    .expect("client was checked above")
                    .events
                    .push_back(StreamEvent::Frame {
                        connection_id: 0,
                        bytes: bytes.to_vec(),
                    });
            }
            MemoryRole::Client(client_id) => {
                if connection_id != 0 {
                    return Err(transport_error("client transport only has connection zero"));
                }
                let closed = state
                    .clients
                    .get(&client_id)
                    .map(|client| client.closed)
                    .ok_or_else(|| transport_error("unknown or closed transport connection"))?;
                if closed {
                    return Err(transport_error("unknown or closed transport connection"));
                }
                if state.host_events.len() >= EVENT_QUEUE_CAPACITY {
                    close_memory_client(&mut state, client_id);
                    return Err(transport_error("in-memory transport output queue is full"));
                }
                state.host_events.push_back(StreamEvent::Frame {
                    connection_id: client_id,
                    bytes: bytes.to_vec(),
                });
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.stopped {
            return Err(transport_error("in-memory transport is shut down"));
        }
        // In-memory sends are enqueued synchronously, so this is already a
        // local write barrier; there is no remote acknowledgement to await.
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<StreamEvent>> {
        if self.stopped {
            return Ok(None);
        }
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| transport_error("in-memory transport state is busy"))?;
        let event = match self.role {
            MemoryRole::Host => state.host_events.pop_front(),
            MemoryRole::Client(client_id) => state
                .clients
                .get_mut(&client_id)
                .and_then(|client| client.events.pop_front()),
        };
        if let Some(event) = &event {
            mark_memory_event_delivered(&mut state, &self.role, event);
        }
        retry_memory_closures(&mut state);
        reap_memory_clients(&mut state);
        Ok(event)
    }

    fn disconnect(&mut self, connection_id: u64) {
        if self.stopped {
            return;
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        match self.role {
            MemoryRole::Host => close_memory_client(&mut state, connection_id),
            MemoryRole::Client(client_id) if connection_id == 0 => {
                close_memory_client(&mut state, client_id)
            }
            MemoryRole::Client(_) => {}
        }
        retry_memory_closures(&mut state);
        reap_memory_clients(&mut state);
    }

    fn shutdown(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        match self.role {
            MemoryRole::Host => {
                state.stopped = true;
                let ids: Vec<_> = state.clients.keys().copied().collect();
                for connection_id in ids {
                    close_memory_client(&mut state, connection_id);
                    if let Some(client) = state.clients.get_mut(&connection_id) {
                        client.host_closed_delivered = true;
                    }
                }
            }
            MemoryRole::Client(connection_id) => {
                close_memory_client(&mut state, connection_id);
                if let Some(client) = state.clients.get_mut(&connection_id) {
                    // A stopped client can no longer receive its local
                    // closure event, so retire that side of the tombstone.
                    client.client_closed_delivered = true;
                }
            }
        }
        retry_memory_closures(&mut state);
        reap_memory_clients(&mut state);
    }
}

impl Drop for InMemoryStreamTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn close_memory_client(state: &mut MemoryHubState, connection_id: u64) {
    if let Some(client) = state.clients.get_mut(&connection_id) {
        client.closed = true;
    }
    retry_memory_closures(state);
}

fn retry_memory_closures(state: &mut MemoryHubState) {
    let ids: Vec<_> = state.clients.keys().copied().collect();
    for connection_id in ids {
        let Some(client) = state.clients.get(&connection_id) else {
            continue;
        };
        if !client.closed {
            continue;
        }

        let enqueue_client_closed =
            !client.client_closed_enqueued && client.events.len() < EVENT_QUEUE_CAPACITY;
        if enqueue_client_closed {
            let client = state
                .clients
                .get_mut(&connection_id)
                .expect("client was checked above");
            client
                .events
                .push_back(StreamEvent::Closed { connection_id: 0 });
            client.client_closed_enqueued = true;
        }
        let enqueue_host_closed = state
            .clients
            .get(&connection_id)
            .map(|client| !client.host_closed_enqueued)
            .unwrap_or(false)
            && state.host_events.len() < EVENT_QUEUE_CAPACITY;
        if enqueue_host_closed {
            state
                .host_events
                .push_back(StreamEvent::Closed { connection_id });
            state
                .clients
                .get_mut(&connection_id)
                .expect("client was checked above")
                .host_closed_enqueued = true;
        }
    }
}

fn mark_memory_event_delivered(state: &mut MemoryHubState, role: &MemoryRole, event: &StreamEvent) {
    if !matches!(event, StreamEvent::Closed { .. }) {
        return;
    }
    match role {
        MemoryRole::Host => {
            if let StreamEvent::Closed { connection_id } = event {
                if let Some(client) = state.clients.get_mut(connection_id) {
                    client.host_closed_delivered = true;
                }
            }
        }
        MemoryRole::Client(connection_id) => {
            if let Some(client) = state.clients.get_mut(connection_id) {
                client.client_closed_delivered = true;
            }
        }
    }
}

fn reap_memory_clients(state: &mut MemoryHubState) {
    state.clients.retain(|_, client| {
        !(client.closed && client.client_closed_delivered && client.host_closed_delivered)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    fn drain_event<T: StreamTransport>(transport: &mut T) -> StreamEvent {
        transport.receive().unwrap().expect("expected event")
    }

    fn local_socket_pair() -> (TorStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let peer = TcpStream::connect(address).unwrap();
        let (stream, _) = listener.accept().unwrap();
        (TorStream::from_incoming(stream), peer)
    }

    fn local_transport(
        read_timeout: Duration,
    ) -> (TorTransport, Arc<TorTransportInner>, TcpStream) {
        let (stream, peer) = local_socket_pair();
        let (transport, inner) = TorTransport::empty();
        install_connection(&inner, 1, stream, read_timeout, read_timeout).unwrap();
        (transport, inner, peer)
    }

    fn read_wire_frame(peer: &mut TcpStream) -> Vec<u8> {
        let mut prefix = [0_u8; 4];
        peer.read_exact(&mut prefix).unwrap();
        let mut payload = vec![0_u8; u32::from_be_bytes(prefix) as usize];
        peer.read_exact(&mut payload).unwrap();
        payload
    }

    #[test]
    fn in_memory_hub_assigns_client_zero_and_host_ids_from_one() {
        let (mut host, hub) = InMemoryStreamTransport::hub();
        let mut client = hub.connect().unwrap();
        assert_eq!(
            drain_event(&mut host),
            StreamEvent::Connected { connection_id: 1 }
        );
        assert_eq!(
            drain_event(&mut client),
            StreamEvent::Connected { connection_id: 0 }
        );

        client.send(0, &[0, 0xff, 7]).unwrap();
        assert_eq!(
            drain_event(&mut host),
            StreamEvent::Frame {
                connection_id: 1,
                bytes: vec![0, 0xff, 7]
            }
        );
        host.send(1, &[9, 8]).unwrap();
        assert_eq!(
            drain_event(&mut client),
            StreamEvent::Frame {
                connection_id: 0,
                bytes: vec![9, 8]
            }
        );
    }

    #[test]
    fn in_memory_transport_rejects_empty_and_oversized_frames() {
        let (mut host, hub) = InMemoryStreamTransport::hub();
        let mut client = hub.connect().unwrap();
        let _ = host.receive().unwrap();
        let _ = client.receive().unwrap();
        assert!(client.send(0, &[]).is_err());
        assert!(client
            .send(0, &vec![0_u8; DEFAULT_MAX_FRAME_SIZE + 1])
            .is_err());
    }

    #[test]
    fn in_memory_disconnect_is_delivered_to_both_sides() {
        let (mut host, hub) = InMemoryStreamTransport::hub();
        let mut client = hub.connect().unwrap();
        let _ = host.receive().unwrap();
        let _ = client.receive().unwrap();
        host.disconnect(1);
        assert_eq!(
            drain_event(&mut host),
            StreamEvent::Closed { connection_id: 1 }
        );
        assert_eq!(
            drain_event(&mut client),
            StreamEvent::Closed { connection_id: 0 }
        );
    }

    #[test]
    fn tor_flush_keeps_frames_ordered_before_returning() {
        let (mut transport, _inner, mut peer) = local_transport(Duration::from_millis(50));
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        assert_eq!(
            drain_event(&mut transport),
            StreamEvent::Connected { connection_id: 1 }
        );

        transport.send(1, b"first").unwrap();
        transport.send(1, b"second").unwrap();
        transport.flush().unwrap();

        assert_eq!(read_wire_frame(&mut peer), b"first");
        assert_eq!(read_wire_frame(&mut peer), b"second");
        transport.shutdown();
    }

    #[test]
    fn tor_reader_uses_idle_and_total_partial_frame_deadlines() {
        let (mut stream, peer) = local_socket_pair();
        let started = Instant::now();
        assert!(matches!(
            read_frame_once(&mut stream, Duration::from_millis(25)),
            FrameRead::Idle
        ));
        assert!(started.elapsed() < Duration::from_millis(250));
        drop(peer);

        let (mut stream, mut peer) = local_socket_pair();
        let writer = thread::spawn(move || {
            for (index, byte) in [0_u8, 0, 0, 1].into_iter().enumerate() {
                let _ = peer.write_all(&[byte]);
                if index < 3 {
                    thread::sleep(Duration::from_millis(20));
                }
            }
        });
        let started = Instant::now();
        assert!(matches!(
            read_frame_once(&mut stream, Duration::from_millis(55)),
            FrameRead::Closed
        ));
        assert!(started.elapsed() < Duration::from_millis(250));
        let _ = writer.join();
    }

    #[test]
    fn tor_reader_starts_partial_frame_budget_after_first_byte() {
        let (mut stream, mut peer) = local_socket_pair();
        let writer = thread::spawn(move || {
            let wire = [0_u8, 0, 0, 1, 7];
            thread::sleep(Duration::from_millis(100));
            for byte in wire {
                let _ = peer.write_all(&[byte]);
                thread::sleep(Duration::from_millis(20));
            }
        });
        assert!(matches!(
            read_frame_once(&mut stream, Duration::from_millis(160)),
            FrameRead::Frame(bytes) if bytes == vec![7]
        ));
        let _ = writer.join();
    }

    struct FixtureStream(io::Cursor<Vec<u8>>);

    impl Read for FixtureStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0.read(bytes)
        }
    }

    impl TimeoutStream for FixtureStream {
        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn tor_frame_reader_accepts_exact_maximum_opaque_bytes_and_rejects_partial_eof() {
        let bytes: Vec<u8> = (0..DEFAULT_MAX_FRAME_SIZE)
            .map(|index| index as u8)
            .collect();
        let wire = frame_bytes(&bytes).unwrap();
        let mut stream = FixtureStream(io::Cursor::new(wire));
        assert!(matches!(
            read_frame_once(&mut stream, Duration::from_secs(1)),
            FrameRead::Frame(received) if received == bytes
        ));
        for partial in [vec![], vec![0, 0], vec![0, 0, 0, 4, 0xff, 0]] {
            let mut stream = FixtureStream(io::Cursor::new(partial));
            assert!(matches!(
                read_frame_once(&mut stream, Duration::from_secs(1)),
                FrameRead::Closed
            ));
        }
        for length in [0_u32, (DEFAULT_MAX_FRAME_SIZE + 1) as u32, u32::MAX] {
            let mut stream = FixtureStream(io::Cursor::new(length.to_be_bytes().to_vec()));
            assert!(matches!(
                read_frame_once(&mut stream, Duration::from_secs(1)),
                FrameRead::Invalid
            ));
        }
    }

    struct DribbleWriter {
        written: usize,
        timeouts: std::cell::RefCell<Vec<Duration>>,
    }

    impl TimeoutStream for DribbleWriter {
        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.timeouts.borrow_mut().push(timeout.unwrap());
            Ok(())
        }
    }

    impl Write for DribbleWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            thread::sleep(Duration::from_millis(10));
            self.written += 1;
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_writes_share_one_total_frame_deadline() {
        let mut writer = DribbleWriter {
            written: 0,
            timeouts: std::cell::RefCell::new(Vec::new()),
        };
        let error = write_all_until(
            &mut writer,
            &[0_u8; 20],
            Instant::now() + Duration::from_millis(60),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(writer.written < 20);
        let timeouts = writer.timeouts.into_inner();
        assert!(timeouts.windows(2).all(|pair| pair[1] <= pair[0]));
    }

    #[test]
    fn flush_deadline_is_aggregate_across_connections() {
        let (mut transport, inner) = TorTransport::empty();
        let mut connections = Vec::new();
        let mut peers = Vec::new();
        let mut writers = Vec::new();
        for connection_id in 1..=2 {
            let (socket, peer) = local_socket_pair();
            peers.push(peer);
            let (outbound, input) = mpsc::sync_channel(1);
            let connection = Arc::new(TorConnection {
                connection_id,
                socket: Arc::new(socket),
                outbound,
                stop: AtomicBool::new(false),
                closed: AtomicBool::new(false),
                event_gate: Mutex::new(()),
                closed_event_enqueued: AtomicBool::new(false),
                closed_event_delivered: AtomicBool::new(false),
            });
            inner
                .connections
                .lock()
                .unwrap()
                .insert(connection_id, Arc::clone(&connection));
            connections.push(connection);
            writers.push(thread::spawn(move || {
                if let Ok(WriterCommand::Flush(ack)) = input.recv_timeout(Duration::from_secs(1)) {
                    thread::sleep(Duration::from_millis(100));
                    let _ = ack.send(Ok(()));
                }
            }));
        }
        assert!(flush_connections(
            &inner,
            connections,
            Instant::now() + Duration::from_millis(150),
        )
        .is_err());
        transport.shutdown();
        for writer in writers {
            writer.join().unwrap();
        }
    }

    #[test]
    fn tor_closed_event_survives_a_saturated_event_queue_once() {
        let (mut transport, inner, _peer) = local_transport(Duration::from_millis(50));
        assert_eq!(
            drain_event(&mut transport),
            StreamEvent::Connected { connection_id: 1 }
        );
        for _ in 0..EVENT_QUEUE_CAPACITY {
            inner
                .events
                .try_send(StreamEvent::Frame {
                    connection_id: 1,
                    bytes: vec![7],
                })
                .unwrap();
        }

        transport.disconnect(1);
        for _ in 0..EVENT_QUEUE_CAPACITY {
            assert_eq!(
                drain_event(&mut transport),
                StreamEvent::Frame {
                    connection_id: 1,
                    bytes: vec![7]
                }
            );
        }
        assert_eq!(
            drain_event(&mut transport),
            StreamEvent::Closed { connection_id: 1 }
        );
        assert_eq!(transport.receive().unwrap(), None);
        transport.shutdown();
    }

    #[test]
    fn tor_shutdown_joins_workers_after_connection_close() {
        let (mut transport, inner, peer) = local_transport(Duration::from_millis(50));
        assert_eq!(
            drain_event(&mut transport),
            StreamEvent::Connected { connection_id: 1 }
        );
        drop(peer);

        transport.shutdown();
        assert!(inner.join_handles.lock().unwrap().is_empty());
        assert_eq!(inner.live_workers.load(Ordering::Acquire), 0);
        assert!(inner
            .connections
            .lock()
            .unwrap()
            .get(&1)
            .expect("connection tombstone remains until its Closed event is received")
            .closed
            .load(Ordering::Acquire));
    }

    #[test]
    fn connection_install_respects_shutdown_duplicate_ids_and_live_worker_limit() {
        let (mut transport, inner, _peer) = local_transport(Duration::from_secs(1));
        let original = inner.connections.lock().unwrap().get(&1).cloned().unwrap();
        let (duplicate, _duplicate_peer) = local_socket_pair();
        assert!(install_connection(
            &inner,
            1,
            duplicate,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err());
        assert!(Arc::ptr_eq(
            inner.connections.lock().unwrap().get(&1).unwrap(),
            &original
        ));
        transport.shutdown();
        let (late, _late_peer) = local_socket_pair();
        assert!(install_connection(
            &inner,
            2,
            late,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err());
        assert_eq!(inner.live_workers.load(Ordering::Acquire), 0);

        let (mut transport, inner) = TorTransport::empty();
        // Simulate already-started workers whose Closed events were consumed
        // before the OS has scheduled their exit: freed IDs aren't new slots.
        inner
            .live_workers
            .store(MAX_CONNECTION_WORKERS, Ordering::Release);
        let (stream, _peer) = local_socket_pair();
        assert!(install_connection(
            &inner,
            1,
            stream,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err());
        assert!(inner.connections.lock().unwrap().is_empty());
        inner.live_workers.store(0, Ordering::Release);
        transport.shutdown();
    }

    #[test]
    fn in_memory_hub_reclaims_closed_clients_for_rejoin() {
        let (mut host, hub) = InMemoryStreamTransport::hub();
        for _ in 0..(MAX_ACCEPTED_CONNECTIONS * 3) {
            let mut client = hub.connect().unwrap();
            assert!(matches!(
                host.receive().unwrap(),
                Some(StreamEvent::Connected { .. })
            ));
            assert_eq!(
                drain_event(&mut client),
                StreamEvent::Connected { connection_id: 0 }
            );

            client.disconnect(0);
            assert_eq!(
                drain_event(&mut client),
                StreamEvent::Closed { connection_id: 0 }
            );
            assert!(matches!(
                host.receive().unwrap(),
                Some(StreamEvent::Closed { .. })
            ));
        }

        let mut client = hub.connect().unwrap();
        assert!(matches!(
            host.receive().unwrap(),
            Some(StreamEvent::Connected { .. })
        ));
        assert_eq!(
            drain_event(&mut client),
            StreamEvent::Connected { connection_id: 0 }
        );
        client.shutdown();
    }

    #[test]
    fn in_memory_closed_event_retries_after_a_saturated_queue() {
        let (mut host, hub) = InMemoryStreamTransport::hub();
        let mut client = hub.connect().unwrap();
        let _ = host.receive().unwrap();
        let _ = client.receive().unwrap();
        for _ in 0..EVENT_QUEUE_CAPACITY {
            client.send(0, &[1]).unwrap();
        }

        client.disconnect(0);
        assert_eq!(
            drain_event(&mut client),
            StreamEvent::Closed { connection_id: 0 }
        );
        for _ in 0..EVENT_QUEUE_CAPACITY {
            assert!(matches!(
                host.receive().unwrap(),
                Some(StreamEvent::Frame {
                    connection_id: 1,
                    ..
                })
            ));
        }
        assert_eq!(
            drain_event(&mut host),
            StreamEvent::Closed { connection_id: 1 }
        );

        let mut rejoined = hub.connect().unwrap();
        assert!(matches!(
            host.receive().unwrap(),
            Some(StreamEvent::Connected { .. })
        ));
        assert_eq!(
            drain_event(&mut rejoined),
            StreamEvent::Connected { connection_id: 0 }
        );
        rejoined.shutdown();
    }
}
