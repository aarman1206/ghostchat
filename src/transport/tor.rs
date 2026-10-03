//! Blocking Tor transport primitives.
//!
//! This module deliberately stops at the byte stream boundary.  It does not
//! serialize GhostChat envelopes, assign `ParticipantId` values, or provide a
//! direct-network fallback when Tor is unavailable.  The parent transport can
//! use [`TorStream`] as its byte-oriented connection and apply its own framing
//! above it.
//!
//! The control connection uses Tor's SAFECOOKIE authentication when it is
//! advertised by `PROTOCOLINFO`, falling back to COOKIE only when SAFECOOKIE
//! is unavailable.  Cookie contents are never included in errors.

use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

use super::framing::TimeoutStream;
use crate::core::GhostChatError;
use hmac::{Hmac, Mac};
use rand::random;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// The largest timeout accepted by [`TorConfig`].
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONTROL_LINE_LIMIT: usize = 64 * 1024;
const DEFAULT_CONTROL_DATA_LIMIT: usize = 4 * 1024 * 1024;
// Shared by every status/data line and asynchronous reply in one command.
const MAX_CONTROL_REPLY_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTROL_REPLY_LINES: usize = 1024;
const MAX_ONION_CLEANUP_WORKERS: usize = 8;
const DEFAULT_COOKIE_PATH: &str = "/run/tor/control.authcookie";
const TOR_COOKIE_LENGTH: usize = 32;
const V3_ONION_ID_LENGTH: usize = 56;

/// Result type returned by the Tor adapter.
pub type TorResult<T> = std::result::Result<T, TorError>;

/// Errors raised by the blocking Tor adapter.
#[derive(Debug)]
pub enum TorError {
    /// The configured Tor endpoint could not be reached.
    Unavailable,
    /// The adapter configuration or a local endpoint is invalid.
    Config(String),
    /// Tor rejected authentication, or the configured cookie could not be
    /// used.  Cookie contents are never included in this error.
    Authentication(String),
    /// The SOCKS proxy rejected or could not establish an onion connection.
    Connect(String),
    /// Tor returned a non-success control-port status.
    Control { code: u16, message: String },
    /// A control or SOCKS response was malformed or exceeded a bound.
    Protocol(String),
    /// A bounded socket operation timed out.
    Timeout,
    /// A local I/O operation failed.
    Io(io::Error),
    /// The onion service could not be created or used.
    Service(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("Tor daemon unavailable"),
            Self::Config(message) => write!(formatter, "invalid Tor configuration: {message}"),
            Self::Authentication(message) => {
                write!(formatter, "Tor authentication failed: {message}")
            }
            Self::Connect(message) => write!(formatter, "Tor connection failed: {message}"),
            Self::Control { code, message } => {
                write!(formatter, "Tor control command failed ({code}): {message}")
            }
            Self::Protocol(message) => {
                write!(formatter, "invalid Tor protocol response: {message}")
            }
            Self::Timeout => formatter.write_str("Tor operation timed out"),
            Self::Io(error) => write!(formatter, "Tor I/O error: {error}"),
            Self::Service(message) => write!(formatter, "Tor onion service error: {message}"),
        }
    }
}

impl std::error::Error for TorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for TorError {
    fn from(error: io::Error) -> Self {
        map_io_error(error)
    }
}

impl From<TorError> for GhostChatError {
    fn from(error: TorError) -> Self {
        GhostChatError::TransportError(error.to_string())
    }
}

impl TorError {
    /// Convert this adapter error to the repository's transport error type.
    pub fn into_transport_error(self) -> GhostChatError {
        self.into()
    }
}

/// Configuration for the local Tor SOCKS and control endpoints.
#[derive(Clone, Debug)]
pub struct TorConfig {
    /// Tor's SOCKS5 listener.  No connection is attempted directly to the
    /// requested onion host.
    pub socks_addr: SocketAddr,
    /// Tor's control-port listener.
    pub control_addr: SocketAddr,
    /// Optional cookie override.  When absent, the path reported by
    /// `PROTOCOLINFO` is used, falling back to the system default only when
    /// the response omits a path.
    pub cookie_path: Option<PathBuf>,
    /// Timeout for establishing either local Tor TCP connection.
    pub connect_timeout: Duration,
    /// Timeout applied to reads; also the total budget for a partial frame.
    /// Control commands use the larger read/write timeout as a total budget.
    pub read_timeout: Duration,
    /// Timeout applied to writes; also the total budget for writing one frame.
    /// SOCKS setup uses the largest configured timeout as its total budget.
    pub write_timeout: Duration,
    /// Maximum bytes in one control-port CRLF line.
    pub max_control_line_bytes: usize,
    /// Maximum bytes in one control-port data block.
    pub max_control_data_bytes: usize,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            control_addr: SocketAddr::from(([127, 0, 0, 1], 9051)),
            cookie_path: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            max_control_line_bytes: DEFAULT_CONTROL_LINE_LIMIT,
            max_control_data_bytes: DEFAULT_CONTROL_DATA_LIMIT,
        }
    }
}

impl TorConfig {
    /// Build a Tor-only configuration from optional process environment
    /// overrides. Invalid overrides fail closed rather than being ignored.
    pub fn from_env() -> TorResult<Self> {
        let mut config = Self::default();
        if let Some(value) = std::env::var_os("GHOSTCHAT_TOR_SOCKS") {
            let value = value
                .to_str()
                .ok_or_else(|| TorError::Config("GHOSTCHAT_TOR_SOCKS is not UTF-8".to_owned()))?;
            config.socks_addr = value.parse().map_err(|_| {
                TorError::Config("GHOSTCHAT_TOR_SOCKS is not a socket address".to_owned())
            })?;
        }
        if let Some(value) = std::env::var_os("GHOSTCHAT_TOR_CONTROL") {
            let value = value
                .to_str()
                .ok_or_else(|| TorError::Config("GHOSTCHAT_TOR_CONTROL is not UTF-8".to_owned()))?;
            config.control_addr = value.parse().map_err(|_| {
                TorError::Config("GHOSTCHAT_TOR_CONTROL is not a socket address".to_owned())
            })?;
        }
        if let Some(value) = std::env::var_os("GHOSTCHAT_TOR_COOKIE") {
            config.cookie_path = Some(PathBuf::from(value));
        }
        config.validate()?;
        Ok(config)
    }

    /// Use Tor's default local endpoints but let `PROTOCOLINFO` select the
    /// cookie path.
    pub fn discover_cookie_path(mut self) -> Self {
        self.cookie_path = None;
        self
    }

    /// Set the SOCKS endpoint while retaining the rest of this configuration.
    pub fn with_socks_addr(mut self, address: SocketAddr) -> Self {
        self.socks_addr = address;
        self
    }

    /// Set the control endpoint while retaining the rest of this
    /// configuration.
    pub fn with_control_addr(mut self, address: SocketAddr) -> Self {
        self.control_addr = address;
        self
    }

    /// Override the cookie path used for COOKIE authentication.
    pub fn with_cookie_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cookie_path = Some(path.into());
        self
    }

    /// Set all socket timeouts.  Values are validated by
    /// [`TorDaemon::connect`] and [`TorStream::connect_with_config`].
    pub fn with_timeouts(
        mut self,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        self.connect_timeout = connect_timeout;
        self.read_timeout = read_timeout;
        self.write_timeout = write_timeout;
        self
    }

    fn validate(&self) -> TorResult<()> {
        if !self.socks_addr.ip().is_loopback() {
            return Err(TorError::Config(
                "Tor SOCKS endpoint must use a loopback address".to_owned(),
            ));
        }
        if !self.control_addr.ip().is_loopback() {
            return Err(TorError::Config(
                "Tor control endpoint must use a loopback address".to_owned(),
            ));
        }

        for (name, timeout) in [
            ("connect_timeout", self.connect_timeout),
            ("read_timeout", self.read_timeout),
            ("write_timeout", self.write_timeout),
        ] {
            if timeout.is_zero() || timeout > MAX_TIMEOUT {
                return Err(TorError::Config(format!(
                    "{name} must be greater than zero and no more than {} seconds",
                    MAX_TIMEOUT.as_secs()
                )));
            }
        }

        if self.max_control_line_bytes == 0 {
            return Err(TorError::Config(
                "max_control_line_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_control_data_bytes == 0 {
            return Err(TorError::Config(
                "max_control_data_bytes must be greater than zero".to_owned(),
            ));
        }
        if let Some(path) = &self.cookie_path {
            if path.as_os_str().is_empty() {
                return Err(TorError::Config("cookie_path must not be empty".to_owned()));
            }
        }
        Ok(())
    }
}

/// Tor control-port response separator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlSeparator {
    /// The response has another status line.
    More,
    /// The status line is followed by a dot-terminated data block.
    Data,
    /// The response is complete.
    End,
}

/// One parsed Tor control-port status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlLine {
    pub code: u16,
    pub separator: ControlSeparator,
    pub text: String,
    /// Data following a `+` status line, with Tor dot-stuffing removed.
    pub data: Option<Vec<u8>>,
}

/// A complete Tor control-port response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlReply {
    pub code: u16,
    pub lines: Vec<ControlLine>,
}

impl ControlReply {
    /// Whether the Tor status code is in the 2xx success class.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    fn control_error(&self, operation: &str) -> TorError {
        TorError::Control {
            code: self.code,
            message: format!("{operation} was rejected by Tor"),
        }
    }
}

/// Parse one complete CRLF-delimited Tor control response.
///
/// This parser is independent of a live Tor daemon and is public so callers
/// that need diagnostics can validate captured protocol fixtures without
/// exposing a control socket.
pub fn parse_control_reply(bytes: &[u8]) -> TorResult<ControlReply> {
    let mut cursor = Cursor::new(bytes);
    let reply = read_control_reply(
        &mut cursor,
        DEFAULT_CONTROL_LINE_LIMIT,
        DEFAULT_CONTROL_DATA_LIMIT,
    )?;
    if cursor.position() != bytes.len() as u64 {
        return Err(TorError::Protocol(
            "trailing bytes after control response".to_owned(),
        ));
    }
    Ok(reply)
}

/// An authenticated, serialized Tor control-port connection.
#[derive(Clone)]
pub struct TorDaemon {
    inner: Arc<TorDaemonInner>,
}

struct TorDaemonInner {
    control: Arc<ControlConnection>,
    config: TorConfig,
}

impl TorDaemon {
    /// Connect to the configured control port and authenticate with the Tor
    /// control cookie.
    pub fn connect(config: TorConfig) -> TorResult<Self> {
        config.validate()?;

        let stream = TcpStream::connect_timeout(&config.control_addr, config.connect_timeout)
            .map_err(map_control_connect_error)?;
        set_stream_timeouts(&stream, &config)?;

        let control = Arc::new(ControlConnection::new(stream, &config)?);

        let protocol_info = control.command("PROTOCOLINFO 1")?;
        if !protocol_info.is_success() {
            return Err(protocol_info.control_error("PROTOCOLINFO"));
        }
        let auth = parse_protocol_info(&protocol_info)?;

        if !auth.cookie && !auth.safecookie {
            return Err(TorError::Authentication(
                "Tor control port does not advertise COOKIE or SAFECOOKIE authentication"
                    .to_owned(),
            ));
        }

        let cookie_path = config
            .cookie_path
            .clone()
            .or(auth.cookie_file)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_COOKIE_PATH));
        let cookie = read_cookie(&cookie_path)?;

        if auth.safecookie {
            authenticate_safe_cookie(&control, &cookie[..])?;
        } else {
            let encoded = Zeroizing::new(hex_encode(&cookie[..]));
            let authenticate_command = Zeroizing::new(format!("AUTHENTICATE {}", encoded.as_str()));
            let authenticated = control.command(&authenticate_command)?;
            if !authenticated.is_success() {
                return Err(TorError::Authentication(
                    "Tor control port rejected the authentication cookie".to_owned(),
                ));
            }
        }

        Ok(Self {
            inner: Arc::new(TorDaemonInner { control, config }),
        })
    }

    /// Connect using the system Tor addresses and `/run/tor/control.authcookie`.
    pub fn connect_default() -> TorResult<Self> {
        Self::connect(TorConfig::default())
    }

    /// Return the immutable configuration used by this daemon connection.
    pub fn config(&self) -> &TorConfig {
        &self.inner.config
    }

    /// Interrupt and close the authenticated control connection without
    /// waiting for another control command to complete. Ephemeral onion
    /// services created through this connection are removed by Tor when the
    /// control connection closes.
    pub(crate) fn shutdown(&self) {
        self.inner.control.shutdown();
    }

    /// Return Tor's current bootstrap percentage from the authenticated
    /// control port.
    pub fn bootstrap_progress(&self) -> TorResult<u8> {
        let reply = self
            .inner
            .control
            .command("GETINFO status/bootstrap-phase")?;
        if !reply.is_success() {
            return Err(reply.control_error("GETINFO status/bootstrap-phase"));
        }

        let progress = reply.lines.iter().find_map(|line| {
            if !line.text.starts_with("status/bootstrap-phase=") {
                return None;
            }
            control_parameter(&line.text, "PROGRESS").ok().flatten()
        });
        let progress = progress
            .ok_or_else(|| TorError::Protocol("bootstrap response omitted PROGRESS".to_owned()))?;
        let value = progress
            .parse::<u16>()
            .map_err(|_| TorError::Protocol("bootstrap PROGRESS is not numeric".to_owned()))?;
        u8::try_from(value)
            .ok()
            .filter(|value| *value <= 100)
            .ok_or_else(|| TorError::Protocol("bootstrap PROGRESS is outside 0..=100".to_owned()))
    }

    fn add_onion(&self, local_addr: SocketAddr, virtual_port: u16) -> TorResult<String> {
        if virtual_port == 0 {
            return Err(TorError::Config(
                "onion virtual_port must be greater than zero".to_owned(),
            ));
        }

        let target = format_socket_addr(local_addr);
        let command =
            format!("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port={virtual_port},{target}");
        let reply = self.inner.control.command(&command)?;
        if !reply.is_success() {
            return Err(reply.control_error("ADD_ONION"));
        }

        let service_id = reply
            .lines
            .iter()
            .find_map(|line| line.text.strip_prefix("ServiceID="))
            .ok_or_else(|| TorError::Protocol("ADD_ONION response omitted ServiceID".to_owned()))?;
        validate_service_id(service_id)?;
        Ok(service_id.to_owned())
    }

    fn remove_onion(&self, service_id: &str) -> TorResult<()> {
        validate_service_id(service_id)?;
        let reply = self
            .inner
            .control
            .command(&format!("DEL_ONION {service_id}"))?;
        if !reply.is_success() {
            return Err(reply.control_error("DEL_ONION"));
        }
        Ok(())
    }
}

struct ControlConnection {
    stream: Mutex<TcpStream>,
    // A separate handle can interrupt a command that owns the stream mutex.
    interrupt: TcpStream,
    closed: AtomicBool,
    pending_onion_cleanups: AtomicUsize,
    read_timeout: Duration,
    write_timeout: Duration,
    max_line_bytes: usize,
    max_data_bytes: usize,
}

impl ControlConnection {
    fn new(stream: TcpStream, config: &TorConfig) -> TorResult<Self> {
        Ok(Self {
            interrupt: stream.try_clone().map_err(map_io_error)?,
            stream: Mutex::new(stream),
            closed: AtomicBool::new(false),
            pending_onion_cleanups: AtomicUsize::new(0),
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            max_line_bytes: config.max_control_line_bytes,
            max_data_bytes: config.max_control_data_bytes,
        })
    }

    fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.interrupt.shutdown(Shutdown::Both);
    }

    fn command(&self, command: &str) -> TorResult<ControlReply> {
        if command.is_empty() || command.contains(['\r', '\n']) {
            return Err(TorError::Config(
                "control command must be non-empty and contain no line breaks".to_owned(),
            ));
        }

        // Include serialization, writes, and all asynchronous events in one
        // deadline. Neither short reads nor an event flood reset the budget.
        let deadline = Instant::now() + self.read_timeout.max(self.write_timeout);
        let mut stream = loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(TorError::Unavailable);
            }
            let remaining = remaining_time(deadline).map_err(map_io_error)?;
            match self.stream.try_lock() {
                Ok(stream) => break stream,
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(remaining.min(Duration::from_millis(5)));
                }
                Err(TryLockError::Poisoned(_)) => {
                    self.shutdown();
                    return Err(TorError::Service(
                        "control connection lock poisoned".to_owned(),
                    ));
                }
            }
        };
        let mut stream = DeadlineIo {
            stream: &mut *stream,
            deadline,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
        };
        let result = self.command_inner(&mut stream, command);
        if result.is_err() {
            // A partial exchange cannot safely be reused by another command.
            self.shutdown();
        }
        result
    }

    fn command_inner<S: Read + Write>(
        &self,
        stream: &mut S,
        command: &str,
    ) -> TorResult<ControlReply> {
        stream.write_all(command.as_bytes()).map_err(map_io_error)?;
        stream.write_all(b"\r\n").map_err(map_io_error)?;
        stream.flush().map_err(map_io_error)?;
        let mut budget = ControlBudget::new();
        loop {
            let reply = read_control_reply_bounded(
                stream,
                self.max_line_bytes,
                self.max_data_bytes,
                &mut budget,
            )?;
            // Tor may interleave asynchronous 650 events with a command
            // response.  They are consumed without being exposed to callers.
            if reply.code == 650 {
                continue;
            }
            return Ok(reply);
        }
    }
}

/// Configuration for an ephemeral onion service.
#[derive(Clone, Debug)]
pub struct OnionServiceConfig {
    /// Local listener address.  Port zero asks the OS for an available port.
    pub bind_addr: SocketAddr,
    /// Virtual port exposed by the `.onion` address.
    pub virtual_port: u16,
}

impl Default for OnionServiceConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            virtual_port: 80,
        }
    }
}

/// An ephemeral `ADD_ONION` service backed by a local TCP listener.
pub struct TorOnionService {
    daemon: TorDaemon,
    service_id: String,
    onion_address: String,
    listener: TcpListener,
    closed: bool,
}

impl TorOnionService {
    /// Bind a local listener and register it with Tor using an ephemeral key.
    pub fn create(daemon: &TorDaemon, config: OnionServiceConfig) -> TorResult<Self> {
        if config.virtual_port == 0 {
            return Err(TorError::Config(
                "onion virtual_port must be greater than zero".to_owned(),
            ));
        }
        if !config.bind_addr.ip().is_loopback() {
            return Err(TorError::Config(
                "onion service bind address must use a loopback address".to_owned(),
            ));
        }

        let listener = TcpListener::bind(config.bind_addr).map_err(map_io_error)?;
        let local_addr = listener.local_addr().map_err(map_io_error)?;
        let service_id = daemon.add_onion(local_addr, config.virtual_port)?;
        let onion_address = format!("{service_id}.onion");

        Ok(Self {
            daemon: daemon.clone(),
            service_id,
            onion_address,
            listener,
            closed: false,
        })
    }

    /// The service ID returned by `ADD_ONION`, without the `.onion` suffix.
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// The routable onion hostname.
    pub fn onion_address(&self) -> &str {
        &self.onion_address
    }

    /// The local address to which Tor forwards incoming onion connections.
    pub fn local_addr(&self) -> TorResult<SocketAddr> {
        self.listener.local_addr().map_err(map_io_error)
    }

    /// Borrow the underlying blocking local listener.
    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Clone the listener for a dedicated accept thread while retaining this
    /// service object for lifecycle cleanup.
    pub fn try_clone_listener(&self) -> TorResult<TcpListener> {
        self.listener.try_clone().map_err(map_io_error)
    }

    /// Accept one incoming onion connection.
    pub fn accept(&self) -> TorResult<(TorStream, SocketAddr)> {
        if self.closed {
            return Err(TorError::Service(
                "onion service has already been cleaned up".to_owned(),
            ));
        }
        let (stream, peer_addr) = self.listener.accept().map_err(map_io_error)?;
        set_stream_timeouts(&stream, self.daemon.config())?;
        Ok((TorStream::from_incoming(stream), peer_addr))
    }

    /// Run a synchronous accept loop until the handler or an accept operation
    /// returns an error.  The caller can use [`Self::listener`] from another
    /// coordination path if it needs a different lifecycle strategy.
    pub fn accept_loop<F>(&self, mut handler: F) -> TorResult<()>
    where
        F: FnMut(TorStream, SocketAddr) -> TorResult<()>,
    {
        loop {
            let (stream, peer_addr) = self.accept()?;
            handler(stream, peer_addr)?;
        }
    }

    /// Remove this ephemeral service from Tor.  The operation is idempotent
    /// after a successful cleanup.
    pub fn cleanup(&mut self) -> TorResult<()> {
        if self.closed {
            return Ok(());
        }
        self.daemon.remove_onion(&self.service_id)?;
        self.closed = true;
        Ok(())
    }

    /// Stop the service and interrupt its control connection immediately.
    /// This is intended for transport shutdown paths where waiting for a
    /// potentially unresponsive control command would keep worker joins open.
    pub fn shutdown(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.daemon.shutdown();
    }
}

impl Drop for TorOnionService {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        // Drop must not wait for DEL_ONION. Limit cleanup workers even if
        // services are dropped faster than a busy control connection drains.
        let control = Arc::clone(&self.daemon.inner.control);
        if control
            .pending_onion_cleanups
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_ONION_CLEANUP_WORKERS).then_some(count + 1)
            })
            .is_err()
        {
            self.shutdown();
            return;
        }
        let slot = OnionCleanupSlot(control);
        let daemon = self.daemon.clone();
        let service_id = self.service_id.clone();
        if std::thread::Builder::new()
            .name("ghostchat-tor-onion-cleanup".to_owned())
            .spawn(move || {
                let _slot = slot;
                if daemon.remove_onion(&service_id).is_err() {
                    daemon.shutdown();
                }
            })
            .is_err()
        {
            self.daemon.shutdown();
        }
    }
}

struct OnionCleanupSlot(Arc<ControlConnection>);

impl Drop for OnionCleanupSlot {
    fn drop(&mut self) {
        self.0.pending_onion_cleanups.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A blocking byte stream established through Tor's SOCKS5 proxy, or an
/// accepted stream from a local onion-service listener.
#[derive(Debug)]
pub struct TorStream {
    inner: TcpStream,
    onion_host: Option<String>,
    onion_port: Option<u16>,
}

impl TorStream {
    /// Connect to an onion hostname through the daemon's SOCKS5 listener.
    pub fn connect(daemon: &TorDaemon, onion_host: &str, onion_port: u16) -> TorResult<Self> {
        Self::connect_with_config(daemon.config(), onion_host, onion_port)
    }

    /// Connect through a configured SOCKS5 listener without requiring a
    /// control-port connection.  This still performs only a SOCKS5 onion
    /// connection and never falls back to direct TCP.
    pub fn connect_with_config(
        config: &TorConfig,
        onion_host: &str,
        onion_port: u16,
    ) -> TorResult<Self> {
        config.validate()?;
        let stream = socks5_connect(config, onion_host, onion_port)?;
        Ok(Self {
            inner: stream,
            onion_host: Some(onion_host.to_owned()),
            onion_port: Some(onion_port),
        })
    }

    pub(crate) fn from_incoming(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            onion_host: None,
            onion_port: None,
        }
    }

    /// The requested onion hostname for an outbound stream, if known.
    pub fn onion_host(&self) -> Option<&str> {
        self.onion_host.as_deref()
    }

    /// The requested onion port for an outbound stream, if known.
    pub fn onion_port(&self) -> Option<u16> {
        self.onion_port
    }

    /// Clone the underlying stream for a separate reader or writer half.
    pub fn try_clone(&self) -> TorResult<Self> {
        Ok(Self {
            inner: self.inner.try_clone().map_err(map_io_error)?,
            onion_host: self.onion_host.clone(),
            onion_port: self.onion_port,
        })
    }

    /// Set the read timeout on the underlying stream.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> TorResult<()> {
        self.inner.set_read_timeout(timeout).map_err(map_io_error)
    }

    /// Set the write timeout on the underlying stream.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> TorResult<()> {
        self.inner.set_write_timeout(timeout).map_err(map_io_error)
    }

    /// Close both directions of the underlying stream so reader tasks wake
    /// promptly during room shutdown.
    pub fn shutdown(&self) -> TorResult<()> {
        self.inner.shutdown(Shutdown::Both).map_err(map_io_error)
    }
}

impl Read for TorStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Write for TorStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.inner.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl TimeoutStream for TorStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
}

fn remaining_time(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Tor operation deadline exceeded",
        ))
    } else {
        Ok(remaining)
    }
}

/// Shrink the native timeout on every short operation; `read_exact` and
/// `write_all` must never restart an operation's wall-clock budget.
struct DeadlineIo<'a, S> {
    stream: &'a mut S,
    deadline: Instant,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl<S: Read + TimeoutStream> Read for DeadlineIo<'_, S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = remaining_time(self.deadline)?;
        self.stream
            .set_read_timeout(Some(remaining.min(self.read_timeout)))?;
        let read = self.stream.read(buffer)?;
        remaining_time(self.deadline)?;
        Ok(read)
    }
}

impl<S: Write + TimeoutStream> Write for DeadlineIo<'_, S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = remaining_time(self.deadline)?;
        self.stream
            .set_write_timeout(Some(remaining.min(self.write_timeout)))?;
        let written = self.stream.write(buffer)?;
        remaining_time(self.deadline)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let remaining = remaining_time(self.deadline)?;
        self.stream
            .set_write_timeout(Some(remaining.min(self.write_timeout)))?;
        self.stream.flush()?;
        remaining_time(self.deadline)?;
        Ok(())
    }
}

fn socks5_connect(config: &TorConfig, onion_host: &str, onion_port: u16) -> TorResult<TcpStream> {
    validate_onion_host(onion_host)?;
    if onion_port == 0 {
        return Err(TorError::Config(
            "onion port must be greater than zero".to_owned(),
        ));
    }

    let deadline = Instant::now()
        + config
            .connect_timeout
            .max(config.read_timeout)
            .max(config.write_timeout);
    let mut stream = TcpStream::connect_timeout(&config.socks_addr, config.connect_timeout)
        .map_err(map_socks_connect_error)?;
    let mut handshake = DeadlineIo {
        stream: &mut stream,
        deadline,
        read_timeout: config.read_timeout,
        write_timeout: config.write_timeout,
    };

    // SOCKS5 greeting: version 5, one method, NO AUTHENTICATION REQUIRED.
    handshake
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(map_socks_io_error)?;
    let mut greeting_reply = [0_u8; 2];
    read_exact(&mut handshake, &mut greeting_reply, "SOCKS5 greeting")?;
    if greeting_reply[0] != 0x05 {
        return Err(TorError::Protocol(
            "SOCKS5 proxy returned an invalid version".to_owned(),
        ));
    }
    if greeting_reply[1] != 0x00 {
        return Err(TorError::Connect(
            "SOCKS5 proxy does not allow no-authentication mode".to_owned(),
        ));
    }

    let host_bytes = onion_host.as_bytes();
    let host_len = u8::try_from(host_bytes.len())
        .map_err(|_| TorError::Config("onion hostname is too long for SOCKS5".to_owned()))?;
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_len]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&onion_port.to_be_bytes());
    handshake.write_all(&request).map_err(map_socks_io_error)?;

    let mut response_head = [0_u8; 4];
    read_exact(
        &mut handshake,
        &mut response_head,
        "SOCKS5 connect response",
    )?;
    if response_head[0] != 0x05 {
        return Err(TorError::Protocol(
            "SOCKS5 proxy returned an invalid response version".to_owned(),
        ));
    }
    if response_head[2] != 0x00 {
        return Err(TorError::Protocol(
            "SOCKS5 proxy returned a nonzero reserved byte".to_owned(),
        ));
    }
    consume_socks_bound_address(&mut handshake, response_head[3])?;
    let reply_code = response_head[1];
    if reply_code != 0x00 {
        return Err(TorError::Connect(format!(
            "SOCKS5 proxy rejected the onion request (reply code 0x{reply_code:02x})"
        )));
    }

    // Handshake deadlines must not leak a nearly-expired native timeout into
    // the established byte stream.
    set_stream_timeouts(&stream, config)?;
    Ok(stream)
}

fn consume_socks_bound_address(stream: &mut impl Read, address_type: u8) -> TorResult<()> {
    match address_type {
        0x01 => {
            let mut address = [0_u8; 4];
            read_exact(stream, &mut address, "SOCKS5 IPv4 bound address")?;
        }
        0x03 => {
            let mut length = [0_u8; 1];
            read_exact(stream, &mut length, "SOCKS5 domain bound address length")?;
            if length[0] == 0 {
                return Err(TorError::Protocol(
                    "SOCKS5 bound domain is empty".to_owned(),
                ));
            }
            let mut address = [0_u8; 255];
            read_exact(
                stream,
                &mut address[..usize::from(length[0])],
                "SOCKS5 domain bound address",
            )?;
        }
        0x04 => {
            let mut address = [0_u8; 16];
            read_exact(stream, &mut address, "SOCKS5 IPv6 bound address")?;
        }
        _ => {
            return Err(TorError::Protocol(
                "SOCKS5 proxy returned an unknown address type".to_owned(),
            ));
        }
    }

    let mut port = [0_u8; 2];
    read_exact(stream, &mut port, "SOCKS5 bound port")
}

pub(crate) fn validate_onion_host(host: &str) -> TorResult<()> {
    if host.len() != V3_ONION_ID_LENGTH + ".onion".len()
        || !host.is_ascii()
        || !host.ends_with(".onion")
    {
        return Err(TorError::Config(
            "onion hostname must be a v3 .onion address".to_owned(),
        ));
    }
    if !valid_v3_identifier(&host[..V3_ONION_ID_LENGTH]) {
        return Err(TorError::Config(
            "onion hostname has an invalid v3 identifier".to_owned(),
        ));
    }
    Ok(())
}

fn validate_service_id(service_id: &str) -> TorResult<()> {
    if !valid_v3_identifier(service_id) {
        return Err(TorError::Protocol(
            "Tor returned an invalid onion service identifier".to_owned(),
        ));
    }
    Ok(())
}

fn valid_v3_identifier(label: &str) -> bool {
    if label.len() != V3_ONION_ID_LENGTH {
        return false;
    }
    // A v3 label is exactly 35 bytes: public key (32), checksum (2), version (1).
    let mut decoded = [0_u8; 35];
    let mut accumulator = 0_u16;
    let mut bits = 0;
    let mut offset = 0;
    for byte in label.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return false,
        };
        accumulator = (accumulator << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded[offset] = (accumulator >> bits) as u8;
            offset += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    if decoded[34] != 3 {
        return false;
    }
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(&decoded[..32]);
    hash.update([decoded[34]]);
    decoded[32..34] == hash.finalize()[..2]
}

#[cfg(test)]
pub(crate) fn test_onion_host() -> String {
    test_onion_with_version(3)
}

#[cfg(test)]
fn test_onion_with_version(version: u8) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0x42_u8; 35];
    bytes[34] = version;
    let mut hash = Sha3_256::new();
    hash.update(b".onion checksum");
    hash.update(&bytes[..32]);
    hash.update([version]);
    bytes[32..34].copy_from_slice(&hash.finalize()[..2]);
    let mut host = String::with_capacity(62);
    let mut accumulator = 0_u16;
    let mut bits = 0;
    for byte in bytes {
        accumulator = (accumulator << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            host.push(ALPHABET[usize::from((accumulator >> bits) & 31)] as char);
        }
        accumulator &= (1 << bits) - 1;
    }
    host.push_str(".onion");
    host
}

fn format_socket_addr(address: SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => address.to_string(),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

fn set_stream_timeouts(stream: &TcpStream, config: &TorConfig) -> TorResult<()> {
    stream
        .set_read_timeout(Some(config.read_timeout))
        .map_err(map_io_error)?;
    stream
        .set_write_timeout(Some(config.write_timeout))
        .map_err(map_io_error)?;
    Ok(())
}

fn read_exact(stream: &mut impl Read, buffer: &mut [u8], context: &str) -> TorResult<()> {
    stream
        .read_exact(buffer)
        .map_err(|error| match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TorError::Timeout,
            _ => TorError::Connect(context.to_owned()),
        })
}

fn map_io_error(error: io::Error) -> TorError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TorError::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotFound => TorError::Unavailable,
        _ => TorError::Io(error),
    }
}

fn map_control_connect_error(error: io::Error) -> TorError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TorError::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotFound => TorError::Unavailable,
        _ => TorError::Io(error),
    }
}

fn map_socks_connect_error(error: io::Error) -> TorError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TorError::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotFound => TorError::Unavailable,
        _ => TorError::Connect("could not connect to the Tor SOCKS listener".to_owned()),
    }
}

fn map_socks_io_error(error: io::Error) -> TorError {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => TorError::Timeout,
        _ => TorError::Connect("communication with the Tor SOCKS listener failed".to_owned()),
    }
}

struct ControlBudget {
    lines: usize,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
}

impl ControlBudget {
    fn new() -> Self {
        Self {
            lines: 0,
            bytes: 0,
            max_lines: MAX_CONTROL_REPLY_LINES,
            max_bytes: MAX_CONTROL_REPLY_BYTES,
        }
    }

    fn start_line(&mut self) -> TorResult<()> {
        if self.lines >= self.max_lines {
            return Err(TorError::Protocol(
                "control response has too many lines".to_owned(),
            ));
        }
        self.lines += 1;
        Ok(())
    }

    fn read_byte<R: Read>(&mut self, reader: &mut R) -> TorResult<u8> {
        // Check before reading or allocating even if max_line_bytes is set
        // higher than the aggregate cap. Include CRLF and dot terminators.
        if self.bytes >= self.max_bytes {
            return Err(TorError::Protocol(
                "control response exceeds aggregate limit".to_owned(),
            ));
        }
        let byte = read_one_byte(reader)?;
        self.bytes = self
            .bytes
            .checked_add(1)
            .ok_or_else(|| TorError::Protocol("control response is too large".to_owned()))?;
        Ok(byte)
    }
}

fn read_control_reply<R: Read>(
    reader: &mut R,
    max_line_bytes: usize,
    max_data_bytes: usize,
) -> TorResult<ControlReply> {
    let mut budget = ControlBudget::new();
    read_control_reply_bounded(reader, max_line_bytes, max_data_bytes, &mut budget)
}

fn read_control_reply_bounded<R: Read>(
    reader: &mut R,
    max_line_bytes: usize,
    max_data_bytes: usize,
    budget: &mut ControlBudget,
) -> TorResult<ControlReply> {
    let mut lines = Vec::new();
    let mut response_code = None;

    loop {
        let raw_line = read_crlf_line_bounded(reader, max_line_bytes, budget)?;
        let (code, separator, text) = parse_status_line(&raw_line)?;
        if let Some(expected_code) = response_code {
            if code != expected_code {
                return Err(TorError::Protocol(
                    "control response changed status code mid-response".to_owned(),
                ));
            }
        } else {
            response_code = Some(code);
        }

        let data = if separator == ControlSeparator::Data {
            Some(read_dot_block_bounded(
                reader,
                max_line_bytes,
                max_data_bytes,
                budget,
            )?)
        } else {
            None
        };
        let is_end = separator == ControlSeparator::End;
        lines.push(ControlLine {
            code,
            separator,
            text,
            data,
        });
        if is_end {
            return Ok(ControlReply {
                code: response_code.expect("response code set before line insertion"),
                lines,
            });
        }
    }
}

#[cfg(test)]
fn read_crlf_line<R: Read>(reader: &mut R, max_line_bytes: usize) -> TorResult<Vec<u8>> {
    let mut budget = ControlBudget {
        lines: 0,
        bytes: 0,
        max_lines: usize::MAX,
        max_bytes: usize::MAX,
    };
    read_crlf_line_bounded(reader, max_line_bytes, &mut budget)
}

fn read_crlf_line_bounded<R: Read>(
    reader: &mut R,
    max_line_bytes: usize,
    budget: &mut ControlBudget,
) -> TorResult<Vec<u8>> {
    budget.start_line()?;
    let mut line = Vec::new();
    loop {
        let byte = budget.read_byte(reader)?;
        match byte {
            b'\r' => {
                let next = budget.read_byte(reader)?;
                if next != b'\n' {
                    return Err(TorError::Protocol(
                        "control response line is not CRLF terminated".to_owned(),
                    ));
                }
                return Ok(line);
            }
            b'\n' => {
                return Err(TorError::Protocol(
                    "control response contains a bare LF".to_owned(),
                ));
            }
            _ => {
                if line.len() >= max_line_bytes {
                    return Err(TorError::Protocol(
                        "control response line exceeds configured limit".to_owned(),
                    ));
                }
                line.push(byte);
            }
        }
    }
}

fn read_one_byte<R: Read>(reader: &mut R) -> TorResult<u8> {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err(TorError::Protocol(
                    "unexpected end of control response".to_owned(),
                ))
            }
            Ok(_) => return Ok(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(map_io_error(error)),
        }
    }
}

fn parse_status_line(line: &[u8]) -> TorResult<(u16, ControlSeparator, String)> {
    if line.len() < 4 || !line[..3].iter().all(u8::is_ascii_digit) {
        return Err(TorError::Protocol(
            "control response line has no three-digit status code".to_owned(),
        ));
    }
    let code = u16::from(line[0] - b'0') * 100
        + u16::from(line[1] - b'0') * 10
        + u16::from(line[2] - b'0');
    let separator = match line[3] {
        b'-' => ControlSeparator::More,
        b'+' => ControlSeparator::Data,
        b' ' => ControlSeparator::End,
        _ => {
            return Err(TorError::Protocol(
                "control response line has an invalid separator".to_owned(),
            ));
        }
    };
    let text = String::from_utf8(line[4..].to_vec())
        .map_err(|_| TorError::Protocol("control response line is not valid UTF-8".to_owned()))?;
    Ok((code, separator, text))
}

fn read_dot_block_bounded<R: Read>(
    reader: &mut R,
    max_line_bytes: usize,
    max_data_bytes: usize,
    budget: &mut ControlBudget,
) -> TorResult<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let line = read_crlf_line_bounded(reader, max_line_bytes, budget)?;
        if line == b"." {
            return Ok(data);
        }
        let line = if line.starts_with(b"..") {
            &line[1..]
        } else {
            line.as_slice()
        };
        let required = line
            .len()
            .checked_add(2)
            .and_then(|length| data.len().checked_add(length))
            .ok_or_else(|| TorError::Protocol("control data block is too large".to_owned()))?;
        if required > max_data_bytes {
            return Err(TorError::Protocol(
                "control data block exceeds configured limit".to_owned(),
            ));
        }
        data.extend_from_slice(line);
        data.extend_from_slice(b"\r\n");
    }
}

#[derive(Default)]
struct ProtocolInfo {
    cookie: bool,
    safecookie: bool,
    cookie_file: Option<PathBuf>,
}

fn parse_protocol_info(reply: &ControlReply) -> TorResult<ProtocolInfo> {
    let mut info = ProtocolInfo::default();
    for line in &reply.lines {
        if !line.text.starts_with("AUTH ") {
            continue;
        }
        if let Some(methods) = control_parameter(&line.text[5..], "METHODS")? {
            for method in methods.split(',') {
                match method.trim().to_ascii_uppercase().as_str() {
                    "COOKIE" => info.cookie = true,
                    "SAFECOOKIE" => info.safecookie = true,
                    _ => {}
                }
            }
        }
        if let Some(path) = control_parameter(&line.text[5..], "COOKIEFILE")? {
            if path.as_bytes().contains(&0) {
                return Err(TorError::Protocol(
                    "PROTOCOLINFO returned a cookie path containing NUL".to_owned(),
                ));
            }
            info.cookie_file = Some(PathBuf::from(path));
        }
    }
    Ok(info)
}

fn authenticate_safe_cookie(control: &ControlConnection, cookie: &[u8]) -> TorResult<()> {
    let client_nonce = Zeroizing::new(random::<[u8; 32]>());
    let encoded_nonce = Zeroizing::new(hex_encode(&client_nonce[..]));
    let challenge_command = Zeroizing::new(format!(
        "AUTHCHALLENGE SAFECOOKIE {}",
        encoded_nonce.as_str()
    ));
    let challenge = control.command(&challenge_command)?;
    if !challenge.is_success() {
        return Err(challenge.control_error("AUTHCHALLENGE"));
    }
    let line = challenge
        .lines
        .iter()
        .find(|line| line.text.contains("SERVERHASH=") && line.text.contains("SERVERNONCE="))
        .ok_or_else(|| {
            TorError::Authentication("Tor SAFECOOKIE challenge omitted its nonce".to_owned())
        })?;
    let server_hash = control_parameter(&line.text, "SERVERHASH")?
        .ok_or_else(|| TorError::Authentication("Tor SAFECOOKIE server hash is missing".to_owned()))
        .and_then(|value| decode_hex(&value, "SAFECOOKIE server hash"))?;
    let server_nonce = control_parameter(&line.text, "SERVERNONCE")?
        .ok_or_else(|| {
            TorError::Authentication("Tor SAFECOOKIE server nonce is missing".to_owned())
        })
        .and_then(|value| decode_hex(&value, "SAFECOOKIE server nonce"))?;
    if server_hash.len() != 32 || server_nonce.len() != 32 {
        return Err(TorError::Authentication(
            "Tor SAFECOOKIE challenge has invalid lengths".to_owned(),
        ));
    }

    let mut challenge_input = Zeroizing::new(Vec::with_capacity(cookie.len() + 64));
    challenge_input.extend_from_slice(cookie);
    challenge_input.extend_from_slice(&client_nonce[..]);
    challenge_input.extend_from_slice(&server_nonce);

    verify_safe_cookie_hmac(
        b"Tor safe cookie authentication server-to-controller hash",
        &challenge_input,
        &server_hash,
    )?;
    let client_hash = safe_cookie_hmac(
        b"Tor safe cookie authentication controller-to-server hash",
        &challenge_input,
    )?;
    let encoded_hash = Zeroizing::new(hex_encode(&client_hash));
    let authenticate_command = Zeroizing::new(format!("AUTHENTICATE {}", encoded_hash.as_str()));
    let authenticated = control.command(&authenticate_command)?;
    if !authenticated.is_success() {
        return Err(TorError::Authentication(
            "Tor control port rejected SAFECOOKIE authentication".to_owned(),
        ));
    }
    Ok(())
}

fn safe_cookie_hmac(key: &[u8], message: &[u8]) -> TorResult<Zeroizing<Vec<u8>>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| TorError::Authentication("invalid SAFECOOKIE hash key".to_owned()))?;
    mac.update(message);
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

fn verify_safe_cookie_hmac(key: &[u8], message: &[u8], expected: &[u8]) -> TorResult<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| TorError::Authentication("invalid SAFECOOKIE hash key".to_owned()))?;
    mac.update(message);
    mac.verify_slice(expected).map_err(|_| {
        TorError::Authentication("Tor SAFECOOKIE server proof did not verify".to_owned())
    })
}

fn decode_hex(value: &str, context: &str) -> TorResult<Zeroizing<Vec<u8>>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(TorError::Authentication(format!(
            "{context} is not valid hexadecimal"
        )));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            TorError::Authentication(format!("{context} is not valid hexadecimal"))
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            TorError::Authentication(format!("{context} is not valid hexadecimal"))
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn read_cookie(path: &Path) -> TorResult<Zeroizing<[u8; TOR_COOKIE_LENGTH]>> {
    // Reject special files before opening them, then recheck the open handle
    // so oversized or changed regular files never turn into an unbounded read.
    let metadata = fs::metadata(path)
        .map_err(|_| TorError::Authentication("Tor control cookie could not be read".to_owned()))?;
    if !metadata.is_file() || metadata.len() != TOR_COOKIE_LENGTH as u64 {
        return Err(TorError::Authentication(
            "Tor control cookie has an invalid length or type".to_owned(),
        ));
    }
    let mut file = fs::File::open(path)
        .map_err(|_| TorError::Authentication("Tor control cookie could not be read".to_owned()))?;
    let metadata = file
        .metadata()
        .map_err(|_| TorError::Authentication("Tor control cookie could not be read".to_owned()))?;
    if !metadata.is_file() || metadata.len() != TOR_COOKIE_LENGTH as u64 {
        return Err(TorError::Authentication(
            "Tor control cookie has an invalid length or type".to_owned(),
        ));
    }
    let mut cookie = Zeroizing::new([0_u8; TOR_COOKIE_LENGTH]);
    file.read_exact(cookie.as_mut_slice()).map_err(|_| {
        TorError::Authentication("Tor control cookie has an invalid length".to_owned())
    })?;
    let mut extra = Zeroizing::new([0_u8; 1]);
    let extra_len = file
        .read(extra.as_mut_slice())
        .map_err(|_| TorError::Authentication("Tor control cookie could not be read".to_owned()))?;
    if extra_len != 0 {
        return Err(TorError::Authentication(
            "Tor control cookie has an invalid length".to_owned(),
        ));
    }
    Ok(cookie)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn control_parameter(text: &str, key: &str) -> TorResult<Option<String>> {
    let key_bytes = key.as_bytes();
    let mut offset = 0;
    while let Some(relative) = text[offset..].find(key) {
        let start = offset + relative;
        let boundary_before = start == 0 || text.as_bytes()[start - 1].is_ascii_whitespace();
        let equals = start + key_bytes.len();
        let boundary_after = text.as_bytes().get(equals) == Some(&b'=');
        if !boundary_before || !boundary_after {
            offset = equals.min(text.len());
            continue;
        }

        let value_start = equals + 1;
        if text.as_bytes().get(value_start) == Some(&b'"') {
            let mut value = String::new();
            let mut escaped = false;
            for (index, character) in text[value_start + 1..].char_indices() {
                if escaped {
                    value.push(character);
                    escaped = false;
                    continue;
                }
                if character == '\\' {
                    escaped = true;
                    continue;
                }
                if character == '"' {
                    return Ok(Some(value));
                }
                value.push(character);
                if index > 4096 {
                    return Err(TorError::Protocol(
                        "quoted control parameter exceeds configured limit".to_owned(),
                    ));
                }
            }
            return Err(TorError::Protocol(
                "unterminated quoted control parameter".to_owned(),
            ));
        }

        let end = text[value_start..]
            .find(char::is_whitespace)
            .map(|relative_end| value_start + relative_end)
            .unwrap_or(text.len());
        return Ok(Some(text[value_start..end].to_owned()));
    }
    Ok(None)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn control_pair(timeout: Duration) -> (TorDaemon, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let config = TorConfig::default()
            .with_control_addr(listener.local_addr().unwrap())
            .with_timeouts(timeout, timeout, timeout);
        let stream = TcpStream::connect(config.control_addr).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let control = Arc::new(ControlConnection::new(stream, &config).unwrap());
        (
            TorDaemon {
                inner: Arc::new(TorDaemonInner { control, config }),
            },
            peer,
        )
    }

    #[test]
    fn parses_crlf_multiline_control_response() {
        let response = b"250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/run/tor/control.authcookie\"\r\n250 OK\r\n";
        let parsed = parse_control_reply(response).unwrap();

        assert_eq!(parsed.code, 250);
        assert_eq!(parsed.lines.len(), 3);
        assert_eq!(parsed.lines[0].separator, ControlSeparator::More);
        assert_eq!(parsed.lines[2].separator, ControlSeparator::End);
        let info = parse_protocol_info(&parsed).unwrap();
        assert!(info.cookie);
        assert!(info.safecookie);
        assert_eq!(
            info.cookie_file,
            Some(PathBuf::from("/run/tor/control.authcookie"))
        );
    }

    #[test]
    fn parses_and_unstuffs_dot_terminated_control_data() {
        let response = b"250+DATA=\r\nfirst\r\n..starts-with-dot\r\n.\r\n250 OK\r\n";
        let parsed = parse_control_reply(response).unwrap();

        assert_eq!(parsed.lines.len(), 2);
        assert_eq!(
            parsed.lines[0].data,
            Some(b"first\r\n.starts-with-dot\r\n".to_vec())
        );
    }

    #[test]
    fn rejects_non_crlf_control_framing() {
        let error = parse_control_reply(b"250 OK\n").unwrap_err();
        assert!(matches!(error, TorError::Protocol(_)));
    }

    #[test]
    fn socks5_uses_domain_request_and_no_authentication() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let host = test_onion_host();
        let expected_host = host.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).unwrap();

            let mut request_head = [0_u8; 5];
            stream.read_exact(&mut request_head).unwrap();
            assert_eq!(request_head[..4], [0x05, 0x01, 0x00, 0x03]);
            let host_length = usize::from(request_head[4]);
            let mut host = vec![0_u8; host_length];
            stream.read_exact(&mut host).unwrap();
            assert_eq!(host, expected_host.as_bytes());
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34])
                .unwrap();
        });

        let config = TorConfig::default().with_socks_addr(address).with_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        );
        let stream = TorStream::connect_with_config(&config, &host, 443).unwrap();
        assert_eq!(stream.onion_port(), Some(443));
        server.join().unwrap();
    }

    #[test]
    fn socks5_rejects_non_onion_hosts_without_connecting() {
        let config = TorConfig::default();
        let error = TorStream::connect_with_config(&config, "example.com", 443).unwrap_err();
        assert!(matches!(error, TorError::Config(_)));
    }

    fn spawn_socks_server(response: Vec<u8>) -> (SocketAddr, thread::JoinHandle<()>) {
        spawn_socks_with_greeting([0x05, 0x00], response)
    }

    fn spawn_socks_with_greeting(
        greeting_reply: [u8; 2],
        response: Vec<u8>,
    ) -> (SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut greeting = [0_u8; 3];
            if stream.read_exact(&mut greeting).is_err() {
                return;
            }
            if stream.write_all(&greeting_reply).is_err() || greeting_reply != [0x05, 0x00] {
                return;
            }
            let mut request_head = [0_u8; 5];
            if stream.read_exact(&mut request_head).is_err() {
                return;
            }
            let mut host = vec![0_u8; usize::from(request_head[4])];
            if stream.read_exact(&mut host).is_err() {
                return;
            }
            let mut port = [0_u8; 2];
            if stream.read_exact(&mut port).is_err() {
                return;
            }
            let _ = stream.write_all(&response);
        });
        (address, server)
    }

    fn socks_config(address: SocketAddr, timeout: Duration) -> TorConfig {
        TorConfig::default()
            .with_socks_addr(address)
            .with_timeouts(timeout, timeout, timeout)
    }

    #[test]
    fn socks5_rejects_bad_greeting_version_and_authentication_methods() {
        for (greeting, bad_version) in [([4, 0], true), ([5, 0xff], false), ([5, 2], false)] {
            let (address, server) = spawn_socks_with_greeting(greeting, Vec::new());
            let error = TorStream::connect_with_config(
                &socks_config(address, Duration::from_millis(500)),
                &test_onion_host(),
                443,
            )
            .unwrap_err();
            assert!(matches!(error, TorError::Protocol(_)) == bad_version);
            assert!(matches!(error, TorError::Connect(_)) != bad_version);
            server.join().unwrap();
        }
    }

    #[test]
    fn socks5_consumes_all_supported_bound_addresses_and_restores_timeouts() {
        for (address_type, bound) in [
            (1, vec![127, 0, 0, 1]),
            (3, vec![3, b't', b'o', b'r']),
            (4, vec![0_u8; 16]),
        ] {
            let mut reply = vec![5, 0, 0, address_type];
            reply.extend_from_slice(&bound);
            reply.extend_from_slice(&[0, 80, 0xff, 0, 7]);
            let (address, server) = spawn_socks_server(reply);
            let config = socks_config(address, Duration::from_millis(500));
            let mut stream =
                TorStream::connect_with_config(&config, &test_onion_host(), 443).unwrap();
            assert_eq!(
                stream.inner.read_timeout().unwrap(),
                Some(config.read_timeout)
            );
            assert_eq!(
                stream.inner.write_timeout().unwrap(),
                Some(config.write_timeout)
            );
            let mut bytes = [0_u8; 3];
            stream.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, [0xff, 0, 7]);
            server.join().unwrap();
        }
    }

    #[test]
    fn socks5_rejects_empty_bound_domain_and_truncated_responses() {
        let (address, server) = spawn_socks_server(vec![5, 0, 0, 3, 0]);
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(500)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Protocol(_)));
        server.join().unwrap();
        for response in [
            vec![5, 0],
            vec![5, 0, 0, 1, 127, 0],
            vec![5, 0, 0, 1, 127, 0, 0, 1, 0],
        ] {
            let (address, server) = spawn_socks_server(response);
            let error = TorStream::connect_with_config(
                &socks_config(address, Duration::from_millis(500)),
                &test_onion_host(),
                443,
            )
            .unwrap_err();
            assert!(matches!(error, TorError::Connect(_)));
            server.join().unwrap();
        }
    }

    #[test]
    fn socks5_rejects_nonzero_reserved_response_byte() {
        let (address, server) =
            spawn_socks_server(vec![0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 80]);
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(250)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Protocol(_)));
        server.join().unwrap();
    }

    #[test]
    fn socks5_rejects_invalid_response_version() {
        let (address, server) =
            spawn_socks_server(vec![0x04, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(250)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Protocol(_)));
        server.join().unwrap();
    }

    #[test]
    fn socks5_rejects_unknown_bound_address_type() {
        let (address, server) = spawn_socks_server(vec![0x05, 0x00, 0x00, 0x02]);
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(250)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Protocol(_)));
        server.join().unwrap();
    }

    #[test]
    fn socks5_reports_proxy_rejection_after_consuming_bound_address() {
        let (address, server) =
            spawn_socks_server(vec![0x05, 0x05, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(250)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Connect(_)));
        server.join().unwrap();
    }

    #[test]
    fn socks5_handshake_has_one_total_deadline() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut greeting = [0_u8; 3];
            let _ = stream.read_exact(&mut greeting);
            thread::sleep(Duration::from_millis(250));
        });
        let started = Instant::now();
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(50)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Timeout));
        assert!(started.elapsed() < Duration::from_millis(200));
        server.join().unwrap();
    }

    #[test]
    fn socks5_dribbled_handshake_cannot_extend_the_total_deadline() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).unwrap();
            stream.write_all(&[5, 0]).unwrap();
            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).unwrap();
            let mut remaining = vec![0_u8; usize::from(request[4]) + 2];
            stream.read_exact(&mut remaining).unwrap();
            for byte in [5, 0, 0, 1, 127, 0, 0, 1, 0, 80] {
                thread::sleep(Duration::from_millis(25));
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
            }
        });
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(100)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Timeout));
        server.join().unwrap();
    }

    #[test]
    fn socks5_reports_unavailable_listener() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let error = TorStream::connect_with_config(
            &socks_config(address, Duration::from_millis(250)),
            &test_onion_host(),
            443,
        )
        .unwrap_err();
        assert!(matches!(error, TorError::Unavailable));
    }

    #[test]
    fn control_reports_unavailable_listener_and_rejects_zero_onion_port_without_connecting() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let config = TorConfig::default().with_control_addr(address);
        assert!(matches!(
            TorDaemon::connect(config),
            Err(TorError::Unavailable)
        ));
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let config = socks_config(listener.local_addr().unwrap(), Duration::from_millis(250));
        assert!(matches!(
            TorStream::connect_with_config(&config, &test_onion_host(), 0),
            Err(TorError::Config(_)),
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn rejects_non_loopback_tor_endpoints() {
        let config = TorConfig::default().with_socks_addr(SocketAddr::from(([10, 0, 0, 1], 9050)));
        assert!(matches!(config.validate(), Err(TorError::Config(_))));

        let config =
            TorConfig::default().with_control_addr(SocketAddr::from(([10, 0, 0, 1], 9051)));
        assert!(matches!(config.validate(), Err(TorError::Config(_))));
    }

    #[test]
    fn validates_exact_v3_onion_identifiers() {
        let valid = test_onion_host();
        // Checked independently with Python's base32 / hashlib.sha3_256.
        assert_eq!(
            valid,
            "ijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbeeqscijbezhid.onion"
        );
        assert!(validate_onion_host(&valid).is_ok());
        assert!(validate_service_id(&valid[..V3_ONION_ID_LENGTH]).is_ok());

        let wrong_length = format!("{}.onion", "a".repeat(V3_ONION_ID_LENGTH - 1));
        assert!(validate_onion_host(&wrong_length).is_err());
        let wrong_character = format!("a{}{}.onion", "a".repeat(V3_ONION_ID_LENGTH - 2), "0");
        assert!(validate_onion_host(&wrong_character).is_err());
        assert!(validate_service_id(&valid[..V3_ONION_ID_LENGTH - 1]).is_err());

        let mut wrong_checksum = valid.clone().into_bytes();
        wrong_checksum[0] = if wrong_checksum[0] == b'a' {
            b'b'
        } else {
            b'a'
        };
        assert!(validate_onion_host(std::str::from_utf8(&wrong_checksum).unwrap()).is_err());
        let wrong_version = test_onion_with_version(2);
        assert!(validate_onion_host(&wrong_version).is_err());
        assert!(validate_onion_host(&valid.to_ascii_uppercase()).is_err());
        let real_host = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
        assert!(validate_onion_host(real_host).is_ok());
        let mut invalid_real = real_host.as_bytes().to_vec();
        invalid_real[0] = b'a';
        assert!(validate_onion_host(std::str::from_utf8(&invalid_real).unwrap()).is_err());
    }

    #[test]
    fn control_parser_bounds_reply_line_count_and_aggregate_bytes() {
        let mut flood = Vec::new();
        for _ in 0..=MAX_CONTROL_REPLY_LINES {
            flood.extend_from_slice(b"650-event\r\n");
        }
        flood.extend_from_slice(b"250 OK\r\n");
        assert!(matches!(
            parse_control_reply(&flood),
            Err(TorError::Protocol(_))
        ));

        let mut aggregate = Vec::new();
        let line = vec![b'x'; 9_000];
        for _ in 0..1_000 {
            aggregate.extend_from_slice(b"650-");
            aggregate.extend_from_slice(&line);
            aggregate.extend_from_slice(b"\r\n");
        }
        assert!(matches!(
            parse_control_reply(&aggregate),
            Err(TorError::Protocol(_))
        ));
    }

    #[test]
    fn control_parser_aggregate_cap_applies_before_allocating_a_large_line() {
        let mut cursor = Cursor::new(vec![b'x'; 128]);
        let mut budget = ControlBudget::new();
        budget.max_bytes = 32;
        assert!(matches!(
            read_control_reply_bounded(&mut cursor, usize::MAX, usize::MAX, &mut budget),
            Err(TorError::Protocol(_))
        ));
        assert_eq!(cursor.position(), 32);
    }

    #[test]
    fn control_parser_rejects_malformed_status_data_and_trailing_bytes() {
        for response in [
            &b"25 OK\r\n"[..],
            &b"250?OK\r\n"[..],
            &b"250 OK\rX"[..],
            &b"250-x\r\n251 OK\r\n"[..],
            &b"250 \xff\r\n"[..],
            &b"250+DATA=\r\nx\r\n"[..],
            &b"250 OK\r\n250 OK\r\n"[..],
        ] {
            assert!(matches!(
                parse_control_reply(response),
                Err(TorError::Protocol(_))
            ));
        }
        let mut cursor = Cursor::new(b"250+DATA=\r\n1234\r\n.\r\n250 OK\r\n");
        assert!(matches!(
            read_control_reply(&mut cursor, 32, 5),
            Err(TorError::Protocol(_))
        ));
        let mut cursor = Cursor::new(b"250 a-long-line\r\n");
        assert!(matches!(
            read_control_reply(&mut cursor, 8, 32),
            Err(TorError::Protocol(_))
        ));
    }

    #[test]
    fn control_command_bounds_asynchronous_event_flood() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            if read_crlf_line(&mut stream, 1024).is_err() {
                return;
            }
            for _ in 0..=MAX_CONTROL_REPLY_LINES {
                if stream.write_all(b"650-event\r\n").is_err() {
                    break;
                }
            }
        });
        let config = TorConfig::default()
            .with_control_addr(address)
            .with_timeouts(
                Duration::from_millis(500),
                Duration::from_millis(500),
                Duration::from_millis(500),
            );
        let stream = TcpStream::connect(address).unwrap();
        let control = ControlConnection::new(stream, &config).unwrap();
        let error = control
            .command("GETINFO status/bootstrap-phase")
            .unwrap_err();
        assert!(matches!(error, TorError::Protocol(_)));
        server.join().unwrap();
    }

    #[test]
    fn control_command_deadline_covers_a_dribbled_reply() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            if read_crlf_line(&mut stream, 1024).is_err() {
                return;
            }
            for byte in b"650-dribbled-event-that-never-ends\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
        });
        let config = TorConfig::default()
            .with_control_addr(address)
            .with_timeouts(
                Duration::from_millis(80),
                Duration::from_millis(80),
                Duration::from_millis(80),
            );
        let stream = TcpStream::connect(address).unwrap();
        let control = ControlConnection::new(stream, &config).unwrap();
        let started = Instant::now();
        let error = control
            .command("GETINFO status/bootstrap-phase")
            .unwrap_err();
        assert!(matches!(error, TorError::Timeout));
        assert!(started.elapsed() < Duration::from_millis(300));
        server.join().unwrap();
    }

    #[test]
    fn control_shutdown_interrupts_a_command_holding_the_stream_lock() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            if read_crlf_line(&mut stream, 1024).is_err() {
                return;
            }
            let _ = ready_sender.send(());
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte);
        });
        let config = TorConfig::default()
            .with_control_addr(address)
            .with_timeouts(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            );
        let control = Arc::new(
            ControlConnection::new(TcpStream::connect(address).unwrap(), &config).unwrap(),
        );
        let command_control = Arc::clone(&control);
        let command =
            thread::spawn(move || command_control.command("GETINFO status/bootstrap-phase"));
        ready_receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        control.shutdown();
        let result = command.join().unwrap();
        assert!(matches!(
            result,
            Err(TorError::Protocol(_)
                | TorError::Unavailable
                | TorError::Io(_)
                | TorError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn control_command_serialization_wait_has_a_deadline() {
        let (daemon, _peer) = control_pair(Duration::from_millis(50));
        let _held_stream = daemon.inner.control.stream.lock().unwrap();
        let error = daemon
            .inner
            .control
            .command("GETINFO status/bootstrap-phase")
            .unwrap_err();
        assert!(matches!(error, TorError::Timeout));
    }

    #[test]
    fn safecookie_does_not_send_authentication_after_a_bad_server_proof() {
        const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
        let (daemon, mut peer) = control_pair(Duration::from_millis(500));
        let cookie = [0x5a_u8; 32];
        let server = thread::spawn(move || {
            let command = String::from_utf8(read_crlf_line(&mut peer, 1024).unwrap()).unwrap();
            let nonce = decode_hex(
                command.strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap(),
                "nonce",
            )
            .unwrap();
            let server_nonce = [0x42_u8; 32];
            let mut input = cookie.to_vec();
            input.extend_from_slice(&nonce);
            input.extend_from_slice(&server_nonce);
            let mut wrong_hash = safe_cookie_hmac(SERVER_KEY, &input).unwrap();
            wrong_hash[0] ^= 1;
            peer.write_all(
                format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    hex_encode(&wrong_hash),
                    hex_encode(&server_nonce),
                )
                .as_bytes(),
            )
            .unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(peer.read(&mut trailing).unwrap(), 0);
        });
        let error = authenticate_safe_cookie(&daemon.inner.control, &cookie).unwrap_err();
        assert!(matches!(error, TorError::Authentication(_)));
        daemon.shutdown();
        server.join().unwrap();
    }

    #[test]
    fn onion_service_requests_v3_discarded_key_and_drop_preserves_shared_daemon() {
        let (daemon, mut peer) = control_pair(Duration::from_millis(500));
        let service_id = test_onion_host()[..V3_ONION_ID_LENGTH].to_owned();
        let expected_id = service_id.clone();
        let (deleted_sender, deleted_receiver) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let command = String::from_utf8(read_crlf_line(&mut peer, 1024).unwrap()).unwrap();
            assert!(
                command.starts_with("ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:")
            );
            peer.write_all(format!("250-ServiceID={expected_id}\r\n250 OK\r\n").as_bytes())
                .unwrap();
            let command = String::from_utf8(read_crlf_line(&mut peer, 1024).unwrap()).unwrap();
            assert_eq!(command, format!("DEL_ONION {expected_id}"));
            peer.write_all(b"250 OK\r\n").unwrap();
            deleted_sender.send(()).unwrap();
            assert_eq!(
                read_crlf_line(&mut peer, 1024).unwrap(),
                b"GETINFO status/bootstrap-phase"
            );
            peer.write_all(
                b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100\r\n250 OK\r\n",
            )
            .unwrap();
        });
        let service = TorOnionService::create(&daemon, OnionServiceConfig::default()).unwrap();
        assert_eq!(service.service_id(), service_id);
        assert!(service.local_addr().unwrap().ip().is_loopback());
        drop(service);
        deleted_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert_eq!(daemon.bootstrap_progress().unwrap(), 100);
        server.join().unwrap();
    }

    #[test]
    fn onion_service_drop_returns_while_control_is_busy_and_cleanup_is_bounded() {
        let (daemon, mut peer) = control_pair(Duration::from_millis(500));
        let service_id = test_onion_host()[..V3_ONION_ID_LENGTH].to_owned();
        let service = TorOnionService {
            daemon: daemon.clone(),
            service_id: service_id.clone(),
            onion_address: test_onion_host(),
            listener: TcpListener::bind(("127.0.0.1", 0)).unwrap(),
            closed: false,
        };
        let server = thread::spawn(move || {
            assert_eq!(
                read_crlf_line(&mut peer, 1024).unwrap(),
                format!("DEL_ONION {service_id}").as_bytes()
            );
            peer.write_all(b"250 OK\r\n").unwrap();
        });
        let held_stream = daemon.inner.control.stream.lock().unwrap();
        let (dropped_sender, dropped_receiver) = std::sync::mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(service);
            let _ = dropped_sender.send(());
        });
        let dropped = dropped_receiver.recv_timeout(Duration::from_millis(200));
        drop(held_stream);
        dropper.join().unwrap();
        assert!(dropped.is_ok());
        server.join().unwrap();

        let (daemon, _peer) = control_pair(Duration::from_millis(500));
        // Exhausting the bounded cleanup slots disconnects the controller,
        // letting Tor remove all its ephemeral services without another worker.
        daemon
            .inner
            .control
            .pending_onion_cleanups
            .store(MAX_ONION_CLEANUP_WORKERS, Ordering::Release);
        drop(TorOnionService {
            daemon: daemon.clone(),
            service_id: test_onion_host()[..V3_ONION_ID_LENGTH].to_owned(),
            onion_address: test_onion_host(),
            listener: TcpListener::bind(("127.0.0.1", 0)).unwrap(),
            closed: false,
        });
        assert!(daemon.inner.control.closed.load(Ordering::Acquire));
    }

    #[test]
    fn safecookie_proof_uses_verification_and_rejects_wrong_proof() {
        let error = verify_safe_cookie_hmac(b"key", b"message", &[0_u8; 32]).unwrap_err();
        assert!(matches!(error, TorError::Authentication(_)));
    }

    #[test]
    fn cookie_reader_rejects_extra_bytes_without_unbounded_read() {
        let path = std::env::temp_dir().join(format!(
            "ghostchat-cookie-bound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, vec![0x5a_u8; TOR_COOKIE_LENGTH + 1]).unwrap();
        assert!(matches!(
            read_cookie(&path),
            Err(TorError::Authentication(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn authenticates_control_port_with_reported_cookie() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let cookie_path = std::env::temp_dir().join(format!(
            "ghostchat-tor-cookie-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cookie = [0x00_u8; TOR_COOKIE_LENGTH];
        std::fs::write(&cookie_path, cookie).unwrap();
        let cookie_path_text = cookie_path.to_str().unwrap().to_owned();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                read_crlf_line(&mut stream, 1024).unwrap(),
                b"PROTOCOLINFO 1"
            );
            let protocol_info = format!(
                "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"{cookie_path_text}\"\r\n250 OK\r\n"
            );
            stream.write_all(protocol_info.as_bytes()).unwrap();

            let challenge = String::from_utf8(read_crlf_line(&mut stream, 1024).unwrap()).unwrap();
            let nonce_text = challenge.strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap();
            let client_nonce = decode_hex(nonce_text, "client nonce").unwrap();
            let server_nonce = vec![0x2a_u8; TOR_COOKIE_LENGTH];
            let mut input =
                Vec::with_capacity(cookie.len() + client_nonce.len() + server_nonce.len());
            input.extend_from_slice(&cookie);
            input.extend_from_slice(&client_nonce);
            input.extend_from_slice(&server_nonce);
            let server_hash = safe_cookie_hmac(
                b"Tor safe cookie authentication server-to-controller hash",
                &input,
            )
            .unwrap();
            stream
                .write_all(
                    format!(
                        "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                        hex_encode(&server_hash),
                        hex_encode(&server_nonce)
                    )
                    .as_bytes(),
                )
                .unwrap();
            let client_hash = safe_cookie_hmac(
                b"Tor safe cookie authentication controller-to-server hash",
                &input,
            )
            .unwrap();
            assert_eq!(
                read_crlf_line(&mut stream, 1024).unwrap(),
                format!("AUTHENTICATE {}", hex_encode(&client_hash)).as_bytes()
            );
            stream.write_all(b"250 OK\r\n").unwrap();
        });

        let config = TorConfig::default()
            .with_control_addr(address)
            .with_timeouts(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            );
        let _daemon = TorDaemon::connect(config).unwrap();
        server.join().unwrap();
        std::fs::remove_file(cookie_path).unwrap();
    }

    #[test]
    fn authenticates_safecookie_and_verifies_server_and_client_proofs() {
        const SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
        const CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let cookie_path = std::env::temp_dir().join(format!(
            "ghostchat-tor-safecookie-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cookie: Vec<u8> = (0..TOR_COOKIE_LENGTH as u8).collect();
        std::fs::write(&cookie_path, &cookie).unwrap();
        let cookie_path_text = cookie_path.to_str().unwrap().to_owned();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                read_crlf_line(&mut stream, 1024).unwrap(),
                b"PROTOCOLINFO 1"
            );
            let protocol_info = format!(
                "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE COOKIEFILE=\"{cookie_path_text}\"\r\n250 OK\r\n"
            );
            stream.write_all(protocol_info.as_bytes()).unwrap();

            let challenge = String::from_utf8(read_crlf_line(&mut stream, 1024).unwrap()).unwrap();
            let nonce_text = challenge.strip_prefix("AUTHCHALLENGE SAFECOOKIE ").unwrap();
            let client_nonce = decode_hex(nonce_text, "client nonce").unwrap();
            assert_eq!(client_nonce.len(), TOR_COOKIE_LENGTH);
            let server_nonce = vec![0x5a_u8; TOR_COOKIE_LENGTH];
            let mut input =
                Vec::with_capacity(cookie.len() + client_nonce.len() + server_nonce.len());
            input.extend_from_slice(&cookie);
            input.extend_from_slice(&client_nonce);
            input.extend_from_slice(&server_nonce);
            let server_hash = safe_cookie_hmac(SERVER_KEY, &input).unwrap();
            let challenge_reply = format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                hex_encode(&server_hash),
                hex_encode(&server_nonce)
            );
            stream.write_all(challenge_reply.as_bytes()).unwrap();

            let authenticate =
                String::from_utf8(read_crlf_line(&mut stream, 1024).unwrap()).unwrap();
            let client_hash = safe_cookie_hmac(CLIENT_KEY, &input).unwrap();
            assert_eq!(
                authenticate,
                format!("AUTHENTICATE {}", hex_encode(&client_hash))
            );
            stream.write_all(b"250 OK\r\n").unwrap();
        });

        let config = TorConfig::default()
            .with_control_addr(address)
            .with_cookie_path(cookie_path.clone())
            .with_timeouts(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            );
        let _daemon = TorDaemon::connect(config).unwrap();
        server.join().unwrap();
        std::fs::remove_file(cookie_path).unwrap();
    }

    #[test]
    fn reports_bootstrap_progress_from_getinfo() {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let address = listener.local_addr().unwrap();
        let cookie_path = std::env::temp_dir().join(format!(
            "ghostchat-tor-bootstrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cookie = [0x11_u8; TOR_COOKIE_LENGTH];
        std::fs::write(&cookie_path, cookie).unwrap();
        let cookie_path_text = cookie_path.to_str().unwrap().to_owned();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                read_crlf_line(&mut stream, 1024).unwrap(),
                b"PROTOCOLINFO 1"
            );
            stream
                .write_all(
                    format!(
                        "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE COOKIEFILE=\"{cookie_path_text}\"\r\n250 OK\r\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            assert_eq!(
                read_crlf_line(&mut stream, 1024).unwrap(),
                format!("AUTHENTICATE {}", hex_encode(&cookie)).as_bytes()
            );
            stream.write_all(b"250 OK\r\n").unwrap();
            assert_eq!(
                read_crlf_line(&mut stream, 1024).unwrap(),
                b"GETINFO status/bootstrap-phase"
            );
            stream.write_all(
                b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=42 TAG=loading SUMMARY=\"Loading\"\r\n250 OK\r\n",
            )
            .unwrap();
        });

        let config = TorConfig::default()
            .with_control_addr(address)
            .with_cookie_path(cookie_path.clone())
            .with_timeouts(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            );
        let daemon = TorDaemon::connect(config).unwrap();
        assert_eq!(daemon.bootstrap_progress().unwrap(), 42);
        server.join().unwrap();
        std::fs::remove_file(cookie_path).unwrap();
    }

    #[test]
    fn hex_encoding_is_lowercase_and_binary_safe() {
        assert_eq!(hex_encode(&[0x00, 0x01, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn socket_address_formats_ipv4_and_ipv6_for_add_onion() {
        assert_eq!(
            format_socket_addr(SocketAddr::from(([127, 0, 0, 1], 1234))),
            "127.0.0.1:1234"
        );
        assert_eq!(
            format_socket_addr(SocketAddr::new(
                std::net::IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1]),
                1234,
            )),
            "[::1]:1234"
        );
    }
}
