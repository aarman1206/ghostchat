//! Length-prefixed framing for opaque transport bytes.
//!
//! This module deliberately operates on byte slices only.  Callers encode a
//! `protocol::Envelope` before handing it to the framer and decode it after a
//! frame has been received; the framing layer never interprets the payload.
//!
//! Frames use a four-byte, big-endian `u32` length prefix followed by exactly
//! that many payload bytes.  A zero-length frame is rejected because a valid
//! encoded envelope is non-empty.  The default bound is the protocol's
//! one-megabyte encoded-message limit.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::Duration;

/// Maximum encoded payload size used by the protocol.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1_048_576;

/// Size of the length prefix on the wire, in bytes.
pub const FRAME_LENGTH_PREFIX_SIZE: usize = std::mem::size_of::<u32>();

const MAX_REPRESENTABLE_FRAME_SIZE: usize = u32::MAX as usize;

/// Part of a frame that was being read when the stream ended early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSection {
    /// The four-byte length prefix.
    LengthPrefix,
    /// The opaque payload described by the length prefix.
    Payload,
}

impl fmt::Display for FrameSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix => formatter.write_str("length prefix"),
            Self::Payload => formatter.write_str("payload"),
        }
    }
}

/// Errors returned while framing or deframing an opaque byte sequence.
#[derive(Debug)]
pub enum FrameError {
    /// The stream reached EOF before another frame started.
    EndOfStream,
    /// The stream ended after only part of a prefix or payload was received.
    UnexpectedEof {
        /// Which part of the frame was incomplete.
        section: FrameSection,
        /// Number of bytes required for that part.
        expected: usize,
        /// Number of bytes received before EOF.
        received: usize,
    },
    /// The length prefix described a frame that cannot be represented by the
    /// framing format.  Currently this is a zero-length frame.
    InvalidFrameLength {
        /// Length decoded from the wire.
        length: u32,
    },
    /// The frame length exceeded the configured bound.
    FrameTooLarge {
        /// Length requested by the caller or decoded from the wire.
        length: usize,
        /// Maximum length accepted by this codec.
        max: usize,
    },
    /// The configured bound cannot be represented by the four-byte prefix.
    InvalidMaxFrameSize {
        /// Invalid configured bound.
        max: usize,
        /// Largest bound representable by the wire format.
        representable: usize,
    },
    /// The underlying stream reported a connection-level failure.
    Disconnected(io::Error),
    /// Any other underlying I/O failure, including a stream timeout.
    Io(io::Error),
}

impl FrameError {
    /// Returns whether this error means that the peer or stream disconnected.
    pub fn is_disconnected(&self) -> bool {
        matches!(
            self,
            Self::EndOfStream | Self::UnexpectedEof { .. } | Self::Disconnected(_)
        )
    }

    /// Returns whether this error was caused by a clean EOF or truncation.
    pub fn is_eof(&self) -> bool {
        matches!(self, Self::EndOfStream | Self::UnexpectedEof { .. })
    }

    fn from_io(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected => Self::Disconnected(error),
            _ => Self::Io(error),
        }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndOfStream => formatter.write_str("end of stream before the next frame"),
            Self::UnexpectedEof {
                section,
                expected,
                received,
            } => write!(
                formatter,
                "unexpected EOF while reading {section}: expected {expected} bytes, received {received}"
            ),
            Self::InvalidFrameLength { length } => {
                write!(formatter, "invalid frame length {length}: zero-length frames are not allowed")
            }
            Self::FrameTooLarge { length, max } => {
                write!(formatter, "frame length {length} exceeds configured maximum {max}")
            }
            Self::InvalidMaxFrameSize { max, representable } => write!(
                formatter,
                "configured maximum frame size {max} exceeds the representable maximum {representable}"
            ),
            Self::Disconnected(error) => write!(formatter, "transport stream disconnected: {error}"),
            Self::Io(error) => write!(formatter, "transport I/O error: {error}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Disconnected(error) | Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// A stream capability for configuring native read and write timeouts.
///
/// Framing itself does not emulate timeouts or spawn a timer.  A stream that
/// has native timeout support implements this trait, and [`FramedStream`]
/// delegates the requested values to it.  The core [`FrameCodec`] API remains
/// available for every `Read + Write` stream, including streams with no
/// timeout facility.
pub trait TimeoutStream {
    /// Delegate a read timeout to the underlying stream.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Delegate a write timeout to the underlying stream.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl TimeoutStream for std::net::TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_write_timeout(self, timeout)
    }
}

#[cfg(unix)]
impl TimeoutStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, timeout)
    }
}

/// Bounded synchronous encoder/decoder for opaque transport frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameCodec {
    max_frame_size: usize,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_SIZE)
    }
}

impl FrameCodec {
    /// Construct a codec with the supplied maximum payload size.
    ///
    /// Use [`Self::try_new`] when the bound may come from untrusted or
    /// platform-sized configuration.  An invalid bound is reported when an
    /// operation is attempted rather than silently clamped.
    pub const fn new(max_frame_size: usize) -> Self {
        Self { max_frame_size }
    }

    /// Construct a codec and reject bounds that cannot fit in the wire prefix.
    pub const fn try_new(max_frame_size: usize) -> Result<Self, FrameError> {
        if max_frame_size > MAX_REPRESENTABLE_FRAME_SIZE {
            Err(FrameError::InvalidMaxFrameSize {
                max: max_frame_size,
                representable: MAX_REPRESENTABLE_FRAME_SIZE,
            })
        } else {
            Ok(Self { max_frame_size })
        }
    }

    /// Alias for [`Self::new`] that makes the configured bound explicit at a
    /// call site.
    pub const fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self::new(max_frame_size)
    }

    /// Return the maximum payload size accepted by this codec.
    pub const fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Write one length-prefixed opaque frame.
    ///
    /// The prefix is written in network byte order.  `write_all` semantics
    /// are used for both prefix and payload, so short writes are retried by
    /// the underlying `Write` implementation.  A failed write can leave a
    /// partial frame in the stream; no stream API can roll that back.
    pub fn write_frame<W: Write>(&self, writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
        self.validate_max_frame_size()?;

        if payload.is_empty() {
            return Err(FrameError::InvalidFrameLength { length: 0 });
        }
        if payload.len() > self.max_frame_size {
            return Err(FrameError::FrameTooLarge {
                length: payload.len(),
                max: self.max_frame_size,
            });
        }

        let length = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
            length: payload.len(),
            max: self.max_frame_size,
        })?;
        writer
            .write_all(&length.to_be_bytes())
            .map_err(FrameError::from_io)?;
        writer.write_all(payload).map_err(FrameError::from_io)
    }

    /// Read one length-prefixed opaque frame.
    ///
    /// A clean EOF before any prefix byte is [`FrameError::EndOfStream`].  A
    /// clean EOF after a partial prefix or payload is reported as
    /// [`FrameError::UnexpectedEof`].  The length is checked before allocating
    /// the payload buffer.
    pub fn read_frame<R: Read>(&self, reader: &mut R) -> Result<Vec<u8>, FrameError> {
        self.validate_max_frame_size()?;

        let mut prefix = [0u8; FRAME_LENGTH_PREFIX_SIZE];
        if !read_fully(reader, &mut prefix, FrameSection::LengthPrefix, true)? {
            return Err(FrameError::EndOfStream);
        }

        let encoded_length = u32::from_be_bytes(prefix);
        if encoded_length == 0 {
            return Err(FrameError::InvalidFrameLength {
                length: encoded_length,
            });
        }

        let length =
            usize::try_from(encoded_length).map_err(|_| FrameError::InvalidMaxFrameSize {
                max: self.max_frame_size,
                representable: usize::MAX,
            })?;
        if length > self.max_frame_size {
            return Err(FrameError::FrameTooLarge {
                length,
                max: self.max_frame_size,
            });
        }

        let mut payload = vec![0u8; length];
        read_fully(reader, &mut payload, FrameSection::Payload, false)?;
        Ok(payload)
    }

    fn validate_max_frame_size(&self) -> Result<(), FrameError> {
        if self.max_frame_size > MAX_REPRESENTABLE_FRAME_SIZE {
            Err(FrameError::InvalidMaxFrameSize {
                max: self.max_frame_size,
                representable: MAX_REPRESENTABLE_FRAME_SIZE,
            })
        } else {
            Ok(())
        }
    }
}

/// Read one frame with the default one-megabyte bound.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    FrameCodec::default().read_frame(reader)
}

/// Write one frame with the default one-megabyte bound.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    FrameCodec::default().write_frame(writer, payload)
}

/// A stream paired with a [`FrameCodec`] for convenient synchronous use.
pub struct FramedStream<S> {
    stream: S,
    codec: FrameCodec,
}

impl<S: Read + Write> FramedStream<S> {
    /// Wrap a stream with the default codec.
    pub fn new(stream: S) -> Self {
        Self::with_codec(stream, FrameCodec::default())
    }

    /// Wrap a stream with an explicit codec.
    pub const fn with_codec(stream: S, codec: FrameCodec) -> Self {
        Self { stream, codec }
    }

    /// Wrap a stream with a configured maximum payload size.
    pub const fn with_max_frame_size(stream: S, max_frame_size: usize) -> Self {
        Self::with_codec(stream, FrameCodec::new(max_frame_size))
    }

    /// Access the codec.
    pub const fn codec(&self) -> &FrameCodec {
        &self.codec
    }

    /// Mutably access the codec.
    pub fn codec_mut(&mut self) -> &mut FrameCodec {
        &mut self.codec
    }

    /// Borrow the wrapped stream.
    pub const fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Mutably borrow the wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Unwrap and return the stream.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Read one frame from the wrapped stream.
    pub fn read_frame(&mut self) -> Result<Vec<u8>, FrameError> {
        self.codec.read_frame(&mut self.stream)
    }

    /// Write one frame to the wrapped stream.
    pub fn write_frame(&mut self, payload: &[u8]) -> Result<(), FrameError> {
        self.codec.write_frame(&mut self.stream, payload)
    }
}

impl<S: Read + Write + TimeoutStream> FramedStream<S> {
    /// Delegate a read timeout to the wrapped stream.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), FrameError> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(FrameError::from_io)
    }

    /// Delegate a write timeout to the wrapped stream.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), FrameError> {
        self.stream
            .set_write_timeout(timeout)
            .map_err(FrameError::from_io)
    }

    /// Delegate both optional timeouts to the wrapped stream.
    pub fn set_timeouts(
        &self,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Result<(), FrameError> {
        self.set_read_timeout(read_timeout)?;
        self.set_write_timeout(write_timeout)
    }

    /// Wrap a stream and immediately delegate its optional timeouts.
    pub fn with_timeouts(
        stream: S,
        codec: FrameCodec,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Result<Self, FrameError> {
        let framed = Self::with_codec(stream, codec);
        framed.set_timeouts(read_timeout, write_timeout)?;
        Ok(framed)
    }
}

/// Compatibility alias for callers that prefer the shorter name.
pub type FrameStream<S> = FramedStream<S>;

fn read_fully<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    section: FrameSection,
    allow_clean_eof: bool,
) -> Result<bool, FrameError> {
    let mut received = 0;
    while received < buffer.len() {
        match reader.read(&mut buffer[received..]) {
            Ok(0) if received == 0 && allow_clean_eof => return Ok(false),
            Ok(0) => {
                return Err(FrameError::UnexpectedEof {
                    section,
                    expected: buffer.len(),
                    received,
                });
            }
            Ok(read) => {
                let remaining = buffer.len() - received;
                if read > remaining {
                    return Err(FrameError::from_io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "stream returned more bytes than requested",
                    )));
                }
                received += read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(FrameError::from_io(error)),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Cursor, Read, Write};

    struct PartialReader {
        inner: Cursor<Vec<u8>>,
        chunk_size: usize,
    }

    impl PartialReader {
        fn new(bytes: Vec<u8>, chunk_size: usize) -> Self {
            assert!(chunk_size > 0);
            Self {
                inner: Cursor::new(bytes),
                chunk_size,
            }
        }
    }

    impl Read for PartialReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let end = buffer.len().min(self.chunk_size);
            self.inner.read(&mut buffer[..end])
        }
    }

    struct PartialWriter {
        bytes: Vec<u8>,
        chunk_size: usize,
    }

    impl PartialWriter {
        fn new(chunk_size: usize) -> Self {
            assert!(chunk_size > 0);
            Self {
                bytes: Vec::new(),
                chunk_size,
            }
        }
    }

    impl Write for PartialWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let count = buffer.len().min(self.chunk_size);
            self.bytes.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn round_trip_preserves_opaque_bytes() {
        let codec = FrameCodec::default();
        let payload = [0, 7, 0xff, 42];
        let mut wire = Vec::new();

        codec.write_frame(&mut wire, &payload).unwrap();

        assert_eq!(&wire[..FRAME_LENGTH_PREFIX_SIZE], &[0, 0, 0, 4]);
        let mut reader = Cursor::new(wire);
        assert_eq!(codec.read_frame(&mut reader).unwrap(), payload);
        assert!(matches!(
            codec.read_frame(&mut reader),
            Err(FrameError::EndOfStream)
        ));
    }

    #[test]
    fn partial_reader_and_writer_are_supported() {
        let codec = FrameCodec::new(32);
        let payload = b"fragmented opaque envelope bytes";
        let mut writer = PartialWriter::new(2);

        codec.write_frame(&mut writer, payload).unwrap();

        let mut reader = PartialReader::new(writer.bytes, 1);
        assert_eq!(codec.read_frame(&mut reader).unwrap(), payload);
    }

    #[test]
    fn oversized_frames_are_rejected_before_payload_allocation_or_write() {
        let codec = FrameCodec::new(3);
        let mut writer = Vec::new();
        assert!(matches!(
            codec.write_frame(&mut writer, b"four"),
            Err(FrameError::FrameTooLarge { length: 4, max: 3 })
        ));
        assert!(writer.is_empty());

        let mut wire = 4u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"four");
        assert!(matches!(
            codec.read_frame(&mut Cursor::new(wire)),
            Err(FrameError::FrameTooLarge { length: 4, max: 3 })
        ));
    }

    #[test]
    fn malformed_and_truncated_input_is_rejected() {
        let codec = FrameCodec::new(32);

        assert!(matches!(
            codec.read_frame(&mut Cursor::new(0u32.to_be_bytes())),
            Err(FrameError::InvalidFrameLength { length: 0 })
        ));
        assert!(matches!(
            codec.read_frame(&mut Cursor::new(vec![0, 0])),
            Err(FrameError::UnexpectedEof {
                section: FrameSection::LengthPrefix,
                expected: FRAME_LENGTH_PREFIX_SIZE,
                received: 2,
            })
        ));

        let mut truncated_payload = 4u32.to_be_bytes().to_vec();
        truncated_payload.extend_from_slice(&[1, 2]);
        assert!(matches!(
            codec.read_frame(&mut Cursor::new(truncated_payload)),
            Err(FrameError::UnexpectedEof {
                section: FrameSection::Payload,
                expected: 4,
                received: 2,
            })
        ));
    }

    #[test]
    fn multiple_frames_remain_in_fifo_order() {
        let codec = FrameCodec::new(32);
        let frames: &[&[u8]] = &[b"first", b"second", b"third"];
        let mut wire = Vec::new();
        for frame in frames {
            codec.write_frame(&mut wire, frame).unwrap();
        }

        let mut reader = PartialReader::new(wire, 3);
        for expected in frames {
            assert_eq!(codec.read_frame(&mut reader).unwrap(), *expected);
        }
        assert!(matches!(
            codec.read_frame(&mut reader),
            Err(FrameError::EndOfStream)
        ));
    }

    struct TimeoutTestStream {
        inner: Cursor<Vec<u8>>,
        read_timeout: Cell<Option<Duration>>,
        write_timeout: Cell<Option<Duration>>,
    }

    impl TimeoutTestStream {
        fn new() -> Self {
            Self {
                inner: Cursor::new(Vec::new()),
                read_timeout: Cell::new(None),
                write_timeout: Cell::new(None),
            }
        }
    }

    impl Read for TimeoutTestStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl Write for TimeoutTestStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.inner.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl TimeoutStream for TimeoutTestStream {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.read_timeout.set(timeout);
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.write_timeout.set(timeout);
            Ok(())
        }
    }

    #[test]
    fn optional_timeouts_are_delegated_to_the_stream() {
        let read_timeout = Some(Duration::from_millis(250));
        let write_timeout = Some(Duration::from_secs(1));
        let stream = TimeoutTestStream::new();
        let framed =
            FramedStream::with_timeouts(stream, FrameCodec::default(), read_timeout, write_timeout)
                .unwrap();

        assert_eq!(framed.get_ref().read_timeout.get(), read_timeout);
        assert_eq!(framed.get_ref().write_timeout.get(), write_timeout);
    }
}
