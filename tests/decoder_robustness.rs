//! Deterministic property-style decoder checks without a fuzzing dependency.
//! This corpus is regression evidence, not an exhaustive fuzzing claim.

use std::io::Cursor;
use std::panic::catch_unwind;

use ghostchat::protocol::{Envelope, ErrorCode, Message, RoomConfig, PROTOCOL_VERSION};
use ghostchat::transport::tor::parse_control_reply;
use ghostchat::transport::{FrameCodec, FrameError, DEFAULT_MAX_FRAME_SIZE};
use ghostchat::TorInvitation;
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn check_decoders(bytes: &[u8]) {
    assert!(
        catch_unwind(|| Envelope::decode(bytes)).is_ok(),
        "envelope decoder panicked"
    );
    assert!(
        catch_unwind(|| FrameCodec::default().read_frame(&mut Cursor::new(bytes))).is_ok(),
        "frame decoder panicked"
    );
    assert!(
        catch_unwind(|| parse_control_reply(bytes)).is_ok(),
        "control decoder panicked"
    );
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    assert!(
        catch_unwind(|| TorInvitation::decode_code(&hex)).is_ok(),
        "invitation decoder panicked"
    );
}

#[test]
fn attacker_bytes_never_panic_public_decoders_in_seeded_corpus() {
    let mut rng = StdRng::seed_from_u64(0x6768_6f73_7463_6861);
    for length in 0..2048 {
        let mut bytes = vec![0_u8; length];
        rng.fill_bytes(&mut bytes);
        check_decoders(&bytes);
        if length < 64 {
            check_decoders(&vec![0xff; length]);
            check_decoders(&vec![0; length]);
        }
    }
}

#[test]
fn truncations_mutations_and_trailing_bytes_remain_safe() {
    let messages = [
        Envelope::room_intro([1; 16], vec![2; 32], RoomConfig::default()),
        Envelope::join_request(vec![3; 32], "Peer".into(), vec![4; 100]),
        Envelope::mls_welcome(vec![5; 100], vec![6; 100]),
        Envelope::mls_handshake(vec![7; 100]),
        Envelope::mls_application(vec![8; 100]),
        Envelope::shutdown("local legacy fixture"),
        Envelope::new(Message::Error {
            code: ErrorCode::MalformedMessage,
            description: "fixture".into(),
        }),
    ];
    for message in messages {
        let encoded = message.encode().unwrap();
        assert_eq!(Envelope::decode(&encoded).unwrap(), message);
        for end in 0..encoded.len() {
            check_decoders(&encoded[..end]);
        }
        for offset in 0..encoded.len() {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 0xff;
            check_decoders(&mutated);
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(Envelope::decode(&trailing).is_err());
    }
}

#[test]
fn forged_collection_lengths_are_rejected_from_tiny_inputs() {
    // Fixed-width bincode: version u8, variant u32, first Vec/String length u64.
    for variant in [1_u32, 3, 4, 5, 6, 7, 8] {
        for length in [
            u64::MAX,
            u32::MAX as u64,
            (DEFAULT_MAX_FRAME_SIZE + 1) as u64,
        ] {
            let mut bytes = vec![PROTOCOL_VERSION];
            bytes.extend_from_slice(&variant.to_le_bytes());
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&[0; 8]);
            assert!(Envelope::decode(&bytes).is_err());
            check_decoders(&bytes);
        }
    }
}

#[test]
fn frame_boundaries_are_enforced_before_payload_read() {
    let codec = FrameCodec::default();
    let payload = vec![0x81; DEFAULT_MAX_FRAME_SIZE];
    let mut wire = Vec::new();
    codec.write_frame(&mut wire, &payload).unwrap();
    assert_eq!(codec.read_frame(&mut Cursor::new(&wire)).unwrap(), payload);
    for length in [DEFAULT_MAX_FRAME_SIZE as u32 + 1, u32::MAX] {
        let mut reader = Cursor::new(length.to_be_bytes());
        assert!(matches!(
            codec.read_frame(&mut reader),
            Err(FrameError::FrameTooLarge { .. })
        ));
        assert_eq!(
            reader.position(),
            4,
            "oversized length must not read a payload"
        );
    }
    assert!(codec.read_frame(&mut Cursor::new([0; 4])).is_err());
    assert!(codec.write_frame(&mut Vec::new(), &[]).is_err());
}
