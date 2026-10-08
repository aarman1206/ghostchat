#![no_main]

use ghostchat::session::SessionManager;
use ghostchat::{Envelope, Message, RoomConfig, SessionConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut session) = SessionManager::create(SessionConfig::default()) else {
        return;
    };

    // Each record selects a legal envelope constructor or sends raw bytes.
    // This gives libFuzzer valid state-machine edges as well as malformed
    // inputs, rather than only testing the decoder's reject path.
    let mut offset = 0;
    while offset < data.len() {
        let opcode = data[offset] & 0x07;
        offset += 1;
        let end = (offset + u16::from_le_bytes([data[offset.min(data.len()) - 1], 0]) as usize)
            .min(data.len());
        let body = &data[offset..end];
        offset = if end == offset {
            offset.saturating_add(1)
        } else {
            end
        };

        let envelope = match opcode {
            0 => None,
            1 => Some(Envelope::shutdown(
                String::from_utf8_lossy(body).into_owned(),
            )),
            2 => Some(Envelope::peer_ready()),
            3 => Some(Envelope::participant_event(
                String::from_utf8_lossy(body).into_owned(),
                "peer".to_string(),
                true,
            )),
            4 => Some(Envelope::room_intro(
                [0x41; 16],
                vec![0x42; 32],
                RoomConfig::default(),
            )),
            5 => Some(Envelope::mls_handshake(body.to_vec())),
            6 => Some(Envelope::mls_application(body.to_vec())),
            _ => Some(Envelope::new(Message::Error {
                code: ghostchat::protocol::ErrorCode::MalformedMessage,
                description: String::from_utf8_lossy(body).into_owned(),
            })),
        };

        if let Some(envelope) = envelope {
            let _ = session.receive_envelope(envelope);
        } else {
            let _ = session.receive_envelope_bytes(body);
        }
    }
});
