#![no_main]

use ghostchat::session::SessionManager;
use ghostchat::SessionConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut session) = SessionManager::create(SessionConfig::default()) else {
        return;
    };

    // Interpret the fuzz input as a sequence of length-prefixed operations.
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if len == 0 || offset + len > data.len() {
            break;
        }

        let operation = &data[offset..offset + len];
        offset += len;

        let _ = session.receive_envelope_bytes(operation);
    }
});
