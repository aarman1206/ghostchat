#![no_main]

use ghostchat::TorInvitation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise both the UI-facing hexadecimal boundary and malformed UTF-8.
    // The decoder has its own 16 KiB text/8 KiB binary bounds.
    if data.len() <= 32 * 1024 {
        let text = String::from_utf8_lossy(data);
        let _ = TorInvitation::decode_code(&text);
    }

    // Mutations of arbitrary bytes into hexadecimal preserve a useful path
    // through the bounded bincode decoder without needing a live Tor daemon.
    if data.len() <= 8 * 1024 {
        let mut hex = String::with_capacity(data.len() * 2);
        for byte in data {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        let _ = TorInvitation::decode_code(&hex);
    }
});
