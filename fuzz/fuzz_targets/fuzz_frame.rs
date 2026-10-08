#![no_main]

use ghostchat::transport::FrameCodec;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let codec = FrameCodec::default();
    let mut reader = Cursor::new(data);
    let _ = codec.read_frame(&mut reader);
});
