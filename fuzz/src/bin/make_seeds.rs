use ghostchat::{Envelope, RoomConfig};

fn write_seed(name: &str, envelope: Envelope) {
    let bytes = envelope.encode().expect("seed must encode");
    std::fs::write(format!("corpus/fuzz_target_1/{name}"), bytes).expect("failed to write seed");
}

fn main() {
    std::fs::create_dir_all("corpus/fuzz_target_1").unwrap();

    write_seed("shutdown", Envelope::shutdown("test shutdown"));

    write_seed("peer_ready", Envelope::peer_ready());

    write_seed(
        "participant_event",
        Envelope::participant_event("participant-test".into(), "Alice".into(), true),
    );

    write_seed(
        "room_intro",
        Envelope::room_intro([0x41; 16], vec![0x42; 32], RoomConfig::default()),
    );

    write_seed(
        "join_request",
        Envelope::join_request(vec![0x43; 32], "Alice".into(), vec![0x44; 32]),
    );

    write_seed("mls_handshake", Envelope::mls_handshake(vec![0x45; 32]));

    write_seed(
        "mls_welcome",
        Envelope::mls_welcome(vec![0x46; 32], vec![0x47; 32]),
    );

    write_seed("mls_application", Envelope::mls_application(vec![0x48; 32]));
}
