//! Let OpenMLS handle its authenticated per-sender ratchet/replay window;
//! GhostChat must not add a home-grown message sequence cryptosystem.

use ghostchat::crypto::CryptoManager;
use ghostchat::identity::EphemeralIdentity;
use ghostchat::protocol::Envelope;
use ghostchat::session::{SessionEvent, SessionManager};
use ghostchat::SessionConfig;

#[test]
fn reordered_current_epoch_messages_authenticate_once() {
    let config = SessionConfig::default();
    let room_id = [42; 16];
    let mut alice = SessionManager::create_for_room(config.clone(), &room_id).unwrap();
    let crypto = CryptoManager::new(config.clone());
    let identity = EphemeralIdentity::generate(config.ciphersuite, &crypto.provider).unwrap();
    let key_package = identity
        .key_package(config.ciphersuite, &crypto.provider)
        .unwrap();
    let (_, welcome, _) = alice.add_member(key_package).unwrap();
    let envelope = Envelope::mls_welcome(
        welcome.to_bytes().unwrap(),
        alice.export_ratchet_tree_bytes().unwrap(),
    );
    let mut bob = SessionManager::join_verified(
        crypto,
        identity,
        envelope,
        Some((&alice.participant_id(), &room_id)),
    )
    .unwrap();
    let first = alice.send_application(b"first").unwrap();
    let second = alice.send_application(b"second").unwrap();
    let third = alice.send_application(b"third").unwrap();
    for (envelope, expected) in [
        (&third, b"third".as_slice()),
        (&first, b"first"),
        (&second, b"second"),
    ] {
        match bob.receive_envelope(envelope.clone()).unwrap() {
            SessionEvent::Application {
                plaintext,
                sender,
                epoch,
            } => {
                assert_eq!(plaintext, expected);
                assert_eq!(sender, Some(alice.participant_id()));
                assert_eq!(epoch, alice.epoch());
            }
            _ => panic!("expected authenticated application"),
        }
    }
    assert!(bob.receive_envelope(first).is_err());
    assert!(bob.receive_envelope(third).is_err());
}
