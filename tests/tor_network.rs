//! Opt-in, three-independent-process Tor/OpenMLS lifecycle and failure test.
//! Commands and condition waits are bounded; invitation/message values are
//! never included in diagnostics. Drop reaps owned children even on failure.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
const STATE_TIMEOUT: Duration = Duration::from_secs(60);

struct PeerProcess {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<String>,
    reader: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct Snapshot {
    state: String,
    epoch: u64,
    participants: usize,
    messages: usize,
}

impl PeerProcess {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ghostchat-peer"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("peer process should start");
        let input = child.stdin.take().expect("peer stdin");
        let stdout = child.stdout.take().expect("peer stdout");
        let (tx, output) = mpsc::sync_channel(2);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if line.len() > 32 * 1024 || tx.try_send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input: Some(input),
            output,
            reader: Some(reader),
        }
    }

    fn request(&mut self, command: &str) -> String {
        // Only the verb is safe to display; JOIN is a bearer secret and SEND
        // contains plaintext. Responses are inspected without printing them.
        let verb = command.split_whitespace().next().unwrap_or("empty");
        let input = self.input.as_mut().expect("peer input is open");
        writeln!(input, "{command}").expect("peer command write");
        input.flush().expect("peer command flush");
        self.output
            .recv_timeout(COMMAND_TIMEOUT)
            .unwrap_or_else(|_| panic!("peer {verb} response timed out or process exited"))
    }

    fn command(&mut self, command: &str) -> String {
        let response = self.request(command);
        let verb = command.split_whitespace().next().unwrap_or("empty");
        assert!(
            !response.starts_with("ERR "),
            "peer {verb} operation failed (details redacted)"
        );
        response
    }

    fn snapshot(&mut self) -> Snapshot {
        let response = self.command("SNAP");
        let mut fields = response.split_whitespace();
        assert_eq!(fields.next(), Some("SNAP"));
        Snapshot {
            state: fields.next().expect("snapshot state").to_string(),
            epoch: fields.next().expect("epoch").parse().expect("epoch number"),
            participants: fields
                .next()
                .expect("participants")
                .parse()
                .expect("participant number"),
            messages: fields
                .next()
                .expect("messages")
                .parse()
                .expect("message number"),
        }
    }

    fn poll(&mut self) {
        let response = self.command("POLL");
        assert!(
            !response.starts_with("EVENTERR ") || response.contains(" SNAP closed "),
            "peer poll rejected a message (details redacted)"
        );
    }

    fn poll_expected_capacity_refusal(&mut self) {
        let response = self.command("POLL");
        assert!(
            response.starts_with("EVENTS ")
                || response.starts_with("EVENTERR maximum participant limit reached SNAP active "),
            "owner reported an unexpected error while refusing a fourth member"
        );
    }

    fn join(&mut self, invitation: &str, name: &str) {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let response = self.request(&format!("JOIN {invitation} {name}"));
            if response == "OK joined" {
                return;
            }
            // Only retry failed SOCKS establishment, before a room exists.
            // Never retry uncertain sends/commits or protocol rejections.
            assert!(
                response.starts_with("ERR Transport error:"),
                "join failed outside transport establishment"
            );
            assert!(
                Instant::now() < deadline,
                "onion publication/connection deadline exceeded"
            );
            thread::sleep(Duration::from_secs(2));
        }
    }

    fn stop(&mut self) {
        assert_eq!(self.command("SHUTDOWN"), "BYE");
        self.input.take();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().expect("peer exit status") {
                assert!(status.success(), "peer should exit successfully");
                break;
            }
            assert!(Instant::now() < deadline, "peer shutdown deadline exceeded");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn crash(&mut self) {
        self.child.kill().expect("terminate owned peer");
        self.child.wait().expect("reap terminated peer");
        self.input.take();
    }
}

impl Drop for PeerProcess {
    fn drop(&mut self) {
        self.input.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn wait_for(
    peers: &mut [&mut PeerProcess],
    description: &str,
    condition: impl Fn(&[Snapshot]) -> bool,
) {
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        for peer in peers.iter_mut() {
            peer.poll();
        }
        let snapshots: Vec<_> = peers.iter_mut().map(|peer| peer.snapshot()).collect();
        if condition(&snapshots) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}: {snapshots:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_members(peers: &mut [&mut PeerProcess], count: usize, messages: usize) {
    wait_for(peers, "converged MLS membership/epoch/history", |states| {
        states.iter().all(|s| {
            s.state == "active"
                && s.participants == count
                && s.messages == messages
                && s.epoch == states[0].epoch
        })
    });
}

#[test]
#[ignore = "requires a bootstrapped Tor daemon with SOCKS and authenticated control ports"]
fn three_independent_processes_complete_tor_mls_lifecycle() {
    let mut alice = PeerProcess::spawn();
    let invitation = alice
        .command("CREATE Alice")
        .strip_prefix("INVITE ")
        .expect("creator invitation response")
        .to_string();
    assert_eq!(alice.snapshot().participants, 1);

    let mut bob = PeerProcess::spawn();
    bob.join(&invitation, "Bob");
    wait_for_members(&mut [&mut alice, &mut bob], 2, 0);
    let mut charlie = PeerProcess::spawn();
    charlie.join(&invitation, "Charlie");
    wait_for_members(&mut [&mut alice, &mut bob, &mut charlie], 3, 0);

    let mut fourth = PeerProcess::spawn();
    fourth.join(&invitation, "Fourth");
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        alice.poll_expected_capacity_refusal();
        bob.poll();
        charlie.poll();
        let _ = fourth.request("POLL"); // A refusal is expected, not a test failure.
        if fourth.snapshot().state == "closed" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fourth participant must be rejected"
        );
        thread::sleep(Duration::from_millis(50));
    }
    fourth.stop();
    wait_for_members(&mut [&mut alice, &mut bob, &mut charlie], 3, 0);

    assert!(alice.command("SEND alice-one").starts_with("SENT "));
    wait_for_members(&mut [&mut alice, &mut bob, &mut charlie], 3, 1);
    assert!(bob.command("SEND bob-one").starts_with("SENT "));
    wait_for_members(&mut [&mut alice, &mut bob, &mut charlie], 3, 2);
    assert!(charlie.command("SEND charlie-one").starts_with("SENT "));
    wait_for_members(&mut [&mut alice, &mut bob, &mut charlie], 3, 3);
    let previous = alice.snapshot().epoch;
    assert!(alice.command("EPOCH").starts_with("EPOCH "));
    wait_for(
        &mut [&mut alice, &mut bob, &mut charlie],
        "updated epoch",
        |states| {
            states
                .iter()
                .all(|s| s.epoch == previous + 1 && s.messages == 3)
        },
    );

    charlie.stop();
    wait_for_members(&mut [&mut alice, &mut bob], 2, 3);
    let mut charlie = PeerProcess::spawn();
    charlie.join(&invitation, "Charlie fresh");
    wait_for(
        &mut [&mut alice, &mut bob, &mut charlie],
        "fresh rejoin without old history",
        |states| {
            states
                .iter()
                .all(|s| s.state == "active" && s.participants == 3 && s.epoch == states[0].epoch)
                && states[0].messages == 3
                && states[1].messages == 3
                && states[2].messages == 0
        },
    );
    charlie.crash();
    wait_for_members(&mut [&mut alice, &mut bob], 2, 3);
    assert!(bob.command("SEND after-disconnect").starts_with("SENT "));
    wait_for_members(&mut [&mut alice, &mut bob], 2, 4);

    alice.stop();
    wait_for(
        &mut [&mut bob],
        "owner shutdown clearing remote state",
        |s| s[0].state == "closed" && s[0].participants == 0 && s[0].messages == 0,
    );
    bob.stop();
}

#[test]
#[ignore = "requires a bootstrapped Tor daemon and real onion networking"]
fn creator_disappears_and_joiner_clears_runtime_state() {
    let mut alice = PeerProcess::spawn();
    let invitation = alice
        .command("CREATE Alice")
        .strip_prefix("INVITE ")
        .expect("creator invitation response")
        .to_string();
    let mut bob = PeerProcess::spawn();
    bob.join(&invitation, "Bob");
    wait_for_members(&mut [&mut alice, &mut bob], 2, 0);
    assert!(bob.command("SEND crash-test").starts_with("SENT "));
    wait_for_members(&mut [&mut alice, &mut bob], 2, 1);
    alice.crash();
    wait_for(&mut [&mut bob], "creator disconnect cleanup", |s| {
        s[0].state == "closed" && s[0].participants == 0 && s[0].messages == 0
    });
    bob.stop();
}

#[test]
fn peer_harness_rejects_unknown_commands_without_tor() {
    let mut peer = PeerProcess::spawn();
    assert_eq!(peer.request("UNKNOWN"), "ERR unknown command");
    peer.stop();
}
