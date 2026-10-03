//! Small line-oriented process harness used by the real Tor integration test.
//! It intentionally exposes only safe room snapshots and never prints MLS
//! keys, invite contents except for the explicit CREATE result, or plaintext
//! network payloads.

use std::io::{self, BufRead, Read, Write};

use ghostchat::{NetworkRoom, SessionConfig};

const MAX_COMMAND_BYTES: usize = 32 * 1024;

fn read_command(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    if reader
        .take((MAX_COMMAND_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)?
        == 0
    {
        return Ok(None);
    }
    if bytes.len() > MAX_COMMAND_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "command exceeds limit",
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "command is not UTF-8"))
}

fn main() {
    let stdin = io::stdin();
    let mut output = io::BufWriter::new(io::stdout());
    let mut room: Option<NetworkRoom> = None;

    let mut input = stdin.lock();
    while let Ok(Some(line)) = read_command(&mut input) {
        let line = line.trim_end();
        let response = handle_command(&mut room, line);
        if writeln!(output, "{response}")
            .and_then(|_| output.flush())
            .is_err()
        {
            break;
        }
        if response == "BYE" {
            break;
        }
    }
    if let Some(room) = room {
        let _ = room.shutdown();
    }
}

fn handle_command(room: &mut Option<NetworkRoom>, command: &str) -> String {
    if (command.starts_with("CREATE ") || command.starts_with("JOIN "))
        && room.as_ref().is_some_and(|room| {
            room.snapshot()
                .is_ok_and(|snapshot| snapshot.state != "closed")
        })
    {
        return "ERR room already active".to_string();
    }
    if let Some(name) = command.strip_prefix("CREATE ") {
        match NetworkRoom::create(
            SessionConfig::default(),
            Some("Tor test room".to_string()),
            name,
        ) {
            Ok(created) => match created.invite_code() {
                Ok(invitation) => {
                    *room = Some(created);
                    format!("INVITE {invitation}")
                }
                Err(error) => format!("ERR {error}"),
            },
            Err(error) => format!("ERR {error}"),
        }
    } else if let Some(arguments) = command.strip_prefix("JOIN ") {
        let mut parts = arguments.splitn(2, ' ');
        let Some(invitation) = parts.next() else {
            return "ERR missing invitation".to_string();
        };
        let Some(name) = parts.next() else {
            return "ERR missing display name".to_string();
        };
        match NetworkRoom::join(invitation, SessionConfig::default(), name) {
            Ok(joined) => {
                *room = Some(joined);
                "OK joined".to_string()
            }
            Err(error) => format!("ERR {error}"),
        }
    } else if command == "POLL" {
        let Some(active) = room.as_ref() else {
            return "ERR no room".to_string();
        };
        match active.poll() {
            Ok(events) => {
                let event_error = events.iter().find_map(|event| match event {
                    ghostchat::NetworkUiEvent::Error(message) => Some(message.as_str()),
                    _ => None,
                });
                let participant_events = events
                    .iter()
                    .filter(|event| matches!(event, ghostchat::NetworkUiEvent::Participant(_)))
                    .count();
                match active.snapshot() {
                    Ok(snapshot) => event_error.map_or_else(
                        || format!("EVENTS {participant_events} {}", snapshot_line(&snapshot)),
                        |message| format!("EVENTERR {message} {}", snapshot_line(&snapshot)),
                    ),
                    Err(error) => format!("ERR {error}"),
                }
            }
            Err(error) => format!("ERR {error}"),
        }
    } else if command == "SNAP" {
        let Some(active) = room.as_ref() else {
            return "ERR no room".to_string();
        };
        match active.snapshot() {
            Ok(snapshot) => snapshot_line(&snapshot),
            Err(error) => format!("ERR {error}"),
        }
    } else if let Some(body) = command.strip_prefix("SEND ") {
        let Some(active) = room.as_ref() else {
            return "ERR no room".to_string();
        };
        match active.send_message(body) {
            Ok(message) => format!("SENT {}", message.id),
            Err(error) => format!("ERR {error}"),
        }
    } else if command == "EPOCH" {
        let Some(active) = room.as_ref() else {
            return "ERR no room".to_string();
        };
        match active.advance_epoch() {
            Ok(epoch) => format!("EPOCH {epoch}"),
            Err(error) => format!("ERR {error}"),
        }
    } else if command == "SHUTDOWN" {
        if let Some(active) = room.take() {
            match active.shutdown() {
                Ok(()) => "BYE".to_string(),
                Err(error) => format!("ERR {error}"),
            }
        } else {
            "BYE".to_string()
        }
    } else {
        "ERR unknown command".to_string()
    }
}

fn snapshot_line(snapshot: &ghostchat::RoomSnapshot) -> String {
    format!(
        "SNAP {} {} {} {}",
        snapshot.state,
        snapshot.epoch,
        snapshot.participants.len(),
        snapshot.messages.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn command_reader_bounds_input_before_allocation_and_handles_eof() {
        let mut reader = Cursor::new(b"SNAP\nSHUTDOWN");
        assert_eq!(
            read_command(&mut reader).unwrap().as_deref(),
            Some("SNAP\n")
        );
        assert_eq!(
            read_command(&mut reader).unwrap().as_deref(),
            Some("SHUTDOWN")
        );
        assert!(read_command(&mut reader).unwrap().is_none());
        assert!(read_command(&mut Cursor::new(vec![b'x'; MAX_COMMAND_BYTES + 1])).is_err());
        assert!(read_command(&mut Cursor::new(vec![0xff, b'\n'])).is_err());
    }
}
