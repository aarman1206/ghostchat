# GhostChat

Invitation-only, session-scoped chat for at most three participants, using
OpenMLS and Tor v3 onion services. The creator is both an MLS participant and
a ciphertext relay. There is no room directory, account service, central
plaintext server, or clearnet fallback.

This is a hardened prototype, **not an independently certified anonymity
product**. Read [SECURITY_AUDIT.md](SECURITY_AUDIT.md) before relying on it.

## Architecture

```text
Bundled HTML / JavaScript
        ↓ validated Tauri IPC and session-scoped events
GhostChat desktop state + bounded network pump
        ↓
NetworkRoom → SessionManager → OpenMLS + in-memory crypto provider
        ↓ versioned envelopes containing opaque MLS bytes
StreamTransport
        ↓
TorTransport → loopback Tor SOCKS5 / authenticated control port
        ↓ ephemeral ADD_ONION ED25519-V3 service
Independent GhostChat peers through Tor
```

`LocalRoom` + `InMemoryTransport`, and `InMemoryStreamTransport`, remain
separate deterministic test/development adapters. The normal release desktop
path is `create_room` / `join_room` → `NetworkRoom` → `TorTransport`.
An IPC failure never selects a browser mock or a local transport.

## Requirements

- Rust/Cargo, Tauri CLI v2 (`cargo install tauri-cli --version '^2' --locked`).
- A running system Tor daemon with a bootstrapped SOCKS listener and
  cookie-authenticated control port. GhostChat does not launch or configure Tor.
- Linux desktop build prerequisites: GTK3, WebKitGTK 4.1, development headers,
  a C/C++ toolchain, pkg-config, and the usual Tauri platform prerequisites.
  On Debian/Ubuntu, these commonly include `build-essential`, `pkg-config`,
  `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`,
  `librsvg2-dev`, `libssl-dev`, and `patchelf`.

Frontend files are static; no Node package install or JS build is needed.
Node is needed only for frontend regression tests. Keep the system Tor,
WebKit and OS security updates current.

## Tor configuration

Defaults:

| Endpoint | Default | Constraint |
| --- | --- | --- |
| SOCKS5 | `127.0.0.1:9050` | Loopback socket address only |
| Control | `127.0.0.1:9051` | Loopback, COOKIE or SAFECOOKIE |
| Control cookie | Reported by `PROTOCOLINFO` | Readable by the application user |

Optional process-environment overrides:

```sh
export GHOSTCHAT_TOR_SOCKS=127.0.0.1:9050
export GHOSTCHAT_TOR_CONTROL=127.0.0.1:9051
# Only if the daemon-reported path is unsuitable:
export GHOSTCHAT_TOR_COOKIE=/path/to/control.authcookie
```

SOCKS port `9150` can be selected when available; a readable, authenticated
control port is still required. Do not expose Tor control/SOCKS ports to the
Internet or make the authentication cookie world-readable. A Tor configuration
may use `SocksPort 127.0.0.1:9050`, `ControlPort 127.0.0.1:9051`, and
`CookieAuthentication 1`; inspect and merge your existing configuration rather
than replacing it. Tor setup is an administrator task, not a frontend option.

GhostChat prefers SAFECOOKIE and verifies Tor's server proof before sending
its proof. COOKIE is supported only when SAFECOOKIE is not advertised.
Creating/joining requires `PROGRESS=100`; an authenticated control connection
alone is not readiness. Invalid configuration or unavailable Tor fails closed.

The ephemeral service uses `DiscardPK` and no `Detach` flag. Its listener is
bound to loopback on an OS-selected port. The Internet cannot directly reach
that listener absent external port forwarding; **local processes can reach it**
and must still pass invitation and MLS checks. A compromised local machine or
administrator is outside the anonymity boundary.

## Build and run

From the repository root:

```sh
cargo build --workspace --locked
cargo run -p ghostchat-app
```

Or run Tauri from its application directory (the CLI has no `--manifest-path`
option):

```sh
cd app/src-tauri
cargo tauri dev
# Production Debian package, default features:
cargo tauri build --bundles deb
```

Outputs are `target/release/ghostchat-app` and
`target/release/bundle/deb/GhostChat_0.1.0_amd64.deb` on the verified Linux host.
Do not ship a build made with the `local-transport` feature. Default release
builds reject `GHOSTCHAT_TRANSPORT=local`; debug builds allow it explicitly for
host-only development:

```sh
GHOSTCHAT_TRANSPORT=local cargo run -p ghostchat-app
```

Browser-only layout preview:

```sh
python3 -m http.server 4174 --bind 127.0.0.1 --directory app/src
```

Open `http://127.0.0.1:4174`. It is prominently labeled simulated and
unencrypted; message sending is disabled. It is not a Tor client.

## Create, invite, join, leave

1. Start Tor; wait for **Tor ready** in the desktop app.
2. Choose **Create a room**, set a display name and optional local room label.
3. Copy the signed bearer invitation and send it through a trusted out-of-band
   channel. Do not put it in public posts, logs or bug reports.
4. On another GhostChat instance, select **Join a room** and paste the code.
5. Wait for the authenticated MLS Welcome **and creator confirmation** before
   sending. The status shows transport, Tor state, membership and epoch.
6. The owner can rotate epochs or remove a member. Joiners use **Leave room**;
   the owner uses **End session** to close everyone’s room.

A fourth member is rejected by the core, not just the UI. Joins are serialized:
if another join is in progress, retry with a fresh join after it finishes.
Disconnect/reconnection never reuses stale MLS state. A new process/identity
joins using a still-valid invitation; it does not recover earlier messages.

Invitations are reusable while the room lives, not one-time tickets or human
identity proofs. Removing a member does not ban a person who still holds the
invitation and can generate a fresh identity. End the room and create another
to revoke all old invitations. The owner cannot transfer room ownership.

## Cryptographic and protocol boundaries

The ciphersuite stays
`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` with OpenMLS `0.9.0`.
Each process owns an independent fresh identity, provider, KeyPackage and group.
Welcome signatures, group IDs, ciphersuite and membership are pinned to the
invitation. Only the creator may issue network-room commits. Receivers enforce
the three-member capacity before merging a commit or accepting a Welcome.

Invitations are hex-encoded, bounded to 8 KiB binary / 16 KiB text, and signed
over the endpoint, port, random 32-byte bearer token and room introduction.
Onion validation checks canonical base32, the v3 version byte and SHA3 checksum;
no IP, ordinary DNS name, URL, extra label or TCP target is accepted.
The signature binds the token to the room; it does **not** authenticate a
human creator independently of the trusted channel that supplied the code.

Protocol **version 4** rejects earlier envelopes. Updated peers are required:
post-Welcome chat, names, readiness, leave and shutdown are MLS application
ciphertexts, not legacy plaintext controls. OpenMLS validates signatures,
epochs and replay/ratchet state; GhostChat enforces routing and control roles.
Current-epoch out-of-order application messages are supported within OpenMLS's
ratchet window. Duplicate, stale, future or malformed network MLS traffic is
rejected and the affected session/connection is closed rather than guessed at.

## Bounds and failure behavior

- Four-byte big-endian framing; nonzero payloads up to 1 MiB, checked before
  allocation. Envelopes use fixed-width, size-limited bincode without trailing
  data. No unsafe code is defined by GhostChat itself.
- At most eight accepted connections, sixteen connection workers, 128 incoming
  events and 32 outgoing frames per connection. These are frame-count bounds,
  not a claim of negligible worst-case memory consumption.
- Unknown connections, incomplete joins and creator confirmation have
  60-second deadlines driven by `poll` (the desktop pumps every 100 ms).
- Default socket/handshake/frame/control budgets are bounded (normally 30 s);
  the local TCP connect budget is 10 s. Slow partial traffic cannot reset a
  complete-operation budget. TorConfig timeout overrides are capped at 300 s.
- Silent, already-authenticated rooms may stay idle intentionally. There is no
  application heartbeat or automatic ban for a quiet member; the owner can
  remove it. Tor disconnect detection may be delayed.
- Shutdown uses a two-second aggregate **local write barrier**, then closes
  sockets and joins network workers. This is not remote receipt confirmation.
- Desktop exit cleanup has a two-second budget; process exit then releases OS
  handles. Faults/stuck tasks cannot promise authenticated shutdown delivery.
- A partially delivered commit/fanout closes the room rather than leaving
  uncertain split MLS state. There is no durable replay queue or offline send.
- The UI labels sent messages queued/delivery-unconfirmed. Retry an unknown send
  only after checking the room; automatic retry could duplicate messages.

## Privacy, persistence and limitations

Tor hides the user's direct network address from the peer under its intended
threat model. MLS protects application confidentiality/integrity between
members. There is no clearnet DNS resolution of onion destinations.

The owner is a member and **can read the room's messages**, not a blind server.
Any member can copy text, capture screens, disclose invitations, relay metadata
or share its own secrets. A malicious member can deny service. Display names
and signing-key IDs are session metadata, not verified real-world identities.

Tor/local-network observers can see Tor use, packet lengths and timing. Powerful
observers may correlate streams, room-creation times and traffic patterns.
The onion endpoint and room ID/key/epoch/membership are known to invite holders
and relevant participants. There is no traffic padding, cover traffic, or
constant-rate schedule. The Tor daemon also has its own state and diagnostics.

GhostChat deliberately does not write private MLS keys, group state,
invitations or chat history to files, databases, localStorage or sessionStorage.
Core/local/frontend history is capped at the most recent 500 messages. Close
clears owned room data and the UI; owned serialized provider/key/history
buffers receive best-effort zeroization. This is **not forensic erasure**:
returned copies, JavaScript garbage collection, upstream allocations, swap,
hibernation, core dumps, clipboard managers, screenshots and OS/WebView caches
or telemetry remain outside that guarantee. Test/CLI CREATE returns an invite
on stdout explicitly; capturing stdout makes that capture sensitive.

Endpoint/local-machine compromise defeats these protections. GhostChat is not
"untraceable", "100% anonymous", or protection from a global observer.

## Tests and current validation

Run normal checks without a Tor daemon:

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
node --check app/src/main.js
node --test app/tests/frontend.test.cjs
```

Opt-in real Tor tests:

```sh
cargo test --test tor_network -- --ignored --nocapture
cargo test -p ghostchat-app --lib real_tor_backend_create_join_send_poll_shutdown -- --ignored --test-threads=1
```

Real-world validation includes **three independent GhostChat processes
communicating through Tor while completing an OpenMLS lifecycle**: 1→2→3,
fourth-member rejection, encrypted exchange, epoch update, leave, fresh join,
abrupt disconnect and shutdown. A second opt-in process test kills the creator.
The harness uses bounded condition waits, redacted errors, and child cleanup.

The desktop test dispatches the actual generated Tauri command handlers with
real Tor/core state and the network pump. Only its window runtime is mocked;
this is not a claim of three live native WebViews being tested. Native Linux
startup/rendering and browser layouts are separate smoke checks. These runs
use one existing local Tor daemon, not three isolated daemons or devices.

Deterministic tests cover malformed SOCKS/control replies, unavailable daemons,
SAFECOOKIE proof failure, stalled/partial framing, bounded queues/cleanup,
invitation tampering, MLS control policies and join races. Seeded decoder
corpora are lightweight property-style regressions, not exhaustive fuzzing.

For a dependency check with an installed cargo-audit:

```sh
cargo audit
```

The reviewed lockfile retains OpenMLS and compatible crypto versions; unused
direct dependencies were removed and a yanked derive package replaced with a
compatible patch. RustSec still flags **GLib 0.18.5 unsoundness and eight
unmaintained packages**, including bincode 1.3.3. No incompatible GTK/MLS or
serialization migration was forced just to silence warnings. Details, actual
results and release-readiness gaps are in `SECURITY_AUDIT.md`.
