# GhostChat security and release-readiness review

Review completed against the current working tree, October 3–4, 2026
(Asia/Calcutta). This is an implementation review with executable regressions,
not an independent pentest, cryptographic proof, or anonymity certification.
The existing networking hardening commits were preserved; this audit did not
create a commit or reconfigure Tor. Audit-only fuzz/report changes remain
uncommitted.

## Scope and method

Reviewed `src/`, `tests/`, `src/bin/`, frontend/backend Tauri code, manifests,
lockfile, capabilities, CSP, configuration and README. Graph discovery was
refreshed, paths/coverage checked, then relevant source was read directly.
Changed source and actual tests, not graph absence, establish the findings.

Work used bounded independent implementations for transport, session and
desktop fixes; combined changes were reviewed and tested together. Existing
OpenMLS/Tor mechanisms were retained instead of replacing cryptography or
adding a new framework. No managed paid scanner, external source upload, or
Strix exploitation run was performed. The dependency check used cargo-audit
0.22.2 and the public RustSec database; seeded property-style tests are not
continuous cargo-fuzz coverage.

## Architecture reviewed

```text
Packaged JS/HTML
  → validated, session-scoped Tauri commands/events
  → AppState / admission leases / background network pump
  → NetworkRoom → SessionManager / OpenMLS 0.9.0
  → byte-only StreamTransport → TorTransport
  → loopback SOCKS5 and cookie-authenticated Tor control
  → ephemeral ED25519-V3 onion service → remote processes
```

The owner is a participating MLS member and relay. It decrypts the chat as a
member and forwards encoded ciphertext, not centrally stored plaintext.
Deterministic `LocalRoom`, `InMemoryTransport` and `InMemoryStreamTransport`
remain separate. Normal release builds reject the runtime local-mode setting;
an explicit compile-time `local-transport` feature is development-only.

## Attack surfaces and boundaries

| Boundary | Untrusted input / metadata | Enforcement |
| --- | --- | --- |
| Network destination | Invitation onion/port | Shared canonical v3 checksum/version validation; only loopback Tor endpoints; no direct destination TCP/DNS |
| Tor control / SOCKS | Replies, lengths, async events, proof | Total deadlines, aggregate byte/line caps, response fields, HMAC server verification |
| Onion listener | Any Tor peer or local process | Loopback bind; eight connections; bounded workers/queues; join deadline |
| Invitation | Hex and bounded bincode / bearer capability | Version, sizes, no trailing data, Ed25519 signature over all fields and validated RoomIntro |
| MLS | KeyPackage, Welcome, commits, applications | OpenMLS validates crypto/epoch/ratchets; GhostChat pins creator/group, roles, capacity and connection sender |
| IPC | Bundled frontend arguments, concurrent/stale calls | Bounds/canonical IDs, role/admission leases, single-flight snapshots/status, cancellation-safe ownership |
| UI | Peer text, late events and responses | Text-only rendering, session scoping, bounded history, desktop fail-closed behavior |
| Filesystem / OS | Tor cookie path and runtime environment | Fixed-size cookie read; no GhostChat history/key persistence; host is trusted |

The listener has no direct `Internet → TCP` exposure in GhostChat. It is
loopback-bound, not a guarantee against local users, privileged port forwarding,
container/host network changes or local-machine compromise. Local Tor is a
trusted component. COOKIE fallback has weaker server-authentication properties
than SAFECOOKIE and is used only if SAFECOOKIE is not advertised.

IPC exposes room/status/snapshot/chat/lifecycle operations only. It does not
expose private keys, raw protocol frames, shell/process execution, arbitrary
paths or destinations. Plaintext messages and the invite necessarily cross
IPC to be displayed; calling these entirely "non-sensitive" would be false.
CSP denies remote scripts/frames/workers/forms; navigation is restricted to
the packaged origin. Capabilities grant event listen/unlisten, not event emit
or shell/filesystem/network plugins. An injected script could still read the
current displayed conversation: CSP is not protection from endpoint compromise.

## Findings summary

Severity reflects demonstrated scope, not worst-case speculation. No Critical
or High exploit was demonstrated by this review; that is not proof of absence.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F1 | Medium | Legacy/unbounded network controls and inconsistent sender policy | Fixed; deterministic authorization regressions |
| F2 | Medium | Incomplete joins and commit/readiness races | Fixed; deadline/concurrency regressions + Tor lifecycle |
| F3 | Medium | Control/SOCKS and short-write budgets could be extended | Fixed; total deadline/aggregate cap regressions |
| F4 | Medium | Async cancellation, unbounded exit wait, stale IPC work | Fixed; generated-handler/cancellation/cleanup tests |
| F5 | Low | Shape-only onion validation and unchecked SOCKS fields | Fixed; shared strict validation/proof fixtures |
| F6 | Low | Bearer invites exposed by failing test assertions; weak process cleanup | Fixed; bounded redacted harness + live crash tests |
| F7 | Low | Incomplete owned-buffer/history cleanup | Hardened and tested; full forensic erasure not claimed |
| F8 | Low | Transitive GLib unsoundness | Open; no reachability/exploit demonstrated |
| F9 | Informational | Unmaintained serialization/build dependencies | Open; bounded decoding maintained |
| F10 | Informational | Anonymity, delivery and validation-scope overstatements | Documentation/UI corrected; architectural limits remain |

### F1 — Network control authorization (Medium)

- **Description:** Legacy outer participant/shutdown handlers bypassed MLS
  control authentication; arbitrary metadata could accumulate. Connection
  sender checks differed between chat and leave/shutdown.
- **Impact:** Violated the application's authenticated-control policy and could
  produce misleading state/resource growth if an untrusted stream supplied
  these messages. This is not evidence that MLS encryption was broken.
- **Evidence:** `src/session/network.rs`: `handle_joiner_peer_frame`,
  `handle_creator_peer_frame`, `validate_names`, `apply_session_event`.
- **Remediation:** Reject legacy controls on network rooms; bind every received
  member application to the connection's MLS identity; accept owner-only
  Names/Shutdown; replace names with a unique, bounded current-member subset;
  map outer error codes to static text instead of reflecting descriptions.
  Envelope version is now **4** to reject incompatible older peers explicitly.
- **Verification:** Passing tests `outer_controls_are_rejected_and_outer_error_text_is_never_reflected`,
  `all_creator_received_applications_are_bound_to_the_connection`,
  `names_are_owner_only_unique_bounded_current_member_snapshots`, and
  `forwarded_peer_shutdown_never_acquires_owner_authority`.

### F2 — Pending joins, ordering and epochs (Medium)

- **Description:** Pending members were double-counted, could stall forever,
  and could miss a removal commit while joining. Welcome processing alone
  unlocked sending before the creator had confirmed readiness.
- **Impact:** Occupied room slots, inconsistent membership/epoch state or failed
  joins under normal bidirectional ordering. The owner remains an availability
  bottleneck; this fix does not add owner failover.
- **Evidence:** `NetworkRoom::poll_at`, `expire_connections`,
  `handle_join_request`, `handle_pending_ready`, `send_ready_if_needed`,
  `remove_member_and_broadcast`, `SessionManager::receive_authorized`.
- **Remediation:** Serialize joins, 60-second phase deadlines, authenticated
  ReadyAccepted/ReadyRetry, include pending members in commit propagation,
  rollback/close failed fanouts, enforce capacity before receiver merge.
- **Verification:** Passing three-member/fourth rejection, concurrent joins,
  expired Welcome/Ready/confirmation, removal-crossing-Ready and send-failure
  tests. Real Tor test additionally exercises fresh rejoin and crash removal.
  `tests/session_ordering.rs` proves current-epoch reordered messages still
  authenticate once under OpenMLS, without redundant application cryptography.

### F3 — Bounded exchanges and shutdown (Medium)

- **Description:** Per-read/per-write timeouts did not bound an entire short
  read/write sequence. Control replies capped individual lines/blocks but not
  their aggregate or a continuing asynchronous-event stream. Busy control
  shutdown could fail to acquire the lock.
- **Impact:** Local proxy/control stalls or malicious partial network frames
  could hold workers/locks beyond the intended deadline or accumulate replies.
- **Evidence:** `src/transport/tor.rs`: `DeadlineIo`, `ControlBudget`,
  `ControlConnection::command`, `TorDaemon::shutdown`;
  `src/transport/stream.rs`: frame read/write/flush and worker registration.
- **Remediation:** One total exchange deadline; 8 MiB/1024-line aggregate
  control budget, including events; fixed-size cookie read; separate socket
  interruption; aggregate two-second flush; bounded cleanup workers. Partial
  frame timing starts when progress begins, preserving intentional idle rooms.
  Accept stops before worker join; closure tombstones preserve FIFO/exactly-once
  Closed events even under saturated queues. Drop onion cleanup is bounded and
  asynchronous; explicit cleanup supplies a result.
- **Verification:** Passing dribbled SOCKS/control/frame, partial EOF,
  short-write, aggregate flush, busy-control interruption, saturated closure,
  connection-worker-cap and worker-join regressions. Tests run without Tor.

### F4 — Desktop cancellation and stale work (Medium)

- **Description:** Async caller cancellation could drop an operation guard while
  a blocking worker still performed side effects. Exit could wait indefinitely;
  snapshot work and stale events/responses were not sufficiently bounded/scoped.
- **Impact:** Resource duplication or confusing/revived state under concurrent
  IPC, cancellation and closing. No arbitrary-command/key-extraction primitive
  was demonstrated.
- **Evidence:** `app/src-tauri/src/lib.rs`: generated command handler,
  `OperationGuard`, `InFlightLease`, `cleanup_on_exit_with_budget`,
  `validate_session_id`; `app/src/main.js`: session generation/event handling.
- **Remediation:** Worker owns admission through installation/teardown;
  single-flight status/snapshot; one total exit budget; canonical required
  active IDs/role checks; session-scoped events and responses; input bounds.
  Default releases reject local mode, desktop bridge failures reject mocks,
  navigation remains at the packaged origin.
- **Verification:** Passing actual async-cancellation and blocked-snapshot
  tests, generated IPC handler rejection tests, stuck-worker/scheduler/lock
  exit tests, release local-mode gates and frontend stale-response tests.
  Ignored real-Tor generated-handler test passes with the actual network pump.

### F5 — Tor parser and destination validation (Low)

- **Description:** Onion validators previously checked only length/alphabet;
  SOCKS reserved bytes and empty bound domains were not rejected consistently.
- **Impact:** Invalid addresses could pass initial validation, misleading users
  or unnecessarily invoking Tor. Shape checks already excluded clearnet; no
  demonstrated clearnet bypass existed before the fix.
- **Evidence:** Shared `tor::validate_onion_host`, `valid_v3_identifier`,
  `socks5_connect`, `consume_socks_bound_address`, SAFECOOKIE fixtures.
- **Remediation:** Check v3 canonical base32, checksum/version; validate every
  SOCKS response field. SAFECOOKIE uses HMAC `verify_slice`, and bearer comparison
  uses the established `subtle` constant-time primitive, not a handwritten loop.
  Request `NEW:ED25519-V3` with `DiscardPK` and no detached identity.
- **Verification:** Invalid checksum/version/IP/IPv6/domain/extra-label/port,
  malformed reply/rejection/EOF/unavailable listener and incorrect server-proof
  tests pass. Real Tor create/join tests confirm strict validation accepts
  real services. SOCKS bound IPv4/IPv6/domain replies are consumed only;
  they never become connection destinations.

### F6 — Test privacy and child cleanup (Low)

- **Description:** The former failing JOIN assertion interpolated its complete
  bearer invitation. Fixed sleep settling and blocking response reads could
  obscure failure or strand child processes.
- **Impact:** Test transcript/log readers could obtain a live invitation and
  failed runs could retain owned peer/onion resources. No real-user invitation
  is included in this report or committed fixtures.
- **Evidence:** `tests/tor_network.rs`: `PeerProcess::request`, Drop,
  `wait_for`; `src/bin/ghostchat-peer.rs`: `read_command`.
- **Remediation:** Print command verb only, redact response details, bound
  response/condition/exit waits, reap children on all paths, and limit CLI lines
  to 32 KiB before allocation. Retry only pre-room transport-establishment
  failures, never sends or commits. Expected capacity rejection is checked
  specifically, not ignored as a generic error.
- **Verification:** Normal CLI boundary test and both live ignored process
  tests pass. A first expanded test run failed because the harness classified
  the owner's expected fourth-member refusal as an error; the specific
  expectation was corrected and the complete tests rerun successfully.

### F7 — Sensitive state and memory (Low)

- **Description:** Terminal paths retained owned room/invitation/join buffers;
  deterministic local history/queues could grow, and serialized provider copies
  were not explicitly erased on teardown.
- **Impact:** Unnecessary memory retention and growth. This finding does not
  mean that private keys or history were written to disk.
- **Evidence:** `NetworkRoomInner::drop`, `close_room`,
  `CryptoManager::clear_storage`, `LocalRoom::shutdown`, local transport caps,
  frontend terminal reset and 500-message cap.
- **Remediation:** Central idempotent terminal cleanup; best-effort zeroization
  of owned token/invitation/history/provider buffers; drop MLS/join material;
  clear DOM/drafts; cap local/core/frontend history and deterministic queues.
  Last-owner Arc destruction closes resources even for concurrent handle drops.
- **Verification:** Passing teardown/provider-copy, concurrent-drop, bounded
  local-history/queue, fresh-rejoin and abrupt-creator tests. Returned snapshots
  and upstream/JS/OS copies are **not** proven erased.

### F8 — GLib upstream unsoundness (Low, open)

- **Description:** RustSec `RUSTSEC-2024-0429` flags `glib 0.18.5` used through
  GTK3/Tauri. Its VariantStrIter implementation passes an incorrectly mutable
  pointer; optimized iteration can dereference NULL.
- **Impact:** Potential crash/undefined behavior if affected iteration is
  reached. This review did not demonstrate a GhostChat network/IPC route to it.
- **Evidence:** Lockfile, `cargo tree -p ghostchat-app -i glib`, advisory's
  affected functions. Targeted source checks found no `VariantStrIter` or
  `.str_iter()` call in the inspected Tauri/GTK/GIO/WebKit wrapper sources;
  this is bounded evidence, not full transitive reachability proof.
- **Remediation:** **Not fixed.** Upstream patched range is GLib >=0.20, not a
  drop-in compatible replacement for this GTK3 dependency graph. Evaluate a
  compatible upstream migration or reviewed backport before a high-assurance
  release; do not force an incompatible crypto/GUI upgrade to silence audit.
- **Verification:** cargo-audit still reports this unsoundness warning. Native
  startup rendering succeeds, but that is not proof the affected APIs are safe.

### F9 — Dependency maintenance (Informational, open)

- **Description:** RustSec reports eight unmaintained packages: bincode 1.3.3,
  proc-macro-error 1.0.4, proc-macro-error2 2.0.1, unic-char-property,
  unic-char-range, unic-common, unic-ucd-ident and unic-ucd-version (0.9.0).
- **Impact:** Future maintenance risk, not a demonstrated runtime exploit.
- **Evidence:** cargo-audit 0.22.2; database fetched at commit
  `ef6173cbc5c50ec8166f9a5b28f07834144373ee`, updated October 3, 2026.
- **Remediation:** Retain bounded fixed-width serialization with rejection of
  trailing data. Plan a versioned format migration separately. Unused direct
  `log`, `anyhow`, and full-featured test Tokio were removed; serde_json is
  test-only. Yanked yoke-derive 0.8.3 was upgraded only to compatible 0.8.4.
  OpenMLS remains pinned at 0.9.0. Crypto duplicates follow upstream version
  requirements and were not forcibly unified.
- **Verification:** Final scanner reports zero vulnerability-class advisories,
  eight unmaintained and one unsoundness warning, no yanked warning. All warnings
  remain disclosed; scanner exit zero is not equivalent to "dependency clean".

### F10 — Accurate privacy/delivery claims (Informational)

- **Description:** Blanket "no trail"/preview-encryption promises and treating
  a successful enqueue as confirmed delivery overstated guarantees. README
  Tauri commands used an unsupported `--manifest-path` argument.
- **Impact:** Users could rely on privacy or delivery guarantees not supplied
  by this architecture, or fail to build the intended app.
- **Evidence:** Frontend status/sending code, README commands, Tor flush API.
- **Remediation:** Preview sends disabled; visible readiness/Tor/room states;
  sent messages labeled unconfirmed; explicit threat/persistence model;
  correct CLI working directory; protocol-4 compatibility notes.
- **Verification:** Frontend runtime/preview/pending/send/status/late-event tests
  pass; Playwright desktop/mobile preview inspected with zero console errors.
  Real native Linux home renders **Tor ready**, not browser preview.

| Before | After | Why |
| --- | --- | --- |
| Possible desktop-to-preview fallback | Desktop IPC failure locks actions | Never imply a real encrypted room when the bridge failed |
| Welcome alone enabled sending | Welcome plus creator confirmation | Reflect actual membership readiness |
| Successful send presented without receipt distinction | Queued / delivery unconfirmed | Socket enqueue is not remote delivery |
| "No trail" language | Session-scoped state plus explicit OS/clipboard limits | Avoid unsupported anonymity/erasure promises |

## Confirmed vulnerabilities

No new unremediated application vulnerability was confirmed in the current
working tree. Historical confirmed findings F1–F7 were fixed or hardened and
have deterministic regressions; no Critical or High exploit was demonstrated.
F8 is an open transitive dependency unsoundness warning, not a demonstrated
GhostChat exploit.

## Potential weaknesses and hardening opportunities

- **Open dependency risk:** RustSec still flags GLib 0.18.5 unsoundness and
  eight unmaintained packages. A reviewed GTK/GLib migration or backport is
  required for a higher-assurance release.
- **Availability:** the creator is the relay and commit authority; an attacker
  who knows the invitation can occupy bounded join/handshake capacity. There
  is no failover or offline delivery.
- **Bearer invitation model:** a member who retains the invitation can retry
  with a fresh ephemeral identity after removal. The token is not a human
  identity proof and is reusable until room shutdown.
- **Privacy model:** Tor does not prevent traffic analysis, global timing
  correlation, endpoint compromise, screenshots, clipboard retention, swap,
  WebView/OS caches or telemetry.

## Protocol/state-machine results

Invalid outer controls, unsupported versions, malformed/truncated frames,
duplicate Welcome/commit/application messages, future/old epochs, stale room
events, unauthorized role transitions, concurrent joins, join timeouts and
fresh-rejoin ordering were rejected, disconnected, or closed fail-closed in
the exercised paths. The room deliberately has no owner failover; callers must
drive `poll` for pending-phase expiry.

## MLS security results

OpenMLS performed signature, group, epoch, ratchet and ciphertext validation.
GhostChat additionally enforced the three-member cap, invitation-bound group
and creator identity, connection-to-MLS-sender binding, creator-only commits,
authenticated owner controls and readiness gating. Replay and old-epoch
application regressions passed. This is not MLS formal verification or a
cryptographic proof.

## Tor/network results

SOCKS5 is loopback-only, uses onion-host requests, validates v3 checksum/version
and rejects malformed replies. Control-port parsing has CRLF, line/count,
aggregate-byte and total-deadline bounds; SAFECOOKIE server proof is verified.
Adversarial local SOCKS/control fixtures and two opt-in real-Tor process tests
passed. No clearnet fallback or direct peer destination path was found in the
reviewed implementation.

## DoS/resource-exhaustion results

Envelope, invitation, frame, queue, connection, worker, message-history,
control-reply, CLI-line and frontend-input bounds were exercised. Slow/partial
readers, short writers, saturated queues, invalid joins and blocked cleanup
were tested. Near-limit inputs still consume bounded CPU/memory, and a known
invitation holder can cause availability pressure; no unbounded growth or
crash was demonstrated.

## Concurrency results

Join serialization, removal crossing readiness, disconnect/message ordering,
worker cleanup, saturated closure delivery, cancellation, blocked snapshots,
stuck scheduler/locks and bounded desktop exit were exercised. No deadlock,
task leak or state resurrection was reproduced in the tested scenarios.

## Tauri/frontend results

Commands validate bounded canonical inputs, session identity and creator role;
release builds reject requested local transport. IPC cancellation and stale
responses/events are scoped, navigation is restricted to the packaged origin,
and rendering uses text nodes rather than HTML injection. Frontend tests and
desktop/mobile browser smoke checks passed with zero console errors; a full
three-native-WebView end-to-end test was not run.

## Dependency/supply-chain results

`cargo-audit 0.22.2` reported zero vulnerability-class advisories, one
unsoundness warning (`RUSTSEC-2024-0429`, GLib 0.18.5), and eight unmaintained
packages. No managed scanner or source upload was used. Duplicate crypto
versions are inherited from OpenMLS and were not forcibly unified.

## Static-analysis results

Formatting, workspace check, tests and Clippy with `-D warnings` passed. The
reviewed application source contains no unsafe blocks, shell/process command
surface, arbitrary frontend URL navigation or application logging sink. The
remaining `unwrap`/`expect` uses are in tests or after local invariant checks;
the report does not treat that scan as a proof of panic-freedom.

## AI red-team results

Reasoning passes for malicious creator, joiner, existing member, compromised
endpoint, network observer, local process, frontend input and Tor endpoint
produced the bearer-invite, owner-availability, traffic-analysis and local
compromise limits documented above. No additional reproducible authorization,
confidentiality or integrity exploit was validated.

## Fixed vulnerabilities and regression tests

F1–F7 are documented with affected components, impact, remediation and test
names above. Regression coverage includes decoder bounds, invitation tampering,
MLS replay/order/capacity, authenticated controls, join deadlines/races,
SOCKS/SAFECOOKIE/control limits, stream deadlines/queues/cleanup, subprocess
failure paths, Tauri cancellation/stale sessions and frontend preview/send
state. The audit-only fuzz harness is separate from production behavior.

## Security assumptions

The user verifies invitations out of band; the local OS, bundled WebView and
Tor daemon are trusted; OpenMLS 0.9.0 and its configured ciphersuite provide
their documented guarantees; participants can read/copy plaintext; and the
threat model excludes a compromised endpoint or global traffic-analysis
observer. Runtime cleanup is best effort, not forensic erasure.

## What was not verified

No independent pentest, Strix exploitation run, exhaustive fuzzing campaign,
formal MLS proof, constant-time audit, isolated multi-daemon/device test,
full native multi-window chat test, package installation/signing check, or
macOS/Windows/AppImage build was completed. See the operational limitations
below for the full release gaps.

## Overall risk rating

**Medium risk for a hardened prototype; not high-assurance release-ready.**
The reviewed application boundaries have no demonstrated Critical/High issue,
but the open GLib warning, owner/availability architecture, bearer-invite
semantics, endpoint privacy limits and incomplete independent validation rule
out a clean security sign-off.

## Privacy and anonymity assessment

- **Network:** Tor hides direct peer IP addresses under its intended model.
  Local-network/ISP observers can identify Tor use; global traffic analysis,
  packet-length/timing correlation and room-creation correlation are not solved.
  There is no traffic padding, cover traffic or fixed-rate transmission.
- **Participants:** The owner and every member can read/copy messages. Invite
  holders know the onion endpoint, room introduction, creator public key and
  bearer token. Members learn names, ephemeral IDs, epochs and membership.
  Owner serialization avoids competing commits but cannot prevent owner DoS.
- **Invitation:** The Ed25519 signature genuinely binds the token to endpoint
  and room fields; the token is an authorization bearer capability, not merely
  an identifier and not a human identity proof. Trust in the creator still
  comes from the out-of-band invitation channel. It is reusable until shutdown.
  Removal is not a ban for a person retaining the invite and generating new keys.
- **Endpoint:** Local compromise, screen capture, clipboard retention, browser
  debugging, swap/hibernation/core dumps, OS telemetry and upstream memory copies
  defeat or exceed the protections. No forensic-erasure claim is made.
- **Persistence/logs:** GhostChat has no history/key database or JS storage.
  Source contains no application console/log/tracing/debug-print sinks or unsafe
  blocks. CLI stdout is an explicit response channel, including CREATE's sensitive
  invite. Error events are bounded operational text; protocol/MLS bytes are not
  printed. Tor/GTK/WebView/OS diagnostics and external test captures are separate
  and may persist. Clear the clipboard yourself; clearing it cannot recall copies.

## Remaining operational and validation limits

1. GLib unsoundness and eight maintenance advisories remain. A high-assurance
   public release needs a reviewed GUI dependency/backport strategy and ongoing
   dependency monitoring; this pass did not independently pentest the product.
2. Owner disappearance ends the room; no failover, offline delivery, durable
   receipts or transparent MLS resume. Send/flush confirms local queuing/writing,
   never the recipient's receipt. Reject reasons may be lost when a stream closes.
3. Established authenticated quiet rooms intentionally have no idle eviction or
   heartbeat. Unjoined/pending phases expire through `poll`; library callers
   must drive it. Tor failure detection and OS scheduling can delay closure.
4. Queue and frame count bounds prevent unlimited accumulation, but adversarial
   near-limit frames can still consume substantial bounded memory/CPU. There is
   no claim that every tiny-memory platform can withstand maximum-load abuse.
   An attacker knowing the onion endpoint can occupy limited handshake slots;
   expiration mitigates but cannot eliminate denial of service. The configured
   shared Tor daemon, rather than GhostChat, manages circuit isolation/lifetime.
5. Busy joins are rejected for fresh retry. Epoch changes crossing in-flight
   application traffic can cause fail-closed disconnection instead of resync.
6. Normal network shutdown joins its reader/writer/accept workers. Desktop exit
   uses one two-second cleanup budget; still-running bounded workers may be
   terminated by process exit rather than deliver an authenticated shutdown.
   Filesystem reads/OS facilities are not cancellable with hard real-time bounds.
7. Tests used one existing local Tor daemon, not isolated daemons, separate
   physical devices or hostile public networks. Raw SOCKS port 9150 success was
   supplied as earlier context, not re-verified in this pass.
8. Native Linux home/status rendering was checked under D-Bus/Xvfb. Plain Xvfb
   initially timed out; isolated D-Bus allowed rendering and showed Tor ready.
   A later native create-click attempt did not reach a visible window within its
   startup deadline; it is not counted as a passed native create test. Full
   multi-WebView end-to-end chat and macOS/Windows packaging remain unverified.
9. Seeded decoder regressions and static review are not exhaustive fuzzing,
   constant-time proofs, MLS formal verification, or an OS-level telemetry audit.

## Fuzzing results

This audit also ran bounded local libFuzzer sessions with `cargo-fuzz 0.13.2`
using the available Rust nightly toolchain (`rustc 1.101.0-nightly`). The first
stable-toolchain invocation was rejected by cargo-fuzz because its sanitizer
build uses nightly-only `-Z` flags; that failed build was not counted as a test
result. The nightly runs completed without crashes, hangs, sanitizer findings,
or crash artifacts:

| Target | Harness | Seed corpus | Duration | Executions | Final coverage | Peak RSS |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| `fuzz_target_1` | Versioned/bounded `Envelope::decode` with valid envelope seeds and mutations | 130 files / 3,115 B | 30 s | 1,821,525 | 331 PCs / 439 features | 83 MiB |
| `fuzz_session` | Length-prefixed stateful operation sequence into `SessionManager::receive_envelope_bytes` | 860 files / 55,891 B | 30 s | 33,691 | 4,621 PCs / 6,041 features | 195 MiB |

These targets exercise decoder and session-operation boundaries, rather than
claiming full coverage of room lifecycle, Tauri IPC, MLS formal state space, or
the Tor daemon. Deterministic adversarial tests cover those additional
boundaries; no continuous fuzzing campaign, coverage-guided Tor-control target,
or independent pentest was performed.

## Files changed in this hardening pass

- `Cargo.toml`, `Cargo.lock`, `app/src-tauri/Cargo.toml`: minimal dependencies,
  compatible yanked-package patch, explicit development release gate/test support.
- `src/transport/tor.rs`, `src/transport/stream.rs`, `src/transport/mod.rs`:
  destination/control/SOCKS/framing/deadline/cleanup/local queue hardening and tests.
- `src/session/network.rs`, `src/session/mod.rs`, `src/session/local.rs`:
  authentication, readiness, joins, member cap, cleanup and bounded local history.
- `src/crypto/mod.rs`, `src/protocol/mod.rs`: memory-provider teardown,
  ciphersuite health check and protocol-4 compatibility boundary.
- `src/bin/ghostchat-peer.rs`, `tests/tor_network.rs`: bounded/redacted
  subprocess harness and real-Tor leave/rejoin/crash/refusal cases.
- `tests/decoder_robustness.rs`, `tests/session_ordering.rs`: new public decoder
  corpus/boundary and OpenMLS out-of-order regressions.
- `app/src-tauri/src/lib.rs`, `app/src-tauri/tauri.conf.json`,
  `app/src/main.js`, `app/src/index.html`, `app/tests/frontend.test.cjs`:
  IPC/lifecycle/navigation/CSP/status/privacy improvements and regressions.
- `README.md`, `SECURITY_AUDIT.md`: current setup, threat model, review and receipts.

Other pre-existing uncommitted files, icons and workspace changes were preserved.
The audit-only workspace also contains an uncommitted `fuzz/` harness, seed
corpora under `corpus/`, and generated local fuzz corpora; these are not
production behavior changes.

## Test evidence and exact verification commands

Linux x86_64; Rust/Cargo 1.98.0, Tauri CLI 2.11.5, Node 26.5.0.
The normal workspace run discovers **141 passing Rust tests**:
118 core + 1 CLI unit + 4 decoder + 1 ordering + 1 CLI-process + 16 desktop;
three real-Tor tests remain appropriately ignored in that run.
Frontend tests: **10 passed**. Both opt-in Tor process tests passed; the
actual generated-handler Tor desktop test passed separately. No Tor test was
faked, removed, or newly ignored to conceal an implementation failure.

From the repository root, executed:

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --test tor_network -- --ignored --nocapture
cargo test -p ghostchat-app --lib real_tor_backend_create_join_send_poll_shutdown -- --ignored --test-threads=1
node --check app/src/main.js
node --test app/tests/frontend.test.cjs
git diff --check
```

All commands above passed. Final process tests include
`three_independent_processes_complete_tor_mls_lifecycle` and
`creator_disappears_and_joiner_clears_runtime_state`.

Additional targeted checks included `cargo test --test decoder_robustness
--test session_ordering`, JSON configuration parsing, relevant graph coverage,
source privacy/unsafe scans, and `cargo tree -d` / inverse GLib/Yoke dependency
traces. cargo-audit was installed in a temporary tooling directory, not added
to project/global settings:

```sh
cargo install cargo-audit --locked --root /tmp/opencode/ghostchat-audit-tool
/tmp/opencode/ghostchat-audit-tool/bin/cargo-audit audit --json
/tmp/opencode/ghostchat-audit-tool/bin/cargo-audit audit --no-fetch --json
```

The bounded fuzz commands were:

```sh
cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=30 -rss_limit_mb=768
cargo +nightly fuzz run fuzz_session -- -max_total_time=30 -rss_limit_mb=768
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
```

Scanner warnings are explained in F8/F9. An initial shell wrapper used zsh's
read-only `status` variable and failed after the scanner had produced its JSON;
the JSON was inspected and the corrected final scanner command passed. This
wrapper failure is not reported as a clean scanner result.

Playwright used a dedicated ephemeral test browser with desktop 1280×800 and
mobile 390×844 layouts, create-preview and chat-lock interactions, and console
inspection (zero errors/warnings). It never captured real invitations/chat.
Native rendering used isolated `dbus-run-session` / `xvfb-run`, observing the
actual packaged frontend/backend status path; startup/environment warnings
are retained as limitations above, not claimed as application console success.

Release checks (default features, from `app/src-tauri`):

```sh
cargo test -p ghostchat-app --release --lib
cargo tauri build --bundles deb
```

The optimized desktop suite passed **17 tests**, with its live Tor case ignored
in that command (and passed separately above). Default-release rejection of
requested local transport is explicitly exercised. Release startup/rendering
also succeeded under isolated D-Bus/Xvfb and showed **Tor ready**.
The Debian package is structurally valid; package description metadata was
filled instead of leaving `(none)` during final inspection. The exact artifact
is `target/release/bundle/deb/GhostChat_0.1.0_amd64.deb`. AppImage, cross-platform
packages, signing and a full package installation were not verified.

Final Debian SHA-256:
`6b5a0417ba0155132366c261f879a054e38c41072fbe98ed333d3470b57c31b6`.
The final two process tests completed in 115.96 s and the Tauri Tor handler
test in 43.03 s; Tor publication/retries vary, so no 45-second guarantee is made.
A combined invocation from the app directory initially selected the wrong
package for `--test tor_network`; the target was rerun successfully from the
repository root. This was a command-selection error, not an ignored failing test.
