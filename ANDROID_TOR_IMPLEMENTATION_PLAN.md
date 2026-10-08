# Self-contained Android Tor: feasibility and implementation plan

Date: 2026-10-09. Status: **Android supervisor/provider integration is implemented. Tor 0.4.9.14 was built from the signature-checked official release source, and ARM64 debug/release APKs plus an AAB were built and inspected with `libtor.so` packaged. No device runtime test has been performed.**

## 1. Decision

**A self-contained Android implementation is technically feasible without
replacing GhostChat's TorTransport, OpenMLS, invitations or wire protocol.**
Use the maintained **C Tor Android native runtime**, with a GhostChat-owned
supervisor, authenticated loopback endpoints and app-private state. The leading
candidate is Guardian Project's `tor-android` native payload. The inspected
release is `0.4.9.13.2`, containing Tor `0.4.9.13` and OpenSSL `3.5.9`.

Do **not** adopt its stock `TorService` or blindly import its complete AAR:

- The stock service explicitly supplies `CookieAuthentication 0`, authenticates
  with an empty value, uses a Unix control socket, and enables an HTTP tunnel.
  GhostChat requires authenticated TCP control and SOCKS-only application
  networking. A torrc override is insufficient because the service supplies
  the authentication setting on the command line. [S1]
- The inspected AAR requires compile SDK **37.1** and contains Java **24**
  classfiles. GhostChat uses compile/target SDK 36, Java 21 on the build host,
  and Java/Kotlin target 1.8. Native-only packaging avoids importing this
  incompatible Java/Gradle surface or changing the desktop toolchain.
- The Maven POM says BSD-3-Clause, but the native build enables GPL mode.
  **The binary itself contains a GPL license notice.** Licensing is an
  implementation/distribution gate, not a detail to infer from the POM. [S2–S4]

Recommended delivery: a native-only `libtor.so` plus a small, reviewed JNI
bridge to Tor's public C embedding API, running once in a private Android
worker process. A main-process foreground session service supervises that
worker and keeps the Rust session process important while backgrounded.

### Implementation status update

The Android-only Rust provider, SAFECOOKIE/runtime lease integration, Tauri
native plugin, foreground session service, private `:tor` worker, JNI symbol
bridge, generation-scoped lifecycle handling, and consumer UI work are present.
The Guardian recipe builds Tor 0.4.9.14 from the official source archive for
`arm64-v8a`; its checksum/signature, pinned dependencies, local recipe patches,
licenses, corresponding-source archive and SBOM are recorded in the working
tree. The debug APK, unsigned release APK and unsigned release AAB all include
the built library. ELF exports and artifact paths are verified. Android
`dlopen`, Tor startup, SAFECOOKIE and room workflow remain unverified without a
device or emulator. See [ANDROID_RELEASE.md](ANDROID_RELEASE.md) for the final
artifact hashes and signing state.

## 2. Repository evidence and required protocol contract

Baseline: repository HEAD `cb84549`, plus the existing uncommitted Android
scaffold and other user changes. Source was inspected directly. The local
codebase graph service reported zero indexed projects, so no graph-derived
coverage or call-chain claim is made.

| Requirement | Actual implementation |
| --- | --- |
| Local endpoints only | `src/transport/tor.rs:231–271`: both SOCKS/control addresses must be loopback; socket timeouts are nonzero and capped at 300 seconds. |
| Control discovery | `tor.rs:351–378`: TCP connection, `PROTOCOLINFO 1`, COOKIE/SAFECOOKIE methods and a 32-byte cookie file. An explicit cookie path already overrides the daemon-reported path. |
| Control authentication | `tor.rs:1432–1486`: `AUTHCHALLENGE SAFECOOKIE <32-byte client nonce>`, verify the server HMAC, then `AUTHENTICATE <client HMAC>`. COOKIE is used only when SAFECOOKIE is absent. No NULL/password-only acceptance. |
| Readiness | `tor.rs:418–442`: authenticated `GETINFO status/bootstrap-phase`; parse bounded numeric `PROGRESS` in 0–100. `src/transport/stream.rs:114–163,210–219` requires 100 for both host and join. |
| Hosting | `tor.rs:444–465,589–632`: bind `127.0.0.1:0`; issue `ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:<allocated-port>`; validate returned ServiceID. Virtual port 80 transports GhostChat bytes, not HTTP. |
| Onion teardown | `tor.rs:468–478,688–742`: `DEL_ONION <ServiceID>` on its creating connection, or close that connection. No `Detach`; shutdown interrupts control rather than blocking indefinitely. |
| Outbound SOCKS | `tor.rs:907–982`: SOCKS5 greeting `05 01 00`, then CONNECT (`CMD=01`) with domain-name address type (`ATYP=03`), the complete onion hostname and big-endian destination port. |
| Strict destinations | `tor.rs:1021–1078`: exact lowercase 56-character base32 v3 label plus `.onion`; validate decoded version byte and SHA3 checksum. Reject URLs, IPs, ordinary DNS, extra labels, noncanonical identifiers and port zero before connecting. |
| Bounded replies | `tor.rs:32–39,512–575`: CRLF parsing, bounded status/data/aggregate reply sizes, total-operation deadlines, consume interleaved 650 events; close a desynchronized connection. |
| Encrypted room behavior | `src/session/network.rs:262–271,342–358`: `create_with_tor` / `join_with_tor` already accept an explicit `TorConfig`. `591–669` sends encrypted shutdown/leave, flushes locally, closes transports and clears owned session material. |

**Control operations currently used:** PROTOCOLINFO, AUTHCHALLENGE,
AUTHENTICATE, GETINFO bootstrap, ADD_ONION and DEL_ONION. GhostChat does not
currently need SETCONF, SETEVENTS, RESOLVE, an HTTP proxy, VPN APIs or Tor
network-relay functionality. Its creator is an application ciphertext relay;
this is different from operating a Tor relay.

**Small additional supervisor operations:** authenticated `GETINFO
net/listeners/socks`, optionally `GETINFO version`, `TAKEOWNERSHIP`, and
`SIGNAL SHUTDOWN` (optionally HALT for bounded escalation). These should be
typed, bounded native APIs, not arbitrary frontend control commands. [S5]

The present SOCKS greeting is intentionally no-username/no-password. That
does **not** mean control authentication can be disabled. Preserve the current
SOCKS handshake and require cookie-authenticated control.

## 3. Candidate comparison

| Candidate | Android/ARM64 and required capabilities | Fit / licensing / native requirements |
| --- | --- | --- |
| Guardian C Tor native payload + owned wrapper | Published Android API-24+ ARM64 binary; C Tor SOCKS5, SAFECOOKIE control, v3 onion hosting and exact ADD_ONION semantics. | **Recommended runtime family.** Native-only package, own lifecycle/configuration. Inspect GPL-mode licensing; OpenSSL/libevent/zlib/zstd are statically included. JNI bridge needed for the recommended embedding mode. |
| Same maintained C Tor as a packaged subprocess | Upstream README explicitly supports using `libtor.so` directly as a daemon; inspected ELF has an executable entry point and Android linker interpreter. Same protocol capabilities. | Viable alternative spike. Execute only OS-installed APK native code, never a binary copied into writable app storage. Requires native-library extraction/packaging and device execution checks; Kotlin ProcessBuilder supervision can avoid Tor C FFI. Not the initial recommendation because packaging/execution behavior needs validation across target devices. |
| Arti / Arti Mobile | Current Arti supports SOCKS and onion services; Android JNI/mobile integrations exist. MIT OR Apache-2.0 at the Arti crate level; selected TLS/crypto/storage and mobile-wrapper dependencies need their own audit. | **Not a drop-in replacement.** Official docs say C Tor control protocol is unsupported; Arti uses a different RPC/API. SAFECOOKIE, ADD_ONION/DiscardPK and connection-owned teardown would require a substantial compatibility layer or transport change. Size/native dependency set depends on selected features and was not measured. [S6–S8] |
| Rust `libtor` / `libtor-sys` | Documents Android NDK cross-compilation and bundles C Tor/OpenSSL/libevent/zlib; can offer the same C Tor control/SOCKS interfaces. | Published latest docs identify `47.13.0+0.4.7.x`, an old Tor family. MIT wrapper does not license away bundled dependencies. Do not ship this old runtime merely for easier Rust integration; a maintained-source update, NDK validation and security ownership would be necessary. Not preferred. [S9] |

Arti is rejected here for **interface compatibility**, not because onion
services are impossible in Arti. Some upstream compatibility pages contain
old 2023 wording; the current landing page and crate features explicitly
include onion-service support. Neither Orbot nor Tor Browser is a runtime
dependency of the proposed design.

## 4. Inspected artifact, native libraries and size

Artifact: `info.guardianproject:tor-android:0.4.9.13.2`, fetched at immutable
gpmaven commit `8654669c6ead4b9f987dc5691550f4f081a1ccc2`.
The release changelog dates it October 5, 2026. [S2,S10]

| Measurement | Result |
| --- | --- |
| Whole four-ABI AAR | 12,960,573 bytes, approximately 12.36 MiB compressed |
| ARM64 `jni/arm64-v8a/libtor.so` | 7,575,472 bytes, approximately 7.22 MiB uncompressed |
| ARM64 member in the AAR | 3,121,205 bytes, approximately 2.98 MiB compressed |
| All four native libraries | 30,059,412 bytes, approximately 28.67 MiB uncompressed |
| ARM64 architecture | ELF64, AArch64, Android `/system/bin/linker64` interpreter |
| ELF LOAD alignment | All LOAD segments use `0x4000` / 16 KiB alignment |
| Dynamic dependencies | `libm.so`, `liblog.so`, `libdl.so`, `libc.so` — Android system libraries |
| Native API exports | `tor_main_configuration_new`, `tor_main_configuration_set_command_line`, `tor_run_main`, `tor_main_configuration_free`, `tor_api_get_provider_version` |
| Embedded version strings | Tor `0.4.9.13`, source prefix `8aa9ce2e4e3332ef`; OpenSSL `3.5.9` |
| Complete AAR compatibility | `minSdk=24`; `minCompileSdk=37`, `minCompileMinorSdk=1`; all six Java classes have classfile major 68 / Java 24 |

The native recipe statically links OpenSSL, libevent, zlib and zstd. No separate
`libssl.so`, `libcrypto.so`, `libevent.so`, zstd library or C++ shared runtime
is required by the inspected ARM64 library. A new JNI bridge would itself be
packaged and should avoid adding a C++ runtime unnecessarily. [S3]

Artifact SHA-256:
`40be745450a8ecfaac8558950bf046f596d7ef6e88107f69334a8c4b6e7d14be`.
ARM64 library SHA-256:
`25fb2bb6b7f23db1f7f56eb8444cae365ccdfe75dfa803f72c6bbaad03db63a2`.
These are inspection/reproduction checksums, **not verification of a trusted
publisher's signature**. Verify the available detached signature against an
independently trusted maintainer key before using a prebuilt in a deliverable.

There are no `assets/` entries in this AAR. GeoIP databases and pluggable
transports are not part of the measured payload. If later required, their
size and licenses must be counted separately; do not assume a complete
censorship-circumvention bundle is included.

The existing debug APK is 204,691,471 bytes (about 195.21 MiB). With its current
uncompressed native-library packaging, adding this ARM64 library alone would
add about 7.22 MiB, producing a rough 202.43 MiB baseline plus JNI, service
classes, resources and alignment overhead. This is **an estimate, not a rebuilt
APK measurement**. A compressed-native packaging mode could approach the AAR
member's 2.98 MiB contribution, but installed size, extraction and existing
Rust-library packaging would also change. Filter ABIs explicitly; otherwise a
four-ABI dependency can silently enlarge the APK. RSS/battery cannot be
inferred from library file size.

Upstream native source builds currently require NDK r30 / `30.0.16248370`
for reproducibility. GhostChat's installed r29 can still be evaluated for
building a C bridge against an existing C ABI; this is not proof of link/load
compatibility. Keep any Tor source-build toolchain isolated from desktop
settings. [S3]

This section records an inspected AAR reference artifact only; that AAR and its checksum were **not used**. The shipped working-tree payload is the source-built artifact documented in section 15.

## 5. Licensing implications — required gate

Tor and the Android wrapper normally advertise BSD-3-Clause, but that is **not
the complete license of the inspected binary**:

1. Guardian's pinned `external/Makefile` passes `--enable-gpl`.
2. The matching Tor `configure.ac` explicitly describes this as building Tor
   and libtor under the GPL rather than their usual BSD license.
3. It enables the optional onion proof-of-work module in that mode; bundled
   Equi-X and HashX carry LGPL-3.0 license files.
4. The inspected library's own strings state: “This build of Tor is covered
   by the GNU General Public License”, linking GPL-3.0. [S3,S4,S11]

Therefore treat this native binary as GPL-covered for distribution planning,
not as an entirely permissive BSD AAR. Removing the Java service or placing
the runtime in another process does not remove binary redistribution duties.
Determine applicable corresponding-source, notice, linking/relinking and
installation-information obligations for the chosen native bridge/APK with
appropriate licensing review. This report is not legal advice and does not
assume that every component of the APK must automatically be relicensed.

Other required notices include Tor's bundled permissive components,
OpenSSL 3.x (Apache-2.0), libevent (BSD), zlib and zstd (choose an applicable
license from its BSD/GPL dual licensing). If GeoIP databases are added, Tor's
license file identifies CC BY-SA 4.0 data obligations. Audit the exact selected
source commits, not the Android project's old omnibus Orbot/Privoxy text. No
Privoxy or Orbot application code is needed here.

Possible decisions:

- Use the maintained GPL-mode runtime with a compatible distribution/compliance
  plan and a reviewed bridge.
- If a permissive-only binary is required, explicitly review a maintained Tor
  source build without optional GPL-mode code. It can still supply the
  currently required non-PoW ADD_ONION/control operations, but changes optional
  DoS capabilities and demands a separate security/interoperability review.
  **Do not silently disable protection just to resolve licensing.**

GhostChat's root currently has no standalone license file; this investigation
does not invent a distribution license or approve either option. A pinned
native manifest, SBOM, third-party notices, source/build provenance and a Tor
security-update process are required before distribution.

## 6. Original integration boundary and repository changes

Keep the data path:

`GhostChat Rust → NetworkRoom → TorTransport → local authenticated control /`
`SOCKS5 → app-owned C Tor → Tor network → v3 onion peers`.

Add the following Android-only pieces; names below are proposed, not files
already implemented:

| Location | Planned change |
| --- | --- |
| `app/src-tauri/src/android_tor.rs` (new) | Runtime manager/state machine, generation-bound leases, explicit managed `TorConfig`, redacted status and loss/stop coordination. |
| `app/src-tauri/src/lib.rs` | Add an Android-only provider/plugin setup. Replace all three environment configuration reads at create (`506`), join (`533`) and status (`1082`) with a provider: desktop still calls `TorConfig::from_env`; Android uses only its owned runtime. Coordinate terminal room cleanup and pending operation generations. |
| `src/transport/tor.rs` | Small additive typed supervisor methods using the existing authenticated connection/parser/deadlines; an Android managed-runtime SAFECOOKIE-required policy while retaining the desktop COOKIE compatibility policy. No replacement SOCKS/control implementation. |
| `gen/android/app/src/main/java/org/lord/ghostchat/tor/` (new) | Tauri-native coordinator/plugin, main-process `GhostChatSessionService`, private `GhostChatTorWorkerService`, Binder contract, JNI runner, notification/Stop handling. All services non-exported. |
| `gen/android/app/src/main/cpp/` (new) | Minimal C JNI bridge using only the exported public Tor API; documented argument/configuration ownership and one Tor run per worker process. |
| Android Gradle/native configuration | Package only the selected verified ABI payload and bridge, with pinned provenance/checksum verification and offline-capable build caching. Do not import the incompatible upstream service/classes/transitive jtorctl dependency. Keep custom source separate from build-generated Tauri files. |
| Android manifest/resources | Foreground service declarations/permissions, private `:tor` worker process, generic notification/Stop action, explicit backup/data-transfer exclusions. No storage permission, VPN service or arbitrary IPC/configuration exposure. |
| Tests and docs | Android instrumentation/lifecycle/runtime tests, managed-config and generation-race regressions, privacy/network tests, notices/SBOM, revised Android instructions and limitations. |

No changes are needed to the OpenMLS provider/ciphersuite, `EphemeralIdentity`,
invitation signatures/token rules, versioned envelopes, participant cap,
framing, onion validation, or the normal host/join transport abstraction.
Do not change frontend proxy settings or add a WebView direct-network rule.

Use Tauri 2.11.6's existing native plugin support to bridge Rust coordination
to Kotlin; the installed runtime exposes `register_android_plugin` and
`run_mobile_plugin`. Keep lifecycle callbacks and owned endpoint/cookie-path
metadata in native code, not JavaScript. No Rust Tor C FFI is necessary if
the worker uses the small JNI/C bridge. Any new dependency should be Android-
scoped, locked and kept separate from MLS versions.

## 7. Authentication and sandbox storage

Both GhostChat processes must have the **same application UID**. The Tor worker
is a non-exported `android:process=":tor"` service, not an `isolatedProcess`
service with a different UID. This permits the existing Rust cookie reader to
read only GhostChat's own cookie; no file sharing, filesystem permission grants
to other apps or external-cookie discovery is needed.

Use Android Context paths, not hardcoded `/data/...` paths:

| Material | Proposed location and lifetime |
| --- | --- |
| Runtime code | Signed APK/native-library installation, read-only executable code; never downloaded or copied to writable app storage for execution. |
| Tor guard/state data | `getNoBackupFilesDir()/tor/data`, private 0700 directory; minimal persistent Tor operational state only. |
| Consensus/microdescriptor cache | `getNoBackupFilesDir()/tor/cache`, private and size-bounded; disposable cache, no chat or invitation material. |
| Per-run torrc, control port file and cookie | `getNoBackupFilesDir()/tor/run/<fresh-run-id>/`; private 0700 directory, files 0600; cookie freshly generated by Tor, removed after confirmed stop and stale-run cleanup. |
| Onion service private key | Tor process memory only via NEW:ED25519-V3 + DiscardPK; no HiddenServiceDir, saved private key, Detach or onion identity recovery. |
| MLS identity/provider/group state, bearer invitations and chat | Existing Rust/JS memory only; never service extras, Binder persistence, preferences, databases, saved instance state, notifications, logcat or crash reports. |

**Important distinction:** ephemeral GhostChat identity is not the same as
throwing away Tor's guard selection on every room. Tor's `state` stores entry
guards; Tor explicitly warns that dropping guards increases tracking risk.
Retain normal private Tor guard state across launches rather than repeatedly
sampling new guards. This does not restore an onion address, MLS identity,
room, invitation or history. The existing design already permitted the
external Tor daemon to have its own state. Document the new app-owned Tor
metadata and audit actual files; do not promise “Tor writes nothing”. [S5,S12]

`getNoBackupFilesDir()` is excluded from Android backup/transfer. Also declare
backup policy/exclusions explicitly and test device-transfer behavior. Keep
Tor files outside the existing FileProvider's cache/external roots. A private
Tor cookie is unavoidable operational authentication state here, but it is
**created and managed inside the APK's own sandbox**, not a separately
installed/readable prerequisite supplied by a user or another application.
Deletion and existing zeroization remain best-effort, not forensic erasure. [S13]

Configure an allowlisted native Tor launch with:

- `RunAsDaemon 0`, `ClientOnly 1`, explicit private DataDirectory/CacheDirectory,
  `ORPort 0`, `DirPort 0`, no transparent/DNS/HTTP proxy and no relay settings.
- A loopback SOCKS listener selected by Tor (`SocksPort auto OnionTrafficOnly`)
  and loopback `ControlPort auto`, with `ControlPortWriteToFile` in the private
  run directory. Verify actual resolved addresses and ports before use; never
  probe-and-assume a supposedly free fixed port or attach to ports 9050/9051.
- `CookieAuthentication 1`, explicit private `CookieAuthFile`, group-readable
  settings disabled. No NULL auth, empty AUTHENTICATE, hashed-password
  substitution or preauthenticated owning-FD shortcut.
- Standard anonymous onion mode: both HiddenServiceNonAnonymousMode and
  HiddenServiceSingleHopMode remain off. No custom directory authority,
  relaxed TLS/consensus checks, reduced anonymity circuit length or fallback.
- Safe logging; no raw control transcripts, destination/onion identifiers,
  invite codes or cookies. Native error output must be bounded and reviewed.

The manager reads the control address from the current private run file,
supplies `TorConfig::with_cookie_path` for the exact owned cookie, completes
SAFECOOKIE using the existing Rust verifier, then discovers the SOCKS listener
through authenticated GETINFO. Enforce **SAFECOOKIE for the bundled runtime**;
unexpected absence is an Android runtime error, not a reason to downgrade.
Keep the desktop's existing COOKIE compatibility behavior unchanged.

Loopback is not per-app network isolation: another local app can attempt to
connect to a loopback port. SAFECOOKIE protects control, and invitations/MLS
protect the local incoming room listener. The current no-auth SOCKS endpoint
can be used/DoS'ed by a local process; random ports are not authentication.
OnionTrafficOnly adds defense in depth but does not replace Rust's checksum
and canonical-host validation. Do not claim the service is protected against
a compromised endpoint or same-UID code.

## 8. Startup and monitoring

State machine: **Stopped → Starting → Authenticating → Bootstrapping → Ready
→ Stopping → Stopped**, with Failed as a terminal state for a run. Each run
has a fresh generation ID; endpoints, cookie path, pending calls and room
installation are bound to that generation.

1. Start as a result of opening/interacting with the visible app, not silently
   from boot, an alarm, a background receiver or an external app intent.
   Initialize asynchronously: no Tor bootstrap on the Android UI thread.
2. Main-process SessionService creates its notification, binds the private Tor
   worker and acquires single-instance ownership. Clean only confirmed-dead
   run metadata. Never delete active Tor state/locks to force a second instance.
3. Worker loads the packaged native library and runs `tor_run_main` on its
   own native thread. Use only public tor_api functions; copied argv data must
   live until Tor returns, and free the configuration only afterward.
   Tor's API warns against concurrent instances and repeated runs in one
   process; use one run per worker process, then exit that worker. [S14]
4. Await the owned control port and a regular, exactly 32-byte cookie under a
   bounded local-start deadline. Reject stale/foreign paths and non-loopback
   endpoints. Authenticate as above before any room command.
5. Retain a **separate long-lived authenticated supervisor connection** and
   send TAKEOWNERSHIP on it. Do not send that command on the temporary
   app_status connection or a room connection. Losing the parent/controller
   then stops its Tor instance; Binder death also handles the pre-auth startup
   window. No unauthenticated ownership socket is used.
6. Poll authenticated GETINFO bootstrap with bounded operations and modest
   cadence, not 100-ms control reconnects. Existing app_status can present
   starting/connecting/percentage/unavailable states without secrets. A
   separate overall bootstrap deadline offers explicit Retry/Cancel; it does
   not relax existing socket budgets or silently select another transport.
7. Only publish Ready and allow create/join when authentication succeeds,
   required listeners are validated and bootstrap is 100. Tor bootstrap is
   not itself confirmation of onion descriptor publication or an MLS join;
   retain the existing Welcome + creator-confirmation gate.
8. A live runtime lease is held while a room is active. Monitor worker/Binder
   death, native exit, control closure and bounded health checks. On loss,
   mark unavailable, invalidate the generation, terminate the affected room
   and clear stale UI state. Old asynchronous create/join completions must
   shut down their result rather than installing it into a newer run.

Do not make process-global `GHOSTCHAT_TOR_*` environment mutations after
threads start. Explicit values already fit `create_with_tor`/`join_with_tor`.
Android must never consult another app's control file or fall back to the
system/default Tor addresses when its managed runtime fails.

## 9. Android foreground/background lifecycle

The current manifest declares only INTERNET and an activity; it has no service
or background ownership. Current `run()` cleans up only on Tauri ExitRequested
or Exit. Activity/process lifecycle therefore needs real integration, not a
claim that adding a foreground service automatically solves everything.

Recommended split:

- **Main-process GhostChatSessionService:** user-visible foreground service
  and owner of the native runtime lease/session stop pathway. This keeps the
  process containing Rust AppState, OpenMLS and the network pump important
  when the activity is backgrounded.
- **Private :tor worker:** bound service in a second process, same application
  UID, containing only the native Tor runner. The main foreground service's
  binding maintains worker importance; Binder death/runtime exit are failures
  the parent must handle. Do not initialize a second Tauri app or MLS room
  inside the worker.

A foreground service running **only in the Tor process** would not adequately
own/protect the Rust/MLS process. Keeping Tor alive while the chat process is
gone is neither session continuity nor correct privacy cleanup.

For target SDK 36, declare FOREGROUND_SERVICE and an appropriate type-specific
permission. Proposed type: **specialUse**, with an accurate subtype explaining
a user-started, ongoing Tor-only ephemeral chat/onion relay session. Android
requires that explanation; Play distribution would require review. The
remoteMessaging type should only be used if its actual cross-device messaging
use case is applicable, not merely because this is a chat app. Do not misuse
VPN/systemExempted or dataSync; dataSync has a six-hour background limit on
Android 15+. WorkManager is not a replacement for a live onion service. [S15]

Provide an ongoing generic notification with a Stop action, immutable explicit
PendingIntents and no messages, room names, peers, onion addresses or invites.
Handle POST_NOTIFICATIONS on API 33+ appropriately: a foreground service still
needs a notification even if the user denies notification permission. Promote
the service promptly after a legal foreground start; do not wait for bootstrap.

- Rotation/recreation should rebind, not spawn another Tor instance or clear
  a healthy room. Home/background keeps an active room on a best-effort basis.
- Explicit End/Leave, notification Stop and a deliberate task-removal/exit
  policy should close sessions and the owned runtime. Document whether a swipe
  ends a room; the recommended privacy-first behavior is to end it.
- No boot auto-start and no START_STICKY session restoration. When idle without
  a room and the UI is backgrounded, stop after a short documented grace
  period. Avoid an always-running Tor service merely to show a ready badge.
- Initialize the Tauri/Kotlin bridge while an activity is present, but make
  established health/Stop/cleanup independent of WebView/plugin-call
  availability. Maintain native callbacks/state across activity pause. Verify
  Tauri's actual mobile exit/suspend events on devices.
- Foreground service importance does not guarantee immunity to Doze, network
  suspension, force-stop, OEM battery policies or process death. Core state may
  be lost and sessions must then end. Do not promise uninterrupted background
  delivery or hide failures behind “connected”. [S16]

Native process separation improves failure containment, not a new cryptographic
security boundary: the worker shares the UID and is trusted code. Bundled C
Tor/dependencies/JNI add to the app's trusted computing base and require
security-update ownership. Existing endpoint-compromise limitations still apply.

## 10. Shutdown and crash recovery

**Orderly stop:** first prevent new operations and invalidate the runtime's
ready lease. Off the Android UI thread, use existing NetworkRoom shutdown:
encrypted owner Shutdown or joiner Leave, existing aggregate local flush,
close peer sockets and the onion-owning control connection, release owned
MLS/session/history and stop/reap the network pump. Then send authenticated
SIGNAL SHUTDOWN on the supervisor connection. Await Tor's native return and
worker exit under a separate, bounded lifecycle budget; free the C configuration
only after return. Finally delete per-run control/cookie/config files, unbind
the worker and remove the foreground notification/service.

**Escalation:** if the authenticated control/runner does not stop, close the
owning supervisor connection; if necessary terminate only the dedicated Tor
worker process. Never terminate an external/system daemon, signal an unrelated
PID, free a running native configuration, or block an Android lifecycle callback
on an unbounded join. Retain the desktop's current two-second exit cleanup
behavior and its external daemon lifetime unchanged.

**Runtime crash while the main app lives:** Binder/control failure invalidates
the generation, marks Tor unavailable and closes the current room. Use a bounded
session-level terminal/release path, not `cleanup_on_exit`, which permanently
sets AppState's process-closing gate. Pending operations cannot install old
rooms. Explicit Retry starts a fresh Tor worker and fresh room/join identity;
do not reconnect or resend messages automatically with stale MLS state.

**Main app crash/OS kill:** authenticated TAKEOWNERSHIP closure stops Tor after
ownership is established; Binder owner-death covers the startup window. Do not
depend on onDestroy/onTaskRemoved for guaranteed cleanup. The next app launch
removes only confirmed-stale private run metadata and starts fresh, while
retaining normal Tor guard state. Native runtime termination and connection-
owned ADD_ONION remove the service; no persisted key exists to restore it.
Published descriptor caches may outlive local shutdown, so do not promise
instant removal of all network metadata.

**Force-stop/reboot/update:** no automatic room recovery. No previous messages,
participant key, MLS group or creator onion identity is restored. Existing
invitations may still be valid for a surviving remote creator; joining again
requires a new explicit join and fresh identity, never old group state.

## 11. Battery, bandwidth and memory

Expect more resource use than the present APK without Tor: bootstrap consensus
downloads/signature checks, encrypted guard links, circuits, onion descriptor
publication/introduction circuits, and active network/service overhead. A room
creator maintains an onion service as well as peer streams. Tor can still do
protocol-required traffic while chat is idle; do not change padding, guards,
circuit construction or cryptography merely to claim a battery improvement.

The existing Rust pump wakes about every 100 ms and frontend app_status runs
every 15 seconds. Do not add a second fast polling loop. Cache supervisor
status and use bounded/adaptive native readiness checks. Keep the initial
integration's MLS epochs, join deadlines and transport bounds unchanged;
any later Android-only polling optimization needs measured regression evidence.

Stop unused runtime work, avoid endless bootstrap/restart loops, reuse normal
Tor caches/guard state, and keep notification content private. Do not acquire
indefinite wake locks or request battery-optimization exemptions silently.
If user-configurable exemptions are justified later, document consent and test
the policy; wake locks alone do not overcome Doze's network restriction.
Do not add FCM, push servers, clearnet connectivity checks or an account service
to improve wakeup behavior. [S16]

Measure cold/warm bootstrap, native RSS/PSS, CPU, wakeups, traffic and battery
on a real ARM64 device: foreground idle, active two/three-party chat, creator
versus joiner, background screen-off, Doze and blocked/offline network. There
are no numerical battery/RAM claims from this investigation.

## 12. Phased implementation and test plan

Do not call Android self-contained Tor support complete until every phase below
has passed. Each phase preserves the desktop path and leaves the existing
external Tor integration available for desktop.

### Phase 0 — provenance and legal gate

1. Pin a chosen Tor source commit, Guardian Android build commit, all submodule
   commits, NDK/SDK/compiler versions and artifact hashes.
2. Resolve the GPL-mode versus BSD-only decision with an actual license review.
   Produce source/build instructions, third-party notices, SBOM and update
   owner. Do not use the inspected AAR solely because its POM says BSD.
3. Decide whether to ship a maintained GPL-mode runtime with a compatible
   distribution/compliance plan or produce a reviewed BSD-mode native build
   with optional GPL-only modules explicitly considered. **Do not silently
   change runtime security features to resolve licensing.**
4. Create a reproducible ARM64 native build in CI/local tooling without writing
   the repository's global SDK/JAVA settings. Run `readelf`, symbol, alignment,
   provenance and license checks on the exact library that enters the APK.

### Phase 1 — native runtime smoke test, no GhostChat room

1. Add only native wrapper/service code and a hidden test/debug harness. Start
   Tor once, in the private worker, with explicit paths/ports and no UI room.
2. Verify on API 24, current API 35/36 and a current ARM64 physical device:
   native load, Tor start/return, same-UID private files, cookie permissions,
   control-port file, loopback listener discovery and process death.
3. Through the actual GhostChat Rust control parser, verify PROTOCOLINFO,
   SAFECOOKIE server proof, client proof, bootstrap progress and authenticated
   GETINFO. Negative tests: stale cookie, wrong cookie, NULL auth, foreign
   cookie path, non-loopback address, oversized/malformed port file, stale
   run generation and worker death.
4. Verify `SocksPort auto OnionTrafficOnly` with the existing SOCKS parser:
   known v3 onion succeeds in a controlled Tor test network; IP, DNS, malformed
   v2/uppercase/extra-label onion and noncanonical destinations fail closed.
   Confirm no HTTP tunnel, DNS listener, ORPort or direct socket path.

### Phase 2 — onion-service and TorTransport integration

1. Add an Android `TorRuntimeProvider` that returns explicit managed
   `TorConfig`/runtime lease values. The core `TorTransport::host/connect`
   methods remain the data-plane implementation.
2. Test authenticated ADD_ONION NEW:ED25519-V3 with `DiscardPK`, loopback
   target, returned 56-character service ID and port forwarding to the actual
   GhostChat listener. Test DEL_ONION and control-close removal.
3. Use two and then three independent app/runtime instances (separate app
   sandboxes or physical devices) through real Tor: create → invite → join →
   Welcome/creator confirmation → encrypted messages → epoch update → leave /
   shutdown → fresh join. Include fourth-member rejection and malformed
   invitations. Do not use local transport for this acceptance test.
4. Verify a creator's address is fresh after a process restart and that no
   onion private key, hostname, invitation, MLS state or history is recovered.
   Verify normal Tor guard/cache files are the only intended retained state.

### Phase 3 — lifecycle and failure tests

1. Activity rotation, split-screen, background/foreground and task removal;
   notification Stop; explicit Leave/End; worker Binder death; native Tor
   return; control socket close; network offline during bootstrap; network
   loss after Ready; OS process kill; force-stop; reboot; upgrade/install.
2. Assert every path terminates the room without stale message resend, closes
   active sockets, invalidates generation/leases, stops the worker and leaves
   no cookie/control run files. Assert no old async operation installs a room
   after a retry.
3. Force Doze/App Standby with documented `adb` commands, screen-off and OEM
   battery policy. Record whether the user-visible foreground service keeps
   the room alive; if not, expose disconnected/closed behavior rather than
   pretending delivery is reliable.
4. Verify Android 14+ foreground-service permission/type behavior, Android 15+
   timeout behavior for any declared type, notification denial behavior and
   Play policy metadata. Use a generic notification without private content.

### Phase 4 — security, performance and release verification

1. Static/dynamic review: JNI pointer/thread lifetime, fd ownership, exception
   paths, native crash/return handling, argument injection, path traversal,
   service export status, Binder caller validation and log redaction.
2. Run existing Rust format/check/test/clippy/frontend checks on desktop and
   Android cross-build. Run all control/SOCKS/TorTransport tests against the
   owned runtime, plus Tor-specific end-to-end tests on ARM64 devices.
3. Record APK per-ABI size, installed size, RSS/PSS, CPU/wakeups, traffic and
   battery. Validate 16 KiB page-size behavior and ABI splits on supported
   devices.
4. Rebuild from pinned source, verify notices/SBOM and artifact checksums,
   install with `adb`, query package/permissions/services, and capture a
   redacted test receipt. Only then update README to say self-contained Tor is
   supported and only then build a new debug APK. No release-signing claim is
   implied by a debug build.

## 13. Current blockers and non-claims

The following are intentionally unresolved until implementation/testing:

- Licensing choice for the inspected GPL-mode native payload.
- Whether the chosen maintained native source can be built reproducibly in the
  repository's Android/CI toolchain with the desired ABI set.
- Device behavior of the native-only C API/JNI bridge, `tor_run_main` return,
  fd ownership, same-UID `:tor` process and 16 KiB page-size alignment.
- Whether the selected foreground-service subtype is acceptable for the
  intended distribution channel and user-visible lifecycle.
- Actual cold bootstrap time, RAM, traffic, CPU and battery on ARM64 hardware.
- Real three-process/onion-service behavior using the exact integrated APK.

Until those are complete, the accurate status is:

> **The Android supervisor and transport seam are integrated and build, but
> self-contained Tor is not operational or supported in GhostChat because the
> native Tor payload is absent and device/runtime validation remains outstanding.**

The minimum architectural change is an Android-only, app-owned Tor runtime
supervisor plus native bridge and lifecycle service, with a provider seam so
desktop continues to use its existing environment-configured external daemon.
The minimum security change is not a relaxation: it is moving the cookie and
Tor data directory into the same app sandbox, requiring SAFECOOKIE, and
refusing system/Orbot/other-app endpoints. The minimum transport change is
explicitly supplying the managed loopback addresses/cookie path and retaining
 the current parser, bounds, SOCKS-only routing and onion validation.

## Sources

- **[S1]** Repository source: `src/transport/tor.rs` and
  `src/transport/stream.rs`, especially lines 351–478, 512–575, 589–742 and
  907–1079; `src/session/network.rs` lines 262–358 and 591–669;
  `app/src-tauri/src/lib.rs` lines 506, 533 and 1068–1111. These are the
  primary architecture sources.
- **[S2]** Guardian Project, `tor-android` README and changelog at commit
  `4052acd898b2ccc7bebb3fe55505ad527a6ac4db`, and immutable gpmaven artifact
  commit `8654669c6ead4b9f987dc5691550f4f081a1ccc`:
  `https://github.com/guardianproject/tor-android`,
  `https://raw.githubusercontent.com/guardianproject/tor-android/4052acd898b2ccc7bebb3fe55505ad527a6ac4db/README.md`,
  `https://raw.githubusercontent.com/guardianproject/tor-android/4052acd898b2ccc7bebb3fe55505ad527a6ac4db/CHANGELOG.md`.
- **[S3]** Guardian `external/Makefile`, `tor-droid-make.sh`, `tor_api.h`,
  `tor_api.c`, `org_torproject_jni_TorService.c`, and Tor `configure.ac` at
  the pinned source commits. Build recipe, JNI/API contract, GPL switch and
  NDK r30 requirement were inspected directly.
- **[S4]** Inspected published artifact:
  `https://raw.githubusercontent.com/guardianproject/gpmaven/8654669c6ead4b9f987dc5691550f4f081a1ccc/info/guardianproject/tor-android/0.4.9.13.2/tor-android-0.4.9.13.2.pom`
  and AAR. POM license metadata was compared with native strings and build
  source; native sizes/ELF/symbols were measured locally.
- **[S5]** Tor control specification, especially PROTOCOLINFO, SAFECOOKIE,
  TAKEOWNERSHIP, ADD_ONION and DEL_ONION:
  `https://spec.torproject.org/control-spec/commands.html`.
- **[S6]** Arti landing page and compatibility guide:
  `https://arti.torproject.org/` and
  `https://arti.torproject.org/guides/compatibility`.
- **[S7]** Arti control replacement note:
  `https://blog.torproject.org/arti_1_4_0_released/` and
  `https://arti.torproject.org/integrating-arti/using-tor/`.
- **[S8]** Current Arti crate feature/license metadata:
  `https://docs.rs/crate/arti/latest/source/Cargo.toml`.
- **[S9]** `libtor-sys`/`libtor` documentation:
  `https://docs.rs/crate/libtor-sys/latest` and
  `https://docs.rs/crate/libtor/latest`.
- **[S10]** Tor Android source license and Android manifest:
  `https://raw.githubusercontent.com/guardianproject/tor-android/4052acd898b2ccc7bebb3fe55505ad527a6ac4db/LICENSE` and the matching
  `tor-android-binary/src/main/AndroidManifest.xml`.
- **[S11]** Tor bundled Equi-X/HashX LGPL notices and build feature gates:
  `https://raw.githubusercontent.com/bitmold/tor/8aa9ce2e4e3332ef10f5b7f7e0562c60affe2ece/src/ext/equix/LICENSE`,
  `.../src/ext/equix/hashx/LICENSE`, and the pinned `configure.ac`.
- **[S12]** Tor manual options/files for DataDirectory, CookieAuthFile,
  ControlPortWriteToFile, OnionTrafficOnly, AvoidDiskWrites and key/state
  behavior: pinned Tor manual fetched from the Tor Android source tree and
  `https://spec.torproject.org/control-spec/commands.html`.
- **[S13]** Android Auto Backup and no-backup storage:
  `https://developer.android.com/guide/topics/data/autobackup`.
- **[S14]** Tor public C embedding API limitations in `tor_api.h` and Guardian
  JNI implementation, cited in [S3].
- **[S15]** Android foreground service types/permissions/time limits:
  `https://developer.android.com/develop/background-work/services/fgs/service-types`
  and
  `https://developer.android.com/develop/background-work/services/fgs/timeout`.
- **[S16]** Android Doze/App Standby behavior and testing:
  `https://developer.android.com/training/monitoring-device-state/doze-standby`.

URLs and upstream text are external untrusted research inputs; repository
source and locally verified artifact measurements take precedence where they
conflict. All claims marked as current remain subject to rechecking when the
implementation is started.


## 15. Actual source-built payload and current verification

The packaged Tor version is `0.4.9.14`, built from the official Tor release
archive with SHA-256
`182449ac1c8ff43278da27b69b02040e11d03d0327db6d9126e4190ec6235e4a`. The
detached checksum signatures were inspected; Alexander Færøy's key signature
was valid and David Goulet's signature key was expired. The Guardian build
recipe is pinned to `4052acd898b2ccc7bebb3fe55505ad527a6ac4db`; the bundled
dependency pins are recorded in [THIRD_PARTY_NOTICES_ANDROID.md](THIRD_PARTY_NOTICES_ANDROID.md)
and [SBOM.android.spdx.json](SBOM.android.spdx.json). The recipe and source
inputs are included in the corresponding-source archive documented in
[ANDROID_TOR_SOURCE_PACKAGE.md](ANDROID_TOR_SOURCE_PACKAGE.md).

The native build used Java 25.0.4, NDK `30.0.16248370`, Android API 24,
`SOURCE_DATE_EPOCH=1234567890`, `-Os`, static native dependencies, Guardian's
`llvm-strip` and `termux-elf-cleaner`, and the recorded Tor configure/export
patches. The packaged output is an ELF64 AArch64 `ET_DYN` shared object at
`app/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libtor.so`, size
7,162,688 bytes, SHA-256
`922c95204461afff3aae5962dd9a7d91f36c5858aba62c945cb572f699c2cdf3`.
`llvm-readelf` reports Android API 24 and system dependencies only on
`libm.so`, `libdl.so`, and `libc.so`; the Tor ELF LOAD segments use 16 KiB
alignment. `llvm-nm -D` confirms all five public C embedding symbols used by
the bridge. APK/AAB inspection confirms the library and bridge are packaged
under the ARM64 paths.

Guardian's recipe enables Tor's GPL mode. License copies are under
`app/src/licenses/tor/`; source/license details and the SPDX SBOM are recorded
in the notices and corresponding-source package. The package and rebuild
instructions are prepared. A genuine release signing key was not available,
and distribution/legal review plus installation information where required
remain open; see [ANDROID_RELEASE.md](ANDROID_RELEASE.md).

No Android device/emulator is currently attached. JNI loading, Tor startup,
SAFECOOKIE, bootstrap, onion creation/removal, and the complete GhostChat
workflow remain unverified. Static build and package checks do not establish
those runtime results.
