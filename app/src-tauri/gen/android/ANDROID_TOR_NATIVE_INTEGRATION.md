# Android Tor native boundary

This directory contains the Android-only service and JNI boundary for an
app-owned Tor runtime. It deliberately does not import Guardian's stock
`TorService`, `jtorctl`, Orbot, a system Tor binary, an external SOCKS proxy,
or any clearnet fallback.

## Runtime contract

The Android Rust provider registers:

```rust
api.register_android_plugin("org.lord.ghostchat.tor", "GhostChatTorPlugin")
```

and uses the `ghostchat_tor` mobile plugin commands:

| Command | Result |
| --- | --- |
| `start` | Starts the foreground owner, then asynchronously resolves after the generation's worker is running and the loopback control port and cookie are ready. |
| `status` | Returns the current bounded snapshot. Polling is intentionally slow; it is not a control channel. |
| `stop` | Requests generation-scoped shutdown, waits for worker cleanup, and removes the generic notification. |

Before starting the Android service, Rust attaches the event channel to the
generation. The service promotes the foreground owner before starting the
worker. The start response contains `generation`, `noBackupDir`, `runDir`,
`controlPortFile`, `cookiePath`, `appUid`, and `workerUid`. Channel events are
raw JSON objects shaped as `{ "generation": "…", "event": "controlReady" }`
or `{ "generation": "…", "event": "failed" }`; the bounded status command
remains authoritative if channel delivery fails. `status` returns `state`,
`generation`, `controlHost`, `controlPort`, those private paths/UIDs, `error`,
and `torProviderVersion`. The provider must require
`controlHost == 127.0.0.1`, read the exact 32-byte cookie from `cookiePath`,
and use the existing Rust SAFECOOKIE verifier. It must then use authenticated
`GETINFO net/listeners/socks` to discover the SOCKS endpoint and retain the
existing `OnionTrafficOnly`/canonical onion validation. `cookiePath` is a
private same-UID file path; cookie bytes and control transcripts never cross
this boundary.

The `controlReady` event is not final GhostChat readiness. The Rust provider
authenticates the control endpoint, verifies the SOCKS listener and bootstrap
progress, and binds the resulting explicit `TorConfig`/lease to the current
generation. A failed, stopped, or replaced generation invalidates pending room
operations and cannot be reused.

## Process and lifecycle contract

- `GhostChatSessionService` runs in the main app process as the foreground
  owner for the Rust/OpenMLS session.
- `GhostChatTorWorkerService` runs in the non-exported `:tor` process with the
  same application UID and is the only caller of `tor_run_main`.
- The worker accepts only a generated four-argument launch bundle pointing at
  its generation directory. It does not accept arbitrary Tor options.
- Tor configuration is generated under
  `getNoBackupFilesDir()/tor/{data,cache,run/<generation>}` with private
  permissions. The run directory contains a strict per-run `torrc`, control
  port file, and cookie path.
- The worker is one-run-per-process. Stop is expected to send authenticated
  `SIGNAL SHUTDOWN` first; the worker's bounded process kill is escalation
  for this dedicated PID only.
- The foreground notification is generic and has an explicit immutable,
  generation-scoped Stop action. A null restart is not restored because the
  room/keys live only in memory. Lifecycle callbacks stop only their captured
  generation. There is no boot receiver, VPN service, or stored
  room/invitation/MLS material.

## Native payload gate

`jni/tor_bridge.c` dynamically resolves only the public Tor embedding symbols
listed in `app/src/main/assets/tor-runtime-provenance.json`. The bridge builds
without the Tor payload and reports `-1001`/`FAILED` if `libtor.so` is absent
or incompatible. The current APKs do not contain `libtor.so`; Android Tor
startup is therefore implemented at the seam but not operational. This is
intentional: the inspected Guardian artifact is
available in the research cache, but its GPL-mode notice, detached-signature
verification, corresponding-source obligations, and reproducible ABI build
have not been approved for APK redistribution. No prebuilt native binary is
copied into this scaffold and no runtime fallback is allowed.

Before enabling payload packaging, T1/release engineering must provide an
approved, independently verified `libtor.so` for every shipped ABI, preserve
the exact public symbol contract, and update the provenance/SBOM/notices. A
real-device smoke test is still required for native loading, 16 KiB page
alignment, control/cookie files, bootstrap, onion service behavior, Binder
death, and bounded cleanup.
