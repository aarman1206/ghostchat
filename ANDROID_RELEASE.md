# GhostChat Android build and release record

Updated 2026-10-09. These are the current ARM64 working-tree artifacts. No
Android device or emulator was attached during this validation.

## Build inputs

- Java 21 for Android Gradle; Java 25.0.4 and NDK `30.0.16248370` for Tor.
- NDK `29.0.13846066` for GhostChat's JNI bridge.
- Android SDK platform 36, Rust target `aarch64-linux-android`, and Tauri CLI
  v2.
- Linux x86_64 host with GNU make, C/C++ tools, Perl, Autoconf, Automake,
  Libtool, pkg-config and standard shell/core utilities.
- Tor source build and provenance are in the corresponding-source archive
  documented in [ANDROID_TOR_SOURCE_PACKAGE.md](ANDROID_TOR_SOURCE_PACKAGE.md).

Build the Tor library from that package, copy it to
`app/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libtor.so`, then run
from `app/src-tauri`:

```sh
cargo tauri android build --apk --debug --target aarch64 --ci
cargo tauri android build --apk --target aarch64 --ci
cargo tauri android build --aab --target aarch64 --ci
```

## Artifact record

- Application ID: `org.lord.ghostchat`.
- Version: `0.1.0` (version code `1000`).
- Minimum SDK 24; compile and target SDK 36.
- Native ABI: `arm64-v8a`.
- Embedded runtime: Tor `0.4.9.14`, ELF64 AArch64, Android API 24, 7,162,688
  bytes, SHA-256
  `922c95204461afff3aae5962dd9a7d91f36c5858aba62c945cb572f699c2cdf3`.
- The Android JNI bridge is packaged in both APKs and the AAB. Static
  `llvm-nm -D` inspection confirms that `libtor.so` exports the five symbols
  the bridge looks up. This confirms package contents and symbol visibility;
  it does not prove Android `dlopen` or runtime operation.

| Artifact | Size | SHA-256 | Signing |
| --- | ---: | --- | --- |
| [Debug APK](app/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk) | 403,188,235 bytes | `14d27a1d05bf23fe2eece320d696e0a4b9514465102c449a67dc4e806176c2c7` | Android debug key; `apksigner verify` passed |
| [Release APK](app/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk) | 17,340,610 bytes | `119ac1424ab890b6d6f30b613f9e55471ac5fb834f231c21163f405c70ec83e1` | unsigned |
| [Release AAB](app/src-tauri/gen/android/app/build/outputs/bundle/universalRelease/app-universal-release.aab) | 9,403,755 bytes | `8d49c5908bc372455609de2e74a2a75cb8df8a2116a77f83055f62773e64c897` | unsigned |

Direct archive inspection confirmed `lib/arm64-v8a/libtor.so` and
`lib/arm64-v8a/libghostchat_tor_bridge.so` in both APKs, and
`base/lib/arm64-v8a/libtor.so` plus the bridge in the AAB. Each contains the
same Tor library hash above. APK local-entry data offsets for packaged native
libraries are 16 KiB aligned; the Tor ELF LOAD segments also use 16 KiB
alignment. The available system `zipalign` is too old to provide its `-P 16`
check, so the APK alignment result was verified from ZIP local headers.

## Build checks and device status

The Android debug and release APKs and release AAB built successfully. The
universal debug Kotlin and Java compile tasks passed. The release APK metadata
reports application ID `org.lord.ghostchat`, version `0.1.0`, min SDK 24 and
target SDK 36. `libtor.so` is present in the final APK/AAB and the JNI bridge's
five required public Tor symbols are in the library's dynamic symbol table.

No Android device or emulator is currently attached. As a result, the JNI
bridge loading the library, embedded Tor startup, app-private directory use,
control/SOCKS listeners, SAFECOOKIE, bootstrap, ADD_ONION/DEL_ONION and all
GhostChat room behavior are **unverified**. The device workflow must not be
described as tested.

Release signing variables (`GHOSTCHAT_ANDROID_KEYSTORE`,
`GHOSTCHAT_ANDROID_STORE_PASSWORD`, `GHOSTCHAT_ANDROID_KEY_ALIAS`, and
`GHOSTCHAT_ANDROID_KEY_PASSWORD`) were unset, and no keystore file was found
in the repository. No production signing identity was created. Supply a
real private keystore and its passwords/alias through the documented Gradle
environment configuration to sign distribution artifacts; keep those
credentials outside version control.

The GPL-mode Tor corresponding-source archive, pinned source inputs, notices
and build instructions are prepared under `compliance/` and documented in
[ANDROID_TOR_SOURCE_PACKAGE.md](ANDROID_TOR_SOURCE_PACKAGE.md). This does not
by itself establish distribution readiness: release signing, installation
information where required, and a distribution/legal review remain open.
