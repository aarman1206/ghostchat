# Android Tor runtime: third-party notices and build provenance

Updated 2026-10-09. The packaged ARM64 Tor runtime was built from source. No
Tor Browser APK, Tor Browser source tree, Linux expert bundle, or Guardian AAR
was used as the GhostChat runtime.

## Runtime and provenance

- Tor: `0.4.9.14`, from the official Tor release source archive. Source archive
  SHA-256:
  `182449ac1c8ff43278da27b69b02040e11d03d0327db6d9126e4190ec6235e4a`.
  The signed checksum has a good signature from Alexander Færøy's Tor signing
  subkey `514102454D0A87DB0767A1EBBE6A0531C18A9179`; the included David Goulet
  key signature is expired. Local source checksum matched the signed value.
- Guardian Project `tor-android` build recipe: base revision
  `4052acd898b2ccc7bebb3fe55505ad527a6ac4db`, version string
  `0.4.9.13.2-1-g4052acd`. Its upstream Tor submodule is 0.4.9.13; the packaged
  runtime uses the separately verified official 0.4.9.14 source archive.
- OpenSSL `3.5.9`: `45e844fa2a14ec92d146bd8f5778ac130b6625fb`.
- libevent `2.1.13`: `79ddfb460847999b807cba76d04e73891f29c6ee`.
- zlib `1.3.2`: `da607da739fa6047df13e66a2af6b8bec7c2a498`.
- zstd `1.5.7`: `f8745da6ff1ad1e7bab384bd1f9d742439278e99`.
- Guardian ELF cleaner `2.2.1`: `e4f87f8d13541779756f4907c6957d2a000653da`
  (build tool, not packaged).
- Build: Linux x86_64; Java `25.0.4`; NDK `30.0.16248370`; Android API 24;
  `SOURCE_DATE_EPOCH=1234567890`; `-Os`; static dependency builds followed by
  Guardian `llvm-strip` and `termux-elf-cleaner` steps.
- ABI and APK path: `arm64-v8a`, `lib/arm64-v8a/libtor.so`.
- Library size and SHA-256: 7,162,688 bytes,
  `922c95204461afff3aae5962dd9a7d91f36c5858aba62c945cb572f699c2cdf3`.
- ELF: 64-bit AArch64 ET_DYN; LOAD alignment `0x4000`; dynamic dependencies
  only on Android `libm.so`, `libdl.so`, and `libc.so`. OpenSSL, libevent,
  zlib and zstd are statically linked.
- Dynamic symbols verified for the GhostChat JNI bridge:
  `tor_main_configuration_new`, `tor_main_configuration_set_command_line`,
  `tor_main_configuration_free`, `tor_run_main`, and
  `tor_api_get_provider_version`.

The native artifact is a local source build, not a signed upstream binary.
Static symbol/ELF inspection does not prove Android `dlopen` or that Tor starts.
No device or emulator was attached, so runtime loading and all embedded Tor
network operations remain unverified.

## Corresponding source and rebuild instructions

The source package is
[`compliance/ghostchat-android-tor-corresponding-source-0.4.9.14.tar.gz`](compliance/ghostchat-android-tor-corresponding-source-0.4.9.14.tar.gz),
SHA-256
`1d6e85bcd731de6df32a98bad14acc3fe6e49fa07b76edf2ddbf061838689f1e`.
It includes the official Tor release source, checksum/signatures/public keys,
Guardian build recipe, pinned static dependency sources, build script, patch
records, and source retrieval/build information. Verify the package with:

```sh
cd compliance
sha256sum -c ghostchat-android-tor-corresponding-source-0.4.9.14.tar.gz.sha256
```

Extract the archive, set `JAVA_HOME` to Java 25 and
`ANDROID_NDK_HOME` to NDK `30.0.16248370`, then run the included
`build-android-libtor.sh /path/to/libtor.so`. The script checks the Tor source
hash and NDK revision, builds ARM64, then verifies the ELF machine and all five
required dynamic symbols. Copy the output to
`app/src-tauri/gen/android/app/src/main/jniLibs/arm64-v8a/libtor.so`; build
GhostChat with Java 21, Android SDK platform 36 and NDK `29.0.13846066` for
its JNI bridge.

The recipe has two GhostChat-specific changes: use the `configure` script
from the official release archive, and force the NDK-supported `-rdynamic`
linker option. Tor's legacy configure probe uses `main()` without a prototype;
the strict-prototype `-Werror` flags cause that probe to report a false
negative. The recipe checks the final dynamic symbol table to prevent a
library without the bridge API from being accepted.

The user's Firefox/Tor Browser source tree
`firefox-tor-browser-153.4.0esr-16.0-1-build3` was inspected as a reference.
It identifies Firefox 153.4.0 ESR and includes Android `TorAndroidIntegration`
which launches `<app library dir>/libTor.so` through `ProcessBuilder` as a
separate executable. The tree contains neither that binary nor a pinned Tor
source/build recipe for GhostChat's JNI embedding API. It is not included in
GhostChat or used to build the runtime. The supplied Tor Browser APK and Linux
expert bundle were also not used: the former's library is Tor 0.4.9.13 without
the five required embedding exports; the latter is x86_64/glibc.

## Licenses and notices

The Guardian recipe enables Tor's GPL mode. Tor's configure help describes
that mode as GPL-covered Tor/libtor rather than its usual 3-clause BSD license.
For distribution review, treat the built Tor library as GPL-3.0-only.
Bundled Equi-X and HashX notices are LGPL-3.0-only. The static dependency
licenses recorded by the source package are:

- Tor: GPL-3.0-only mode and upstream license bundle.
- Equi-X and HashX: LGPL-3.0-only.
- OpenSSL 3.5.9: Apache-2.0.
- libevent 2.1.13: BSD-3-Clause.
- zlib 1.3.2: Zlib.
- zstd 1.5.7: BSD-3-Clause.
- Guardian build tools and recipe: see the included Guardian license and
  individual dependency notices in the source package.

License copies are under `app/src/licenses/tor/` and shown from Android
About → Third-party notices. The SPDX SBOM is `SBOM.android.spdx.json`.
Corresponding source and build instructions have been prepared; this is not a
legal determination or confirmation that all installation-information
requirements for a particular distribution method have been met. The unsigned
artifacts are not release-ready until signed with a genuine release key and
distribution requirements have been reviewed.

## Final artifact checksums

| Artifact | Size | SHA-256 | Signing |
| --- | ---: | --- | --- |
| Debug APK | 403,188,235 bytes | `14d27a1d05bf23fe2eece320d696e0a4b9514465102c449a67dc4e806176c2c7` | Android debug key |
| Release APK | 17,340,610 bytes | `119ac1424ab890b6d6f30b613f9e55471ac5fb834f231c21163f405c70ec83e1` | unsigned |
| Release AAB | 9,403,755 bytes | `8d49c5908bc372455609de2e74a2a75cb8df8a2116a77f83055f62773e64c897` | unsigned |

Each APK has the Tor payload at `lib/arm64-v8a/libtor.so`; the AAB has it at
`base/lib/arm64-v8a/libtor.so`. The payload checksum is identical in all
three artifacts.
