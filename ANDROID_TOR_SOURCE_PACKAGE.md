# Android Tor corresponding source

The Tor 0.4.9.14 corresponding-source package is
[`compliance/ghostchat-android-tor-corresponding-source-0.4.9.14.tar.gz`](compliance/ghostchat-android-tor-corresponding-source-0.4.9.14.tar.gz).
Its SHA-256 is
`1d6e85bcd731de6df32a98bad14acc3fe6e49fa07b76edf2ddbf061838689f1e` and is
recorded beside it in the `.sha256` file. The archive contains
the Guardian Android build recipe, its pinned native dependency sources, the
official Tor release source tarball, checksum and detached signatures, the
Tor configure and public-symbol export patches, build instructions, and public
signing keys. It has no prebuilt native libraries.

Tor source provenance:

- Tor 0.4.9.14 official source tarball SHA-256:
  `182449ac1c8ff43278da27b69b02040e11d03d0327db6d9126e4190ec6235e4a`.
- The checksum file's detached signature has a good signature from Alexander
  Færøy's Tor signing subkey `514102454D0A87DB0767A1EBBE6A0531C18A9179`.
  It also carries a signature from David Goulet's key; that key expired on
  2026-03-24. The local tarball hash matches the signed checksum.
  See [Tor's signing-key verification guidance](https://support.torproject.org/little-t-tor/getting-started/verifying/).
- Guardian Project `tor-android` base revision:
  `4052acd898b2ccc7bebb3fe55505ad527a6ac4db` (`0.4.9.13.2-1-g4052acd`).
  Its upstream Tor submodule is 0.4.9.13; the packaged runtime is instead
  compiled from the verified 0.4.9.14 release source above.
- Static source pins and build details are in the archive's
  `PINNED-SOURCES.txt` and `README.md`.

The user-provided Tor Browser 15.0.24 ARM64 APK was also inspected as a
reference input. Its SHA-256 is
`4b8d51527ab516c5e8ecf7ea25dabbcb0e4bdfb54d55eadb12ad09a36f227cda`; its
bundled `libTor.so` is Tor 0.4.9.13 and does not export GhostChat's five public
embedding symbols. It is not copied into GhostChat or used as a runtime
dependency. The Linux expert bundle is Tor 0.4.9.13 for x86_64/glibc and is
also unsuitable for Android ARM64.

The user-provided Firefox/Tor Browser source tree
`firefox-tor-browser-153.4.0esr-16.0-1-build3` was also inspected. Its
Firefox source identifies version 153.4.0 ESR, and its Android
`TorAndroidIntegration` starts `<app library dir>/libTor.so` with
`ProcessBuilder` as a standalone Tor executable. This tree contains neither
that Tor binary nor a pinned Tor source/build recipe for GhostChat's JNI
embedding API, so it remains a reference input and is not included in the
application or corresponding-source archive.

The Tor native build uses Guardian's GPL-enabled recipe with static OpenSSL,
libevent, zlib and zstd. The Android recipe forces `-rdynamic` because Tor's
configure probe otherwise misdetects support under the NDK's strict-prototype
`-Werror` flags, then rejects the build unless all five JNI bridge API symbols
are present in the dynamic symbol table. Text notices are included in
`app/src/licenses/tor/` and the consumer-facing third-party notices. This
records the source materials and build recipe; it is not a legal opinion on
distribution obligations for the combined application.

The final Tor library SHA-256 is
`922c95204461afff3aae5962dd9a7d91f36c5858aba62c945cb572f699c2cdf3`.
The debug APK, unsigned release APK and unsigned release AAB each contain this
ARM64 library. Their final sizes and SHA-256 values, application metadata,
signing status, and the limits of static validation are recorded in
[ANDROID_RELEASE.md](ANDROID_RELEASE.md). No device/emulator runtime result is
claimed.
