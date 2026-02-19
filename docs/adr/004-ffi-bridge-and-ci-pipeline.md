# ADR-004: FFI Bridge Completion & CI/CD Pipeline

**Status:** Accepted  
**Date:** 2026-02-19  
**Supersedes:** None  
**Related:** ADR-002 (KERI Driver Pattern), ADR-003 (Adaptive Architecture)

## Context

ADR-003 established the three operating modes (Desktop, Mobile Remote, Mobile Standalone) and the Rust bridge (`keriox/keri-core`) for Mobile Standalone mode. The Dart side of the bridge (`keri_bridge.dart`) contained only `UnimplementedError` stubs, and the CI/CD pipeline (`codemagic.yaml`) had the Rust build steps commented out.

This ADR records the decisions made to complete the FFI bridge and create a functional Android build pipeline.

## Decision

### 1. flutter_rust_bridge for FFI

We use **flutter_rust_bridge (FRB) v2.11.1** to generate Dart↔Rust FFI bindings. FRB handles:
- C-ABI symbol exports from Rust
- Dart `dart:ffi` bindings and type marshalling
- Memory safety for strings, `Vec<u8>`, and `Result<T, E>` types
- Platform-specific library loading (`.so` on Android, `.dylib` on iOS)

The Rust crate (`identity_agent_keri`) is annotated with `#[frb(sync)]` on all five public functions matching the Python driver's canonical endpoints (per ADR-002):
- `incept_aid(name, code) → InceptionResult`
- `rotate_aid(name) → RotationResult`
- `sign_payload(name, data) → SignResult`
- `get_current_kel(name) → String`
- `verify_signature(data, signature, public_key) → bool`

### 2. Placeholder-then-Regenerate Pattern

FRB codegen requires a Rust compiler that supports the `keri-core` dependency tree. The Replit development environment has Rust 1.77.2, which is too old for some transitive dependencies. Therefore:

- **Placeholder files** exist in `lib/src/rust/` that define the correct type shapes and API surface. These allow `flutter analyze` to pass during development.
- **CI/CD codegen** runs `flutter_rust_bridge_codegen generate` with a current Rust toolchain, overwriting the placeholders with real FFI bindings before the Flutter build step.

### 3. cargo-ndk for Android Cross-Compilation

We use **cargo-ndk** instead of manually configuring NDK toolchain paths. Benefits:
- Automatically discovers the Android NDK from `$ANDROID_SDK_ROOT`
- Maps Rust targets to Android ABI directories (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`)
- Places `.so` files directly into `android/app/src/main/jniLibs/<abi>/`
- Handles `--platform 21` (minSdk) consistently across all targets

Build targets:
| Rust Target                | Android ABI    | Devices                  |
|---------------------------|----------------|--------------------------|
| `aarch64-linux-android`   | `arm64-v8a`    | Most modern phones       |
| `armv7-linux-androideabi` | `armeabi-v7a`  | Older 32-bit ARM phones  |
| `x86_64-linux-android`    | `x86_64`       | Emulators, Chromebooks   |
| `i686-linux-android`      | `x86`          | Older emulators          |

### 4. Single Codemagic Workflow

The `android-release` workflow in `codemagic.yaml` is a single unified pipeline:
1. Install Rust + Android targets + `cargo-ndk`
2. Cross-compile Rust → `.so` files for all 4 ABIs
3. Run FRB codegen to generate Dart bindings
4. `flutter pub get`
5. Build debug + release APKs

### 5. Platform Detection in KeriBridge

`lib/bridge/keri_bridge.dart` uses runtime platform detection:
- **Android/iOS:** Calls `RustLib.init()` once, then delegates to FRB-generated API
- **Web/Desktop:** Throws `UnsupportedError` with guidance (Desktop uses Python driver via Go backend per ADR-002; web is not supported for KERI operations)

## Consequences

### Positive
- No stubs remain in the bridge — all 5 KERI operations are fully wired
- `flutter analyze` passes during development (placeholder files)
- CI/CD produces APKs with real Rust KERI functionality
- `cargo-ndk` simplifies NDK configuration vs. manual linker paths
- Platform detection prevents runtime crashes on unsupported platforms

### Negative
- Placeholder files must be kept in sync with the Rust API if function signatures change (until codegen can run locally)
- Requires Codemagic's `linux_x2` instance type for the Rust compilation step (build time ~10-15 minutes)

## Future Work

- **iOS build:** Add `aarch64-apple-ios` and `x86_64-apple-ios` targets to `codemagic.yaml` with `cargo lipo` or `cargo-ndk` equivalent
- **Windows/macOS:** Use `cargo build --release` natively on the respective Codemagic instance types
- **Local codegen:** Once Rust toolchain in Replit is updated (≥1.80), FRB codegen can run locally during development
- **Testing:** Add integration tests that exercise the Rust bridge on a real Android device or emulator
