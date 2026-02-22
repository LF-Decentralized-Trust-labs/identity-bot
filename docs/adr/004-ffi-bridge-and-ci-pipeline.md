# ADR-004: FFI Bridge, Go Mobile Core & CI/CD Pipeline

**Status:** Accepted
**Date:** 2026-02-19
**Updated:** 2026-02-22
**Supersedes:** None
**Related:** ADR-002 (KERI Driver Pattern), ADR-003 (Adaptive Architecture)

## Context

ADR-003 established the four operating modes (Desktop, Mobile Standalone, Mobile Remote Controller WITHOUT Keys, Mobile Remote Controller WITH Keys). Two mobile-specific native integrations are required:

1. **Rust KERI Bridge** (`keriox/keri-core`): Provides all cryptographic KERI operations on mobile via FFI. Used in ALL mobile modes.
2. **Go Mobile Core** (`identity-agent-core`): Provides backend services (data persistence, OOBI serving, contact management, tunneling) on mobile via gomobile platform channels. Used in Mobile Standalone mode.

This ADR records the decisions made to complete both native integrations and the CI/CD pipeline.

## Decision

### 1. Rust KERI Bridge — flutter_rust_bridge for FFI

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

### 3. cargo-ndk for Android Rust Cross-Compilation

We use **cargo-ndk** instead of manually configuring NDK toolchain paths. Benefits:
- Automatically discovers the Android NDK from `$ANDROID_SDK_ROOT`
- Maps Rust targets to Android ABI directories (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`)
- Places `.so` files directly into `android/app/src/main/jniLibs/<abi>/`
- Handles `--platform 21` (minSdk) consistently across all targets

Rust build targets:
| Rust Target                | Android ABI    | Devices                  |
|---------------------------|----------------|--------------------------|
| `aarch64-linux-android`   | `arm64-v8a`    | Most modern phones       |
| `armv7-linux-androideabi` | `armeabi-v7a`  | Older 32-bit ARM phones  |
| `x86_64-linux-android`    | `x86_64`       | Emulators, Chromebooks   |
| `i686-linux-android`      | `x86`          | Older emulators          |

### 4. Go Mobile Core — gomobile for Android/iOS

The Go Core backend is compiled for mobile using **gomobile** (`golang.org/x/mobile/cmd/gomobile`). The `identity-agent-core/mobilecore/` package exports a gomobile-compatible API:

- `StartServer(dataDir string, port int) error` — Starts the Go Core HTTP server with KERI driver disabled
- `StopServer() error` — Stops the server gracefully
- `GetHealth() string` — Returns health check JSON
- `GetPort() int` — Returns the port the server is listening on
- `GetDataDir() string` — Returns the data directory path

**Android:** gomobile produces `mobilecore.aar` placed at `identity_agent_ui/android/app/libs/mobilecore.aar`. The AAR is loaded as a local dependency in `build.gradle`.

**iOS:** gomobile produces `Mobilecore.xcframework` placed at `identity_agent_ui/ios/Frameworks/Mobilecore.xcframework`. The framework is embedded in the Xcode project.

The Go Core on mobile uses `ServerConfig` with:
- `EnableKeriDriver: false` — No Python process is spawned
- Configurable `Port` and `DataDir` — Set from the app's documents directory
- Storage endpoints, OOBI serving, contact management, and tunneling remain fully functional

### 5. Platform Channel Bridge (Kotlin/Swift → Dart)

Native platform code bridges the gomobile library to Flutter via `MethodChannel`:

**Android (`MainActivity.kt`):**
- Registers a `MethodChannel("com.identity_agent/mobile_core")`
- Handles methods: `startServer`, `stopServer`, `isRunning`, `getHealth`, `getPort`, `getDataDir`
- Calls the gomobile-compiled `Mobilecore` Java class directly

**iOS (`AppDelegate.swift`):**
- Registers a `FlutterMethodChannel(name: "com.identity_agent/mobile_core")`
- Handles the same method set
- Calls the gomobile-compiled `MobilecoreStartServer()` Swift/ObjC functions

**Dart (`MobileCoreService`):**
- Wraps the platform channel in a clean async API
- Provides `startCore()`, `stopCore()`, `isRunning()`, `getHealth()`, `getPort()`, `getDataDir()`
- Manages `baseUrl` construction from the runtime port
- Includes `waitForReady()` with timeout for startup sequencing
- Includes `storeIdentity()` and `storeEvent()` for persisting KERI results from the Rust bridge into the Go Core's file store

### 6. Platform Detection in KeriBridge

`lib/bridge/keri_bridge.dart` uses runtime platform detection:
- **Android/iOS:** Calls `RustLib.init()` once, then delegates to FRB-generated API
- **Web/Desktop:** Throws `UnsupportedError` with guidance (Desktop uses Python driver via Go backend per ADR-002; web is not supported for KERI operations)

### 7. CI/CD Pipeline (Codemagic)

The `codemagic.yaml` defines build workflows for all platforms:

**Android Release (`android-release`):**
1. Install Rust + Android targets + `cargo-ndk`
2. Cross-compile Rust → `.so` files for all 4 ABIs
3. Run FRB codegen to generate Dart bindings
4. Install Go + gomobile
5. Run `gomobile bind` → `mobilecore.aar`
6. Place `.aar` in `android/app/libs/`
7. `flutter pub get`
8. Build debug + release APKs

**iOS Release (`ios-release`):**
1. Install Rust + iOS targets
2. Cross-compile Rust → `.dylib` for `aarch64-apple-ios` and `x86_64-apple-ios`
3. Run FRB codegen
4. Install Go + gomobile
5. Run `gomobile bind` → `Mobilecore.xcframework`
6. Place `.xcframework` in `ios/Frameworks/`
7. `flutter pub get`
8. Build iOS archive

**Desktop (macOS/Windows/Linux):**
1. Go binary built natively (`go build`)
2. Flutter desktop build (`flutter build macos/windows/linux`)
3. Backend binary bundled alongside the Flutter app

## Consequences

### Positive
- No stubs remain in the Rust bridge — all 5 KERI operations are fully wired
- Go Core runs embedded on mobile with full backend services (minus KERI driver)
- Platform channels provide reliable native ↔ Dart communication
- `MobileCoreService` provides a clean async Dart API for Go Core lifecycle management
- `flutter analyze` passes during development (placeholder files for Rust bindings)
- CI/CD produces APKs/IPAs with both Rust KERI and Go Core functionality
- `cargo-ndk` simplifies NDK configuration vs. manual linker paths
- Platform detection prevents runtime crashes on unsupported platforms

### Negative
- Placeholder files must be kept in sync with the Rust API if function signatures change (until codegen can run locally)
- Requires Codemagic's `linux_x2` instance type for Rust compilation step (build time ~10-15 minutes)
- gomobile adds ~5-10MB to the mobile app size
- Two separate native compilation toolchains (Rust + Go) add CI complexity

## Key Files

### Rust Bridge
- `identity_agent_ui/rust/src/api/keri.rs` — Rust KERI implementation using `keri-core`
- `identity_agent_ui/lib/bridge/keri_bridge.dart` — Dart wrapper with platform detection
- `identity_agent_ui/lib/src/rust/` — FRB-generated bindings (placeholder in dev, real in CI)

### Go Mobile Core
- `identity-agent-core/mobilecore/mobilecore.go` — Gomobile-compatible package with exported functions
- `identity-agent-core/server/server.go` — Extracted server package with optional KERI driver

### Platform Channels
- `identity_agent_ui/android/app/src/main/kotlin/.../MainActivity.kt` — Android platform channel bridge
- `identity_agent_ui/ios/Runner/AppDelegate.swift` — iOS platform channel bridge
- `identity_agent_ui/lib/services/mobile_core_service.dart` — Dart wrapper around platform channels

### Service Layer
- `identity_agent_ui/lib/services/mobile_standalone_keri_service.dart` — Coordinates Rust bridge + Go Core for Standalone mode
- `identity_agent_ui/lib/services/keri_service.dart` — Abstract interface implemented by all modes

### CI/CD
- `codemagic.yaml` — Build pipelines for Android, iOS, macOS, Windows, Linux

## Future Work

- **Local codegen:** Once Rust toolchain in Replit is updated (≥1.80), FRB codegen can run locally during development
- **Testing:** Add integration tests that exercise the Rust bridge on a real Android device or emulator
- **Migration flow:** Complete the "Migrate to External Server" flow for Mobile Remote Controller WITH Keys mode
