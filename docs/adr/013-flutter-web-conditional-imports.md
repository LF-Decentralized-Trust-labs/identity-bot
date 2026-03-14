# ADR-013: Flutter Web Conditional Imports for Native-Only Packages

**Status:** Accepted
**Date:** 2026-03-14
**Related:** ADR-004 (FFI Bridge), ADR-012 (Sandboxed App Marketplace)

## Context

The Identity Agent's Flutter UI compiles to three targets: **web** (served by the Go backend on Replit and desktop), **native desktop** (Windows, macOS, Linux), and **native mobile** (iOS, Android). The same Dart codebase must compile cleanly for all targets.

Two packages caused Flutter web builds to crash:

1. **`flutter_rust_bridge`** — imports `dart:ffi`, which doesn't exist on web. When Dart files importing FRB are included in the web build, dart2js fails to compile.

2. **`flutter_inappwebview`** — the meta-package (v6.x) includes a web plugin (`flutter_inappwebview_web`) that auto-registers during Flutter engine initialization via `web_plugin_registrant.dart`. This plugin calls `nativeCommunication` on `undefined`, causing an unhandled Promise rejection that crashes the app before any Dart code runs. This is a known, unresolved upstream bug (GitHub issues #2076, #1468).

Both packages are only needed on specific platforms (FRB on mobile, InAppWebView on desktop), but Flutter's build system compiles all transitively imported Dart code for the target platform. A file imported anywhere in the dependency tree will be compiled, even if gated by runtime `kIsWeb` checks — runtime guards don't prevent compile-time failures.

## Decision

### 1. Conditional Imports with `dart.library.io`

For any Dart file that imports native-only packages, we use Dart's conditional import/export mechanism:

```dart
export 'component_stub.dart'
    if (dart.library.io) 'component_native.dart';
```

`dart.library.io` evaluates to `true` on native platforms (desktop, mobile) and `false` on web. This is a **compile-time** check — dart2js never parses the native file.

Each component is split into three files:
- **Router** — the original filename, contains only the conditional export
- **Native** — the real implementation with native package imports
- **Stub** — a web-safe fallback exporting the same public API (classes, enums) with no-op or "unsupported" behavior

### 2. Platform-Specific Packages Instead of Meta-Packages

For `flutter_inappwebview`, we replaced the meta-package with individual platform packages:

```yaml
# pubspec.yaml — BEFORE (broken)
flutter_inappwebview: ^6.0.0    # Includes web plugin that crashes

# pubspec.yaml — AFTER (working)
flutter_inappwebview_macos: ^1.1.2
flutter_inappwebview_windows: ^0.6.0
flutter_inappwebview_platform_interface: ^1.3.0
```

This prevents the web plugin from being registered in `web_plugin_registrant.dart` at all. The `_platform_interface` package provides the abstract types (classes, enums) needed for compilation without any native code.

Android and iOS InAppWebView packages are excluded because the sandbox webview feature is desktop-only.

### 3. Stub Contracts

Stubs must export the same public API as their native counterpart:
- Same class names and constructors
- Same enum definitions
- Methods can throw `UnsupportedError` or return safe defaults
- `isAvailable` style getters return `false`

This ensures any file importing the component compiles on all platforms without conditional logic at the call site.

## Components Using This Pattern

| Component | Native File | Stub File | Native Packages |
|---|---|---|---|
| KERI Bridge | `bridge/keri_bridge.dart` | `bridge/keri_bridge_stub.dart` | `flutter_rust_bridge` |
| Sandbox WebView | `widgets/sandbox_webview_native.dart` | `widgets/sandbox_webview_stub.dart` | `flutter_inappwebview_*` |
| Mobile KERI Services | `services/mobile_standalone_keri_service.dart` | (uses bridge stub transitively) | `flutter_rust_bridge` |
| | `services/mobile_remote_keri_service.dart` | (uses bridge stub transitively) | `flutter_rust_bridge` |

## Consequences

**Positive:**
- Flutter web builds succeed without any native-only types leaking into dart2js
- No runtime overhead — the conditional is resolved at compile time
- Desktop and mobile builds are completely unaffected
- Clear pattern for adding future native-only features

**Negative:**
- Each native-only component requires three files instead of one
- Stub files must be kept in sync with the native file's public API
- Developers must know to use this pattern — adding a native package import to a widely-imported file will break web builds

## How to Add a New Native-Only Package

1. Check if the package has a web plugin that auto-registers. If so, use platform-specific sub-packages instead of the meta-package.
2. If Dart code imports native-only types, create the three-file split (router, native, stub).
3. Ensure the stub exports the same public API.
4. Test with `flutter build web` — this is the authoritative check.
5. Update the table in this ADR and in CLAUDE.md.
