# ADR 011: Build Versioning Strategy — Auto-Increment for Development, Semantic for Release

**Date:** 2026-03-07
**Status:** Accepted
**Relates to:** ADR-004 (FFI Bridge & CI/CD Pipeline)

## The Problem This Solves

Every Codemagic build produced an APK/IPA/binary with `versionCode = 1` (from `pubspec.yaml` `version: 1.0.0+1`). On Android, this meant the user had to uninstall the existing app before installing a new build — Android refuses to install an APK with the same or lower version code over an existing installation.

This is a development velocity problem: during active development, the team produces dozens of builds per week. Requiring uninstall/reinstall for every build wastes time and loses app state (SharedPreferences, local data).

The same issue affects iOS (though less critical for simulator testing where apps are always fresh installs), and desktop platforms (where updates are manual file replacement, not OS-managed installs).

## The Decision

### Two Phases

The versioning strategy has two distinct phases, each using a different approach:

### Phase 1: Development (Current)

**Mechanism:** Codemagic's auto-incrementing `$BUILD_NUMBER` environment variable.

Every `flutter build` command in `codemagic.yaml` passes `--build-number` with the Codemagic build counter:

| Platform | Shell | Build Command |
|---|---|---|
| Android | Bash | `flutter build apk --release --target-platform android-arm64 --build-number=$BUILD_NUMBER` |
| iOS | Bash | `flutter build ios --debug --simulator --verbose --build-number=$BUILD_NUMBER` |
| Windows | PowerShell | `flutter build windows --release --build-number=$env:BUILD_NUMBER` |
| macOS | Bash | `flutter build macos --release --build-number=$BUILD_NUMBER` |
| Linux | Bash | `flutter build linux --release --build-number=$BUILD_NUMBER` |

Note: The Windows workflow uses PowerShell, so the environment variable is accessed as `$env:BUILD_NUMBER` instead of `$BUILD_NUMBER`.

**How `$BUILD_NUMBER` works:**
- Codemagic automatically provides this variable for every build.
- It auto-increments per workflow (each workflow has its own counter).
- Values go 1, 2, 3, ... with no upper bound.
- The `--build-number` flag overrides the `+1` in `pubspec.yaml` at build time, so `pubspec.yaml` stays unchanged.

**What this means for each platform:**

| Platform | Effect |
|---|---|
| **Android** | Each APK has a higher `versionCode`. New builds install directly over previous builds without uninstalling. |
| **iOS** | `CFBundleVersion` increments. Not critical for simulator testing (always clean installs), but consistent. |
| **Windows** | Build number increments in the executable metadata. Users identify which build they're running. |
| **macOS** | `CFBundleVersion` increments in the `.app` bundle. |
| **Linux** | Build number increments. Useful for identifying builds in the tarball. |

**What stays the same:**
- `pubspec.yaml` remains at `version: 1.0.0+1`. The `+1` is overridden at build time but the file is not modified.
- The `--build-name` flag is not passed, so the display version stays `1.0.0` across all development builds.
- Build numbers can reach hundreds or thousands — this is expected and fine for internal development.

### Phase 2: Official Releases (Future)

When the project is ready for Play Store / App Store submission:

1. **Remove `--build-number=$BUILD_NUMBER`** from all `flutter build` commands in `codemagic.yaml`.
2. **Switch to semantic versioning** in `pubspec.yaml`:
   - `version: 1.0.0+1` → first official release
   - `version: 1.0.1+2` → patch release
   - `version: 1.1.0+3` → minor release (new features)
   - `version: 2.0.0+4` → major release (breaking changes)
3. **Manually specify versions** for each official release build.

The build number (after the `+`) must still increase monotonically for store submissions. The version name (before the `+`) follows semantic versioning and is controlled by the team.

**Why not set this up now?** During active development, the team produces many builds daily. Manually incrementing version numbers for every build would be tedious and error-prone. The auto-increment approach is specifically designed for this phase. The transition to semantic versioning is a one-time configuration change when the project is ready for public release.

## Platform-Specific Notes

### Android (the critical case)

Android enforces `versionCode` ordering strictly:
- `versionCode` must be a positive integer.
- Installing an APK with `versionCode <= installed versionCode` is rejected by the package manager.
- The `--build-number` flag sets `versionCode` in the generated `AndroidManifest.xml`.
- Debug signing (the current setup) uses a debug keystore. Builds signed with different keystores cannot upgrade each other regardless of version code.

**Important:** If the user switches between Codemagic builds (debug keystore) and local builds (different debug keystore), they will still need to uninstall. This is a signing key mismatch, not a version code issue. To avoid this, always use Codemagic for builds.

### iOS

- `CFBundleVersion` must increase for TestFlight / App Store uploads.
- For simulator testing (current setup — no Apple Developer account), version code doesn't block installation.
- The `--build-number` flag is still applied for consistency and future-proofing.

### Desktop (Windows, macOS, Linux)

- Desktop apps don't have OS-managed installation like mobile apps.
- Users manually download and replace files (ZIP, DMG, tarball).
- Version numbers are useful for identifying which build is running, but don't block installation.
- The `--build-number` flag sets the build metadata in the executable/bundle.

## Consequences

### Positive

- **Android installs work.** New APKs install directly over previous versions without uninstalling. App state (SharedPreferences, local data) is preserved.
- **Zero manual effort.** No version bumping, no config changes, no human intervention for every build. Developers push code, Codemagic produces a correctly-versioned build.
- **All platforms consistent.** The same `--build-number` pattern is applied to all five platform workflows.
- **Clean transition path.** Switching to semantic versioning for official releases is a simple config change — remove `--build-number=$BUILD_NUMBER` from Codemagic and start managing `pubspec.yaml` versions manually.

### Negative

- **Build numbers are not human-friendly.** Build 347 doesn't tell the user what changed. This is acceptable for internal development but not for public releases.
- **Per-workflow counters.** Each Codemagic workflow has its own `$BUILD_NUMBER` counter. Android build 45 and iOS build 12 are different workflows and have different build numbers. This is fine — the counters don't need to be synchronized.
- **Signing key constraint.** Version code auto-increment only works when all builds use the same signing key (Codemagic's debug keystore). Builds from different signing environments still require uninstall/reinstall.

## Key Files

| File | Role |
|---|---|
| `codemagic.yaml` | All five platform workflows with `--build-number=$BUILD_NUMBER` |
| `identity_agent_ui/pubspec.yaml` | Base version (`1.0.0+1`) — overridden at build time |
| `identity_agent_ui/android/app/build.gradle` | Reads `flutterVersionCode` from local.properties (set by `--build-number`) |
