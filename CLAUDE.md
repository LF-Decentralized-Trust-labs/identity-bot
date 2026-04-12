# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Planning Documents (check these at the start of every session)

All planning docs live in `C:\Users\Boogie Bob\Documents\GitHub\strategy\` (also at `https://github.com/bobert600/strategy`).

| Folder | File | Purpose |
|---|---|---|
| `1. Strategy/` | `daily.md` | **Session state** — where to resume, current blockers; read this first at session start |
| `1. Strategy/` | `tasks.md` | **90-day backlog** — all tasks with detailed subtasks; read the relevant section after daily.md |
| `1. Strategy/` | `roadmap.md` | Strategy only — business model, revenue streams, architecture vision |
| `1. Strategy/` | `unknowns.md` | Open questions and unresolved problems that need a decision before building |
| `1. Strategy/` | `tasks-completed.md` | Archive — high-level tasks moved here when fully done |
| `2. Plans/` | `*.md` | Architecture + technical specs — how features work end-to-end; **every plan doc must have a corresponding high-level task entry and detailed breakdown in tasks.md** |
| `3. Design/` | `flows.md` | UX flows & use case scenarios |
| `3. Design/` | `*.md` | UI/UX specifications — visual design, copy, component specs |

**Workflow:**
- At session start ("Start session!"): read `1. Strategy/daily.md` — it tells you exactly where to resume and which section of tasks.md to read. Report to the user what's on deck. If daily.md has no active tasks, read the top of `1. Strategy/tasks.md` and suggest the next unchecked high-level task, recommending the user add it to today's session.
- During session: daily.md is NOT updated constantly — it is a session state file, not a live checklist. Work directly from tasks.md checkboxes.
- At session end ("Stop session!"): update tasks.md checkboxes for everything completed, move any fully-finished high-level tasks to `tasks-completed.md`, then write a fresh resume marker in daily.md (what to pick up, which file/function/section to look at first).

**Plan doc → Task rule (mandatory):** Every new document created in `2. Plans/` MUST have a corresponding entry in the high-level task list in `tasks.md` AND a detailed breakdown section under `## Detailed Breakdown`. Never create a plan document without first adding both. The plan doc is the "why and how"; the task entries are the actionable checkboxes. One cannot exist without the other. See `tasks.md` → "Convention for new high-level tasks" for the full convention.

**Milestone STATUS formatting (mandatory):** When updating STATUS sections in `product-roadmap-v2.md`, follow this convention exactly:
- `[x]` alone = fully complete (NO trailing description, NO file references, NO sizes)
- `[x] note` = started / in-progress (trailing note describes what's done AND what remains)
- `[ ]` alone = not started
- `[ ] note` = not started but has context about what's needed or blocking

**Task list cleanup on completion (mandatory):** When a task or document is finished, distinguish between two kinds of locations and treat them differently:

1. **TODO / "what's missing" / pending-work lists** — these exist ONLY to tell future readers what still needs to be done. Examples: `daily.md` Priority A/B/C action lists, `daily.md` "What's Actually Missing" tables, "Recommended Next Actions" lists, "Pending ARCH docs" sections, ad-hoc TODO bullets. **When the work is done, DELETE the entry entirely. Do NOT replace it with "✅ complete" commentary or "now done — see X" notes.** The list is a queue, not a journal. If it isn't pending, it doesn't belong on the queue. Renumber surrounding items if needed.

2. **High-level completion trackers** — these exist explicitly to record what has been done. Examples: `product-roadmap-v2.md` STATUS checkbox blocks (`- [x] Architecture — ...`), `tasks.md` high-level checkboxes, `tasks-completed.md` archive, milestone STATUS headers. **These get marked done in place** — flip `[ ]` → `[x]`, update the trailing description to point at the completed artifact, follow the Milestone STATUS formatting rules above.

The principle: if the line exists to say "this still needs doing," delete it when it doesn't. If the line exists to track historical completion, mark it done. Never leave completion commentary in pending-work lists — it adds noise and makes the queue harder to scan.

Session-log fields (`daily.md` "Last updated" header, commit messages, audit logs) are journals — they record what happened and stay forever. Don't delete from those.

**Document Status Taxonomy (mandatory — canonical source: `strategy/system/task-creation-process.md`):** Every document in `strategy/2. Plans/`, `strategy/3. Design/`, public docs, and the public website uses a `STATUS:` header. Use these labels verbatim — do NOT invent new words (no "AGREED", "ARCHITECTED", "FINAL", "DRAFT", "BRIEFING", etc.). If a new state seems needed, amend `strategy/system/task-creation-process.md` first.

*Internal work products* — arch docs (`2. Plans/`), design docs (`3. Design/`), and task breakdowns (`1. Strategy/tasks.md` sections):

| Label | Meaning |
|---|---|
| `STATUS: OUTLINE` | In progress. Still being written. Not ready for Rob to read end-to-end. |
| `STATUS: AWAITING REVIEW` | Claude believes it is complete. Rob needs to read and approve or send back. If Rob sends it back, the doc stays in AWAITING REVIEW (or drops to OUTLINE for major rework). |
| `STATUS: APPROVED (YYYY-MM-DD)` | Rob has signed off. Locked in. Include the approval date. |

*Public Documentation* — developer docs, API docs, user guides:
`STATUS: OUTLINE` → `STATUS: AWAITING REVIEW` → `STATUS: APPROVED (YYYY-MM-DD)` → `STATUS: PUBLISHED (YYYY-MM-DD)`

*Public Website* — marketing / landing / pricing pages:
`STATUS: OUTLINE` → `STATUS: COPY` → `STATUS: DESIGN` → `STATUS: AWAITING REVIEW` → `STATUS: APPROVED (YYYY-MM-DD)` → `STATUS: LIVE (YYYY-MM-DD)`

**Important distinction:** Arch docs and design docs are INTERNAL work products (for Rob + Claude). Public documentation and the public website are EXTERNAL outputs shipped to users. Do not conflate phase 9/10 "Docs" and "Website" in task-creation-process.md with internal arch/design docs — they are different things with different lifecycles.

## What This Is

The **Identity Agent** is a self-hosted, self-sovereign digital identity infrastructure. It is software that individuals (and eventually organizations) install on their own devices. It is not a platform — it is a user-controlled agent where the cryptographic identity is fully owned and managed by the user under the KERI (Key Event Receipt Infrastructure) protocol. There is no central server, no third-party custody of keys, and no dependency on any external service for core identity operations.

The codebase implements the **Identity Agent Protocol** — an open, self-sovereign identity infrastructure that the project intends to standardize through a formal standards body over time.

The Identity Agent runs on five target platforms: **Linux, Windows, macOS** (desktop) and **iOS, Android** (mobile). All five run the same Flutter frontend. The backend differs by OS capabilities.

## Build Commands

### Go Backend
```sh
cd identity-agent-core
go build ./...                                                  # Build and check all packages
CGO_ENABLED=0 go build -o bin/identity-agent-core .            # Static binary for deployment
go test ./...                                                   # Run all tests
```

### Flutter UI
```sh
cd identity_agent_ui
flutter pub get
flutter build web --release --base-href="/"   # Web (served by Go backend)
flutter run -d windows                         # Desktop (Windows)
flutter run -d linux                           # Desktop (Linux)
flutter run -d macos                           # Desktop (macOS)
```

### Go Demo Sandbox App
```sh
cd sandbox-apps/go-demo
CGO_ENABLED=0 go build -o ../../bin/go-demo .   # Output must be at bin/go-demo (auto-.exe on Windows)
```

### Full Pipeline (Linux/CI)
```sh
scripts/build-flutter.sh    # Builds Flutter web + Go static binary
scripts/start-backend.sh    # Installs Python deps, builds if needed, starts server
scripts/deploy-run.sh       # Minimal run (skips build steps, uses pre-built binary)
```

### Python KERI Driver (Desktop)
```sh
pip install flask keri==1.1.17
# The driver is spawned automatically by the Go backend — never run it directly
```

## Running Locally

```sh
# Start Go backend (also spawns Python KERI driver automatically)
cd identity-agent-core
go run .
# → API: http://127.0.0.1:5050/api
# → Flutter web UI (if built): http://127.0.0.1:5050/

# Optional: Flutter hot reload during UI development
cd identity_agent_ui
flutter run -d chrome   # Connects to backend on port 5050
```

Key environment variables for the Go backend:
| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5050` | HTTP listen port |
| `AGENT_DATA_DIR` | `./data` | JSON data persistence directory |
| `FLUTTER_WEB_DIR` | `../identity_agent_ui/build/web` | Served Flutter web assets |
| `KERI_DRIVER_SCRIPT` | `./drivers/keri-core/server.py` | Path to Python KERI driver |
| `KERI_DRIVER_PORT` | `9999` | Python driver port |
| `KERI_DRIVER_PYTHON` | `python3` | Python binary |
| `PUBLIC_URL` | _(auto-detected)_ | Explicit override for OOBI URL generation |
| `NGROK_AUTHTOKEN` | _(none)_ | ngrok tunnel auth token |

## Architecture

### Core Concept: 3 Topological States × 2 Device Types

Every running Identity Agent instance is in exactly one of **3 topological states**, on one of **2 device types** — giving 6 architectural combinations. This model from ADR-006 is the authoritative terminology (it supersedes the "four modes" language in older ADRs).

**Three Topological States:**

| State | Description |
|---|---|
| **Standalone** | Device holds root AID keys AND runs all backend services locally. Fully self-contained. |
| **Remote Controller WITHOUT Root Keys** | Device holds a delegated child AID locally. Remote parent server holds the root AID and provides backend services. |
| **Remote Controller WITH Root Keys** | Device holds the primary parent AID and root keys locally. Remote server provides compute-heavy backend services only — never receives private keys. |

**Two Device Types:**

| Device | KERI Engine | Backend Engine |
|---|---|---|
| Desktop (Linux/macOS/Windows) | Go backend → Python `keripy` (child process) | Go Core (local binary, port 5050) |
| Mobile (iOS/Android) | Rust bridge via `flutter_rust_bridge` FFI | Go Core via `gomobile` (embedded, port 8642) |

**6 Architectural Combinations:**

| # | Device | Topology | `KeriService` Implementation | How Entered |
|---|---|---|---|---|
| 1 | Desktop | Standalone | `DesktopOnDeviceKeriService` | "Create New Identity" on desktop |
| 2 | Desktop | Remote WITHOUT Keys | `DesktopOnDeviceKeriService` + remote serverUrl to screens | "Connect to Existing" on desktop |
| 3 | Desktop | Remote WITH Keys | `DesktopOnDeviceKeriService` + remote serverUrl to screens | Planned: migration from Desktop Standalone |
| 4 | Mobile | Standalone | `MobileOnDeviceKeriService()` | "Create New Identity" on mobile |
| 5 | Mobile | Remote WITHOUT Keys | `MobileRemoteKeriService(serverUrl:)` | "Connect to Existing" (Rust bridge unavailable) |
| 6 | Mobile | Remote WITH Keys | `MobileOnDeviceKeriService(pairedServerUrl:)` | "Connect to Existing" (Rust bridge available) |

### Critical Invariant

**Stateful KERI operations always use the LOCAL engine** in all 6 combinations. The remote server is ONLY used for backend services (persistence, OOBI, contacts, tunneling) and stateless KERI operations (format-credential, resolve-oobi, generate-multisig-event). **The remote server never performs stateful KERI operations on behalf of the local device.**

### Port Map

| Service | Port |
|---|---|
| Go backend (desktop) | `127.0.0.1:5050` |
| Go Core (mobile embedded) | `127.0.0.1:8642` |
| Python KERI driver | `127.0.0.1:9999` |

**Always use `127.0.0.1`, never `localhost`.** On Windows, `localhost` can resolve to `::1` (IPv6) while the Go backend only binds IPv4.

### Go Backend (`identity-agent-core/`)

- `main.go` → `server/server.go` (`CoreServer`) — wires all components together
- `server/server.go` — Chi router, all `/api/` routes; calls `sandboxRoutes()` and `traceRoutes()`
- `server/sandbox_handlers.go` — Marketplace REST handlers
- `drivers/keri_driver.go` — Spawns Python driver as child process, proxies all KERI operations over HTTP to `127.0.0.1:9999`
- `endpoint/` — Single source of truth for the agent's public URL; resolution hierarchy: `PUBLIC_URL` env > active tunnel > forwarded headers > local
- `tunnel/` — Multi-provider tunneling (Cloudflare, ngrok, Grape ID via Chisel)
- `store/store.go` — `Store` interface; default is `FileStore` (file-based JSON in `AGENT_DATA_DIR`)
- `sandbox/` — Sandboxed App Marketplace: manifest loading, Podman container runtime, compiled binary runtime, MITM proxy, policy engine, SQLite DB
- `mobilecore/` — `gomobile`-exported API surface for mobile platform channel integration

### Python KERI Driver (`drivers/keri-core/`)

Runs as `127.0.0.1:9999`. The Go Core spawns it via `exec.Command()`, waits up to 15 seconds for `/status` to return `active`, and kills it on shutdown. It is **disabled on mobile** (`EnableKeriDriver: false`).

The driver's endpoint paths are the **single source of truth** for naming — Rust bridge functions and Dart service methods match exactly:

| Driver Endpoint | Type | Purpose |
|---|---|---|
| `POST /inception` | Stateful | Create KERI inception event |
| `POST /rotation` | Stateful | Rotate keys |
| `POST /sign` | Stateful | Sign data |
| `GET /kel` | Stateful | Retrieve Key Event Log |
| `POST /verify` | Stateful | Verify signature |
| `POST /format-credential` | Stateless | Format ACDC credential |
| `POST /resolve-oobi` | Stateless | Resolve OOBI URL |
| `POST /generate-multisig-event` | Stateless | Generate multisig event |

### Flutter UI (`identity_agent_ui/`)

- `lib/main.dart` — App entry point; `AgentRouter` state machine drives the onboarding flow; `_initializeServiceForMode()` instantiates the correct `KeriService`
- `lib/config/agent_config.dart` — Platform-aware backend URL (`defaultDesktopPort=5050`, `mobilePort=8642`); supports `CORE_URL` env override
- `lib/services/keri_service.dart` — Abstract `KeriService` interface; all screens are mode-agnostic
- `lib/services/backend_process_service.dart` — Spawns/monitors the Go binary on desktop; handles port conflicts (auto-kills stale Identity Agent processes, prompts for others)
- `lib/bridge/keri_bridge.dart` — Dart ↔ Rust FFI; gracefully sets `isAvailable=false` if native lib not found (development fallback)

### Onboarding State Machine

```
LOADING → (saved state?) → DASHBOARD
                         ↓ (no saved state)
              MODE SELECTION
              ↙              ↘
   "Create New"           "Connect to Existing"
        ↓                       ↓
  ENTITY TYPE            CONNECT SERVER (validates /api/health)
        ↓                       ↓
  SETUP WIZARD            DASHBOARD
        ↓
   DASHBOARD
```

Onboarding choices are persisted in SharedPreferences via `PreferencesService` (`agent_mode`, `entity_type`, `server_url`, `setup_complete`).

### Sandboxed App Marketplace (Desktop Only)

Apps are defined in `manifests/*.json`. Two runtime types:
- **OCI containers** — run via Podman CLI (rootless, daemonless; not Docker)
- **Compiled binaries** — e.g., `bin/go-demo` (`.exe` appended automatically on Windows)

App lifecycle: `available → installing → stopped → running`. Uninstall resets to `available` so users can reinstall in-session. A Podman setup wizard auto-installs Podman using `winget` / `brew` / `apt` / `dnf` when not found.

**Sandbox security:** Runtime-injected env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `IDENTITY_AGENT_API`) are reserved and cannot be overridden by manifest-defined variables.

## Platform-Specific Notes

### Windows Desktop
- Python is **not** bundled — users install Python 3.10+ manually and run `pip install flask keri==1.1.17`
- `libsodium.dll` is bundled in the app directory (no user action needed)
- See `DESKTOP_SETUP.md` for user-facing instructions

### macOS / Linux Desktop
- Python and dependencies are embedded in the distributed archive

### Mobile (iOS / Android)
- **No App Store or Play Store submissions** — debug/local builds only
- **No code signing or provisioning profiles**
- Android: unsigned APKs via Codemagic (`codemagic.yaml`)
- iOS: Codemagic simulator/virtual testing only (no TestFlight)
- Rust cross-compilation and `gomobile` binding only run in Codemagic CI/CD, not locally

## Commit Requirements

All commits must include a DCO (Developer Certificate of Origin) sign-off. Append this line to every commit message:

```
Signed-off-by: Rob Andersen rob@antispamguy.org
```

Global git config is set to `user.name = "Rob Andersen"` and `user.email = "rob@antispamguy.org"`.

## Flutter Web Compatibility: Conditional Imports

The Flutter UI compiles to **web** (served by the Go backend) and also runs as **native desktop** and **mobile** apps. Several packages use native APIs that don't exist on web. To prevent dart2js compilation failures and runtime crashes, the codebase uses Dart conditional imports.

### The Rule

**Any Dart file that imports a native-only package (`dart:io`, `flutter_rust_bridge`, `flutter_inappwebview`, etc.) must NEVER be directly imported from code that compiles on web.** Instead, use the conditional import pattern:

```dart
// router file (e.g., sandbox_webview.dart)
export 'sandbox_webview_stub.dart'
    if (dart.library.io) 'sandbox_webview_native.dart';
```

Three files per component:
1. **Router** (`foo.dart`) — conditional `export`, no logic
2. **Native** (`foo_native.dart`) — real implementation with native imports
3. **Stub** (`foo_stub.dart`) — web-safe fallback (no native imports)

Both native and stub must export the **same public API** (same class names, same enums).

### Current Conditional Imports

| Component | Router | Native | Stub | Reason |
|---|---|---|---|---|
| KERI Bridge | `keri_bridge.dart` (conditional import in `main.dart`) | `bridge/keri_bridge.dart` | `bridge/keri_bridge_stub.dart` | `flutter_rust_bridge` FFI crashes on web |
| Sandbox WebView | `widgets/sandbox_webview.dart` | `widgets/sandbox_webview_native.dart` | `widgets/sandbox_webview_stub.dart` | `flutter_inappwebview` native types don't exist on web |
| Mobile On-Device KERI | (imports bridge stub/native transitively) | `services/mobile_on_device_keri_service.dart` | — | Uses `flutter_rust_bridge` via bridge conditional import |

### Adding New Native-Only Packages

When adding a Flutter package that uses native platform APIs:

1. **Check if it has a web plugin.** Look at `flutter pub get` output or the package's `pubspec.yaml` for web platform support. If it auto-registers a web plugin that crashes, you must exclude it.
2. **Use platform-specific packages** instead of meta-packages when available (e.g., `flutter_inappwebview_macos` + `flutter_inappwebview_windows` instead of `flutter_inappwebview`). This prevents unwanted web plugin registration.
3. **Apply the conditional import pattern** if the file using the package references native-only types. The web compiler (dart2js) must never see those types.
4. **Test with `flutter build web`** — this is the build that catches missing conditional imports.

See ADR-013 for the full rationale and history.

## Design Conventions

- Dark cyberpunk aesthetic: `AppTheme.darkTheme`, `AppColors.*` from `lib/theme/app_theme.dart`
- Monospace fonts throughout; dark blue/green color palette
- All Flutter ↔ backend communication is REST over HTTP to the local Go backend
- ADR documents in `docs/adr/` are the authoritative source for architectural decisions; ADR-006 is the current topology reference
