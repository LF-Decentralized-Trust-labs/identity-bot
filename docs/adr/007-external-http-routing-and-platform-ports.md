# ADR 007: Flutter Never Calls External URLs Directly — All Outbound Traffic Routes Through Go Backend

**Date:** 2026-03-03
**Status:** Accepted
**Relates to:** ADR-001 (Core Architecture), ADR-006 (Topology)

## The Problem This Solves

Two bugs were discovered and fixed that share the same root cause — Flutter making HTTP calls that bypass the Go backend:

### Bug 1: Name Availability Check Failed on Web (CORS)

`CoreService.checkGrapeIdName()` was calling `https://grapeid.org/check-name?name=...` directly from Flutter/Dart. This worked on desktop (native HTTP, no CORS enforcement) but **failed silently on Flutter Web** — the browser blocks cross-origin requests unless the target server sends `Access-Control-Allow-Origin` headers. The Grape ID hub does not send those headers (it doesn't need to — it's an API for server-to-server calls), so the browser refused the request and Flutter threw a `ClientException: Failed to fetch`.

### Bug 2: Wrong Port Fallback on Mobile

`AgentConfig.coreBaseUrl` returned `http://localhost:5000` for ALL non-web platforms, including Android and iOS, where Go Core runs on port **8642** (not 5000). When `widget.serverUrl` was null — during Go Core startup, a timing race, or any error — every screen's `CoreService` fell back to the wrong port. The result was `Connection refused` on every API call.

## The Decisions

### Decision 1: Flutter only calls its own Go backend

**Rule: All Flutter HTTP calls must target `$baseUrl/api/...` (the local Go backend). Flutter never calls external URLs directly.**

The Go backend (running on the same device) is the only HTTP target for Flutter. When the app needs data from an external service (Grape ID hub, OOBI resolver, any third-party API), the Go backend provides a proxy or adapter endpoint that Flutter calls locally. The Go backend then makes the outbound call server-side.

This rule applies uniformly across all platforms — desktop, mobile, and web. The platform does not change the rule; only the *port* differs (see Decision 2).

**Why this works:**

| Layer | Platform | No CORS | TLS handled by Go | Consistent API surface |
|---|---|---|---|---|
| Flutter → Go (local) | All | No CORS (same origin or loopback) | Go manages TLS itself | Same `baseUrl/api/...` on all platforms |
| Go → External | Server-side | Server has no browser-enforced CORS | Go's TLS client with system certs | Go handles retries, timeouts, auth |

### Decision 2: Platform-aware port configuration via AgentConfig

The Flutter UI needs to know which local port its Go backend is on. This is now defined in one place: `identity_agent_ui/lib/config/agent_config.dart`.

| Platform | Go Backend Port | `AgentConfig.coreBaseUrl` |
|---|---|---|
| Flutter Web | (same origin, no port) | `''` (empty string — relative URLs) |
| Desktop (Linux/macOS/Windows) | 5000 | `http://localhost:5000` |
| Mobile (Android/iOS) | 8642 | `http://127.0.0.1:8642` |

The `dart:io` `Platform` class cannot be imported in files that compile for web. The solution is conditional imports:

```dart
// agent_config.dart
import 'platform_helper_stub.dart'     // web: isMobilePlatform() = false
    if (dart.library.io) 'platform_helper_io.dart'; // native: uses dart:io Platform

// platform_helper_io.dart
import 'dart:io' show Platform;
bool isMobilePlatform() => Platform.isAndroid || Platform.isIOS;

// platform_helper_stub.dart
bool isMobilePlatform() => false;
```

### Decision 3: Consistent server URL resolution across all screens

Every screen that holds a `CoreService` uses the same three-step resolution chain to find the right backend URL:

```
1. widget.serverUrl         — explicitly passed by parent (highest priority)
2. MobileStandaloneKeriService.baseUrl — from running mobile core (if available)
3. AgentConfig.coreBaseUrl  — platform-aware default (final fallback)
```

This is implemented as `_resolveServerUrl()` on all five main screens (Dashboard, Profile, Contacts, OOBI, Settings). The method is identical across screens and must stay that way — it is the safety net that prevents port 5000 from ever being used on mobile.

## How to Add a New External Call

When a new feature needs to call an external API or service, follow this pattern:

### Step 1: Add a proxy endpoint to the Go backend

```go
// In identity-agent-core/server/server.go
r.Get("/settings/my-service/check-something", s.handleCheckSomething)

func (s *CoreServer) handleCheckSomething(w http.ResponseWriter, r *http.Request) {
    param := r.URL.Query().Get("param")
    client := &http.Client{Timeout: 8 * time.Second}
    resp, err := client.Get("https://external-service.example/api?param=" + param)
    // ... forward response to Flutter
}
```

### Step 2: Call the proxy from Flutter via CoreService

```dart
// In identity_agent_ui/lib/services/core_service.dart
Future<bool> checkSomething(String param) async {
  final url = Uri.parse('$baseUrl/api/settings/my-service/check-something?param=${Uri.encodeComponent(param)}');
  final response = await _client.get(url);  // _client, not http.get — uses baseUrl
  // ...
}
```

**Never** do this in Flutter:
```dart
// WRONG — direct external call from Flutter
final response = await http.get(Uri.parse('https://external-service.example/api?param=$param'));
```

## Decision Rule Table

| Scenario | Where does the call go? | Why |
|---|---|---|
| Load profile, contacts, identity | Flutter → `$baseUrl/api/...` | Backend API, always local |
| Check Grape ID name availability | Flutter → Go proxy → hub | External URL — browser CORS, Go owns TLS |
| Claim / reconnect / release Grape ID name | Go backend only | These are tunnel lifecycle ops, never from Flutter |
| Resolve OOBI URL | Flutter → `$baseUrl/api/resolve-oobi` | External but proxied through Go |
| Any `https://external-*.com/...` call | NEVER from Flutter | Add a Go proxy endpoint instead |
| Internal Go Core at 127.0.0.1:8642 | MobileCoreService only | Go Core health/store calls during mobile startup — local loopback, not external |

## External Calls Inventory

All known outbound internet calls as of 2026-03-03:

| Purpose | Caller | Endpoint | Notes |
|---|---|---|---|
| Check Grape ID name availability | Go backend (proxy) | `GET grapeid.org/check-name?name=...` | Flutter calls `GET /api/settings/tunnel/check-name` |
| Claim Grape ID tunnel name | Go backend (`grapeid.go`) | `POST grapeid.org/claim-name` | Triggered on tunnel Start() |
| Reconnect Grape ID tunnel name | Go backend (`grapeid.go`) | `POST grapeid.org/reconnect` | Tried first on Start() before claim |
| Release Grape ID tunnel name | Go backend (`grapeid.go`) | `POST grapeid.org/release-name` | Best-effort on Stop(), 3s timeout |
| Cloudflare tunnel | Go backend | `cloudflared` subprocess | Not an HTTP call — subprocess |
| ngrok tunnel | Go backend | `golang.ngrok.com/ngrok` SDK | SDK manages connection internally |
| OOBI resolution | Go backend (KERI driver) | External OOBI URL | Python keripy handles this on desktop |

When adding new entries to this inventory, update this table.

## Consequences

- **Web platform works correctly.** Browser CORS is never triggered because Flutter only calls same-origin or loopback URLs.
- **Mobile connects to the correct port.** `AgentConfig.coreBaseUrl` now returns port 8642 on Android/iOS, 5000 on desktop, and empty string on web. The wrong-port fallback bug cannot recur.
- **One rule to remember.** Any developer adding a feature that needs an external API knows immediately: add a Go proxy endpoint, then call that from Flutter. No exceptions.
- **Go backend is the trust boundary.** Certificate validation, authentication headers, timeouts, and retries are all handled by Go — not scattered across Flutter code that runs differently on each platform.
- **Mobile core startup calls are exempt.** `MobileCoreService` calls `http://127.0.0.1:8642/api/health` and `/api/store/*` directly during Go Core startup, before `CoreService` is initialized. These are loopback calls to the local embedded Go Core, not external calls, and are intentionally not routed through `CoreService`.
