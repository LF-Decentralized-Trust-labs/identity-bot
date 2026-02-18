# ADR 002: Python KERI Driver Pattern with keripy

**Date:** 2026-02-18
**Updated:** 2026-02-18
**Status:** Accepted
**Supersedes:** KERI-related sections of ADR 001

## Context

The Identity Agent needs a KERI (Key Event Receipt Infrastructure) protocol engine
to create inception events, manage Key Event Logs, and produce interoperable
CESR-encoded identifiers. The initial design (ADR 001) proposed embedding KERI
logic directly in the Go backend using a custom implementation.

After evaluating the output of that approach against the KERI specification, we
found that a custom implementation produces non-interoperable events — wrong CESR
prefix codes, SHA-256 instead of Blake3 SAIDs, and missing event fields. The
WebOfTrust `keripy` reference library (v1.1.17) is the most battle-tested KERI
implementation and produces spec-correct output.

However, keripy is a Python library. Embedding Python in a Go binary or in a
Flutter mobile app is impractical. We needed an architecture that uses keripy
without coupling it to the Go or Flutter processes.

## Decision

### 1. Internal HTTP Microservice ("Driver Pattern")

The Python KERI engine runs as a separate HTTP process on `127.0.0.1:9999`. The
Go Core communicates with it via HTTP requests. This is called the "Driver Pattern"
because the Python process acts as a hardware-like driver: the Go Core sends
commands, the driver executes KERI protocol operations, and returns results.

```
┌──────────────┐       HTTP        ┌──────────────────┐
│   Go Core    │ ───────────────── │  Python KERI      │
│  (port 5000) │  localhost:9999   │  Driver (keripy)  │
└──────────────┘                   └──────────────────┘
       ▲
       │ HTTP (port 5000)
       │
┌──────────────┐
│   Flutter    │
│   Frontend   │
└──────────────┘
```

The Python driver is ALWAYS a local child process spawned by Go on any
Python-capable OS (Linux, macOS, Windows). Go spawns it via `exec.Command()`,
monitors it, and kills it on exit. There is no "external driver" mode — the
driver always runs on `127.0.0.1:9999`.

On mobile OS (iOS/Android), Python cannot run. Mobile devices use the Rust bridge
for KERI operations instead (see ADR 003).

### 2. keripy as a Hard Requirement (No Fallback)

The driver **requires** keripy and will refuse to start without it. This is a
deliberate choice: producing non-interoperable KERI events is worse than failing
loudly. There is no fallback implementation.

If keripy is not installed or libsodium is not available, the driver prints an
error and exits with a non-zero code. The Go Core detects this and reports the
failure via its health endpoint.

### 3. libsodium Detection for Nix Environments

keripy depends on `pysodium`, which requires `libsodium`. In Nix environments,
`ctypes.util.find_library("sodium")` often returns `None` because Nix doesn't
install libraries in standard system paths.

The driver uses a detection strategy:
1. Try `ctypes.util.find_library("sodium")` first (works on standard systems)
2. If that fails, try loading common `.so` names directly (`libsodium.so.26`, etc.)
3. If a load succeeds, inspect `/proc/<pid>/maps` to find the actual file path
4. Monkey-patch `ctypes.util.find_library` to return the discovered path for
   `sodium` lookups, so pysodium's initialization succeeds

### 4. Driver Lifecycle

Go always spawns Python as a local child process:
- `exec.Command(pythonBin, scriptPath)` starts the driver
- The driver binds to `127.0.0.1:{KERI_DRIVER_PORT}` (default 9999)
- Go waits up to 15 seconds for the driver to become ready (`/status` returns `active`)
- On shutdown (SIGINT/SIGTERM), Go kills the driver process

### 5. Driver API — Source of Truth for Naming

The Python KERI driver defines the canonical path names. All other components
(Rust bridge, Remote Helper, Dart code) match the driver's naming exactly.

#### Stateful Endpoints (require identity state)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/status` | GET | Health check and library info |
| `/inception` | POST | Create a KERI inception event (incept_aid) |
| `/rotation` | POST | Rotate keys for an existing AID (rotate_aid) |
| `/sign` | POST | Sign arbitrary data with an AID's current key (sign_payload) |
| `/kel` | GET | Retrieve the Key Event Log (get_current_kel) |
| `/verify` | POST | Verify a signature against a public key (verify_signature) |

#### Stateless Endpoints (public data only, no private keys)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/format-credential` | POST | Format an ACDC credential for client-side signing |
| `/resolve-oobi` | POST | Resolve an OOBI URL to service endpoints |
| `/generate-multisig-event` | POST | Generate a multisig KERI event (icp/rot/ixn) |

### 6. Endpoint Details

**POST /inception**

Request:
```json
{
  "public_key": "<CESR-encoded Ed25519 public key>",
  "next_public_key": "<CESR-encoded Ed25519 next rotation key>",
  "name": "<optional identity name>"
}
```

Response (201):
```json
{
  "aid": "<KERI Autonomic Identifier>",
  "inception_event": { "v": "KERI10JSON...", "t": "icp", ... },
  "public_key": "<CESR verfer qb64>",
  "next_key_digest": "<Blake3 digest of next key>"
}
```

**POST /rotation**

Request:
```json
{
  "name": "<identity name>",
  "new_public_key": "<CESR-encoded new Ed25519 public key>",
  "new_next_public_key": "<CESR-encoded new next rotation key>"
}
```

Response (200):
```json
{
  "aid": "<AID>",
  "new_public_key": "<CESR verfer qb64>",
  "new_next_key_digest": "<Blake3 digest>",
  "rotation_event": { ... },
  "sequence_number": 1
}
```

**POST /sign**

Request:
```json
{
  "name": "<identity name>",
  "data": "<base64-encoded payload>"
}
```

Response (200):
```json
{
  "signature": "<base64-encoded Ed25519 signature>",
  "public_key": "<CESR verfer qb64>"
}
```

**GET /kel?name=<identity_name>**

Response (200):
```json
{
  "aid": "<AID>",
  "kel": [ { ... icp event ... }, { ... rot event ... } ],
  "sequence_number": 1,
  "event_count": 2
}
```

**POST /verify**

Request:
```json
{
  "data": "<base64-encoded payload>",
  "signature": "<base64-encoded signature>",
  "public_key": "<CESR-encoded public key>"
}
```

Response (200):
```json
{
  "valid": true,
  "public_key": "<CESR verfer qb64>"
}
```

**POST /format-credential**

Request:
```json
{
  "claims": { "name": "Alice", "role": "Engineer" },
  "schema_said": "<SAID of credential schema>",
  "issuer_aid": "<AID of issuing agent>"
}
```

Response (200):
```json
{
  "raw_bytes_b64": "<base64-encoded CESR credential bytes>",
  "said": "<Blake3 SAID of credential>",
  "size": 235
}
```

**POST /resolve-oobi**

Request:
```json
{
  "url": "http://example.com/oobi/AID/witness/WITNESS_AID"
}
```

Response (200):
```json
{
  "endpoints": ["http://1.2.3.4:5642"],
  "oobi_url": "http://example.com/...",
  "cid": "<AID>",
  "eid": "<WITNESS_AID>",
  "role": "witness"
}
```

**POST /generate-multisig-event**

Request:
```json
{
  "aids": ["AID1", "AID2"],
  "threshold": 2,
  "current_keys": ["PublicKey1...", "PublicKey2..."],
  "event_type": "inception"
}
```

Response (200):
```json
{
  "raw_bytes_b64": "<base64-encoded event bytes>",
  "said": "<SAID>",
  "pre": "<prefix>",
  "event_type": "icp",
  "size": 487
}
```

## Consequences

### Positive

- **Spec compliance:** keripy produces CESR-encoded keys with correct prefix codes
  (`D` for Ed25519), Blake3 SAIDs, and proper event structure per KERI spec v1.0.
- **Interoperability:** Events generated by this system can be verified by any
  KERI-compliant implementation (KERIA, SignifyPy, etc.).
- **Mobile-ready:** The driver pattern means Flutter on mobile only needs HTTP
  access to the Go Core. No Python runtime on mobile devices.
- **Upgradeable:** When keripy releases new versions, only the Python driver needs
  updating. Go and Flutter are unaffected.
- **Testable:** The driver's HTTP API can be tested independently of Go or Flutter.
- **Path consistency:** All components (Remote Helper, Rust bridge) use the same
  path names defined by the Python driver.

### Negative

- **Process management:** Go must spawn, monitor, and restart the Python process.
  This adds complexity to the backend.
- **Startup latency:** Python + keripy import adds ~2-3 seconds to cold start.
- **Hard dependency:** If keripy or libsodium is unavailable, the entire identity
  system is non-functional. There is no degraded mode.

### Risks

- **keripy API changes:** If the WebOfTrust team changes the keripy API, the
  driver's protocol helpers will need updating. Mitigated by pinning to v1.1.17.
- **libsodium detection fragility:** The `/proc/maps` inspection approach is
  Linux-specific. macOS and Windows would need different detection strategies.

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `KERI_DRIVER_PORT` | `9999` | Port for the Python driver |
| `KERI_DRIVER_SCRIPT` | `./drivers/keri-core/server.py` | Path to the driver script |
| `KERI_DRIVER_PYTHON` | `python3` | Python binary to use |
| `KERI_DRIVER_HOST` | `127.0.0.1` | Host the driver binds to (always localhost) |

## Key Files

- `drivers/keri-core/server.py` — The Python KERI driver (Flask HTTP server, 9 endpoints)
- `drivers/keri-core/requirements.txt` — Python dependencies (flask, keri)
- `identity-agent-core/drivers/keri_driver.go` — Go HTTP client for the driver
- `identity-agent-core/main.go` — Driver lifecycle management (spawn/kill)
