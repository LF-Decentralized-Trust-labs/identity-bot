# Stateless KERI Helper Microservice Documentation

This microservice is a stateless Python FastAPI server that acts as a computational offload engine for KERI (Key Event Receipt Infrastructure) operations. It is designed to handle complex data formatting and resolution tasks for mobile applications while ensuring no private keys are ever handled by the server.

## Features
- **Stateless**: No data is persisted between requests.
- **Privacy-First**: Never accepts or handles private keys; only processes public data.
- **KERI Integration**: Built on `keripy` (v1.1.17) for authentic KERI protocol handling.
- **Path-compatible**: Endpoint paths match the Python KERI driver exactly (driver is source of truth for naming).

## API Endpoints

### 1. Health Check
Returns the server status and the version of the KERI library being used.

- **URL**: `/health`
- **Method**: `GET`
- **Response**:
  ```json
  {
    "status": "ok",
    "version": "1.1.17"
  }
  ```

---

### 2. Format ACDC Credential
Formats an Authentic Chained Data Container (ACDC) credential.

- **URL**: `/format-credential`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "claims": {
      "name": "Alice Smith",
      "role": "Engineer"
    },
    "schema_said": "EExampleSchemaSAID12345...",
    "issuer_aid": "EExampleIssuerAID12345..."
  }
  ```
- **Response**:
  ```json
  {
    "raw_bytes_b64": "...",
    "said": "EMCcsXBr7HnhfXrzoQTtjr0...",
    "size": 235
  }
  ```
- **Note**: The `raw_bytes_b64` contains the serialized CESR bytes that the client should sign locally.

---

### 3. Resolve OOBI
Resolves an Out-Of-Band Introduction (OOBI) URL to find service endpoints.

- **URL**: `/resolve-oobi`
- **Method**: `POST`
- **Request Body**:
  ```json
  {
    "url": "http://example.com/oobi/AID/witness/WITNESS_AID"
  }
  ```
- **Response**:
  ```json
  {
    "endpoints": ["http://1.2.3.4:5642", "tcp://5.6.7.8:1234"],
    "oobi_url": "http://example.com/...",
    "cid": "AID",
    "eid": "WITNESS_AID",
    "role": "witness"
  }
  ```

---

### 4. Generate Multisig Event
Generates KERI events (Inception, Rotation, Interaction) for multisig identifiers.

- **URL**: `/generate-multisig-event`
- **Method**: `POST`
- **Request Body (Inception)**:
  ```json
  {
    "aids": ["AID1", "AID2"],
    "threshold": 2,
    "current_keys": ["PublicKey1...", "PublicKey2..."],
    "event_type": "inception"
  }
  ```
- **Response**:
  ```json
  {
    "raw_bytes_b64": "...",
    "said": "EEDnfZXm_PCZ0-SW_TX4...",
    "pre": "EEDnfZXm_PCZ0-SW_TX4...",
    "event_type": "icp",
    "size": 487
  }
  ```

## Technical Details
- **Base URL**: `https://keri-helper-microservice.replit.app`
- **Dependencies**: Requires `libsodium` system library.
- **Implementation**: Uses FastAPI and `uvicorn`. Temporary workspace directories are used per-request to satisfy KERI library requirements without persisting data.
- **Naming**: All endpoint paths match the Python KERI driver (`server.py`) — the driver is the source of truth for path naming across the entire system.
