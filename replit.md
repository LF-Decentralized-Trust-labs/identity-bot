# Identity Agent - Control Plane

## Overview
Identity Agent is a sandboxed governance wrapper for AI agents. This Replit project serves as the **Control Plane** — the App Store UI and Management API. The actual execution engine (Docker containers, iptables proxy) will be built separately on a VPS.

The architecture follows a **Control Plane / Data Plane** split:
- **Control Plane (this project):** App Store UI, governance policy management, audit log viewer, management API
- **Data Plane (external VPS):** Real sandbox containers, iptables network interception, execution engine (future)

## Project Architecture

### Go Backend (`identity-agent-core/`)
- Chi router HTTP server on port 5000
- KERI protocol endpoints: inception, rotation, signing, verification, KEL, OOBI, contacts
- **App Store API:** `/api/apps`, `/api/policies`, `/api/audit-log`, `/api/audit-log/ingest`
- File-based JSON storage in `data/`
- Tunnel management (ngrok/cloudflare)
- Serves both Flutter web UI and App Store dashboard

### Python KERI Driver (`drivers/keri-core/`)
- Flask microservice on port 9999 (internal only)
- Uses keripy reference library for KERI cryptographic operations
- Spawned as a child process by the Go backend

### Flutter UI (`identity_agent_ui/`)
- Mobile/web app for identity management
- Pre-built web bundle served by Go backend at `/`

### App Store Dashboard (`app-store-ui/`)
- HTML/CSS/JS dashboard served at `/app-store`
- Shows installed apps, governance policies, audit log
- Communicates with Go backend via REST API

### Key Files
- `identity-agent-core/main.go` — Main Go server with routing
- `identity-agent-core/appstore.go` — App Store API handlers
- `identity-agent-core/store/store.go` — Data models and file-based storage
- `identity-agent-core/drivers/keri_driver.go` — KERI driver client
- `app-store-ui/index.html` — App Store dashboard
- `scripts/start-backend.sh` — Startup script

## How to Run
The workflow "Start application" runs `bash scripts/start-backend.sh` which:
1. Installs Python dependencies (flask, keri)
2. Builds the Go binary if not present
3. Starts the Go server on port 5000, which spawns the Python KERI driver on port 9999

## API Endpoints

### App Store (Control Plane)
- `POST /api/apps` — Register a new app
- `GET /api/apps` — List all apps
- `GET /api/apps/{id}` — Get app details
- `DELETE /api/apps/{id}` — Remove an app
- `POST /api/apps/{id}/launch` — Launch app (stubbed, will webhook to VPS)
- `POST /api/apps/{id}/stop` — Stop app
- `PUT /api/apps/{id}/policy` — Assign policy to app
- `POST /api/policies` — Create governance policy
- `GET /api/policies` — List policies
- `DELETE /api/policies/{id}` — Delete policy
- `GET /api/audit-log` — Get audit log entries
- `POST /api/audit-log/ingest` — Webhook endpoint for VPS to send audit events

### Identity (KERI)
- `GET /api/health` — Health check
- `POST /api/inception` — Create identity
- `POST /api/rotation` — Rotate keys
- `POST /api/sign` — Sign data
- `GET /api/kel` — Get key event log
- `POST /api/verify` — Verify signature

## Deployment
Configured as autoscale deployment running the Go binary.

## Recent Changes
- 2026-02-20: Added App Store Control Plane (Milestone 1)
  - New data models: AppRecord, PolicyRecord, AuditLogEntry
  - App Store REST API with full CRUD + launch/stop/policy assignment
  - App Store Dashboard UI at /app-store with dark theme
  - Audit log with webhook ingest endpoint for future VPS integration
  - Stats dashboard with total apps, running count, policies, events
