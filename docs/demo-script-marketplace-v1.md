# Sandboxed App Marketplace V1 — Demo Script

## Prerequisites

- Docker Desktop installed and running
- Identity Agent backend running (port 5000)
- Identity Agent Flutter UI running (desktop build)
- For Open WebUI: OpenRouter API key configured in Identity Agent settings

## Demo 1: Go Demo App (Compiled Binary — Agent Communication Channel)

**Purpose**: Proves the Agent API resource request channel works end-to-end.

### Steps

1. Open the **APPS** tab in the bottom navigation
2. Find **Go Demo App** in the marketplace grid
3. Click **INSTALL** — instant, no Docker pull needed (compiled binary)
4. Click **LAUNCH** — terminal widget opens in the sandbox viewer
5. Observe the Go Demo App output:
   - "Sandbox Agent reporting for duty"
   - Health check against `IDENTITY_AGENT_API`
   - Batch resource request: network, filesystem, camera
6. Switch to the **REQUESTS** tab in the right panel
   - `network:api.example.com` → auto-approved (in manifest)
   - `filesystem:/documents` → pending (user approval required)
   - `device:camera` → auto-denied (blocked in manifest)
7. Click **APPROVE** on the filesystem request
8. Observe the terminal: Go Demo App acknowledges the approval
9. Click **STOP** to terminate

### What It Proves

- Compiled binary ↔ agent communication works
- Resource request channel (batch request/response)
- Policy engine: auto-approve, hold, auto-deny all function
- Terminal display renders correctly

## Demo 2: Chromium Browser (kasmweb — GUI Streaming)

**Purpose**: Proves GUI app streaming and HTTP/HTTPS interception work.

### Steps

1. In the **APPS** tab, find **Chromium Browser**
2. Note the size warning (~2-3 GB download)
3. Click **INSTALL** — Docker image pull begins (progress shown in backend logs)
4. Wait for installation to complete (may take several minutes)
5. Click **LAUNCH** — kasmweb VNC display loads in the WebView
6. Navigate to an allowed domain (e.g., google.com)
7. Switch to the **INTERCEPT** tab in the right panel
   - Requests to `*.google.com`, `*.googleapis.com` → auto-approved
8. Navigate to an unknown domain (e.g., randomsite.com)
   - Request appears as **HELD** in the intercept log
9. Click **APPROVE** on the held request — page loads
10. Check the **HEALTH** tab — CPU/memory gauges show container usage
11. Click **STOP** to terminate

### What It Proves

- Docker GUI app streaming via kasmweb/VNC
- WebView display works on desktop
- HTTP/HTTPS proxy interception
- Policy engine: auto-approve known domains, hold unknown domains
- Resource monitoring (CPU/memory/disk/network gauges)

## Demo 3: Open WebUI (AI Chat — Credential Injection)

**Purpose**: Proves web app proxying and credential vault injection work.

### Steps

1. Ensure an OpenRouter API key is saved in Identity Agent settings
2. In the **APPS** tab, find **Open WebUI**
3. Click **INSTALL** → Docker pull
4. Click **LAUNCH** — Open WebUI chat interface loads in WebView
5. Open WebUI is pre-configured to use `http://agent.internal/llm/v1` as its API base
6. Send a chat message
7. The proxy intercepts the outbound API call to `openrouter.ai`:
   - Domain is pre-approved in manifest → auto-approved
   - Credential vault injects the `Authorization: Bearer` header
   - API key never enters the container
8. Response streams back through the proxy to Open WebUI
9. Check the **INTERCEPT** tab — API calls logged
10. Click **STOP** to terminate

### What It Proves

- Web app proxying through Docker
- Credential vault: API keys injected at proxy layer, never stored in container
- Pre-approved domains work for API calls
- Real AI interaction through the sandbox

## Demo 4: OpenClaw (Complex Docker App)

**Purpose**: Proves complex containerized apps work in the sandbox.

### Steps

1. In the **APPS** tab, find **OpenClaw**
2. Click **INSTALL** → Docker pull
3. Click **LAUNCH** — OpenClaw web UI loads in WebView
4. Interact with the application
5. Check the **INTERCEPT** tab — network requests logged
6. Click **STOP** to terminate

### What It Proves

- Complex TypeScript/Node.js apps work in Docker sandbox
- Full dependency tree runs correctly under proxy
- Network interception captures all traffic

## Clean Shutdown Verification

After each demo, verify the clean shutdown checklist:

1. Docker container stopped and removed (check `docker ps -a`)
2. Custom Docker network deleted (check `docker network ls`)
3. Proxy routes for this app removed
4. Agent API endpoint for this app stopped
5. SQLite instance status = 'stopped'
6. Port bindings released
7. Temporary files cleaned up
8. Resource monitor stopped
9. WebSocket connections closed
10. Event logged: `container_stopped`

## Crash Recovery Test

1. Launch any Docker app
2. Kill the Identity Agent process (SIGKILL or force-quit)
3. Restart the Identity Agent
4. Observe startup logs for reconciliation:
   - "Reconcile: DB=running, Container=running → killing container"
   - "Stopped and removed orphan container"
5. Verify the marketplace shows the app as stopped

## Troubleshooting

- **Docker not available**: Check that Docker Desktop is running. The APPS tab shows a warning banner.
- **WebView blank**: On Linux, install `libwebkit2gtk-4.1-dev`. The "Open in browser" fallback button is always available.
- **Port conflict on 5000**: Run `pkill -f identity-agent-core` then restart the backend.
- **Container won't stop**: Use `docker kill <container_id>` manually, then restart the agent for reconciliation.
