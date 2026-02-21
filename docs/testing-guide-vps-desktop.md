# Identity Agent — VPS & Desktop Testing Guide

This guide walks you through testing the Control Plane from a remote machine (Linux VPS or Windows desktop). The goal is to prove end-to-end communication, telemetry ingestion, policy creation, and enforcement.

## Prerequisites

- The Identity Agent Control Plane is running on Replit (the Go server on port 5000)
- Your Replit app has a public URL (either the Replit dev domain or the Cloudflare tunnel URL)
- A Linux machine (VPS or desktop) and/or a Windows machine for testing
- `curl` installed (Linux) or PowerShell available (Windows)

## Your Control Plane URL

The Control Plane is accessible at one of these URLs:
- **Replit dev URL:** `https://6221e974-6906-4d9c-bffb-54314bab14e0-00-eqimbly2431s.spock.replit.dev`
- **Cloudflare tunnel:** Check the server logs for the current `trycloudflare.com` URL (changes on each restart)

Set this as a variable for convenience:

**Linux:**
```bash
export CP_URL="https://YOUR-REPLIT-URL-HERE"
```

**Windows (PowerShell):**
```powershell
$CP_URL = "https://YOUR-REPLIT-URL-HERE"
```

---

## Step 1: Communication Test

Verify your machine can reach the Control Plane.

### Linux
```bash
curl -s "$CP_URL/api/health" | python3 -m json.tool
```

### Windows (PowerShell)
```powershell
Invoke-RestMethod -Uri "$CP_URL/api/health"
```

**Expected output:** A JSON response with `"status": "active"` and driver info.

If this fails:
- Check your firewall allows outbound HTTPS (port 443)
- Verify the Replit app is running (visit the URL in a browser)
- Try the Cloudflare tunnel URL if the Replit dev URL doesn't work

---

## Step 2: Register an App

Register your OpenClaw instance as a managed app in the Control Plane.

### Linux
```bash
curl -s -X POST "$CP_URL/api/apps" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OpenClaw Desktop",
    "runtime": "python",
    "description": "OpenClaw agent running on local desktop for governance testing",
    "config": {
      "host": "my-desktop",
      "sandbox_type": "native"
    }
  }' | python3 -m json.tool
```

### Windows (PowerShell)
```powershell
$body = @{
    name = "OpenClaw Desktop"
    runtime = "python"
    description = "OpenClaw agent running on local desktop for governance testing"
    config = @{
        host = "my-desktop"
        sandbox_type = "native"
    }
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Method Post -Uri "$CP_URL/api/apps" -ContentType "application/json" -Body $body
```

**Save the returned `id` value** — you'll use it as `APP_ID` in the next steps.

```bash
# Linux
export APP_ID="the-id-from-response"
```
```powershell
# Windows
$APP_ID = "the-id-from-response"
```

---

## Step 3: Send Telemetry (Simulating eBPF Output)

This simulates what the Data Plane agent will eventually do automatically. You're manually sending the same JSON that an eBPF tracer would produce.

### Linux
```bash
curl -s -X POST "$CP_URL/api/telemetry/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "'$APP_ID'",
    "syscall_events": [
      {
        "syscall_name": "openat",
        "syscall_num": 257,
        "pid": 5001,
        "comm": "python3",
        "args": "/home/user/documents/report.txt",
        "return_value": 3,
        "success": true,
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      },
      {
        "syscall_name": "connect",
        "syscall_num": 42,
        "pid": 5001,
        "comm": "python3",
        "args": "AF_INET,142.250.80.46:443",
        "return_value": 0,
        "success": true,
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      },
      {
        "syscall_name": "openat",
        "syscall_num": 257,
        "pid": 5001,
        "comm": "python3",
        "args": "/etc/shadow",
        "return_value": -13,
        "success": false,
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      }
    ],
    "network_events": [
      {
        "direction": "outbound",
        "protocol": "tcp",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "142.250.80.46",
        "dst_port": 443,
        "dns_query": "www.google.com",
        "bytes_sent": 512,
        "bytes_recv": 4096,
        "action": "allowed",
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      },
      {
        "direction": "outbound",
        "protocol": "tcp",
        "src_ip": "192.168.1.100",
        "src_port": 54322,
        "dst_ip": "185.220.101.1",
        "dst_port": 9001,
        "dns_query": "",
        "bytes_sent": 1024,
        "bytes_recv": 0,
        "action": "allowed",
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      }
    ],
    "file_events": [
      {
        "path": "/home/user/documents/report.txt",
        "operation": "read",
        "pid": 5001,
        "comm": "python3",
        "success": true,
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      },
      {
        "path": "/etc/shadow",
        "operation": "read",
        "pid": 5001,
        "comm": "python3",
        "success": false,
        "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
      }
    ]
  }' | python3 -m json.tool
```

### Windows (PowerShell)
```powershell
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$body = @{
    app_id = $APP_ID
    syscall_events = @(
        @{ syscall_name="openat"; syscall_num=257; pid=5001; comm="python3"; args="/home/user/documents/report.txt"; return_value=3; success=$true; timestamp=$timestamp },
        @{ syscall_name="connect"; syscall_num=42; pid=5001; comm="python3"; args="AF_INET,142.250.80.46:443"; return_value=0; success=$true; timestamp=$timestamp },
        @{ syscall_name="openat"; syscall_num=257; pid=5001; comm="python3"; args="/etc/shadow"; return_value=-13; success=$false; timestamp=$timestamp }
    )
    network_events = @(
        @{ direction="outbound"; protocol="tcp"; src_ip="192.168.1.100"; src_port=54321; dst_ip="142.250.80.46"; dst_port=443; dns_query="www.google.com"; bytes_sent=512; bytes_recv=4096; action="allowed"; timestamp=$timestamp },
        @{ direction="outbound"; protocol="tcp"; src_ip="192.168.1.100"; src_port=54322; dst_ip="185.220.101.1"; dst_port=9001; dns_query=""; bytes_sent=1024; bytes_recv=0; action="allowed"; timestamp=$timestamp }
    )
    file_events = @(
        @{ path="/home/user/documents/report.txt"; operation="read"; pid=5001; comm="python3"; success=$true; timestamp=$timestamp },
        @{ path="/etc/shadow"; operation="read"; pid=5001; comm="python3"; success=$false; timestamp=$timestamp }
    )
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method Post -Uri "$CP_URL/api/telemetry/ingest" -ContentType "application/json" -Body $body
```

**Expected output:** `{"status": "ingested", "saved": {"syscall_events": 3, "network_events": 2, "file_events": 2}}`

---

## Step 4: View Telemetry in the Dashboard

1. Open your browser and navigate to: `YOUR-CP-URL/app-store`
2. Click **Telemetry** in the left sidebar
3. You should see:
   - **Stats bar:** updated counts for syscalls, network events, file events
   - **Top Destinations chart:** showing `www.google.com` and the unknown IP
   - **Top Syscalls chart:** showing `openat` and `connect`
   - **Top Files list:** showing `/home/user/documents/report.txt` and `/etc/shadow`
   - **Event tables:** with the individual events you just sent

4. Use the **App Filter** dropdown to filter by your app specifically

---

## Step 5: Create a Policy Based on Observed Telemetry

Now that you can see what the agent is doing, create a Rego policy to control it.

This example policy:
- Blocks access to sensitive files (`/etc/shadow`, `.ssh/`)
- Blocks connections to non-standard ports (anything that isn't 80 or 443)
- Allows everything else

### Linux
```bash
curl -s -X POST "$CP_URL/api/opa/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "openclaw-baseline",
    "description": "Baseline policy for OpenClaw: block sensitive files and non-standard ports",
    "module": "policy.openclaw_baseline",
    "rego": "package sandbox\n\nimport rego.v1\n\ndefault allow := true\n\n# Block access to sensitive system files\nallow := false if {\n  input.path\n  sensitive_paths := [\"/etc/shadow\", \"/etc/gshadow\"]\n  some path in sensitive_paths\n  startswith(input.path, path)\n}\n\nallow := false if {\n  input.path\n  contains(input.path, \".ssh/\")\n}\n\n# Block connections to non-standard ports\nallow := false if {\n  input.dst_port\n  not input.dst_port in [80, 443, 53]\n}"
  }' | python3 -m json.tool
```

### Windows (PowerShell)
```powershell
$rego = @"
package sandbox

import rego.v1

default allow := true

# Block access to sensitive system files
allow := false if {
  input.path
  sensitive_paths := ["/etc/shadow", "/etc/gshadow"]
  some path in sensitive_paths
  startswith(input.path, path)
}

allow := false if {
  input.path
  contains(input.path, ".ssh/")
}

# Block connections to non-standard ports
allow := false if {
  input.dst_port
  not input.dst_port in [80, 443, 53]
}
"@

$body = @{
    name = "openclaw-baseline"
    description = "Baseline policy for OpenClaw: block sensitive files and non-standard ports"
    module = "policy.openclaw_baseline"
    rego = $rego
} | ConvertTo-Json -Depth 3

Invoke-RestMethod -Method Post -Uri "$CP_URL/api/opa/policies" -ContentType "application/json" -Body $body
```

---

## Step 6: Test the Policy (Enforcement Simulation)

### Test 1: Should ALLOW — normal file read
```bash
# Linux
curl -s -X POST "$CP_URL/api/opa/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"query": "data.sandbox.allow", "input": {"path": "/home/user/documents/report.txt", "operation": "read"}}' | python3 -m json.tool
```
```powershell
# Windows
$body = @{ query="data.sandbox.allow"; input=@{ path="/home/user/documents/report.txt"; operation="read" } } | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri "$CP_URL/api/opa/evaluate" -ContentType "application/json" -Body $body
```
**Expected:** `"allow": true, "decision": "allow"`

### Test 2: Should DENY — sensitive file access
```bash
# Linux
curl -s -X POST "$CP_URL/api/opa/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"query": "data.sandbox.allow", "input": {"path": "/etc/shadow", "operation": "read"}}' | python3 -m json.tool
```
```powershell
# Windows
$body = @{ query="data.sandbox.allow"; input=@{ path="/etc/shadow"; operation="read" } } | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri "$CP_URL/api/opa/evaluate" -ContentType "application/json" -Body $body
```
**Expected:** `"allow": false, "decision": "deny"`

### Test 3: Should DENY — connection to non-standard port (e.g., Tor exit node)
```bash
# Linux
curl -s -X POST "$CP_URL/api/opa/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"query": "data.sandbox.allow", "input": {"dst_ip": "185.220.101.1", "dst_port": 9001, "protocol": "tcp"}}' | python3 -m json.tool
```
```powershell
# Windows
$body = @{ query="data.sandbox.allow"; input=@{ dst_ip="185.220.101.1"; dst_port=9001; protocol="tcp" } } | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri "$CP_URL/api/opa/evaluate" -ContentType "application/json" -Body $body
```
**Expected:** `"allow": false, "decision": "deny"`

### Test 4: Should ALLOW — HTTPS connection on port 443
```bash
# Linux
curl -s -X POST "$CP_URL/api/opa/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"query": "data.sandbox.allow", "input": {"dst_ip": "142.250.80.46", "dst_port": 443, "protocol": "tcp"}}' | python3 -m json.tool
```
```powershell
# Windows
$body = @{ query="data.sandbox.allow"; input=@{ dst_ip="142.250.80.46"; dst_port=443; protocol="tcp" } } | ConvertTo-Json -Depth 3
Invoke-RestMethod -Method Post -Uri "$CP_URL/api/opa/evaluate" -ContentType "application/json" -Body $body
```
**Expected:** `"allow": true, "decision": "allow"`

---

## Step 7: Batch Simulation Against Historical Events

You can also simulate a policy against multiple events at once using the simulation endpoint. This is useful for testing a policy against all the telemetry you've already collected.

### Linux
```bash
curl -s -X POST "$CP_URL/api/opa/simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "rego": "package sandbox\n\nimport rego.v1\n\ndefault allow := true\n\nallow := false if {\n  input.path\n  contains(input.path, \"/etc/shadow\")\n}\n\nallow := false if {\n  input.dst_port\n  not input.dst_port in [80, 443, 53]\n}",
    "query": "data.sandbox.allow",
    "events": [
      {"path": "/home/user/report.txt", "operation": "read"},
      {"path": "/etc/shadow", "operation": "read"},
      {"dst_ip": "142.250.80.46", "dst_port": 443},
      {"dst_ip": "185.220.101.1", "dst_port": 9001},
      {"path": "/home/user/.ssh/id_rsa", "operation": "read"}
    ]
  }' | python3 -m json.tool
```

**Expected:** 2 allowed (report.txt, google on 443), 3 denied (shadow, port 9001, ssh key)

---

## Step 8: View Policy in the Dashboard

1. Navigate to `YOUR-CP-URL/app-store`
2. Click **Policy Editor** in the left sidebar
3. You should see the `openclaw-baseline` policy card with:
   - The policy name and description
   - The Rego code preview
   - A delete button
4. Try creating a new policy using the **+ New Rego Policy** button
5. Use the **Simulation** panel at the bottom to paste events and test interactively

---

## What This Proves

After completing these steps, you have verified:

1. **Communication:** Your desktop/VPS can reach the Control Plane over HTTPS
2. **Telemetry Ingestion:** The webhook accepts structured eBPF-format telemetry data
3. **Dashboard Rendering:** Telemetry appears in charts and tables for analysis
4. **Policy Creation:** You can author Rego policies based on observed behavior
5. **Policy Evaluation:** The OPA engine correctly allows/denies based on policy rules
6. **Simulation:** You can batch-test policies against historical events

---

## Next Steps After Testing

Once you've verified the communication layer works:

1. **Build the Data Plane agent** — A lightweight Go binary that runs on the VPS, collects real eBPF telemetry, and ships it to the Control Plane webhook
2. **Run OpenClaw in audit mode** — Let it operate for hours/days while collecting telemetry
3. **Analyze and refine policies** — Use the dashboard to spot patterns, then write Rego rules
4. **Enable enforcement** — The Data Plane agent queries `/api/opa/evaluate` before allowing actions
5. **Test both sandbox types** — microVM (Firecracker) and WASM (Wasmtime) containers
