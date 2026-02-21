# Containerization Testing Guide: MicroVM & WASM

This guide covers testing both sandbox containerization methods with the Identity Agent Control Plane. The goal is to verify that agents running inside each sandbox type can communicate telemetry back to the orchestration layer.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    VPS / Desktop                         │
│                                                         │
│  ┌──────────────────┐    ┌──────────────────────────┐   │
│  │  Method A:       │    │  Method B:               │   │
│  │  Firecracker     │    │  WASM Runtime             │   │
│  │  microVM         │    │  (Wasmtime / WasmEdge)    │   │
│  │                  │    │                           │   │
│  │  ┌────────────┐  │    │  ┌──────────────────┐    │   │
│  │  │ OpenClaw   │  │    │  │ WASM Module      │    │   │
│  │  │ (full OS)  │  │    │  │ (sandboxed code)  │    │   │
│  │  └─────┬──────┘  │    │  └────────┬─────────┘    │   │
│  │        │         │    │           │               │   │
│  │  virtio-net      │    │     WASI sockets          │   │
│  └────────┼─────────┘    └───────────┼───────────────┘   │
│           │                          │                   │
│  ┌────────┴──────────────────────────┴───────────┐      │
│  │         Telemetry Shipper Agent               │      │
│  │  (collects from both sandbox types,           │      │
│  │   ships JSON batches to Control Plane)        │      │
│  └───────────────────┬───────────────────────────┘      │
│                      │ HTTPS POST                        │
└──────────────────────┼───────────────────────────────────┘
                       │
                       ▼
           ┌───────────────────────┐
           │   Control Plane       │
           │   (Replit)            │
           │   /api/telemetry/     │
           │   /api/opa/evaluate   │
           └───────────────────────┘
```

---

## Method A: MicroVM (Firecracker)

Firecracker creates lightweight microVMs with their own kernel and filesystem. This is how you'd run OpenClaw as a full operating system image with complete isolation.

### Why Firecracker
- Full kernel isolation (not just process-level)
- Sub-second boot times (125ms typical)
- Used by AWS Lambda and Fly.io in production
- The agent runs in a real Linux environment with its own network stack
- eBPF tracing happens on the host, monitoring the guest VM

### Prerequisites (Linux VPS only — Firecracker requires KVM)
```bash
# Check KVM support
ls /dev/kvm

# Install Firecracker
curl -L https://github.com/firecracker-microvm/firecracker/releases/download/v1.6.0/firecracker-v1.6.0-x86_64.tgz | tar xz
sudo mv release-v1.6.0-x86_64/firecracker-v1.6.0-x86_64 /usr/local/bin/firecracker

# Download a minimal kernel and rootfs
curl -L -o vmlinux https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/kernels/x86_64/vmlinux-5.10.186
curl -L -o rootfs.ext4 https://s3.amazonaws.com/spec.ccfc.min/ci-artifacts/disks/x86_64/ubuntu-22.04.ext4
```

### Step 1: Create a Firecracker microVM
```bash
# Start Firecracker with API socket
rm -f /tmp/firecracker.socket
firecracker --api-sock /tmp/firecracker.socket &

# Configure the VM
curl --unix-socket /tmp/firecracker.socket -X PUT \
  http://localhost/boot-source \
  -H "Content-Type: application/json" \
  -d '{
    "kernel_image_path": "./vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  }'

curl --unix-socket /tmp/firecracker.socket -X PUT \
  http://localhost/drives/rootfs \
  -H "Content-Type: application/json" \
  -d '{
    "drive_id": "rootfs",
    "path_on_host": "./rootfs.ext4",
    "is_root_device": true,
    "is_read_only": false
  }'

# Configure networking (tap device for host<->guest communication)
sudo ip tuntap add tap0 mode tap
sudo ip addr add 172.16.0.1/24 dev tap0
sudo ip link set tap0 up

curl --unix-socket /tmp/firecracker.socket -X PUT \
  http://localhost/network-interfaces/eth0 \
  -H "Content-Type: application/json" \
  -d '{
    "iface_id": "eth0",
    "guest_mac": "AA:FC:00:00:00:01",
    "host_dev_name": "tap0"
  }'

# Start the VM
curl --unix-socket /tmp/firecracker.socket -X PUT \
  http://localhost/actions \
  -H "Content-Type: application/json" \
  -d '{"action_type": "InstanceStart"}'
```

### Step 2: Inside the VM — Run OpenClaw
```bash
# Inside the Firecracker VM (via serial console or SSH)
# Configure networking
ip addr add 172.16.0.2/24 dev eth0
ip link set eth0 up
ip route add default via 172.16.0.1

# Install and run OpenClaw (or your test agent)
pip install openclaw  # or however you install it
openclaw run --task "browse the web and summarize news"
```

### Step 3: On the Host — Collect Telemetry
```bash
# On the host VPS, trace syscalls from the Firecracker process
# The Firecracker VM runs as a single process on the host
FC_PID=$(pgrep firecracker)

# Simple strace-based collection (placeholder for eBPF)
# In production, this would be a cilium/ebpf Go program
strace -f -p $FC_PID -e trace=openat,connect,read,write \
  -o /tmp/fc-trace.log &

# Meanwhile, capture network traffic on the tap interface
tcpdump -i tap0 -w /tmp/fc-network.pcap &
```

### Step 4: Ship Telemetry to Control Plane
```bash
# Parse the trace output and send to Control Plane
# This is a simplified example — the real agent would do this continuously
export CP_URL="https://YOUR-REPLIT-URL"
export APP_ID="openclaw-firecracker-1"

# Convert observed syscalls to our schema and send
curl -s -X POST "$CP_URL/api/telemetry/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "app_id": "'$APP_ID'",
    "syscall_events": [
      {"syscall_name": "openat", "syscall_num": 257, "pid": '$FC_PID', "comm": "firecracker", "args": "/home/user/task.py", "return_value": 3, "success": true, "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
    ],
    "network_events": [
      {"direction": "outbound", "protocol": "tcp", "dst_ip": "142.250.80.46", "dst_port": 443, "dns_query": "www.google.com", "bytes_sent": 512, "bytes_recv": 2048, "action": "allowed", "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}
    ]
  }'
```

### Firecracker on Windows?
Firecracker requires Linux with KVM. On Windows, you have two options:
1. **WSL2** — Run Firecracker inside WSL2 (requires nested virtualization enabled in Hyper-V)
2. **Skip microVM on Windows** — Use the WASM method instead (see Method B below)

---

## Method B: WASM Runtime (Wasmtime / WasmEdge)

WASM (WebAssembly) runs sandboxed modules with capability-based security. The module can only access resources explicitly granted to it. This is lighter than a full VM and works on both Linux and Windows.

### Why WASM
- Runs on Linux, Windows, and macOS — no KVM required
- Capability-based security model (deny-by-default for filesystem, network)
- Near-native performance with strong isolation
- WASI (WebAssembly System Interface) provides controlled access to system resources
- The orchestration layer controls exactly what the module can see and do

### Prerequisites

**Linux:**
```bash
# Install Wasmtime
curl https://wasmtime.dev/install.sh -sSf | bash
source ~/.bashrc

# Verify
wasmtime --version
```

**Windows (PowerShell):**
```powershell
# Install Wasmtime via installer
iwr https://github.com/bytecodealliance/wasmtime/releases/download/v17.0.0/wasmtime-v17.0.0-x86_64-windows.zip -OutFile wasmtime.zip
Expand-Archive wasmtime.zip -DestinationPath C:\wasmtime
$env:PATH += ";C:\wasmtime\wasmtime-v17.0.0-x86_64-windows"

# Verify
wasmtime --version
```

### Step 1: Create a Test WASM Module

Create a simple Rust program that simulates agent behavior (file reads, network calls):

```bash
# Install Rust WASM target
rustup target add wasm32-wasip1

# Create test project
cargo init wasm-test-agent
cd wasm-test-agent
```

Edit `src/main.rs`:
```rust
use std::fs;
use std::net::TcpStream;

fn main() {
    println!("[agent] Starting WASM test agent...");

    // Attempt file read (will succeed only if dir is granted)
    match fs::read_to_string("/sandbox/config.txt") {
        Ok(contents) => println!("[agent] Read config: {}", contents),
        Err(e) => println!("[agent] File read denied: {}", e),
    }

    // Attempt network connection (will succeed only if network is granted)
    match TcpStream::connect("142.250.80.46:443") {
        Ok(_) => println!("[agent] Connected to google.com:443"),
        Err(e) => println!("[agent] Network denied: {}", e),
    }

    // Attempt to read sensitive file (should be denied)
    match fs::read_to_string("/etc/shadow") {
        Ok(_) => println!("[agent] WARNING: Read /etc/shadow!"),
        Err(e) => println!("[agent] Correctly denied /etc/shadow: {}", e),
    }

    println!("[agent] Test complete.");
}
```

Build:
```bash
cargo build --target wasm32-wasip1 --release
# Output: target/wasm32-wasip1/release/wasm-test-agent.wasm
```

### Step 2: Run with Controlled Permissions

**Audit mode (grant everything, observe what it does):**
```bash
# Linux (Wasmtime v17+)
wasmtime run \
  --dir /tmp/sandbox::/sandbox \
  --inherit-network \
  target/wasm32-wasip1/release/wasm-test-agent.wasm 2>&1 | tee /tmp/wasm-audit.log

# If --inherit-network is not available in your version, use:
# wasmtime run --dir /tmp/sandbox::/sandbox --wasi inherit-network target/...
```
```powershell
# Windows (Wasmtime v17+)
wasmtime run `
  --dir C:\temp\sandbox::/sandbox `
  --inherit-network `
  target\wasm32-wasip1\release\wasm-test-agent.wasm 2>&1 | Tee-Object -FilePath C:\temp\wasm-audit.log
```

> **Note:** Wasmtime network flags vary by version. Run `wasmtime run --help` to see available options for your installed version. The key principle: in audit mode, grant network access; in enforcement mode, remove it.

**Enforcement mode (restrict access):**
```bash
# Linux — only grant /sandbox dir, NO network
wasmtime run \
  --dir /tmp/sandbox::/sandbox \
  target/wasm32-wasip1/release/wasm-test-agent.wasm
# Network calls will fail, /etc/shadow will fail, only /sandbox reads will work
```
```powershell
# Windows — only grant sandbox dir, NO network
wasmtime run `
  --dir C:\temp\sandbox::/sandbox `
  target\wasm32-wasip1\release\wasm-test-agent.wasm
```

### Step 3: Capture and Ship Telemetry

Parse the WASM module's output and ship to Control Plane:

```bash
# Create a telemetry shipper script
cat > ship-wasm-telemetry.sh << 'SCRIPT'
#!/bin/bash
CP_URL="${1:-https://YOUR-REPLIT-URL}"
APP_ID="wasm-agent-1"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Parse WASM audit log for file and network events
FILE_EVENTS='[]'
NET_EVENTS='[]'
SYSCALL_EVENTS='[]'

# Check for file reads in the log
if grep -q "Read config" /tmp/wasm-audit.log; then
  FILE_EVENTS='[{"path":"/sandbox/config.txt","operation":"read","pid":1,"comm":"wasm-agent","success":true,"timestamp":"'$TIMESTAMP'"}]'
fi

if grep -q "denied /etc/shadow" /tmp/wasm-audit.log; then
  FILE_EVENTS=$(echo "$FILE_EVENTS" | python3 -c "
import json,sys
events = json.load(sys.stdin)
events.append({'path':'/etc/shadow','operation':'read','pid':1,'comm':'wasm-agent','success':False,'timestamp':'$TIMESTAMP'})
print(json.dumps(events))")
fi

if grep -q "Connected to" /tmp/wasm-audit.log; then
  NET_EVENTS='[{"direction":"outbound","protocol":"tcp","dst_ip":"142.250.80.46","dst_port":443,"dns_query":"google.com","bytes_sent":0,"bytes_recv":0,"action":"allowed","timestamp":"'$TIMESTAMP'"}]'
fi

curl -s -X POST "$CP_URL/api/telemetry/ingest" \
  -H "Content-Type: application/json" \
  -d "{
    \"app_id\": \"$APP_ID\",
    \"file_events\": $FILE_EVENTS,
    \"network_events\": $NET_EVENTS
  }"

echo ""
echo "Telemetry shipped for $APP_ID"
SCRIPT

chmod +x ship-wasm-telemetry.sh
./ship-wasm-telemetry.sh "$CP_URL"
```

### Step 4: Verify WASM Telemetry in Dashboard

1. Open `YOUR-CP-URL/app-store` in browser
2. Click **Telemetry**
3. Filter by the `wasm-agent-1` app
4. You should see the file access events and network events from the WASM module

### Step 5: Test Policy Enforcement via WASM Capabilities

The WASM sandbox enforces at the runtime level. To test the full loop:

```bash
# 1. Query the Control Plane for a decision
DECISION=$(curl -s -X POST "$CP_URL/api/opa/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"query":"data.sandbox.allow","input":{"path":"/etc/shadow","operation":"read"}}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('allow', False))")

echo "Policy decision for /etc/shadow: $DECISION"

# 2. Based on the decision, configure WASM permissions
if [ "$DECISION" = "False" ]; then
  echo "Policy denies /etc/shadow access — running WASM without /etc mount"
  wasmtime run --dir /tmp/sandbox::/sandbox target/wasm32-wasip1/release/wasm-test-agent.wasm
else
  echo "Policy allows — running WASM with full access"
  wasmtime run --dir /tmp/sandbox::/sandbox --dir /etc::/etc target/wasm32-wasip1/release/wasm-test-agent.wasm
fi
```

---

## Comparison: MicroVM vs WASM

| Feature | Firecracker (microVM) | Wasmtime (WASM) |
|---|---|---|
| **Isolation level** | Full kernel (separate Linux instance) | Process-level (capability sandbox) |
| **Boot time** | ~125ms | ~5ms |
| **Memory overhead** | ~5MB minimum per VM | ~1MB per module |
| **Network isolation** | Full network namespace + virtio-net | WASI socket capabilities |
| **File isolation** | Separate rootfs image | Directory grants only |
| **eBPF tracing** | Trace from host (monitor VM process) | Monitor via WASI hooks |
| **Windows support** | No (requires KVM/Linux) | Yes (native) |
| **Best for** | Running full OS images (OpenClaw) | Running sandboxed code modules |
| **OpenClaw use case** | Run OpenClaw as a full agent with browser/tools | Run individual tasks as WASM modules |

## Recommended Testing Order

1. **Start with the Testing Guide** (`testing-guide-vps-desktop.md`) — verify basic communication using curl
2. **Test WASM on Windows** — easiest to set up, no KVM needed, proves the communication layer
3. **Test WASM on Linux VPS** — same process, different OS, validates cross-platform
4. **Test Firecracker on Linux VPS** — full microVM isolation with OpenClaw running inside
5. **Compare telemetry** from both methods in the dashboard side by side

## The Full Loop (What Success Looks Like)

```
1. Register app          →  POST /api/apps
2. Run agent in sandbox  →  Firecracker VM or WASM module
3. Collect telemetry     →  strace/eBPF (VM) or WASI hooks (WASM)
4. Ship to Control Plane →  POST /api/telemetry/ingest
5. View in dashboard     →  /app-store → Telemetry tab
6. Author policy         →  /app-store → Policy Editor (Rego)
7. Simulate policy       →  POST /api/opa/simulate
8. Enforce policy        →  POST /api/opa/evaluate before each action
9. Iterate               →  Run for weeks, refine policies
```
