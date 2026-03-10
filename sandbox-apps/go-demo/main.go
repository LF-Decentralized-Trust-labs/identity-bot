package main

import (
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "os"
        "time"
)

type ResourceRequest struct {
        Resources []ResourceItem `json:"resources"`
}

type ResourceItem struct {
        Type   string `json:"type"`
        Target string `json:"target"`
}

type ResourceResponse struct {
        Granted []ResourceItem `json:"granted"`
        Denied  []ResourceItem `json:"denied"`
        Pending []ResourceItem `json:"pending"`
}

func main() {
        fmt.Println("╔══════════════════════════════════════════════════════════╗")
        fmt.Println("║          IDENTITY AGENT — SANDBOX DEMO APP             ║")
        fmt.Println("║       Proving the Agent Communication Channel          ║")
        fmt.Println("╚══════════════════════════════════════════════════════════╝")
        fmt.Println()

        agentAPI := os.Getenv("IDENTITY_AGENT_API")
        if agentAPI == "" {
                fmt.Println("[!] IDENTITY_AGENT_API not set — running outside sandbox")
                fmt.Println("    Set IDENTITY_AGENT_API=http://localhost:PORT to test")
                os.Exit(1)
        }

        fmt.Printf("[*] Agent API detected at: %s\n", agentAPI)
        fmt.Println("[*] Sandbox Agent reporting for duty — requesting permission to access the outside world")
        fmt.Println()

        fmt.Println("--- Step 1: Health Check ---")
        if err := healthCheck(agentAPI); err != nil {
                fmt.Printf("[!] Agent health check failed: %v\n", err)
                fmt.Println("[*] Continuing anyway — agent may still be starting")
        } else {
                fmt.Println("[✓] Agent is healthy and responding")
        }
        fmt.Println()

        time.Sleep(time.Second)

        fmt.Println("--- Step 1.5: Test External Network Connectivity ---")
        fmt.Println("[*] Testing outbound network access to antispamguy.com...")
        if err := testExternalNetwork(); err != nil {
                fmt.Printf("[!] External network test failed: %v\n", err)
                fmt.Println("[*] The sandbox may not have internet access configured")
        } else {
                fmt.Println("[✓] Successfully connected to external network!")
        }
        fmt.Println()

        time.Sleep(time.Second)

        fmt.Println("--- Step 2: Resource Requests (Batch) ---")
        fmt.Println("[*] Requesting multiple resources in a single batch:")
        fmt.Println("    1. network:api.example.com   — expected: auto-approve (in manifest)")
        fmt.Println("    2. filesystem:/documents     — expected: pending (user approval)")
        fmt.Println("    3. device:camera             — expected: auto-deny (blocked in manifest)")
        fmt.Println()

        resp, err := requestResources(agentAPI, []ResourceItem{
                {Type: "network", Target: "api.example.com"},
                {Type: "filesystem", Target: "/documents"},
                {Type: "device", Target: "camera"},
        })
        if err != nil {
                fmt.Printf("[!] Resource request failed: %v\n", err)
        } else {
                fmt.Println("[✓] Batch response received:")
                if len(resp.Granted) > 0 {
                        fmt.Println("    GRANTED:")
                        for _, r := range resp.Granted {
                                fmt.Printf("      ✓ %s:%s\n", r.Type, r.Target)
                        }
                }
                if len(resp.Denied) > 0 {
                        fmt.Println("    DENIED:")
                        for _, r := range resp.Denied {
                                fmt.Printf("      ✗ %s:%s\n", r.Type, r.Target)
                        }
                }
                if len(resp.Pending) > 0 {
                        fmt.Println("    PENDING (waiting for operator):")
                        for _, r := range resp.Pending {
                                fmt.Printf("      ⏳ %s:%s\n", r.Type, r.Target)
                        }
                }
        }
        fmt.Println()

        time.Sleep(time.Second)

        fmt.Println("--- Step 3: Check Current Status ---")
        if err := checkStatus(agentAPI); err != nil {
                fmt.Printf("[!] Status check failed: %v\n", err)
        }
        fmt.Println()

        time.Sleep(time.Second)

        fmt.Println("--- Step 4: Poll for Pending Requests ---")
        fmt.Println("[*] Checking if any requests are still pending approval...")
        if err := checkPending(agentAPI); err != nil {
                fmt.Printf("[!] Pending check failed: %v\n", err)
        }
        fmt.Println()

        fmt.Println("--- Step 5: Waiting for Operator Decisions ---")
        fmt.Println("[*] Polling every 5 seconds for pending request resolution...")
        fmt.Println("[*] Approve or deny the filesystem request in the Marketplace UI")
        fmt.Println()

        for i := 0; i < 60; i++ {
                pending, err := getPendingCount(agentAPI)
                if err != nil {
                        fmt.Printf("[!] Poll failed: %v\n", err)
                        break
                }
                if pending == 0 {
                        fmt.Println("[✓] All pending requests have been resolved!")
                        break
                }
                fmt.Printf("[*] %d request(s) still pending... (poll %d/60)\n", pending, i+1)
                time.Sleep(5 * time.Second)
        }

        fmt.Println()
        fmt.Println("╔══════════════════════════════════════════════════════════╗")
        fmt.Println("║              DEMO COMPLETE                             ║")
        fmt.Println("║  This app demonstrated:                                ║")
        fmt.Println("║    • Agent API discovery via IDENTITY_AGENT_API        ║")
        fmt.Println("║    • Batch resource requests                           ║")
        fmt.Println("║    • Auto-approve, auto-deny, and pending flows        ║")
        fmt.Println("║    • Polling for operator decisions                    ║")
        fmt.Println("║  The sandbox communication channel works!              ║")
        fmt.Println("╚══════════════════════════════════════════════════════════╝")
        fmt.Println()
        fmt.Println("[*] Process will stay alive for interactive commands.")
        fmt.Println("[*] Type 'status' to check status, 'quit' to exit.")

        var input string
        for {
                fmt.Print("> ")
                fmt.Scanln(&input)
                switch input {
                case "status":
                        checkStatus(agentAPI)
                case "pending":
                        checkPending(agentAPI)
                case "health":
                        healthCheck(agentAPI)
                case "quit", "exit":
                        fmt.Println("[*] Goodbye from Sandbox Agent!")
                        return
                case "help":
                        fmt.Println("Commands: status, pending, health, quit")
                default:
                        fmt.Printf("[?] Unknown command: %s (type 'help')\n", input)
                }
        }
}

func testExternalNetwork() error {
        client := &http.Client{Timeout: 10 * time.Second}
        resp, err := client.Get("https://antispamguy.com")
        if err != nil {
                return fmt.Errorf("failed to reach antispamguy.com: %w", err)
        }
        defer resp.Body.Close()

        fmt.Printf("[*] Response Status: %d %s\n", resp.StatusCode, resp.Status)
        fmt.Printf("[*] Server: %s\n", resp.Header.Get("Server"))
        return nil
}

func healthCheck(agentAPI string) error {
        resp, err := http.Get(agentAPI + "/health")
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        var result map[string]string
        json.Unmarshal(body, &result)
        fmt.Printf("[*] Health: %s (instance: %s)\n", result["status"], result["instance_id"])
        return nil
}

func requestResources(agentAPI string, items []ResourceItem) (*ResourceResponse, error) {
        payload := ResourceRequest{Resources: items}
        data, _ := json.Marshal(payload)

        resp, err := http.Post(agentAPI+"/request", "application/json", bytes.NewReader(data))
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        var result ResourceResponse
        if err := json.Unmarshal(body, &result); err != nil {
                return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(body))
        }
        return &result, nil
}

func checkStatus(agentAPI string) error {
        resp, err := http.Get(agentAPI + "/status")
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        var result map[string]interface{}
        json.Unmarshal(body, &result)

        fmt.Printf("[*] Instance: %s\n", result["instance_id"])
        fmt.Printf("[*] App: %s\n", result["app_id"])
        if caps, ok := result["capabilities"].([]interface{}); ok && len(caps) > 0 {
                fmt.Printf("[*] Capabilities: %v\n", caps)
        }
        if domains, ok := result["domains"].([]interface{}); ok && len(domains) > 0 {
                fmt.Printf("[*] Allowed domains: %v\n", domains)
        }
        return nil
}

func checkPending(agentAPI string) error {
        resp, err := http.Get(agentAPI + "/pending")
        if err != nil {
                return err
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        var result map[string]interface{}
        json.Unmarshal(body, &result)

        pending, ok := result["pending"].([]interface{})
        if !ok || len(pending) == 0 {
                fmt.Println("[✓] No pending requests")
                return nil
        }

        fmt.Printf("[*] %d pending request(s):\n", len(pending))
        for _, p := range pending {
                if req, ok := p.(map[string]interface{}); ok {
                        fmt.Printf("    ⏳ %s: %s (status: %s)\n",
                                req["resource_type"], req["resource_target"], req["status"])
                }
        }
        return nil
}

func getPendingCount(agentAPI string) (int, error) {
        resp, err := http.Get(agentAPI + "/pending")
        if err != nil {
                return 0, err
        }
        defer resp.Body.Close()

        body, _ := io.ReadAll(resp.Body)
        var result map[string]interface{}
        json.Unmarshal(body, &result)

        pending, ok := result["pending"].([]interface{})
        if !ok {
                return 0, nil
        }
        return len(pending), nil
}
