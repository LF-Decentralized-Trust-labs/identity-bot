package sandbox

import (
        "context"
        "encoding/json"
        "fmt"
        "log"
        "net"
        "net/http"
        "strconv"
        "time"
)

type AgentAPIServer struct {
        instanceID string
        appID      string
        store      *SandboxStore
        policy     *PolicyEngine
        eventBus   *EventBus
        tracer     *Tracer
        server     *http.Server
        listener   net.Listener
        port       int
}

type ResourceRequestPayload struct {
        Resources []ResourceItem `json:"resources"`
}

type ResourceItem struct {
        Type   string `json:"type"`
        Target string `json:"target"`
}

type ResourceResponsePayload struct {
        Granted []ResourceItem `json:"granted"`
        Denied  []ResourceItem `json:"denied"`
        Pending []ResourceItem `json:"pending"`
}

func NewAgentAPIServer(instanceID, appID string, port int, store *SandboxStore, policy *PolicyEngine, eventBus *EventBus, tracer *Tracer) *AgentAPIServer {
        return &AgentAPIServer{
                instanceID: instanceID,
                appID:      appID,
                store:      store,
                policy:     policy,
                eventBus:   eventBus,
                tracer:     tracer,
                port:       port,
        }
}

func (a *AgentAPIServer) Start() error {
        mux := http.NewServeMux()
        mux.HandleFunc("/request", a.handleResourceRequest)
        mux.HandleFunc("/status", a.handleStatus)
        mux.HandleFunc("/pending", a.handlePending)
        mux.HandleFunc("/health", a.handleHealth)

        addr := fmt.Sprintf("0.0.0.0:%d", a.port)
        var err error
        a.listener, err = net.Listen("tcp", addr)
        if err != nil {
                return fmt.Errorf("failed to listen on %s: %w", addr, err)
        }

        a.server = &http.Server{
                Handler:      mux,
                ReadTimeout:  30 * time.Second,
                WriteTimeout: 30 * time.Second,
        }

        go func() {
                if err := a.server.Serve(a.listener); err != nil && err != http.ErrServerClosed {
                        log.Printf("[agent-api] Server error for instance %s: %v", a.instanceID, err)
                }
        }()

        log.Printf("[agent-api] Listening on %s for instance %s (app: %s)", addr, a.instanceID, a.appID)
        return nil
}

func (a *AgentAPIServer) Stop() {
        if a.server != nil {
                ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                defer cancel()
                a.server.Shutdown(ctx)
        }
        log.Printf("[agent-api] Stopped for instance %s", a.instanceID)
}

func (a *AgentAPIServer) Port() int {
        return a.port
}

func (a *AgentAPIServer) handleResourceRequest(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
                http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
                return
        }

        var payload ResourceRequestPayload
        if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
                http.Error(w, "Invalid request body", http.StatusBadRequest)
                return
        }

        response := ResourceResponsePayload{
                Granted: make([]ResourceItem, 0),
                Denied:  make([]ResourceItem, 0),
                Pending: make([]ResourceItem, 0),
        }

        for _, item := range payload.Resources {
                if a.tracer != nil && a.tracer.IsEnabled() {
                        a.tracer.Emit("agent_api", "resource_request", "egress", a.appID, a.instanceID,
                                fmt.Sprintf("Resource request: %s → %s", item.Type, item.Target),
                                map[string]interface{}{"resource_type": item.Type, "target": item.Target})
                }

                status := a.policy.ProcessResourceRequest(a.instanceID, a.appID, item.Type, item.Target)

                if a.tracer != nil && a.tracer.IsEnabled() {
                        a.tracer.Emit("agent_api", "resource_result", "ingress", a.appID, a.instanceID,
                                fmt.Sprintf("Resource %s → %s: %s", item.Type, item.Target, status),
                                map[string]interface{}{"resource_type": item.Type, "target": item.Target, "status": status})
                }

                a.store.SaveResourceRequest(ResourceRequest{
                        InstanceID:     a.instanceID,
                        AppID:          a.appID,
                        ResourceType:   item.Type,
                        ResourceTarget: item.Target,
                        Status:         status,
                })

                switch status {
                case "approved":
                        response.Granted = append(response.Granted, item)
                case "denied":
                        response.Denied = append(response.Denied, item)
                default:
                        response.Pending = append(response.Pending, item)
                }
        }

        if len(response.Pending) > 0 {
                eventData, _ := json.Marshal(map[string]interface{}{
                        "instance_id": a.instanceID,
                        "pending":     response.Pending,
                })
                a.store.InsertEvent(Event{
                        InstanceID: &a.instanceID,
                        AppID:      &a.appID,
                        EventType:  "resource_request_received",
                        EventData:  strPtr(string(eventData)),
                })

                if a.eventBus != nil {
                        a.eventBus.Publish(SandboxEvent{
                                Type:       "resource_request_received",
                                AppID:      a.appID,
                                InstanceID: a.instanceID,
                                Data: map[string]interface{}{
                                        "pending_count": len(response.Pending),
                                },
                        })
                }
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
}

func (a *AgentAPIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
                http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
                return
        }

        rules, _ := a.store.GetPolicyRules(a.appID)

        grantedCapabilities := make([]string, 0)
        grantedDomains := make([]string, 0)

        for _, rule := range rules {
                switch rule.RuleType {
                case "capability_allow":
                        grantedCapabilities = append(grantedCapabilities, rule.Target)
                case "domain_allow":
                        grantedDomains = append(grantedDomains, rule.Target)
                }
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "instance_id":  a.instanceID,
                "app_id":       a.appID,
                "capabilities": grantedCapabilities,
                "domains":      grantedDomains,
        })
}

func (a *AgentAPIServer) handlePending(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
                http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
                return
        }

        reqs, err := a.store.GetPendingResourceRequests(a.appID)
        if err != nil {
                http.Error(w, "Failed to fetch pending requests", http.StatusInternalServerError)
                return
        }

        instanceReqs := make([]ResourceRequest, 0)
        for _, req := range reqs {
                if req.InstanceID == a.instanceID {
                        instanceReqs = append(instanceReqs, req)
                }
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
                "pending": instanceReqs,
        })
}

func (a *AgentAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
                "status":      "ok",
                "instance_id": a.instanceID,
                "app_id":      a.appID,
                "port":        strconv.Itoa(a.port),
        })
}
