package tunnel

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "log"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"

        "identity-agent-core/certs"

        chclient "github.com/jpillora/chisel/client"
)

type GrapeIDProvider struct {
        config    Config
        status    Status
        mu        sync.RWMutex
        client    *chclient.Client
        cancel    context.CancelFunc
        allocPort int
}

func NewGrapeIDProvider(cfg Config) *GrapeIDProvider {
        return &GrapeIDProvider{
                config: cfg,
                status: Status{
                        Provider: ProviderGrapeID,
                        Mode:     "reverse_proxy",
                },
        }
}

type claimResponse struct {
        Name       string `json:"name"`
        Port       int    `json:"port"`
        TunnelPath string `json:"tunnel_path"`
        Message    string `json:"message"`
}

func (p *GrapeIDProvider) Start(ctx context.Context, localPort int) error {
        p.mu.Lock()
        defer p.mu.Unlock()

        domain := p.config.TunnelDomain
        if domain == "" {
                domain = "grapeid.org"
        }
        scheme := "https"
        if strings.Contains(domain, "localhost") {
                scheme = "http"
        }

        extension := strings.TrimSpace(p.config.TunnelExtension)
        if extension == "" {
                return fmt.Errorf("grapeid tunnel extension is required")
        }

        aid := p.config.AID

        resp, err := p.tryReconnect(scheme, domain, extension, aid)
        if err != nil {
                log.Printf("[tunnel] GrapeID reconnect failed, trying claim: %v", err)
                resp, err = p.tryClaim(scheme, domain, extension, aid)
                if err != nil {
                        return err
                }
        }

        p.allocPort = resp.Port
        publicURL := fmt.Sprintf("%s://%s/%s", scheme, domain, resp.Name)
        log.Printf("[tunnel] GrapeID tunnel established. Port: %d. Public URL: %s", p.allocPort, publicURL)

        tunnelPath := resp.TunnelPath
        if tunnelPath == "" {
                tunnelPath = "/tunnel"
        }
        serverURL := fmt.Sprintf("%s://%s%s", scheme, domain, tunnelPath)
        remoteStr := fmt.Sprintf("R:%d:localhost:%d", p.allocPort, localPort)

        auth := p.config.TunnelAuth
        if auth == "" {
                auth = "user:secret-token"
        }

        chConfig := &chclient.Config{
                Server:        serverURL,
                Remotes:       []string{remoteStr},
                Auth:          auth,
                KeepAlive:     25 * time.Second,
                MaxRetryCount: -1,
        }

        client, err := chclient.NewClient(chConfig)
        if err != nil {
                return fmt.Errorf("failed to create chisel client: %v", err)
        }

        clientCtx, cancel := context.WithCancel(ctx)
        p.cancel = cancel
        p.client = client
        p.status.Active = true
        p.status.URL = publicURL
        p.status.Error = ""

        go func() {
                log.Printf("[tunnel] Starting GrapeID tunnel connection to %s", serverURL)
                err := client.Start(clientCtx)
                if err != nil {
                        log.Printf("[tunnel] GrapeID tunnel error: %v", err)
                        p.mu.Lock()
                        p.status.Error = err.Error()
                        p.status.Active = false
                        p.mu.Unlock()
                }
                client.Wait()
                log.Printf("[tunnel] GrapeID tunnel connection closed")

                p.mu.Lock()
                p.status.Active = false
                p.mu.Unlock()
        }()

        return nil
}

func (p *GrapeIDProvider) tryReconnect(scheme, domain, name, aid string) (*claimResponse, error) {
        if aid == "" {
                return nil, fmt.Errorf("no AID available for reconnect")
        }

        reconnectURL := fmt.Sprintf("%s://%s/reconnect", scheme, domain)
        body, _ := json.Marshal(map[string]string{"name": name, "aid": aid})

        httpClient := certs.HTTPClient(15 * time.Second)
        resp, err := httpClient.Post(reconnectURL, "application/json", bytes.NewBuffer(body))
        if err != nil {
                return nil, fmt.Errorf("failed to reach GrapeID hub for reconnect: %v", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusNotFound {
                return nil, fmt.Errorf("name '%s' not found on hub (first registration needed)", name)
        }

        if resp.StatusCode == http.StatusForbidden {
                return nil, fmt.Errorf("AID mismatch: name '%s' is owned by a different AID on %s", name, domain)
        }

        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("reconnect returned HTTP %d for '%s' on %s", resp.StatusCode, name, domain)
        }

        var result claimResponse
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
                return nil, fmt.Errorf("failed to parse reconnect response: %v", err)
        }

        log.Printf("[tunnel] GrapeID reconnected to existing name '%s'", name)
        return &result, nil
}

func (p *GrapeIDProvider) tryClaim(scheme, domain, name, aid string) (*claimResponse, error) {
        claimURL := fmt.Sprintf("%s://%s/claim-name", scheme, domain)
        payload := map[string]string{"name": name}
        if aid != "" {
                payload["aid"] = aid
        }
        body, _ := json.Marshal(payload)

        httpClient := certs.HTTPClient(15 * time.Second)
        resp, err := httpClient.Post(claimURL, "application/json", bytes.NewBuffer(body))
        if err != nil {
                return nil, fmt.Errorf("failed to reach GrapeID hub at %s: %v", domain, err)
        }
        defer resp.Body.Close()

        if resp.StatusCode == 525 {
                return nil, fmt.Errorf("GrapeID hub at %s returned SSL error (525). The server may have an SSL misconfiguration — contact the hub administrator", domain)
        }

        if resp.StatusCode != http.StatusOK {
                var errResp map[string]interface{}
                json.NewDecoder(resp.Body).Decode(&errResp)
                errMsg := errResp["error"]
                if errMsg == nil {
                        errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
                }
                return nil, fmt.Errorf("failed to claim name '%s' on %s: %v", name, domain, errMsg)
        }

        var result claimResponse
        if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
                return nil, fmt.Errorf("failed to parse claim response: %v", err)
        }

        log.Printf("[tunnel] GrapeID claimed new name '%s'", name)
        return &result, nil
}

func (p *GrapeIDProvider) Stop() error {
        p.tryReleaseName()

        p.mu.Lock()
        defer p.mu.Unlock()

        if p.cancel != nil {
                p.cancel()
                p.cancel = nil
        }
        if p.client != nil {
                p.client.Close()
                p.client = nil
        }
        p.status.Active = false
        return nil
}

func (p *GrapeIDProvider) tryReleaseName() {
        domain := p.config.TunnelDomain
        if domain == "" {
                domain = "grapeid.org"
        }
        scheme := "https"
        if strings.Contains(domain, "localhost") {
                scheme = "http"
        }

        extension := strings.TrimSpace(p.config.TunnelExtension)
        aid := p.config.AID
        if extension == "" {
                return
        }

        releaseURL := fmt.Sprintf("%s://%s/release-name", scheme, domain)
        payload := map[string]string{"name": extension}
        if aid != "" {
                payload["aid"] = aid
        }
        body, _ := json.Marshal(payload)

        httpClient := certs.HTTPClient(3 * time.Second)
        resp, err := httpClient.Post(releaseURL, "application/json", bytes.NewBuffer(body))
        if err != nil {
                log.Printf("[tunnel] GrapeID release-name request failed (best-effort): %v", err)
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusOK {
                log.Printf("[tunnel] GrapeID name '%s' released successfully", extension)
        } else {
                log.Printf("[tunnel] GrapeID release-name returned HTTP %d (best-effort, continuing)", resp.StatusCode)
        }
}

func (p *GrapeIDProvider) URL() string {
        p.mu.RLock()
        defer p.mu.RUnlock()
        return p.status.URL
}

func (p *GrapeIDProvider) Listener() net.Listener {
        return nil
}

func (p *GrapeIDProvider) Status() Status {
        p.mu.RLock()
        defer p.mu.RUnlock()
        return p.status
}

func (p *GrapeIDProvider) Type() ProviderType {
        return ProviderGrapeID
}
