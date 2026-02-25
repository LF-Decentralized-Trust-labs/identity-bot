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

        claimURL := fmt.Sprintf("%s://%s/claim-name", scheme, domain)
        claimBody, _ := json.Marshal(map[string]string{"name": extension})

        httpClient := &http.Client{Timeout: 15 * time.Second}
        resp, err := httpClient.Post(claimURL, "application/json", bytes.NewBuffer(claimBody))
        if err != nil {
                return fmt.Errorf("failed to reach GrapeID hub at %s: %v", domain, err)
        }
        defer resp.Body.Close()

        if resp.StatusCode == 525 {
                return fmt.Errorf("GrapeID hub at %s returned SSL error (525). The server may have an SSL misconfiguration — contact the hub administrator", domain)
        }

        if resp.StatusCode != http.StatusOK {
                var errResp map[string]interface{}
                json.NewDecoder(resp.Body).Decode(&errResp)
                errMsg := errResp["error"]
                if errMsg == nil {
                        errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
                }
                return fmt.Errorf("failed to claim name '%s' on %s: %v", extension, domain, errMsg)
        }

        var claimResp struct {
                Name    string `json:"name"`
                Port    int    `json:"port"`
                Message string `json:"message"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&claimResp); err != nil {
                return fmt.Errorf("failed to parse claim response: %v", err)
        }

        p.allocPort = claimResp.Port
        publicURL := fmt.Sprintf("%s://%s/%s", scheme, domain, claimResp.Name)
        log.Printf("[tunnel] GrapeID name claimed successfully. Port: %d. Public URL: %s", p.allocPort, publicURL)

        serverURL := fmt.Sprintf("%s://%s:8080", scheme, domain)
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

func (p *GrapeIDProvider) Stop() error {
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
