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

	"identity-agent-core/relay"
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

	if p.config.NameOwner == nil {
		return fmt.Errorf("a Grape ID tunnel name is owned by the key that claims it, and this agent has no identity to claim one with")
	}
	aid := p.config.NameOwner.AID

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

	clientCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.status.Active = true
	p.status.URL = publicURL
	p.status.Error = ""

	go p.keepConnected(clientCtx, scheme, domain, extension, serverURL, localPort)
	return nil
}

// keepConnected holds the tunnel open, and opens it again whenever it drops —
// the network going away, the machine sleeping, the hub restarting.
//
// Each connection is admitted on a fresh statement signed by the name's key,
// so a dropped connection is not retried with the old one: the hub would
// refuse it as stale. It reconnects to the name first, which may move it to
// another port, and then connects with a new statement.
func (p *GrapeIDProvider) keepConnected(ctx context.Context, scheme, domain, name, serverURL string, localPort int) {
	backoff := time.Second
	for first := true; ; first = false {
		if !first {
			if resp, err := p.tryReconnect(scheme, domain, name, p.config.NameOwner.AID); err != nil {
				log.Printf("[tunnel] GrapeID could not reconnect to '%s' yet: %v", name, err)
			} else {
				p.mu.Lock()
				p.allocPort = resp.Port
				p.mu.Unlock()
			}
		}
		p.mu.RLock()
		port := p.allocPort
		p.mu.RUnlock()

		started := time.Now()
		err := p.connectOnce(ctx, serverURL, name, fmt.Sprintf("R:%d:localhost:%d", port, localPort))
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		p.status.Active = false
		if err != nil {
			p.status.Error = err.Error()
		}
		p.mu.Unlock()
		log.Printf("[tunnel] GrapeID tunnel to '%s' dropped (%v); connecting again in %s", name, err, backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		// A connection that stayed up a while was healthy; start the wait over.
		if time.Since(started) > 2*time.Minute {
			backoff = time.Second
		} else if backoff < time.Minute {
			backoff *= 2
		}
	}
}

// connectOnce opens one tunnel session with a freshly signed statement and
// returns when it ends.
func (p *GrapeIDProvider) connectOnce(ctx context.Context, serverURL, name, remote string) error {
	headers, sig, err := p.connectionStatement(name)
	if err != nil {
		return err
	}
	client, err := chclient.NewClient(&chclient.Config{
		Server:    serverURL,
		Remotes:   []string{remote},
		Auth:      strings.ToLower(name) + ":" + sig,
		Headers:   headers,
		KeepAlive: 25 * time.Second,
		// One statement admits one session, so the client does not retry with
		// it; keepConnected signs a new one.
		MaxRetryCount: 0,
	})
	if err != nil {
		return fmt.Errorf("failed to create chisel client: %v", err)
	}
	p.mu.Lock()
	p.client = client
	p.status.Active = true
	p.status.Error = ""
	p.mu.Unlock()
	log.Printf("[tunnel] Starting GrapeID tunnel connection to %s", serverURL)
	if err := client.Start(ctx); err != nil {
		return err
	}
	return client.Wait()
}

// connectionStatement is the signed statement a hub admits a tunnel connection
// on: this name, this identity, now. Signed over the same canonical form as
// every other request to the hub, and carried in headers because the tunnel's
// own login happens inside the connection, where the hub cannot read it. The
// signature doubles as the login, so nothing else needs sharing.
func (p *GrapeIDProvider) connectionStatement(name string) (http.Header, string, error) {
	owner := p.config.NameOwner
	// The hub knows names in lower case and checks the statement that way.
	name = strings.ToLower(name)
	at := time.Now().UTC().Format(time.RFC3339)
	body := map[string]interface{}{"purpose": "tunnel-connect", "name": name, "aid": owner.AID, "t": at}
	canonical, err := relay.CanonicalBody(body)
	if err != nil {
		return nil, "", err
	}
	sig, err := owner.Sign(canonical)
	if err != nil {
		return nil, "", err
	}
	h := http.Header{}
	h.Set("X-Tunnel-Name", name)
	h.Set("X-Tunnel-Aid", owner.AID)
	h.Set("X-Tunnel-Time", at)
	h.Set("X-Tunnel-Signature", sig)
	return h, sig, nil
}

func (p *GrapeIDProvider) tryReconnect(scheme, domain, name, aid string) (*claimResponse, error) {
	if aid == "" {
		return nil, fmt.Errorf("no AID available for reconnect")
	}

	reconnectURL := fmt.Sprintf("%s://%s/reconnect", scheme, domain)
	body, err := p.signed(map[string]interface{}{"name": name, "aid": aid}, false)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
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
	body, err := p.signed(map[string]interface{}{"name": name, "aid": aid}, true)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
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

func (p *GrapeIDProvider) Disconnect() error {
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
	log.Printf("[tunnel] GrapeID disconnected (name kept for reconnect)")
	return nil
}

// Stop disconnects and keeps the name. The name is this agent's permanent
// address, and releasing it at every shutdown handed it back to the hub, so the
// next start could find it taken. Giving a name up is ReleaseName, said on
// purpose.
func (p *GrapeIDProvider) Stop() error {
	return p.Disconnect()
}

// ReleaseName gives the name back to the hub, so the address stops being this
// agent's.
func (p *GrapeIDProvider) ReleaseName() {
	p.tryReleaseName()
}

// signed is a request body signed by the name's owner over its canonical form,
// carrying the owner's key and key log too when claiming a name.
func (p *GrapeIDProvider) signed(payload map[string]interface{}, claim bool) ([]byte, error) {
	owner := p.config.NameOwner
	if owner == nil || owner.Sign == nil {
		return nil, fmt.Errorf("no identity to sign the request to the Grape ID hub with")
	}
	if claim {
		payload["public_key_b64"] = owner.PublicKeyB64
		payload["kel_cesr_b64"] = owner.KELCESRB64
	}
	canonical, err := relay.CanonicalBody(payload)
	if err != nil {
		return nil, err
	}
	sig, err := owner.Sign(canonical)
	if err != nil {
		return nil, err
	}
	payload["signature"] = sig
	return json.Marshal(payload)
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
	if extension == "" || p.config.NameOwner == nil {
		return
	}

	releaseURL := fmt.Sprintf("%s://%s/release-name", scheme, domain)
	body, err := p.signed(map[string]interface{}{"name": extension, "aid": p.config.NameOwner.AID}, false)
	if err != nil {
		log.Printf("[tunnel] GrapeID release-name could not be signed: %v", err)
		return
	}

	httpClient := &http.Client{Timeout: 3 * time.Second}
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
