package endpoint

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"identity-agent-core/relay"
	"identity-agent-core/tunnel"
)

// EndpointPersister is a minimal interface for persisting endpoint state.
// Implemented by store.SQLiteStore — defined here to avoid a circular import.
type EndpointPersister interface {
	GetEndpoint() (url, source string, err error)
	SaveEndpoint(url, source string) error
}

type EndpointState struct {
	URL       string `json:"url"`
	Source    string `json:"source"`
	UpdatedAt string `json:"updated_at"`
}

type EndpointService struct {
	currentURL    string
	source        string
	updatedAt     time.Time
	tunnelManager *tunnel.Manager
	relayManager  *relay.Manager
	overrideURL   string
	// observedURL is where a trusted proxy said this agent is actually being
	// reached. See SetObservedURL.
	observedURL string
	localPort   int
	store       EndpointPersister
	onChange    []func(newURL, source string)
	mu          sync.RWMutex
}

func New(store EndpointPersister, localPort int) *EndpointService {
	es := &EndpointService{
		store:     store,
		localPort: localPort,
	}
	es.load()
	return es
}

func (es *EndpointService) SetPort(port int) {
	es.mu.Lock()
	es.localPort = port
	es.mu.Unlock()
	es.Refresh()
}

// SetRelayManager installs the relay, which outranks the tunnel when it is up.
//
// The ordering is about what the address is FOR rather than which is better
// plumbing. A tunnel address is ephemeral by nature — it is a byproduct of the
// vendor's product and dies when the process or the account does. A relay
// address is allocated to a signed enrollment, which is what makes it worth
// handing to somebody who has to find this agent again later. When both are
// available the durable one should be the one being published.
func (es *EndpointService) SetRelayManager(rm *relay.Manager) {
	es.mu.Lock()
	es.relayManager = rm
	es.mu.Unlock()
	es.Refresh()
}

func (es *EndpointService) SetTunnelManager(tm *tunnel.Manager) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.tunnelManager = tm
}

func (es *EndpointService) SetOverrideURL(url string) {
	es.mu.Lock()
	es.overrideURL = strings.TrimRight(url, "/")
	es.mu.Unlock()
	es.Refresh()
}

// SetObservedURL records where a proxy in front of this agent says it is
// reached.
//
// An agent behind a reverse proxy cannot work its own public address out. It
// sees a request on loopback; the name, the scheme and the path prefix the
// person actually used are known only to the proxy. Guessing from a local
// interface produces an address that resolves nowhere, and publishing that in
// an OOBI hands counterparties somewhere they cannot reach.
//
// ONLY EVER CALLED FOR A REQUEST THE AGENT HAS BEEN TOLD TO TRUST. Forwarding
// headers are set by whoever sends them, so an agent that believed them from
// any caller could be told it lives at an attacker's address and would publish
// that as its own — which is why this is a separate method rather than
// something Refresh works out for itself.
//
// It sits below an explicit override, which is somebody stating the answer, and
// above a relay or tunnel, which are paths this agent knows about rather than
// the one a request actually arrived by.
func (es *EndpointService) SetObservedURL(url string) {
	es.mu.Lock()
	es.observedURL = strings.TrimRight(url, "/")
	es.mu.Unlock()
	es.Refresh()
}

func (es *EndpointService) OnChange(cb func(newURL, source string)) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.onChange = append(es.onChange, cb)
}

func (es *EndpointService) CurrentURL() string {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return es.currentURL
}

func (es *EndpointService) Source() string {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return es.source
}

func (es *EndpointService) UpdatedAt() time.Time {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return es.updatedAt
}

func (es *EndpointService) State() EndpointState {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return EndpointState{
		URL:       es.currentURL,
		Source:    es.source,
		UpdatedAt: es.updatedAt.UTC().Format(time.RFC3339),
	}
}

func (es *EndpointService) Refresh() {
	newURL, source := es.resolve()

	es.mu.Lock()
	changed := newURL != es.currentURL
	es.currentURL = newURL
	es.source = source
	if changed {
		es.updatedAt = time.Now()
	}
	callbacks := make([]func(string, string), len(es.onChange))
	copy(callbacks, es.onChange)
	es.mu.Unlock()

	if changed {
		log.Printf("[endpoint] URL updated: %s (source: %s)", newURL, source)
		es.save()
		for _, cb := range callbacks {
			cb(newURL, source)
		}
	}
}

func (es *EndpointService) resolve() (string, string) {
	es.mu.RLock()
	override := es.overrideURL
	tm := es.tunnelManager
	rm := es.relayManager
	port := es.localPort
	es.mu.RUnlock()

	if override != "" {
		return override, "override"
	}

	// URL() is empty unless the relay is genuinely connected, so an
	// allocated-but-unreachable relay falls through to the tunnel rather
	// than shadowing it with an address nothing is listening on.
	if rm != nil {
		if relayURL := rm.URL(); relayURL != "" {
			return strings.TrimRight(relayURL, "/"),
				fmt.Sprintf("relay:%s", rm.GetStatus().Provider)
		}
	}

	if tm != nil {
		tunnelURL := tm.URL()
		if tunnelURL != "" {
			status := tm.GetStatus()
			providerName := string(status.Provider)
			return strings.TrimRight(tunnelURL, "/"), fmt.Sprintf("tunnel:%s", providerName)
		}
	}

	if envURL := os.Getenv("PUBLIC_URL"); envURL != "" {
		return strings.TrimRight(envURL, "/"), "env:PUBLIC_URL"
	}

	if ip := detectLocalIP(); ip != "" {
		return fmt.Sprintf("http://%s:%d", ip, port), fmt.Sprintf("local:%s", ip)
	}

	return fmt.Sprintf("http://localhost:%d", port), "localhost"
}

func (es *EndpointService) save() {
	if es.store == nil {
		return
	}
	es.mu.RLock()
	url, source := es.currentURL, es.source
	es.mu.RUnlock()

	if err := es.store.SaveEndpoint(url, source); err != nil {
		log.Printf("[endpoint] Failed to save endpoint to store: %v", err)
	}
}

func (es *EndpointService) load() {
	if es.store == nil {
		return
	}
	url, source, err := es.store.GetEndpoint()
	if err != nil {
		log.Printf("[endpoint] Failed to load endpoint from store: %v", err)
		return
	}
	if url == "" {
		return
	}
	es.currentURL = url
	es.source = source
	es.updatedAt = time.Now()
	log.Printf("[endpoint] Loaded previous state: %s (source: %s)", url, source)
}

func detectLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return ""
}
