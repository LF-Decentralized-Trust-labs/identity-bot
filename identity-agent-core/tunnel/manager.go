package tunnel

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

type Manager struct {
	provider  Provider
	config    Config
	localPort int
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
}

func NewManager(cfg Config, localPort int) *Manager {
	return &Manager{
		config:    cfg,
		localPort: localPort,
	}
}

func (m *Manager) Start(parentCtx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.provider != nil {
		m.provider.Disconnect()
	}

	m.ctx, m.cancel = context.WithCancel(parentCtx)
	m.provider = m.createProvider()

	if m.provider.Type() == ProviderNone {
		m.provider.Start(m.ctx, m.localPort)
		return nil
	}

	if err := m.provider.Start(m.ctx, m.localPort); err != nil {
		log.Printf("[tunnel] Provider %s failed: %v", m.config.Provider, err)
		return err
	}

	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.provider != nil {
		m.provider.Stop()
	}
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.provider != nil {
		m.provider.Disconnect()
	}
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) Restart(parentCtx context.Context, cfg Config) error {
	m.mu.Lock()
	if m.provider != nil {
		m.provider.Disconnect()
	}
	if m.cancel != nil {
		m.cancel()
	}
	m.config = cfg
	m.mu.Unlock()

	return m.Start(parentCtx)
}

func (m *Manager) URL() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.provider == nil {
		return ""
	}
	return m.provider.URL()
}

func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.provider == nil {
		return Status{Provider: m.config.Provider, Active: false}
	}
	return m.provider.Status()
}

func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

func (m *Manager) Provider() Provider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.provider
}

func (m *Manager) createProvider() Provider {
	switch m.config.Provider {
	case ProviderCloudflare:
		token := m.config.CloudflareTunnelToken
		if token == "" {
			token = os.Getenv("CLOUDFLARE_TUNNEL_TOKEN")
		}
		return NewCloudflareProvider(token)

	case ProviderNgrok:
		authToken := m.config.NgrokAuthToken
		if authToken == "" {
			authToken = os.Getenv("NGROK_AUTHTOKEN")
		}
		if authToken == "" {
			log.Println("[tunnel] WARNING: ngrok selected but no auth token provided")
			return NewNoneProvider()
		}
		return NewNgrokProvider(authToken)

	case ProviderGrapeID:
		if m.config.TunnelExtension == "" {
			log.Println("[tunnel] WARNING: grapeid selected but no tunnel extension provided")
			return NewNoneProvider()
		}
		return NewGrapeIDProvider(m.config)

	case ProviderNone:
		return NewNoneProvider()

	default:
		log.Printf("[tunnel] Unknown provider %q, defaulting to none", m.config.Provider)
		return NewNoneProvider()
	}
}

func DefaultConfig() Config {
	// An explicit choice wins over every guess below.
	//
	// This exists because there was no way to say no. The fallback at the end of
	// this function publishes the agent on the public internet, and an operator
	// who did not want that had no variable to set -- TUNNEL_PROVIDER was
	// silently ignored, because nothing read it. An agent started for a
	// local-only test is live on the internet within seconds, which is a
	// surprise in the wrong direction.
	//
	// "none" is the value that matters; the rest are accepted so that stating a
	// provider explicitly always works, rather than working only for the one
	// value somebody happened to need.
	switch ProviderType(strings.ToLower(strings.TrimSpace(os.Getenv("TUNNEL_PROVIDER")))) {
	case ProviderNone:
		return Config{Provider: ProviderNone}
	case ProviderNgrok:
		return Config{Provider: ProviderNgrok, NgrokAuthToken: os.Getenv("NGROK_AUTHTOKEN")}
	case ProviderCloudflare:
		return Config{Provider: ProviderCloudflare, CloudflareTunnelToken: os.Getenv("CLOUDFLARE_TUNNEL_TOKEN")}
	case ProviderGrapeID:
		return Config{Provider: ProviderGrapeID, TunnelDomain: "grapeid.org"}
	}

	if os.Getenv("NGROK_AUTHTOKEN") != "" {
		return Config{
			Provider:       ProviderNgrok,
			NgrokAuthToken: os.Getenv("NGROK_AUTHTOKEN"),
		}
	}

	if os.Getenv("CLOUDFLARE_TUNNEL_TOKEN") != "" {
		return Config{
			Provider:              ProviderCloudflare,
			CloudflareTunnelToken: os.Getenv("CLOUDFLARE_TUNNEL_TOKEN"),
		}
	}

	if _, err := LookupCloudflared(); err == nil {
		return Config{Provider: ProviderCloudflare}
	}

	// Default to Grape ID tunneling. TunnelExtension will be auto-generated
	// by the server on startup if not set.
	return Config{
		Provider:     ProviderGrapeID,
		TunnelDomain: "grapeid.org",
	}
}

func LookupCloudflared() (string, error) {
	path, err := LookupBinary("cloudflared")
	if err != nil {
		return "", fmt.Errorf("cloudflared not found: %w", err)
	}
	return path, nil
}

func LookupBinary(name string) (string, error) {
	path, err := lookupBinaryPath(name)
	return path, err
}

func lookupBinaryPath(name string) (string, error) {
	path, err := findInPath(name)
	if err != nil {
		return "", err
	}
	return path, nil
}

func findInPath(name string) (string, error) {
	for _, dir := range splitPath() {
		candidate := dir + "/" + name
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}

func splitPath() []string {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}
	return splitPathList(pathEnv)
}

func splitPathList(path string) []string {
	var list []string
	for _, p := range splitPathSeparator(path) {
		if p != "" {
			list = append(list, p)
		}
	}
	return list
}

func splitPathSeparator(path string) []string {
	return split(path, ':')
}

func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
