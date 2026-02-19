package tunnel

import (
	"context"
	"net"
)

type ProviderType string

const (
	ProviderCloudflare ProviderType = "cloudflare"
	ProviderNgrok      ProviderType = "ngrok"
	ProviderNone       ProviderType = "none"
)

type Status struct {
	Provider ProviderType `json:"provider"`
	Active   bool         `json:"active"`
	URL      string       `json:"url,omitempty"`
	Error    string       `json:"error,omitempty"`
	Mode     string       `json:"mode,omitempty"`
}

type Config struct {
	Provider             ProviderType `json:"provider"`
	NgrokAuthToken       string       `json:"ngrok_auth_token,omitempty"`
	CloudflareTunnelToken string      `json:"cloudflare_tunnel_token,omitempty"`
}

type Provider interface {
	Start(ctx context.Context, localPort int) error
	Stop() error
	URL() string
	Listener() net.Listener
	Status() Status
	Type() ProviderType
}
