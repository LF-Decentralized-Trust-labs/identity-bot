package tunnel

import (
        "context"
        "net"
)

type ProviderType string

const (
        ProviderCloudflare ProviderType = "cloudflare"
        ProviderNgrok      ProviderType = "ngrok"
        ProviderGrapeID    ProviderType = "grapeid"
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
        Provider              ProviderType `json:"provider"`
        NgrokAuthToken        string       `json:"ngrok_auth_token,omitempty"`
        CloudflareTunnelToken string       `json:"cloudflare_tunnel_token,omitempty"`
        TunnelDomain          string       `json:"tunnel_domain,omitempty"`
        TunnelExtension       string       `json:"tunnel_extension,omitempty"`
        TunnelAuth            string       `json:"tunnel_auth,omitempty"`
        AID                   string       `json:"aid,omitempty"`
}

type Provider interface {
        Start(ctx context.Context, localPort int) error
        Stop() error
        Disconnect() error
        URL() string
        Listener() net.Listener
        Status() Status
        Type() ProviderType
}
