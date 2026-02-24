package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
)

type CloudflareEmbeddedProvider struct {
	token     string
	url       string
	lastError string
}

func NewCloudflareEmbeddedProvider(token string) *CloudflareEmbeddedProvider {
	return &CloudflareEmbeddedProvider{
		token: token,
	}
}

func (p *CloudflareEmbeddedProvider) Start(ctx context.Context, localPort int) error {
	p.lastError = "Cloudflare embedded tunnel not yet available — cloudflared does not publish an importable Go SDK (see github.com/cloudflare/cloudflared/issues/986). Use ngrok for in-memory mobile tunneling, or cloudflare desktop provider (os/exec) on Linux/macOS/Windows."
	log.Printf("[tunnel] %s", p.lastError)
	return fmt.Errorf("%s", p.lastError)
}

func (p *CloudflareEmbeddedProvider) Stop() error {
	return nil
}

func (p *CloudflareEmbeddedProvider) URL() string {
	return p.url
}

func (p *CloudflareEmbeddedProvider) Listener() net.Listener {
	return nil
}

func (p *CloudflareEmbeddedProvider) Status() Status {
	return Status{
		Provider: ProviderCloudflare,
		Active:   false,
		Mode:     "embedded (pending SDK)",
		Error:    p.lastError,
	}
}

func (p *CloudflareEmbeddedProvider) Type() ProviderType {
	return ProviderCloudflare
}
