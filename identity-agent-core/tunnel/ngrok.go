package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"

	"golang.ngrok.com/ngrok"
	ngrokconfig "golang.ngrok.com/ngrok/config"
)

type NgrokProvider struct {
	authToken string
	listener  net.Listener
	url       string
	lastError string
}

func NewNgrokProvider(authToken string) *NgrokProvider {
	return &NgrokProvider{
		authToken: authToken,
	}
}

func (p *NgrokProvider) Start(ctx context.Context, localPort int) error {
	if p.authToken == "" {
		p.lastError = "NGROK_AUTHTOKEN not configured"
		return fmt.Errorf("ngrok auth token is required")
	}

	log.Println("[tunnel] Starting ngrok tunnel (in-memory, mobile-ready)...")

	listener, err := ngrok.Listen(ctx,
		ngrokconfig.HTTPEndpoint(),
		ngrok.WithAuthtoken(p.authToken),
	)
	if err != nil {
		p.lastError = err.Error()
		return fmt.Errorf("failed to create ngrok tunnel: %w", err)
	}

	p.listener = listener
	p.url = listener.URL()
	p.lastError = ""
	log.Printf("[tunnel] ngrok tunnel active: %s", p.url)
	return nil
}

func (p *NgrokProvider) Stop() error {
	if p.listener != nil {
		log.Println("[tunnel] Stopping ngrok tunnel...")
		err := p.listener.Close()
		p.listener = nil
		p.url = ""
		return err
	}
	return nil
}

func (p *NgrokProvider) URL() string {
	return p.url
}

func (p *NgrokProvider) Listener() net.Listener {
	return p.listener
}

func (p *NgrokProvider) Status() Status {
	s := Status{
		Provider: ProviderNgrok,
		Active:   p.listener != nil && p.url != "",
		URL:      p.url,
		Mode:     "in-memory (mobile-ready)",
	}
	if p.lastError != "" {
		s.Error = p.lastError
	}
	return s
}

func (p *NgrokProvider) Type() ProviderType {
	return ProviderNgrok
}
