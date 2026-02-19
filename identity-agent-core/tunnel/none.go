package tunnel

import (
	"context"
	"log"
	"net"
)

type NoneProvider struct{}

func NewNoneProvider() *NoneProvider {
	return &NoneProvider{}
}

func (p *NoneProvider) Start(ctx context.Context, localPort int) error {
	log.Println("[tunnel] Provider: none — no tunnel will be created")
	return nil
}

func (p *NoneProvider) Stop() error {
	return nil
}

func (p *NoneProvider) URL() string {
	return ""
}

func (p *NoneProvider) Listener() net.Listener {
	return nil
}

func (p *NoneProvider) Status() Status {
	return Status{
		Provider: ProviderNone,
		Active:   false,
		Mode:     "disabled",
	}
}

func (p *NoneProvider) Type() ProviderType {
	return ProviderNone
}
