package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

type Tunnel struct {
	listener net.Listener
	url      string
}

func Start(ctx context.Context) (*Tunnel, error) {
	authtoken := os.Getenv("NGROK_AUTHTOKEN")
	if authtoken == "" {
		return nil, nil
	}

	log.Println("[tunnel] NGROK_AUTHTOKEN detected, creating public tunnel...")

	listener, err := ngrok.Listen(ctx,
		config.HTTPEndpoint(),
		ngrok.WithAuthtoken(authtoken),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ngrok tunnel: %w", err)
	}

	url := listener.URL()
	log.Printf("[tunnel] Public HTTPS tunnel active: %s", url)

	return &Tunnel{
		listener: listener,
		url:      url,
	}, nil
}

func (t *Tunnel) URL() string {
	if t == nil {
		return ""
	}
	return t.url
}

func (t *Tunnel) Listener() net.Listener {
	if t == nil {
		return nil
	}
	return t.listener
}

func (t *Tunnel) Close() error {
	if t == nil || t.listener == nil {
		return nil
	}
	return t.listener.Close()
}
