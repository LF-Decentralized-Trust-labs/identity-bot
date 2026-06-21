package update

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

const (
	defaultPollInterval = 6 * time.Hour
	pollJitter          = 1 * time.Hour
)

// Poller fetches manifests anonymously (UM-8, UM-9).
type Poller struct {
	manifestURL string
	client      *http.Client
	interval    time.Duration
	onManifest  func([]byte)
	onError     func(error)

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	pushCh   chan struct{}
}

func NewPoller(manifestURL string) *Poller {
	return &Poller{
		manifestURL: manifestURL,
		interval:    defaultPollInterval,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// UM-8: no cookies on anonymous poll
				req.Header.Del("Cookie")
				return nil
			},
		},
		pushCh: make(chan struct{}, 1),
	}
}

func (p *Poller) SetInterval(d time.Duration) {
	p.interval = d
}

func (p *Poller) OnManifest(fn func([]byte)) {
	p.onManifest = fn
}

func (p *Poller) OnError(fn func(error)) {
	p.onError = fn
}

// Start begins the polling loop with 6h ± 1h jitter.
func (p *Poller) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.running = true
	p.mu.Unlock()

	go p.loop(runCtx)
}

func (p *Poller) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return
	}
	p.cancel()
	p.running = false
}

// CheckNow triggers a contentless re-poll (UM-9: no payload, no injected manifest).
func (p *Poller) CheckNow() {
	select {
	case p.pushCh <- struct{}{}:
	default:
	}
}

func (p *Poller) loop(ctx context.Context) {
	p.pollOnce()

	for {
		jitter := time.Duration(rand.Int63n(int64(pollJitter*2))) - pollJitter
		wait := p.interval + jitter
		if wait < time.Minute {
			wait = time.Minute
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			p.pollOnce()
		case <-p.pushCh:
			timer.Stop()
			p.pollOnce()
		}
	}
}

func (p *Poller) pollOnce() {
	raw, err := p.fetchAnonymous()
	if err != nil {
		log.Printf("[update] poll failed: %v", err)
		if p.onError != nil {
			p.onError(err)
		}
		return
	}
	if p.onManifest != nil {
		p.onManifest(raw)
	}
}

func (p *Poller) fetchAnonymous() ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, p.manifestURL, nil)
	if err != nil {
		return nil, err
	}
	// UM-8: anonymous — no auth, cookies, version, or device identifiers.
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	req.Header.Del("User-Agent")
	req.Header.Del("X-Device-Id")
	req.Header.Del("X-Agent-Version")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, err
		}
		return body, nil
	case http.StatusNotModified:
		return nil, fmt.Errorf("not modified")
	default:
		return nil, fmt.Errorf("manifest fetch status %d", resp.StatusCode)
	}
}

// AssertAnonymousPoll validates UM-8 for test assertions.
func AssertAnonymousPoll(req *http.Request) error {
	if req.Header.Get("Authorization") != "" {
		return fmt.Errorf("poll_leaks_identity: authorization header")
	}
	if req.Header.Get("Cookie") != "" {
		return fmt.Errorf("poll_leaks_identity: cookie header")
	}
	if req.Header.Get("X-Device-Id") != "" {
		return fmt.Errorf("poll_leaks_identity: device id")
	}
	if req.Header.Get("X-Agent-Version") != "" {
		return fmt.Errorf("poll_leaks_identity: version header")
	}
	return nil
}