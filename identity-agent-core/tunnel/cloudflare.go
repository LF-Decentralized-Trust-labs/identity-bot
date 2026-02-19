package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CloudflareProvider struct {
	token     string
	cmd       *exec.Cmd
	url       string
	localPort int
	lastError string
	cancel    context.CancelFunc
	proxy     *http.Server
	proxyLn   net.Listener
	mu        sync.Mutex
}

func NewCloudflareProvider(token string) *CloudflareProvider {
	return &CloudflareProvider{
		token: token,
	}
}

func (p *CloudflareProvider) Start(ctx context.Context, localPort int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.localPort = localPort

	if _, err := exec.LookPath("cloudflared"); err != nil {
		p.lastError = "cloudflared binary not found in PATH"
		return fmt.Errorf("cloudflared not found: %w", err)
	}

	childCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	var args []string
	mode := "quick-tunnel"

	if p.token != "" {
		mode = "authenticated"
		args = []string{"tunnel", "run", "--token", p.token}
		log.Printf("[tunnel] Starting Cloudflare authenticated tunnel...")
	} else {
		args = []string{"tunnel", "--url", fmt.Sprintf("http://localhost:%d", localPort), "--protocol", "http2"}
		log.Printf("[tunnel] Starting Cloudflare Quick Tunnel (free, no account)...")
	}

	cmd := exec.CommandContext(childCtx, "cloudflared", args...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		p.lastError = err.Error()
		return fmt.Errorf("failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		p.lastError = err.Error()
		return fmt.Errorf("failed to start cloudflared: %w", err)
	}

	p.cmd = cmd

	urlChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stderr)
		urlPattern := regexp.MustCompile(`https://[a-zA-Z0-9\-]+\.trycloudflare\.com`)
		connPattern := regexp.MustCompile(`https://[a-zA-Z0-9\-\.]+\.cfargotunnel\.com`)

		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[tunnel:cloudflare] %s", line)

			if match := urlPattern.FindString(line); match != "" {
				select {
				case urlChan <- match:
				default:
				}
			}
			if match := connPattern.FindString(line); match != "" {
				select {
				case urlChan <- match:
				default:
				}
			}
			if strings.Contains(line, "Registered tunnel connection") || strings.Contains(line, "Connection") {
				if p.url != "" {
					continue
				}
			}
		}
	}()

	go func() {
		if err := cmd.Wait(); err != nil {
			if childCtx.Err() == nil {
				errChan <- fmt.Errorf("cloudflared exited unexpectedly: %w", err)
			}
		}
	}()

	select {
	case tunnelURL := <-urlChan:
		p.url = tunnelURL
		p.lastError = ""
		log.Printf("[tunnel] Cloudflare tunnel active (%s): %s", mode, p.url)
		return nil
	case err := <-errChan:
		p.lastError = err.Error()
		return err
	case <-time.After(30 * time.Second):
		p.lastError = "timeout waiting for cloudflared URL"
		cmd.Process.Kill()
		cancel()
		return fmt.Errorf("timeout: cloudflared did not provide a URL within 30 seconds")
	case <-childCtx.Done():
		return childCtx.Err()
	}
}

func (p *CloudflareProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.proxy != nil {
		p.proxy.Close()
		p.proxy = nil
	}
	if p.proxyLn != nil {
		p.proxyLn.Close()
		p.proxyLn = nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	if p.cmd != nil && p.cmd.Process != nil {
		log.Println("[tunnel] Stopping Cloudflare tunnel...")
		p.cmd.Process.Kill()
		p.cmd.Wait()
		p.cmd = nil
	}

	p.url = ""
	return nil
}

func (p *CloudflareProvider) URL() string {
	return p.url
}

func (p *CloudflareProvider) Listener() net.Listener {
	return nil
}

func (p *CloudflareProvider) Status() Status {
	mode := "quick-tunnel"
	if p.token != "" {
		mode = "authenticated"
	}

	s := Status{
		Provider: ProviderCloudflare,
		Active:   p.cmd != nil && p.url != "",
		URL:      p.url,
		Mode:     fmt.Sprintf("desktop (%s)", mode),
	}
	if p.lastError != "" {
		s.Error = p.lastError
	}
	return s
}

func (p *CloudflareProvider) Type() ProviderType {
	return ProviderCloudflare
}

func (p *CloudflareProvider) startReverseProxy(localPort int) (net.Listener, error) {
	target, _ := url.Parse(fmt.Sprintf("http://localhost:%d", localPort))
	proxy := httputil.NewSingleHostReverseProxy(target)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &http.Server{Handler: proxy}
	p.proxy = server
	p.proxyLn = ln

	go server.Serve(ln)
	return ln, nil
}
