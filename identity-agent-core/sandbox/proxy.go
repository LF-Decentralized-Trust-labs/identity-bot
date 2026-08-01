package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	TLSModeMITM    = "mitm"
	TLSModeSNIOnly = "sni_only"
)

type ProxyRoute struct {
	InstanceID string
	AppID      string
	TLSMode    string
	LogLevel   string
	TargetHost string
	TargetPort int

	// ProxyToken authenticates this caller on the proxy, presented as
	// Proxy-Authorization: Bearer <token>.
	//
	// Source-address matching cannot tell two callers apart when they share
	// an egress address — which is the normal case for guests behind
	// user-mode networking, where every guest's traffic leaves through the
	// one hypervisor process. Without a token, several callers are one
	// caller as far as this proxy can see, and a credential scoped to one of
	// them is available to all of them.
	//
	// Empty means this route can only ever be matched by address, and
	// therefore never receives an injected credential — see identifyCaller.
	ProxyToken string

	// CredentialServices names the stored credentials this caller may have
	// injected. Empty means none.
	//
	// Deliberately not "all": a caller that has not been granted a
	// credential should not receive one because nobody thought to restrict
	// it. The vault already matches by destination host; this narrows the
	// other half of the question — WHO is asking — which host matching
	// cannot answer at all.
	CredentialServices []string
}

type ProxyRequestCallback func(instanceID string, req *http.Request, resp *http.Response, duration time.Duration)

type PolicyCheckFunc func(instanceID, appID, domain, method, urlStr string) (action string, rule string)

// CredentialInjectFunc adds any stored credential matching a request's destination
// to that request, reporting whether it applied one.
//
// Sandboxed apps reach the network through this proxy and are given no secrets of
// their own, which is the point: an app that never holds a credential cannot leak
// one, and revoking access is a vault edit rather than a hunt through containers.
// Until this existed the proxy forwarded their traffic unauthenticated, so the only
// way for a sandboxed app to call an authenticated service was to be handed a key —
// exactly what the vault exists to avoid.
//
// It runs after the policy check, so a domain the app may not reach is refused
// before any credential is considered.
type CredentialInjectFunc func(req *http.Request) bool

// ScopedCredentialInjectFunc is CredentialInjectFunc plus the only question the
// unscoped form cannot ask: which stored credentials may THIS caller have. The
// vault matches on destination host; services narrows it by who is asking.
type ScopedCredentialInjectFunc func(req *http.Request, services []string) bool

type ProxyManager struct {
	listenAddr       string
	dataDir          string
	certManager      *CertManager
	store            *SandboxStore
	dnsForwarder     *DNSForwarder
	server           *http.Server
	listener         net.Listener
	routes           map[string]*ProxyRoute
	policyCheck      PolicyCheckFunc
	injectCreds      CredentialInjectFunc
	injectCredsScope ScopedCredentialInjectFunc
	requestCb        ProxyRequestCallback
	pidFile          string
	stopCh           chan struct{}
	wg               sync.WaitGroup
	mu               sync.RWMutex
	running          bool
	port             int
	restartCount     int
	maxRestarts      int
	restartBackoff   time.Duration
	tracer           *Tracer
	ctx              context.Context
	cancel           context.CancelFunc
}

type ProxyManagerConfig struct {
	ListenAddr        string
	DataDir           string
	Store             *SandboxStore
	PolicyCheck       PolicyCheckFunc
	InjectCreds       CredentialInjectFunc
	InjectCredsScoped ScopedCredentialInjectFunc
	RequestCb         ProxyRequestCallback
	DNSListenAddr     string
	DNSUpstream       string
	MaxRestarts       int
	RestartBackoff    time.Duration
	Tracer            *Tracer
}

func NewProxyManager(cfg ProxyManagerConfig) (*ProxyManager, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.MaxRestarts == 0 {
		cfg.MaxRestarts = 5
	}
	if cfg.RestartBackoff == 0 {
		cfg.RestartBackoff = 2 * time.Second
	}

	certMgr, err := NewCertManager(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cert manager: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	pm := &ProxyManager{
		listenAddr:       cfg.ListenAddr,
		dataDir:          cfg.DataDir,
		certManager:      certMgr,
		store:            cfg.Store,
		routes:           make(map[string]*ProxyRoute),
		policyCheck:      cfg.PolicyCheck,
		injectCreds:      cfg.InjectCreds,
		injectCredsScope: cfg.InjectCredsScoped,
		requestCb:        cfg.RequestCb,
		pidFile:          filepath.Join(cfg.DataDir, ".proxy.pid"),
		stopCh:           make(chan struct{}),
		maxRestarts:      cfg.MaxRestarts,
		restartBackoff:   cfg.RestartBackoff,
		tracer:           cfg.Tracer,
		ctx:              ctx,
		cancel:           cancel,
	}

	if cfg.DNSListenAddr != "" {
		pm.dnsForwarder = NewDNSForwarder(cfg.DNSListenAddr, cfg.DNSUpstream, pm.handleDNSLog)
	}

	return pm, nil
}

func (pm *ProxyManager) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return fmt.Errorf("proxy manager already running")
	}

	if err := pm.cleanupOrphan(); err != nil {
		log.Printf("[sandbox-proxy] Orphan cleanup warning: %v", err)
	}

	listener, err := net.Listen("tcp", pm.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", pm.listenAddr, err)
	}
	pm.listener = listener

	addr := listener.Addr().(*net.TCPAddr)
	pm.port = addr.Port
	pm.listenAddr = addr.String()

	pm.server = &http.Server{
		Handler:      pm,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	pm.running = true
	pm.writePIDFile()

	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		if err := pm.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[sandbox-proxy] Server error: %v", err)
			pm.handleCrash()
		}
	}()

	if pm.dnsForwarder != nil {
		if err := pm.dnsForwarder.Start(); err != nil {
			log.Printf("[sandbox-proxy] DNS forwarder failed to start (non-fatal): %v", err)
		}
	}

	log.Printf("[sandbox-proxy] Forward proxy listening on %s (PID file: %s)", pm.listenAddr, pm.pidFile)
	return nil
}

func (pm *ProxyManager) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.running {
		return
	}

	pm.cancel()
	close(pm.stopCh)

	if pm.server != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		pm.server.Shutdown(shutdownCtx)
	}

	if pm.dnsForwarder != nil {
		pm.dnsForwarder.Stop()
	}

	pm.wg.Wait()
	pm.removePIDFile()
	pm.running = false

	log.Printf("[sandbox-proxy] Proxy manager stopped")
}

func (pm *ProxyManager) Port() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.port
}

func (pm *ProxyManager) ListenAddr() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.listenAddr
}

func (pm *ProxyManager) IsRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

func (pm *ProxyManager) CertManager() *CertManager {
	return pm.certManager
}

func (pm *ProxyManager) DNSForwarder() *DNSForwarder {
	return pm.dnsForwarder
}

// NewProxyToken mints a caller token. Exported so whoever registers a route can
// mint one and hand the same value to the caller it identifies.
func NewProxyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("mint proxy token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (pm *ProxyManager) AddRoute(route ProxyRoute) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.routes[route.InstanceID] = &route
	log.Printf("[sandbox-proxy] Added route for instance %s (app: %s, tls: %s, log: %s)",
		route.InstanceID, route.AppID, route.TLSMode, route.LogLevel)
}

func (pm *ProxyManager) RemoveRoute(instanceID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.routes, instanceID)
	log.Printf("[sandbox-proxy] Removed route for instance %s", instanceID)
}

func (pm *ProxyManager) GetRoute(instanceID string) *ProxyRoute {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.routes[instanceID]
}

func (pm *ProxyManager) RouteCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.routes)
}

func (pm *ProxyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		pm.handleConnect(w, r)
		return
	}
	pm.handleHTTP(w, r)
}

// applyCredentials injects a stored credential for this request's destination, if
// one is configured, and traces the fact without ever tracing the value.
//
// Called after headers are copied from the caller so an app cannot pre-set the
// header to something of its own choosing — the vault only fills a header that is
// absent, so a copied-in Authorization would win. Deleting it first would be worse:
// an app legitimately carrying its own end-user token would have it silently
// replaced by the org's. Leaving the caller's header intact and injecting only into
// the gap keeps both cases correct.
func (pm *ProxyManager) applyCredentials(outReq *http.Request, appID, instanceID string) {
	pm.applyCredentialsFor(outReq, appID, instanceID, nil, callerUnknown)
}

// applyCredentialsFor injects only when the caller PROVED who it is and was
// granted the credential in question.
//
// Two conditions, and each closes a different hole.
//
// Proven identity, because the vault matches on destination host alone: it
// answers "is this credential for github.com" and cannot answer "should THIS
// caller be reaching github.com with it". Address-based identification is an
// inference — and behind user-mode networking every guest shares one egress
// address, so the inference is not merely weak, it is uniform across callers.
//
// An explicit grant, because default-allow on a credential means a new caller
// receives every stored secret the moment it is registered, which is precisely
// backwards for the thing whose whole job is holding secrets.
func (pm *ProxyManager) applyCredentialsFor(outReq *http.Request, appID, instanceID string,
	route *ProxyRoute, how callerIdentification) {
	if pm.injectCreds == nil && pm.injectCredsScope == nil {
		return
	}
	if how != callerProven || route == nil {
		// Loud rather than silent: a caller that expected a credential and
		// did not get one otherwise debugs as a broken remote.
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "credential_withheld", "egress", appID, instanceID,
				fmt.Sprintf("No credential injected for %s: the caller was not "+
					"authenticated to the proxy", outReq.URL.Hostname()),
				map[string]interface{}{"host": outReq.URL.Hostname(), "reason": "caller_not_proven"})
		}
		return
	}
	if len(route.CredentialServices) == 0 {
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "credential_withheld", "egress", appID, instanceID,
				fmt.Sprintf("No credential injected for %s: this caller is granted none",
					outReq.URL.Hostname()),
				map[string]interface{}{"host": outReq.URL.Hostname(), "reason": "no_grant"})
		}
		return
	}
	if !pm.injectCredsScoped(outReq, route.CredentialServices) {
		return
	}
	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "credential_injected", "egress", appID, instanceID,
			fmt.Sprintf("Injected stored credential for %s", outReq.URL.Hostname()),
			map[string]interface{}{"host": outReq.URL.Hostname()})
	}
}

// injectCredsScoped applies the scoped injector when one is wired, and otherwise
// falls back to the unscoped one. The fallback is safe only because every caller
// of this has already established that the caller is proven and granted — the
// narrowing lives above, not here.
func (pm *ProxyManager) injectCredsScoped(req *http.Request, services []string) bool {
	if pm.injectCredsScope != nil {
		return pm.injectCredsScope(req, services)
	}
	if pm.injectCreds != nil {
		return pm.injectCreds(req)
	}
	return false
}

func (pm *ProxyManager) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.URL.Host == "" {
		http.Error(w, "Bad Request: missing host", http.StatusBadRequest)
		return
	}

	domain := r.URL.Hostname()
	route, callerHow := pm.identifyCaller(r)

	appID, instanceID := "", ""
	if route != nil {
		appID = route.AppID
		instanceID = route.InstanceID
	}

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "entry", "egress", appID, instanceID,
			fmt.Sprintf("HTTP %s %s", r.Method, r.URL.String()),
			map[string]interface{}{"method": r.Method, "url": r.URL.String(), "domain": domain, "headers": flattenHeaders(r.Header)})
	}

	if route == nil {
		pm.logProxyRequest(nil, r, nil, startTime, "auto_blocked", "unidentified_source")
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "blocked", "egress", "", "",
				fmt.Sprintf("Blocked: unidentified source for %s", domain),
				map[string]interface{}{"action": "auto_blocked", "rule": "unidentified_source", "domain": domain})
		}
		http.Error(w, "Request blocked: unidentified source", http.StatusForbidden)
		return
	}

	action, rule := "auto_approved", ""
	if pm.policyCheck != nil {
		action, rule = pm.policyCheck(route.InstanceID, route.AppID, domain, r.Method, r.URL.String())
	}

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "policy_result", "egress", appID, instanceID,
			fmt.Sprintf("Policy: %s (rule: %s)", action, rule),
			map[string]interface{}{"action": action, "rule": rule, "domain": domain})
	}

	if action == "held" || action == "auto_blocked" {
		pm.logProxyRequest(route, r, nil, startTime, action, rule)
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "blocked", "egress", appID, instanceID,
				fmt.Sprintf("Blocked: %s for %s", action, domain),
				map[string]interface{}{"action": action, "domain": domain, "duration_ms": time.Since(startTime).Milliseconds()})
		}
		if action == "held" {
			http.Error(w, "Request held for operator approval", http.StatusForbidden)
		} else {
			http.Error(w, "Request blocked by policy", http.StatusForbidden)
		}
		return
	}

	outReq, err := http.NewRequestWithContext(pm.ctx, r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del("Proxy-Connection")
	// Stripped before injection, and never forwarded: the token authenticates the
	// caller TO this proxy and means nothing to the destination.
	outReq.Header.Del("Proxy-Authorization")
	pm.applyCredentialsFor(outReq, appID, instanceID, route, callerHow)

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "upstream_send", "egress", appID, instanceID,
			fmt.Sprintf("Sending to %s", r.URL.Host),
			map[string]interface{}{"url": r.URL.String(), "method": r.Method, "headers": flattenHeaders(outReq.Header)})
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		log.Printf("[sandbox-proxy] Upstream request failed for %s: %v", r.URL.String(), err)
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "upstream_error", "ingress", appID, instanceID,
				fmt.Sprintf("Upstream error: %v", err),
				map[string]interface{}{"error": err.Error(), "duration_ms": time.Since(startTime).Milliseconds()})
		}
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	pm.logProxyRequest(route, r, resp, startTime, action, rule)

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "upstream_response", "ingress", appID, instanceID,
			fmt.Sprintf("Response %d from %s (%dms)", resp.StatusCode, domain, time.Since(startTime).Milliseconds()),
			map[string]interface{}{"status_code": resp.StatusCode, "domain": domain, "headers": flattenHeaders(resp.Header), "duration_ms": time.Since(startTime).Milliseconds()})
	}

	ScrubResponseHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (pm *ProxyManager) handleConnect(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	domain := strings.Split(host, ":")[0]

	// The CONNECT request is where a tunnelled caller identifies itself: once the
	// tunnel is established every subsequent request rides inside TLS and carries
	// no proxy header, so this is the only chance to authenticate it.
	route, callerHow := pm.identifyCaller(r)

	appID, instanceID := "", ""
	if route != nil {
		appID = route.AppID
		instanceID = route.InstanceID
	}

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "connect_entry", "egress", appID, instanceID,
			fmt.Sprintf("CONNECT %s", host),
			map[string]interface{}{"host": host, "domain": domain})
	}

	if route == nil {
		pm.logConnectRequest(nil, domain, host, startTime, "auto_blocked", "unidentified_source")
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "connect_blocked", "egress", "", "",
				fmt.Sprintf("CONNECT blocked: unidentified source for %s", domain),
				map[string]interface{}{"action": "auto_blocked", "rule": "unidentified_source", "domain": domain})
		}
		http.Error(w, "Connection blocked: unidentified source", http.StatusForbidden)
		return
	}

	action, rule := "auto_approved", ""
	if pm.policyCheck != nil {
		action, rule = pm.policyCheck(route.InstanceID, route.AppID, domain, "CONNECT", "https://"+host)
	}

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "connect_policy", "egress", appID, instanceID,
			fmt.Sprintf("CONNECT policy: %s (rule: %s)", action, rule),
			map[string]interface{}{"action": action, "rule": rule, "domain": domain})
	}

	if action == "held" || action == "auto_blocked" {
		pm.logConnectRequest(route, domain, host, startTime, action, rule)
		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "connect_blocked", "egress", appID, instanceID,
				fmt.Sprintf("CONNECT blocked: %s for %s", action, domain),
				map[string]interface{}{"action": action, "domain": domain})
		}
		http.Error(w, "Connection blocked", http.StatusForbidden)
		return
	}

	tlsMode := route.TLSMode

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		pm.tracer.Emit("proxy", "connect_mode", "egress", appID, instanceID,
			fmt.Sprintf("TLS mode: %s for %s", tlsMode, domain),
			map[string]interface{}{"tls_mode": tlsMode, "domain": domain})
	}

	if tlsMode == TLSModeMITM {
		pm.handleConnectMITM(w, r, host, domain, route, callerHow, startTime, action, rule)
		return
	}

	pm.handleConnectTunnel(w, r, host, domain, route, startTime, action, rule)
}

func (pm *ProxyManager) handleConnectTunnel(w http.ResponseWriter, r *http.Request, host, domain string, route *ProxyRoute, startTime time.Time, action, rule string) {
	targetConn, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		log.Printf("[sandbox-proxy] Failed to connect to %s: %v", host, err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	pm.logConnectRequest(route, domain, host, startTime, action, rule)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()

	wg.Wait()
	targetConn.Close()
	clientConn.Close()
}

func (pm *ProxyManager) handleConnectMITM(w http.ResponseWriter, r *http.Request, host, domain string, route *ProxyRoute, callerHow callerIdentification, startTime time.Time, action, rule string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := pm.certManager.GenerateHostCert(domain)
	if err != nil {
		log.Printf("[sandbox-proxy] Failed to generate cert for %s: %v", domain, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("[sandbox-proxy] TLS handshake failed for %s: %v", domain, err)
		clientConn.Close()
		return
	}

	_ = clientBuf

	pm.serveMITMRequests(tlsClientConn, host, domain, route, callerHow, startTime, action, rule)
}

func (pm *ProxyManager) serveMITMRequests(clientConn net.Conn, host, domain string, route *ProxyRoute, callerHow callerIdentification, startTime time.Time, action, rule string) {
	defer clientConn.Close()

	appID, instanceID := "", ""
	if route != nil {
		appID = route.AppID
		instanceID = route.InstanceID
	}

	reader := bufio.NewReader(clientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		reqStartTime := time.Now()

		if req.URL.Host == "" {
			req.URL.Host = host
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}

		fullURL := req.URL.String()

		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "entry", "egress", appID, instanceID,
				fmt.Sprintf("MITM %s %s", req.Method, fullURL),
				map[string]interface{}{"method": req.Method, "url": fullURL, "domain": domain, "headers": flattenHeaders(req.Header)})
		}

		mitmAction, mitmRule := action, rule
		if pm.policyCheck != nil && route != nil {
			mitmAction, mitmRule = pm.policyCheck(route.InstanceID, route.AppID, domain, req.Method, fullURL)
		}

		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "policy_result", "egress", appID, instanceID,
				fmt.Sprintf("Policy: %s (rule: %s)", mitmAction, mitmRule),
				map[string]interface{}{"action": mitmAction, "rule": mitmRule, "domain": domain})
		}

		if mitmAction == "held" || mitmAction == "auto_blocked" {
			pm.logProxyRequest(route, req, nil, reqStartTime, mitmAction, mitmRule)
			if pm.tracer != nil && pm.tracer.IsEnabled() {
				pm.tracer.Emit("proxy", "blocked", "egress", appID, instanceID,
					fmt.Sprintf("Blocked: %s for %s", mitmAction, domain),
					map[string]interface{}{"action": mitmAction, "domain": domain, "duration_ms": time.Since(reqStartTime).Milliseconds()})
			}
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Blocked by policy")),
			}
			resp.Write(clientConn)
			continue
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		}

		outReq, err := http.NewRequest(req.Method, fullURL, req.Body)
		if err != nil {
			continue
		}
		copyHeaders(outReq.Header, req.Header)
		// The identification comes from the CONNECT that opened this tunnel — a
		// request inside the tunnel cannot present a proxy header, so it inherits
		// the identity of the connection rather than asserting its own.
		pm.applyCredentialsFor(outReq, appID, instanceID, route, callerHow)

		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "upstream_send", "egress", appID, instanceID,
				fmt.Sprintf("Sending to %s", host),
				map[string]interface{}{"url": fullURL, "method": req.Method, "headers": flattenHeaders(outReq.Header)})
		}

		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			log.Printf("[sandbox-proxy] MITM upstream failed for %s: %v", fullURL, err)
			if pm.tracer != nil && pm.tracer.IsEnabled() {
				pm.tracer.Emit("proxy", "upstream_error", "ingress", appID, instanceID,
					fmt.Sprintf("Upstream error: %v", err),
					map[string]interface{}{"error": err.Error(), "duration_ms": time.Since(reqStartTime).Milliseconds()})
			}
			errResp := &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("Upstream request failed")),
			}
			errResp.Write(clientConn)
			continue
		}

		pm.logProxyRequest(route, req, resp, reqStartTime, mitmAction, mitmRule)

		if pm.tracer != nil && pm.tracer.IsEnabled() {
			pm.tracer.Emit("proxy", "upstream_response", "ingress", appID, instanceID,
				fmt.Sprintf("Response %d from %s (%dms)", resp.StatusCode, domain, time.Since(reqStartTime).Milliseconds()),
				map[string]interface{}{"status_code": resp.StatusCode, "domain": domain, "headers": flattenHeaders(resp.Header), "duration_ms": time.Since(reqStartTime).Milliseconds()})
		}

		ScrubResponseHeaders(resp.Header)
		resp.Write(clientConn)
		resp.Body.Close()
	}
}

// callerIdentification records HOW a caller was recognised, because the answer
// decides what may be done with it.
type callerIdentification int

const (
	// callerUnknown: nothing matched.
	callerUnknown callerIdentification = iota
	// callerInferred: matched by source address, or by being the only route
	// registered. Good enough to attribute a log line to. NOT good enough to
	// hand out a credential: an inference that happens to be right most of
	// the time is not an authentication.
	callerInferred
	// callerProven: presented a proxy token that matched a route.
	callerProven
)

func (pm *ProxyManager) findRouteForRequest(r *http.Request) *ProxyRoute {
	route, _ := pm.identifyCaller(r)
	return route
}

// identifyCaller resolves who is calling, and how firmly.
//
// The token path is checked first and is the only one that proves anything. The
// address paths remain because policy and logging still want a best guess, and
// losing that would be a regression — but they are marked inferred, and
// credential injection refuses anything short of proven.
//
// The single-route fallback is the sharpest edge here. It attributes ANY request
// to the one registered route, so with one instance running, traffic from
// anything at all on the host would previously have been given that instance's
// credentials. It survives for logging because it is usually right; it can no
// longer move a secret.
func (pm *ProxyManager) identifyCaller(r *http.Request) (*ProxyRoute, callerIdentification) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if token := bearerFromProxyAuth(r.Header.Get("Proxy-Authorization")); token != "" {
		for _, route := range pm.routes {
			// Constant time: this is a secret being compared.
			if route.ProxyToken != "" &&
				subtle.ConstantTimeCompare([]byte(route.ProxyToken), []byte(token)) == 1 {
				return route, callerProven
			}
		}
		// A token was presented and matched nothing. Do not fall through
		// to guessing by address — a caller that tried to identify itself
		// and failed is a caller we should not silently misidentify.
		return nil, callerUnknown
	}

	srcIP := extractIP(r.RemoteAddr)
	for _, route := range pm.routes {
		if route.TargetHost != "" && route.TargetHost == srcIP {
			return route, callerInferred
		}
	}
	if len(pm.routes) == 1 {
		for _, route := range pm.routes {
			return route, callerInferred
		}
	}
	return nil, callerUnknown
}

// bearerFromProxyAuth extracts the token from a Proxy-Authorization header.
func bearerFromProxyAuth(h string) string {
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

func (pm *ProxyManager) logProxyRequest(route *ProxyRoute, req *http.Request, resp *http.Response, startTime time.Time, action, rule string) {
	if pm.store == nil {
		return
	}

	logLevel := "metadata"
	instanceID := ""
	if route != nil {
		logLevel = route.LogLevel
		instanceID = route.InstanceID
	}

	if logLevel == "none" || instanceID == "" {
		return
	}

	pl := ProxyLog{
		InstanceID:   instanceID,
		Direction:    "egress",
		PolicyAction: &action,
	}

	if rule != "" {
		pl.PolicyRule = &rule
	}

	method := req.Method
	pl.Method = &method
	urlStr := req.URL.String()
	pl.URL = &urlStr
	domain := req.URL.Hostname()
	pl.Domain = &domain

	if resp != nil {
		statusCode := resp.StatusCode
		pl.StatusCode = &statusCode
	}

	if logLevel == "full" {
		if headersJSON, err := json.Marshal(req.Header); err == nil {
			h := string(headersJSON)
			pl.RequestHeaders = &h
		}
		if resp != nil {
			if headersJSON, err := json.Marshal(resp.Header); err == nil {
				h := string(headersJSON)
				pl.ResponseHeaders = &h
			}
		}
	}

	if _, err := pm.store.InsertProxyLog(pl); err != nil {
		log.Printf("[sandbox-proxy] Failed to log proxy request: %v", err)
	}

	if route != nil {
		eventData, _ := json.Marshal(map[string]interface{}{
			"domain":        domain,
			"method":        method,
			"url":           urlStr,
			"policy_action": action,
			"policy_rule":   rule,
		})
		eventDataStr := string(eventData)
		appID := route.AppID
		pm.store.InsertEvent(Event{
			InstanceID: &instanceID,
			AppID:      &appID,
			EventType:  "proxy_request_" + action,
			EventData:  &eventDataStr,
		})
	}
}

func (pm *ProxyManager) logConnectRequest(route *ProxyRoute, domain, host string, startTime time.Time, action, rule string) {
	if pm.store == nil || route == nil || route.LogLevel == "none" {
		return
	}

	method := "CONNECT"
	urlStr := "https://" + host

	pl := ProxyLog{
		InstanceID:   route.InstanceID,
		Direction:    "egress",
		Method:       &method,
		URL:          &urlStr,
		Domain:       &domain,
		PolicyAction: &action,
	}
	if rule != "" {
		pl.PolicyRule = &rule
	}

	if _, err := pm.store.InsertProxyLog(pl); err != nil {
		log.Printf("[sandbox-proxy] Failed to log CONNECT request: %v", err)
	}
}

func (pm *ProxyManager) handleDNSLog(query DNSQuery) {
	if pm.store == nil {
		return
	}

	pm.mu.RLock()
	var route *ProxyRoute
	for _, r := range pm.routes {
		route = r
		break
	}
	pm.mu.RUnlock()

	appID, instanceID := "", ""
	if route != nil {
		appID = route.AppID
		instanceID = route.InstanceID
	}

	if pm.tracer != nil && pm.tracer.IsEnabled() {
		qtypeStr := "A"
		if query.QueryType == 28 {
			qtypeStr = "AAAA"
		}
		pm.tracer.Emit("dns", "query", "egress", appID, instanceID,
			fmt.Sprintf("DNS %s %s", qtypeStr, query.Domain),
			map[string]interface{}{"domain": query.Domain, "query_type": query.QueryType, "type_str": qtypeStr})
	}

	if route == nil || route.LogLevel == "none" {
		return
	}

	method := "DNS"
	urlStr := fmt.Sprintf("dns://%s?type=%d", query.Domain, query.QueryType)

	pl := ProxyLog{
		InstanceID: route.InstanceID,
		Direction:  "egress",
		Method:     &method,
		URL:        &urlStr,
		Domain:     &query.Domain,
	}

	autoApproved := "auto_approved"
	pl.PolicyAction = &autoApproved

	pm.store.InsertProxyLog(pl)
}

var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"Proxy-Authorization": true,
	"X-Api-Key":           true,
	"X-Auth-Token":        true,
}

func flattenHeaders(h http.Header) map[string]string {
	flat := make(map[string]string, len(h))
	for k, v := range h {
		if sensitiveHeaders[k] {
			flat[k] = "[REDACTED]"
		} else {
			flat[k] = strings.Join(v, ", ")
		}
	}
	return flat
}

func (pm *ProxyManager) handleCrash() {
	pm.mu.Lock()
	if pm.restartCount >= pm.maxRestarts {
		pm.mu.Unlock()
		log.Printf("[sandbox-proxy] Max restart attempts (%d) reached, giving up", pm.maxRestarts)
		return
	}
	pm.restartCount++
	attempt := pm.restartCount
	pm.running = false
	pm.mu.Unlock()

	backoff := pm.restartBackoff * time.Duration(attempt)
	log.Printf("[sandbox-proxy] Proxy crashed, restarting in %v (attempt %d/%d)", backoff, attempt, pm.maxRestarts)

	select {
	case <-time.After(backoff):
	case <-pm.stopCh:
		return
	}

	if err := pm.Start(); err != nil {
		log.Printf("[sandbox-proxy] Failed to restart proxy: %v", err)
	}
}

func (pm *ProxyManager) writePIDFile() {
	pid := os.Getpid()
	content := fmt.Sprintf("%d\n%d\n%s", pid, pm.port, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(pm.pidFile, []byte(content), 0644); err != nil {
		log.Printf("[sandbox-proxy] Failed to write PID file: %v", err)
	}
}

func (pm *ProxyManager) removePIDFile() {
	if err := os.Remove(pm.pidFile); err != nil && !os.IsNotExist(err) {
		log.Printf("[sandbox-proxy] Failed to remove PID file: %v", err)
	}
}

func (pm *ProxyManager) cleanupOrphan() error {
	data, err := os.ReadFile(pm.pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		os.Remove(pm.pidFile)
		return nil
	}

	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil {
		os.Remove(pm.pidFile)
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pm.pidFile)
		return nil
	}

	if err := process.Signal(os.Signal(nil)); err != nil {
		os.Remove(pm.pidFile)
		return nil
	}

	log.Printf("[sandbox-proxy] Found orphan proxy process (PID: %d), terminating", pid)
	if err := process.Kill(); err != nil {
		log.Printf("[sandbox-proxy] Failed to kill orphan process: %v", err)
	}

	if len(lines) >= 2 {
		orphanPort, err := strconv.Atoi(strings.TrimSpace(lines[1]))
		if err == nil {
			pm.cleanupOrphanPort(orphanPort)
		}
	}

	os.Remove(pm.pidFile)
	return nil
}

func (pm *ProxyManager) cleanupOrphanPort(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Printf("[sandbox-proxy] Orphan port %d still in use", port)
		return
	}
	ln.Close()
}

func (pm *ProxyManager) Health() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return map[string]interface{}{
		"running":       pm.running,
		"listen_addr":   pm.listenAddr,
		"port":          pm.port,
		"route_count":   len(pm.routes),
		"restart_count": pm.restartCount,
		"dns_running":   pm.dnsForwarder != nil && pm.dnsForwarder.running,
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func ReverseProxyURL(proxyPort int, targetPort int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", targetPort)
}

func ForwardProxyURL(proxyPort int) *url.URL {
	u, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	return u
}
