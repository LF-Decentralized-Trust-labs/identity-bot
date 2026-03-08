package sandbox

import (
	"bufio"
	"context"
	"crypto/tls"
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
}

type ProxyRequestCallback func(instanceID string, req *http.Request, resp *http.Response, duration time.Duration)

type PolicyCheckFunc func(instanceID, appID, domain, method, urlStr string) (action string, rule string)

type ProxyManager struct {
	listenAddr     string
	dataDir        string
	certManager    *CertManager
	store          *SandboxStore
	dnsForwarder   *DNSForwarder
	server         *http.Server
	listener       net.Listener
	routes         map[string]*ProxyRoute
	policyCheck    PolicyCheckFunc
	requestCb      ProxyRequestCallback
	pidFile        string
	stopCh         chan struct{}
	wg             sync.WaitGroup
	mu             sync.RWMutex
	running        bool
	port           int
	restartCount   int
	maxRestarts    int
	restartBackoff time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

type ProxyManagerConfig struct {
	ListenAddr     string
	DataDir        string
	Store          *SandboxStore
	PolicyCheck    PolicyCheckFunc
	RequestCb      ProxyRequestCallback
	DNSListenAddr  string
	DNSUpstream    string
	MaxRestarts    int
	RestartBackoff time.Duration
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
		listenAddr:     cfg.ListenAddr,
		dataDir:        cfg.DataDir,
		certManager:    certMgr,
		store:          cfg.Store,
		routes:         make(map[string]*ProxyRoute),
		policyCheck:    cfg.PolicyCheck,
		requestCb:      cfg.RequestCb,
		pidFile:        filepath.Join(cfg.DataDir, ".proxy.pid"),
		stopCh:         make(chan struct{}),
		maxRestarts:    cfg.MaxRestarts,
		restartBackoff: cfg.RestartBackoff,
		ctx:            ctx,
		cancel:         cancel,
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

func (pm *ProxyManager) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if r.URL.Host == "" {
		http.Error(w, "Bad Request: missing host", http.StatusBadRequest)
		return
	}

	domain := r.URL.Hostname()
	route := pm.findRouteForRequest(r)

	action, rule := "auto_approved", ""
	if pm.policyCheck != nil && route != nil {
		action, rule = pm.policyCheck(route.InstanceID, route.AppID, domain, r.Method, r.URL.String())
	}

	if action == "held" || action == "auto_blocked" {
		pm.logProxyRequest(route, r, nil, startTime, action, rule)
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
	outReq.Header.Del("Proxy-Authorization")

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
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	pm.logProxyRequest(route, r, resp, startTime, action, rule)

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

	route := pm.findRouteForRequest(r)

	action, rule := "auto_approved", ""
	if pm.policyCheck != nil && route != nil {
		action, rule = pm.policyCheck(route.InstanceID, route.AppID, domain, "CONNECT", "https://"+host)
	}

	if action == "held" || action == "auto_blocked" {
		pm.logConnectRequest(route, domain, host, startTime, action, rule)
		http.Error(w, "Connection blocked", http.StatusForbidden)
		return
	}

	tlsMode := TLSModeSNIOnly
	if route != nil {
		tlsMode = route.TLSMode
	}

	if tlsMode == TLSModeMITM {
		pm.handleConnectMITM(w, r, host, domain, route, startTime, action, rule)
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

func (pm *ProxyManager) handleConnectMITM(w http.ResponseWriter, r *http.Request, host, domain string, route *ProxyRoute, startTime time.Time, action, rule string) {
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

	pm.serveMITMRequests(tlsClientConn, host, domain, route, startTime, action, rule)
}

func (pm *ProxyManager) serveMITMRequests(clientConn net.Conn, host, domain string, route *ProxyRoute, startTime time.Time, action, rule string) {
	defer clientConn.Close()

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

		mitmAction, mitmRule := action, rule
		if pm.policyCheck != nil && route != nil {
			mitmAction, mitmRule = pm.policyCheck(route.InstanceID, route.AppID, domain, req.Method, fullURL)
		}

		if mitmAction == "held" || mitmAction == "auto_blocked" {
			pm.logProxyRequest(route, req, nil, reqStartTime, mitmAction, mitmRule)
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

		resp, err := transport.RoundTrip(outReq)
		if err != nil {
			log.Printf("[sandbox-proxy] MITM upstream failed for %s: %v", fullURL, err)
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

		resp.Write(clientConn)
		resp.Body.Close()
	}
}

func (pm *ProxyManager) findRouteForRequest(r *http.Request) *ProxyRoute {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	srcIP := extractIP(r.RemoteAddr)

	for _, route := range pm.routes {
		if route.TargetHost != "" && route.TargetHost == srcIP {
			return route
		}
	}

	if len(pm.routes) == 1 {
		for _, route := range pm.routes {
			return route
		}
	}

	return nil
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
