package server

import (
	"fmt"
	"net/http"
)

// The forward proxy terminates TLS so it can govern what leaves — which means it
// presents its own certificate, and any client that verifies certificates
// correctly will refuse it until it trusts the proxy's CA.
//
// A workspace on another machine has to obtain that certificate before it can
// make its first outbound request. It cannot authenticate to get it: it holds no
// credential yet, and the credential it will eventually use is injected by the
// very proxy it cannot yet reach. So this endpoint is unauthenticated by
// necessity, and safely so — it serves a CA CERTIFICATE, which is public by
// construction. The private key that makes it useful never leaves the host and
// is not served by anything.
//
// What it does disclose is that this agent runs an intercepting proxy. That is
// not a secret worth keeping: any client that trusts the CA can see the
// interception, and any client that does not will notice the certificate.

func (s *CoreServer) proxyCARoutes(r interface {
	Get(string, http.HandlerFunc)
}) {
	r.Get("/proxy/ca.crt", s.handleProxyCACert)
}

func (s *CoreServer) handleProxyCACert(w http.ResponseWriter, r *http.Request) {
	if s.SandboxManager == nil {
		jsonError(w, "Sandbox not initialized", http.StatusServiceUnavailable)
		return
	}
	proxy := s.SandboxManager.Proxy()
	if proxy == nil || proxy.CertManager() == nil {
		jsonError(w, "the forward proxy is not running, so it has no certificate authority",
			http.StatusServiceUnavailable)
		return
	}
	pem, err := proxy.CertManager().CACertPEM()
	if err != nil {
		jsonError(w, fmt.Sprintf("reading the certificate authority: %v", err),
			http.StatusInternalServerError)
		return
	}
	// application/x-x509-ca-cert is what tooling expects; the filename matters
	// because the usual install step is to drop it into a trust directory and
	// run update-ca-certificates, which ignores anything not named *.crt.
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="identity-agent-proxy-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pem)
}
