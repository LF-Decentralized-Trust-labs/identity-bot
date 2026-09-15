package server

import (
	"net"
	"testing"
)

// The root/management surface must bind loopback by default — never 0.0.0.0 or
// any externally reachable address. External reach is meant to come only through
// a manager-governed ingress (the relay tunnel, or a separate path-scoped bind),
// so a public root bind would make the root URL a universal correlator.
func TestRootListenAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "")

	addr := rootListenAddr(5050)
	if addr != "127.0.0.1:5050" {
		t.Fatalf("root surface must bind loopback by default; got %q", addr)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("addr %q is not host:port: %v", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("root surface bound to non-loopback host %q (addr %q)", host, addr)
	}
	if host == "0.0.0.0" {
		t.Fatalf("root surface must not bind 0.0.0.0")
	}
}

// Binding the computed address actually yields a loopback socket — the property
// the two-listener invariant depends on, verified against a real listener.
func TestRootListenerBindsLoopback(t *testing.T) {
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "")

	// Port 0 lets the OS choose a free port; the host is what we assert on.
	ln, err := net.Listen("tcp4", rootListenAddr(0))
	if err != nil {
		t.Fatalf("listen on root addr: %v", err)
	}
	defer ln.Close()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type %T", ln.Addr())
	}
	if !tcpAddr.IP.IsLoopback() {
		t.Fatalf("root listener bound to non-loopback IP %s", tcpAddr.IP)
	}
}

// The dev escape hatch is the only way to reach a non-loopback bind, and it is
// off unless explicitly set. This documents that the exposure is opt-in.
func TestDirectIngressOverrideIsOptIn(t *testing.T) {
	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "0.0.0.0")
	if got := rootListenAddr(5050); got != "0.0.0.0:5050" {
		t.Fatalf("explicit override should bind the requested host; got %q", got)
	}

	t.Setenv("AGENT_DIRECT_INGRESS_ADDR", "192.168.0.10:9999")
	// The server's chosen port always wins over any port in the override.
	if got := rootListenAddr(5050); got != "192.168.0.10:5050" {
		t.Fatalf("override host with server port expected; got %q", got)
	}
}
