package server

import (
	"strings"
)

// How an agent becomes reachable from outside is a single, governed decision.
//
// There is exactly one default ingress mode per instance, and everything that
// wires up reachability consults resolveIngressMode() for it — there is no
// second place that decides whether to open a public tunnel or stand up a
// relay. The modes are:
//
//   - IngressModeRelay  — a private address at a relay (ADR-048): unlinkable,
//     reaching only what a relationship needs. Privacy by default.
//   - IngressModePublic — one stable public address at a relay, a name there or
//     the identity's own domain. Everything reaches the Identity Agent's own
//     gate, as for any other ingress.
//   - IngressModeTunnel — a development tunnel (Cloudflare, ngrok): one public
//     URL from a vendor, not private. For development, not a product default.
//   - IngressModeDirect — no third-party ingress. The Identity Agent answers at
//     its own reachable address (loopback/LAN, a port-forward, or its own DNS).
//     A developer/testing toggle, never a shipped product default.
//
// Public and private are an identity's choice, not a property of the kind of
// identity it is.
type IngressMode string

const (
	IngressModeRelay  IngressMode = "relay"
	IngressModePublic IngressMode = "public"
	IngressModeTunnel IngressMode = "tunnel"
	IngressModeDirect IngressMode = "direct"
)

// validIngressMode reports whether v names one of the modes.
func validIngressMode(v string) bool {
	switch IngressMode(strings.ToLower(strings.TrimSpace(v))) {
	case IngressModeRelay, IngressModePublic, IngressModeTunnel, IngressModeDirect:
		return true
	default:
		return false
	}
}

// defaultIngressModeForEntity is the open-source core's default when nothing
// is persisted: URL Relay, for every identity, because privacy is the safe
// default.
//
// Public and private addresses are an identity's choice, not a property of
// the kind of identity it is (ADR-048), so the core does not decide that an
// organisation is public. A product built on the core supplies its own
// per-entity default through CoreServer.DefaultIngressMode, and any identity
// can choose either mode in its settings.
//
// Direct is deliberately never a default: it is a developer/testing toggle a
// deployment opts into, not something any product ships with.
func defaultIngressModeForEntity(string) IngressMode {
	return IngressModeRelay
}

// resolveIngressMode returns this instance's default ingress mode: the persisted
// setting when one was explicitly chosen, otherwise the per-product default for
// this agent's entity type. Everything that wires up reachability consults this
// one function so "how is this agent reachable" has a single answer.
func (s *CoreServer) resolveIngressMode() IngressMode {
	if s.DataStore != nil {
		if saved, err := s.DataStore.GetSettings(); err == nil && saved != nil {
			if validIngressMode(saved.IngressMode) {
				return IngressMode(strings.ToLower(strings.TrimSpace(saved.IngressMode)))
			}
		}
	}
	return s.defaultIngressMode()
}

// defaultIngressMode is the deploying product's per-entity default when it
// supplied one, and the core's otherwise. A product's answer that is not a
// valid mode, or is Direct, is ignored rather than acted on.
func (s *CoreServer) defaultIngressMode() IngressMode {
	if s.DefaultIngressMode != nil {
		if m := s.DefaultIngressMode(s.ourEntityType()); validIngressMode(string(m)) && m != IngressModeDirect {
			return m
		}
	}
	return defaultIngressModeForEntity(s.ourEntityType())
}
