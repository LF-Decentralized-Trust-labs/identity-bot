package server

import (
	"strings"

	"identity-agent-core/witness"
)

// How an agent becomes reachable from outside is a single, governed decision.
//
// There is exactly one default ingress mode per instance, and everything that
// wires up reachability consults resolveIngressMode() for it — there is no
// second place that decides whether to open a public tunnel or stand up a
// relay. The three modes are:
//
//   - IngressModeRelay  — a URL-relay operator gives per-relationship opaque
//     URLs; the agent stays reachable through NAT via the relay's own outbound
//     path. Privacy by default: one counterparty cannot correlate its URL with
//     another's.
//   - IngressModeTunnel — a tunnel provider gives ONE public URL for the whole
//     agent. Appropriate for an entity that is public by nature and needs a
//     single discoverable address; structurally cannot compartmentalize per
//     relationship, so it is not-private.
//   - IngressModeDirect — no third-party ingress. The agent answers at its own
//     reachable address (loopback/LAN, a port-forward, or its own DNS). This is
//     a developer/testing toggle, never a shipped product default.
//
// The default mode is per-instance and only a *default*: the one URL manager may
// still allocate other-mode URLs on the same agent (for example an org on a
// Tunnel default allocating relay URLs for confidential counterparties). This
// resolver decides the default, not what any single allocation may be.
type IngressMode string

const (
	IngressModeRelay  IngressMode = "relay"
	IngressModeTunnel IngressMode = "tunnel"
	IngressModeDirect IngressMode = "direct"
)

// validIngressMode reports whether v names one of the three modes.
func validIngressMode(v string) bool {
	switch IngressMode(strings.ToLower(strings.TrimSpace(v))) {
	case IngressModeRelay, IngressModeTunnel, IngressModeDirect:
		return true
	default:
		return false
	}
}

// defaultIngressModeForEntity is the per-product default when nothing is
// persisted.
//
//   - An organization is public by nature and needs only one public address, so
//     it defaults to Tunnel.
//   - Everything else — an individual, and the OSS core itself (which is the
//     template most likely cloned into an individual-type agent) — defaults to
//     URL Relay, for privacy by default.
//
// Direct is deliberately never a default: it is a developer/testing toggle a
// deployment opts into, not something any product ships with.
func defaultIngressModeForEntity(entityType string) IngressMode {
	if witness.NormaliseEntityType(entityType) == witness.EntityOrganization {
		return IngressModeTunnel
	}
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
	return defaultIngressModeForEntity(s.ourEntityType())
}
