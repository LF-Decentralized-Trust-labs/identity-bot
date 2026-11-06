package server

import (
	"fmt"

	"identity-agent-core/endpoint"
)

// Where the root / management surface binds.
//
// This surface carries the agent's OUTBOUND tunnel/relay setup and the
// AUTHENTICATED owner/management API. It is deliberately NOT a place
// counterparties reach: external reach is meant to come only through a
// manager-governed ingress — the relay's own tunnel (which reverse-proxies
// inbound to loopback), or a separate path-scoped ingress bind for a direct
// deployment. Binding the root surface to a public address instead makes the
// root URL a universal correlator ("learn the main URL, ask the agent
// anything"), which is exactly what the per-relationship URL model exists to
// prevent.
//
// So the root surface binds LOOPBACK by default. The tunnel and
// relay transports are unaffected — both dial the local server over loopback,
// so nothing that reaches the agent through a manager-governed path is lost.
//
// DIRECT MODE — an agent with no tunnel or relay (a developer pairing a phone to
// a computer on the same network, say) is reached off-box on a SECOND listener,
// not on this one: directListenAddr / serveDirectIngress in direct_ingress.go,
// which serves only the path-scoped /{aid}/... documents of the identifiers the
// URL manager has allowlisted, and only while the mode is Direct (ADR-042 §2).
// The retired AGENT_DIRECT_INGRESS_ADDR, which bound this whole surface to a
// reachable address, is not read: an agent started with it set refuses to start.
//
// SEALED INSTANCE — a hardware-sealed instance (a confidential VM) is reached
// only through a host reverse proxy that dials the agent over the VM's network
// interface. The host cannot reach guest loopback across the VM boundary, and
// the interface is reachable only from the host, which NATs every request so it
// arrives from a non-loopback source — so the owner gate treats it as
// remote-and-signed, and reaching the management surface through the proxy is
// the whole point. There, binding the interface is the correct production
// posture, not an exposure, and AGENT_SEALED_INSTANCE_INGRESS says so without
// the hatch's warning. It rides the measured image unit, so an owner verifies
// it in the launch measurement. See ADR-042's sealed-instance deviation note.
func rootListenAddr(port int) string {
	// A sealed instance binds its VM network interface so the host reverse proxy
	// (and the provisioner) can reach it; guest loopback is unreachable from the
	// host. Safe because the NAT makes every host-originated request remote to the
	// owner gate — see the SEALED INSTANCE note above and ADR-042.
	if endpoint.SealedInstanceIngress() {
		return fmt.Sprintf("0.0.0.0:%d", port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}
