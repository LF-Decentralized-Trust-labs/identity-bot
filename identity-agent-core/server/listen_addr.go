package server

import (
	"fmt"
	"log"
	"os"
	"strings"

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
// So the root surface binds LOOPBACK by default, in every mode. The tunnel and
// relay transports are unaffected — both dial the local server over loopback,
// so nothing that reaches the agent through a manager-governed path is lost.
//
// DEV ESCAPE HATCH — a direct/LAN deployment with no tunnel (a developer
// pairing a phone to a computer on the same network, say) still needs the agent
// reachable off-box. The correct home for that is a separate, path-scoped,
// manager-governed ingress listener, which is not built yet. Until it is,
// AGENT_DIRECT_INGRESS_ADDR lets a developer explicitly opt the WHOLE surface
// onto a reachable address (e.g. "0.0.0.0") so that flow is not silently
// broken. It is off by default, loud when on, and dev/testing only — it exposes
// the management API and MUST NOT be used as a product default.
func rootListenAddr(port int) string {
	// The host the hatch names (bare "0.0.0.0"/"192.168.0.10" or a host:port; the
	// port this server chose always wins, since it may have fallen back). This is
	// the same signal the advertised address resolves on — endpoint.DirectIngressHost
	// — so binding and advertising cannot disagree about where the agent listens.
	if host := endpoint.DirectIngressHost(); host != "" {
		if !endpoint.IsLoopbackHost(host) {
			log.Printf("[identity-agent-core] WARNING: AGENT_DIRECT_INGRESS_ADDR=%s binds the root/"+
				"management surface to a non-loopback address. This exposes the management API and is a "+
				"developer/testing escape hatch only — never a product default. The governed path-scoped "+
				"ingress is the supported way to be reachable off-box.", strings.TrimSpace(os.Getenv("AGENT_DIRECT_INGRESS_ADDR")))
		}
		return fmt.Sprintf("%s:%d", host, port)
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}
