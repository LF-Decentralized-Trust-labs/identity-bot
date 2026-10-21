package relay

import "github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

// What an Identity Agent exchanges with a relay over HTTPS, beside the session
// itself (ADR-048 §8): the discovery descriptor, and signed control requests.

// ServiceDescriptor is what a relay publishes at
// /.well-known/url-relay-service.json.
type ServiceDescriptor struct {
	// Protocol is the relay protocol version, relayproto.ProtocolVersion.
	Protocol string `json:"protocol"`
	// Service is the relay's name, which every admission challenge and control
	// request carries.
	Service string `json:"service"`
	// Mode is the kind of address this relay hands out. An operator runs
	// public and private service as separate deployments (ADR-048 §1).
	Mode relayproto.Mode `json:"mode"`
	// TunnelEndpoint is the wss:// address of the session websocket.
	TunnelEndpoint string `json:"tunnel_endpoint"`
	// Endpoints maps each control op to the URL it is sent to.
	Endpoints map[string]string `json:"endpoints"`
}

// Control operations. A request names its op, so a signature for one cannot
// be used as another.
const (
	OpAllocate      = "allocate"
	OpBind          = "bind"
	OpRelease       = "release"
	OpClaimName     = "claim-name"
	OpReleaseName   = "release-name"
	OpRequestDomain = "request-domain"
	OpVerifyDomain  = "verify-domain"
	OpReleaseDomain = "release-domain"
)

// defaultPaths are where each op is sent when a descriptor does not say.
var defaultPaths = map[string]string{
	OpAllocate:      "/allocate",
	OpBind:          "/bind",
	OpRelease:       "/release",
	OpClaimName:     "/names/claim",
	OpReleaseName:   "/names/release",
	OpRequestDomain: "/domains/request",
	OpVerifyDomain:  "/domains/verify",
	OpReleaseDomain: "/domains/release",
}

// DomainProof is the DNS record that proves a custom domain is an identity's:
// TXT Name carrying Value.
type DomainProof struct {
	Domain string `json:"domain"`
	Name   string `json:"txt_name"`
	Value  string `json:"txt_value"`
}
