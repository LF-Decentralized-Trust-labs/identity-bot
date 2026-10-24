package server

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"identity-agent-core/authprovider"
	"identity-agent-core/endpoint"
	"identity-agent-core/tunnel"
)

// A development build takes an unmeasured controller as verified.
//
// A controller reaches a raised action only with a statement, signed by the
// device that holds this identity's root key, saying how well the person at the
// machine was authenticated. The side that MAKES that statement — measuring the
// person, and having the root device sign the result — is not built yet. Until
// it is, nothing can produce a statement, so on every build no controller can
// create an AI agent, mint its token, issue a credential, or reach anything else
// raised to the verified level.
//
// A development build stands in for the missing measurement, and only for that:
//
//   - Only when no statement was offered at all. A statement that was made is
//     used as it is — lower than verified, or refused as unvouched or forged —
//     because a person who was checked and fell short, or a statement that did
//     not hold up, has not been checked "by default".
//   - Never above verified. The actions raised to high — rotating keys, exporting
//     backups, replacing the root seed — stay out of reach, because those are the
//     ones a development identity still needs to protect from a stray controller.
//   - Never in a production build. The mode is compiled in, and a development
//     build's identities sit under a separate trust anchor that a production
//     verifier refuses, so nothing granted here is worth anything outside it.
//   - Never for a closed action, which no level opens.
//   - Never while anything outside this computer can reach the Identity Agent,
//     and never for a request that did not arrive from this computer. A
//     development build reached through a relay, a tunnel, a proxy, a published
//     address or a network interface is one a stranger can talk to, and the
//     stand-in would hand every machine holding a grant there the verified
//     actions: issuing credentials, minting tokens, creating AI agents. A
//     separate trust anchor limits what those are worth elsewhere; it does not
//     stop them being used against the identity this Identity Agent holds. See
//     whoCanReachThisIdentityAgent for exactly what counts.
//
// It is recorded under its own provider name, so anything that reads who was
// checked and how can tell a stand-in from a measurement.
const developmentBuildProvider = "development-build-default"

func whatThisBuildTakesAsMeasured(
	measured authprovider.Result, statementOffered, isDevBuild, reachableFromOutside bool, now time.Time,
) authprovider.Result {
	if !isDevBuild || statementOffered || measured.Measured || reachableFromOutside {
		return measured
	}
	return authprovider.Result{
		Level:    authprovider.LevelVerified,
		Measured: true,
		At:       now.UTC(),
		Provider: developmentBuildProvider,
	}
}

// whatThisRequestTakesAsMeasured is whatThisBuildTakesAsMeasured for request r,
// with whether anything outside this computer can reach this Identity Agent
// read from the running server and from r itself.
func (s *CoreServer) whatThisRequestTakesAsMeasured(
	r *http.Request, measured authprovider.Result, statementOffered, isDevBuild bool, now time.Time,
) authprovider.Result {
	outside := false
	if isDevBuild {
		outside, _ = whoCanReachThisIdentityAgent(s.howThisIdentityAgentIsReachedNow(r))
	}
	return whatThisBuildTakesAsMeasured(measured, statementOffered, isDevBuild, outside, now)
}

// howThisIdentityAgentIsReached is everything that decides whether something other than
// this computer can send this Identity Agent a request.
//
// Gathered into one value so the decision is a pure function a test can drive
// through every case, rather than a method that reads the environment.
type howThisIdentityAgentIsReached struct {
	// SealedInstance is the sealed-instance posture: reached through a host
	// proxy on a network interface, by design.
	SealedInstance bool
	// ListensOn is the direct-ingress bind host, or "" for loopback only.
	ListensOn string
	// HoldsRelay is true while a relay manager is installed, connected or not:
	// requests through a relay arrive in-process, and an address a relay holds
	// can be reconnected at any moment.
	HoldsRelay bool
	// RelayConfigured is true when the ingress mode calls for a relay and one is
	// named, so one is being, or about to be, brought up.
	RelayConfigured bool
	// Tunnel is true when a tunnel is configured or up.
	Tunnel bool
	// PublishedSource is where the advertised address came from, as the
	// endpoint service reports it ("localhost" when nothing else applies).
	PublishedSource string
	// PublicURL is the PUBLIC_URL deployment setting.
	PublicURL string
	// BehindAProxy is the deployment saying it always sits behind one
	// (TRUST_FORWARDED_HEADERS).
	BehindAProxy bool
	// TunnelMode is true when the ingress mode is a tunnel, whether or not
	// one has come up.
	TunnelMode bool
	// ThisRequest describes the request being decided on: Local when it came
	// over loopback with no forwarding headers and not through a relay.
	// A proxy that adds no address of its own, a port forward, or a relay
	// stream all show here even when nothing else gives them away.
	ThisRequestIsLocal bool
}

// whoCanReachThisIdentityAgent says whether anything beyond this computer can reach the
// Identity Agent, and if so, why.
//
// FAIL CLOSED, AND ON INTENT AS WELL AS ON STATE. A relay that is configured
// but has not connected yet, a tunnel that is starting, an address that is
// published but not answering: each of those becomes reachable without this
// Identity Agent noticing, so each counts as reachable now. A brief outage of the relay
// does not reopen the stand-in either, because the manager is still installed.
//
// What the server-wide facts cannot see — a proxy or a port forward pointed at
// the loopback listener without telling this Identity Agent — the request
// itself still shows, unless that relaying process strips every forwarding
// header and connects over loopback. So the request must also be local.
func whoCanReachThisIdentityAgent(h howThisIdentityAgentIsReached) (bool, string) {
	switch {
	case !h.ThisRequestIsLocal:
		return true, "this request did not come from this computer"
	case h.SealedInstance:
		return true, "it runs as a sealed instance reached through a host proxy"
	case h.ListensOn != "" && !endpoint.IsLoopbackHost(h.ListensOn):
		return true, "it listens on " + h.ListensOn + ", not only on this computer"
	case h.HoldsRelay:
		return true, "it holds an address at a relay"
	case h.RelayConfigured:
		return true, "it is set to be reached through a relay"
	case h.Tunnel || h.TunnelMode:
		return true, "it is reached through a tunnel"
	case h.BehindAProxy:
		return true, "it is set to sit behind a proxy"
	case strings.TrimSpace(h.PublicURL) != "":
		return true, "it publishes the address " + strings.TrimSpace(h.PublicURL)
	case h.PublishedSource != "" && h.PublishedSource != "localhost":
		return true, "it publishes an address from " + h.PublishedSource
	}
	return false, ""
}

// howThisIdentityAgentIsReachedNow reads the facts whoCanReachThisIdentityAgent
// decides on, for request r.
func (s *CoreServer) howThisIdentityAgentIsReachedNow(r *http.Request) howThisIdentityAgentIsReached {
	_, relayed := relayproto.PreambleFrom(r.Context())
	mode := s.resolveIngressMode()
	h := howThisIdentityAgentIsReached{
		SealedInstance:     endpoint.SealedInstanceIngress(),
		ListensOn:          endpoint.DirectIngressHost(),
		HoldsRelay:         s.currentRelay() != nil,
		PublicURL:          os.Getenv("PUBLIC_URL"),
		BehindAProxy:       trustForwardedHeaders(),
		TunnelMode:         mode == IngressModeTunnel,
		ThisRequestIsLocal: isLocalConnection(r) && !relayed && r.RemoteAddr != sealedRemoteAddr,
	}
	if kind, uses := relayKindFor(mode); uses && s.relayOperator(kind) != "" {
		h.RelayConfigured = true
	}
	if tm := s.TunnelManager; tm != nil {
		p := tm.GetConfig().Provider
		h.Tunnel = tm.URL() != "" || (p != "" && p != tunnel.ProviderNone)
	}
	if s.EndpointService != nil {
		h.PublishedSource = s.EndpointService.Source()
	}
	return h
}
