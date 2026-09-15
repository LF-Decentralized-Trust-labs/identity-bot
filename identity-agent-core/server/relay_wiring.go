package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"identity-agent-core/login"
	"identity-agent-core/relay"
	"identity-agent-core/secureenclave"
)

// Wiring the URL relay in.
//
// The relay package is the single control point for how this agent becomes
// reachable at an address it can hand out and expect to still work later: it
// enrolls a per-relay AID, signs its own requests, and allocates an opaque URL
// bound to that enrollment. Unlike the bare tunnel — one ephemeral vendor URL
// for the whole agent — a relay allocation is provably this agent's, which is
// what makes it worth handing to a counterparty who has to find the agent again
// months from now. `EndpointService` already ranks a live relay above the
// tunnel; this is the piece that actually constructs and installs one so that
// ranking has something to rank.
//
// It is deliberately NEVER the root identity that enrolls. Enrollment is
// per-relay and uses a fresh pairwise AID derived from the root seed, so an
// operator learns only an opaque identifier — never the user's primary
// identity, and never a key that lets it impersonate the user or two operators
// correlate that two enrollments are the same person.

// relayEnrollmentSigner signs relay requests with the pairwise enrollment key.
//
// The operator authenticates the agent by verifying this signature against the
// public key it was given at enrollment. The signature is the same Ed25519 /
// CESR-qb64 primitive the rest of the agent uses, computed over the relay
// package's own canonical encoding, so the bytes signed here are exactly the
// bytes the operator verifies.
type relayEnrollmentSigner struct {
	// seed is the 32-byte Ed25519 seed for the enrollment AID. It is a
	// throwaway relationship key, never the root seed.
	seed []byte
}

func (rs *relayEnrollmentSigner) SignCanonical(enrollmentAID string, body map[string]interface{}) (string, error) {
	canon, err := relay.CanonicalBody(body)
	if err != nil {
		return "", err
	}
	return login.SignString(string(canon), rs.seed)
}

// relayBaseURL is the operator this agent enrolls with, or empty when no relay
// is configured.
//
// Sourced from the environment for now. The OSS core bundles no relay operator,
// so a deployment that wants URL Relay names one here; a deployment that names
// none simply has no relay and stays on whatever the tunnel/direct path
// provides. Persisting the operator in settings alongside the tunnel provider
// (so the UI can select it) is deferred — see the note in loadRelayConfig.
func relayBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("RELAY_BASE_URL")), "/")
}

// loadRelayConfig builds the relay configuration and its signer when a relay is
// configured, mirroring loadTunnelConfig.
//
// It returns ok=false (and does nothing) when no relay operator is configured,
// or when this instance has no identity yet — a relay enrollment must be
// provably somebody's, and the pairwise enrollment AID is derived from the root
// seed, so there is nothing to enroll with before onboarding. In that case the
// relay is simply absent this run and wires itself on a later start once an
// identity exists, exactly as the tunnel does.
//
// Minting the enrollment AID is a real KERI operation (inception, key
// registration, witness broadcast), so this is called from the start-up
// goroutine rather than on the hot path of Start.
func (s *CoreServer) loadRelayConfig() (relay.Config, relay.Signer, bool) {
	base := relayBaseURL()
	if base == "" {
		return relay.Config{}, nil, false
	}

	// Do not force a root seed into existence just because a relay is named. An
	// instance that has not been through onboarding has no identity to make an
	// allocation provably its own, so the relay waits for a later start.
	if _, err := secureenclave.LoadRootSeed(s.DataDir); err != nil {
		log.Printf("[relay] %s is configured but this instance has no identity yet — "+
			"deferring relay enrollment until an identity exists", base)
		return relay.Config{}, nil, false
	}
	if s.KeriDriver == nil {
		log.Printf("[relay] %s is configured but no KERI engine is available — "+
			"cannot mint an enrollment identity, deferring", base)
		return relay.Config{}, nil, false
	}

	// A fresh pairwise AID minted for THIS enrollment, in its own pool so its
	// key range never collides with a contact or login relationship. The same
	// AID serves as the resource being allocated for (its own did:webs /
	// OOBI artifacts): a single foundational allocation, not yet the
	// per-relationship fan-out the capability model calls for — see the deferral
	// note below.
	aid, oobi, seed, _, err := s.mintPairwiseIn("relay-enrollment", "relay")
	if err != nil {
		log.Printf("[relay] could not mint an enrollment identity for %s (%v) — relay not installed this run",
			base, err)
		return relay.Config{}, nil, false
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	cfg := relay.Config{
		BaseURL:       base,
		EnrollmentAID: aid,
		PublicKeyB64:  base64.RawURLEncoding.EncodeToString(pub),
		OOBIUrl:       oobi,
		RAID:          aid,
		LocalBase:     fmt.Sprintf("http://127.0.0.1:%d", s.Port),
	}
	return cfg, &relayEnrollmentSigner{seed: seed}, true
}

// startRelay wires the one URL manager in when a relay is configured: build the
// config (which mints the enrollment identity), construct the manager, install
// it on the endpoint service so a live relay URL outranks the tunnel, register a
// republish hook, and start it.
//
// Runs in its own goroutine off Start for the same reason the tunnel does: the
// network work must not hold up the local server coming up, and a relay that is
// slow or unreachable is reported honestly rather than blocking.
func (s *CoreServer) startRelay() {
	cfg, signer, ok := s.loadRelayConfig()
	if !ok {
		return
	}

	rm := relay.NewManager(cfg, signer)

	// When the relay's public URL appears, changes or is lost, recompute the
	// published endpoint so counterparties are pointed at where this agent
	// currently answers rather than at an address that stopped working.
	rm.OnChange(func(url string, active bool) {
		s.EndpointService.Refresh()
	})

	s.RelayManager = rm
	s.EndpointService.SetRelayManager(rm)

	if err := rm.Start(s.AppCtx); err != nil {
		log.Printf("[relay] failed to bring up %s (non-fatal): %v", cfg.BaseURL, err)
		s.EndpointService.Refresh()
		return
	}
	s.EndpointService.Refresh()
}
