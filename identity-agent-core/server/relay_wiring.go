package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"identity-agent-core/backup"
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
// The enrollment identity is DURABLE. A relay's whole value is a stable address
// an agent can hand out and expect to keep working: the operator maps the
// enrollment AID to an allocation, so presenting a fresh AID each start would
// hand back a fresh allocation and a new public URL, silently breaking every
// address already given out. So the first start mints the enrollment and records
// it; every later start reloads and reuses the SAME AID, which keeps the
// allocation — and therefore the URL — stable across restarts.
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
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		log.Printf("[relay] %s is configured but this instance has no identity yet — "+
			"deferring relay enrollment until an identity exists", base)
		return relay.Config{}, nil, false
	}
	// Reuse the enrollment this agent already minted for THIS operator, if one
	// was recorded. Reusing the AID is what keeps the operator's allocation — and
	// so the public URL — stable across restarts. Reuse re-derives its key from
	// the root seed and needs no KERI engine, so it happens before the engine
	// check: a recorded relay can come back up even while the engine is briefly
	// unavailable.
	if stored, found, lerr := loadRelayEnrollment(s.DataDir); lerr != nil {
		// The record is present but unreadable. Say so and mint a fresh one below
		// rather than refuse the relay entirely — a working relay at a new URL
		// beats no relay at all, and the alternative strands the agent.
		log.Printf("[relay] the recorded enrollment could not be read (%v) — minting a fresh one, "+
			"which changes this agent's relay URL", lerr)
	} else if found && stored.BaseURL == base {
		if cfg, signer, ok := s.reuseRelayEnrollment(base, rootSeed, stored); ok {
			return cfg, signer, true
		}
		// Falling through to a fresh mint: reuse could not re-derive the signer,
		// which reuseRelayEnrollment has already logged.
	}

	if s.KeriDriver == nil {
		log.Printf("[relay] %s is configured but no KERI engine is available — "+
			"cannot mint an enrollment identity, deferring", base)
		return relay.Config{}, nil, false
	}

	// No usable record for this operator — mint a fresh pairwise AID for THIS
	// enrollment, in its own pool so its key range never collides with a contact
	// or login relationship. The same AID serves as the resource being allocated
	// for (its own did:webs / OOBI artifacts): a single foundational allocation,
	// not yet the per-relationship fan-out the capability model calls for — see
	// the deferral note below.
	aid, oobi, seed, idx, err := s.mintPairwiseIn("relay-enrollment", "relay")
	if err != nil {
		log.Printf("[relay] could not mint an enrollment identity for %s (%v) — relay not installed this run",
			base, err)
		return relay.Config{}, nil, false
	}

	// The public key was already derived and registered by mintPairwiseIn; read
	// it back rather than deriving it a second time from the same seed.
	pubB64, ok := getPairwiseKey(aid)
	if !ok {
		pubB64 = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}

	// Record the enrollment so the next start reuses it instead of minting
	// another and moving the URL. Loud but non-fatal if it cannot be written:
	// the relay still comes up this run, and the cost is a URL change at the next
	// restart — which is exactly the state this whole change removes, so it is
	// worth a warning rather than a refusal.
	enr := storedRelayEnrollment{BaseURL: base, AID: aid, RelationshipIndex: idx, PublicKey: pubB64}
	if kel, ok := getPairwiseKEL(aid); ok {
		enr.KEL = kel
	}
	if serr := saveRelayEnrollment(s.DataDir, enr); serr != nil {
		log.Printf("[relay] WARNING: could not record the enrollment identity, so a restart will re-enroll "+
			"and this agent's relay URL will change: %v", serr)
	}

	cfg := relay.Config{
		BaseURL:       base,
		EnrollmentAID: aid,
		PublicKeyB64:  pubB64,
		OOBIUrl:       oobi,
		RAID:          aid,
		LocalBase:     fmt.Sprintf("http://127.0.0.1:%d", s.Port),
	}
	return cfg, &relayEnrollmentSigner{seed: seed}, true
}

// reuseRelayEnrollment rebuilds the relay config and signer from a previously
// recorded enrollment, so the operator's allocation and the public URL stay the
// same across restarts.
//
// The signing seed is re-derived from the root seed and the recorded index — the
// seed itself is never stored, the same rule login follows for its per-site keys.
// The two in-memory registries that make the AID resolvable are repopulated here
// too: both are empty after a restart, so without this the agent would remember
// which AID it enrolled and still be unable to serve its OOBI or did.json.
func (s *CoreServer) reuseRelayEnrollment(base string, rootSeed []byte, stored *storedRelayEnrollment) (relay.Config, relay.Signer, bool) {
	seed, derr := backup.DerivePairwiseSeed(rootSeed, stored.RelationshipIndex, 0)
	if derr != nil {
		log.Printf("[relay] could not re-derive the recorded enrollment key for %s (%v) — minting a fresh one, "+
			"which changes this agent's relay URL", base, derr)
		return relay.Config{}, nil, false
	}

	// Put back what makes the AID resolvable after a restart. Recompute the
	// public key from the seed when the record predates storing it.
	pubB64 := stored.PublicKey
	if pubB64 == "" {
		pubB64 = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	registerPairwiseKey(stored.AID, pubB64)
	if len(stored.KEL) > 0 {
		registerPairwiseKEL(stored.AID, stored.KEL)
	}

	// Composed from where this agent is reachable NOW, exactly as the mint path
	// does — storing the OOBI would pin it to wherever the agent was when it
	// first enrolled.
	oobi := fmt.Sprintf("%s/public/oobi/%s", s.EndpointService.CurrentURL(), stored.AID)

	cfg := relay.Config{
		BaseURL:       base,
		EnrollmentAID: stored.AID,
		PublicKeyB64:  pubB64,
		OOBIUrl:       oobi,
		RAID:          stored.AID,
		LocalBase:     fmt.Sprintf("http://127.0.0.1:%d", s.Port),
	}
	log.Printf("[relay] reusing the enrollment identity recorded for %s (%s), keeping this agent's relay URL stable",
		base, stored.AID)
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

	// Install the manager under the same lock Stop reads it with. This runs in
	// its own goroutine off Start, while Stop reads s.RelayManager under s.mu —
	// assigning it here without the lock is a data race the race detector flags.
	//
	// The lock also closes the lifecycle window. Enrolling a relay is slow, so
	// the server can be stopped before this goroutine gets here — and Stop has
	// by then already passed the point where it stops the relay manager. If that
	// has happened, stop the manager we just built rather than leaving it
	// running with nothing to shut it down.
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		rm.Stop()
		return
	}
	s.RelayManager = rm
	s.mu.Unlock()

	s.EndpointService.SetRelayManager(rm)

	if err := rm.Start(s.AppCtx); err != nil {
		log.Printf("[relay] failed to bring up %s (non-fatal): %v", cfg.BaseURL, err)
		s.EndpointService.Refresh()
		return
	}
	s.EndpointService.Refresh()
}
