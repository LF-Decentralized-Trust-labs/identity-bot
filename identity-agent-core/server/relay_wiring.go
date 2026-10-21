package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"

	"identity-agent-core/backup"
	"identity-agent-core/relay"
)

// Wiring a relay in (ADR-048).
//
// A relay is how an Identity Agent that only dials out stays reachable at an
// address it can hand out and expect to still work later. It opens one session
// to the relay, admitted on a signature by a pairwise enrolment identifier, and
// the relay passes requests for its address down that session.
//
// The address is public (one stable address anybody may find) or private (an
// unlinkable address for relationships). Which is the identity's choice, made
// by the ingress mode. Each mode has its own enrolment identifier, minted for
// that relay alone, so a relay never learns the root identity, and a public
// address and the private ones are never tied together by their enrolment.

// relayKind is what differs between a public and a private relay.
type relayKind struct {
	mode relayproto.Mode
	// pool is the pairwise key range the enrolment identifier is minted in.
	pool string
	// name prefixes the engine's name for the enrolment identifier.
	name string
	// record is the file the enrolment is remembered in.
	record string
	// env is the environment variable naming the operator when settings do not.
	env string
}

var (
	privateRelay = relayKind{mode: relayproto.ModePrivate, pool: "relay-enrollment", name: "relay",
		record: relayEnrollmentFileName, env: "RELAY_BASE_URL"}
	publicRelay = relayKind{mode: relayproto.ModePublic, pool: "relay-public-enrollment", name: "relay-public",
		record: publicRelayEnrollmentFileName, env: "PUBLIC_RELAY_BASE_URL"}
)

// relayEnrollmentSigner signs allocate and release requests with the pairwise
// enrolment key, as a plain Ed25519 signature over relay.CanonicalBody.
type relayEnrollmentSigner struct {
	// seed is the 32-byte Ed25519 seed for the enrolment identifier, never the
	// root seed.
	seed []byte
}

func (rs *relayEnrollmentSigner) SignCanonical(enrollmentAID string, body map[string]interface{}) (string, error) {
	canon, err := relay.CanonicalBody(body)
	if err != nil {
		return "", err
	}
	if len(rs.seed) != ed25519.SeedSize {
		return "", fmt.Errorf("relay enrolment key is %d bytes, expected an Ed25519 seed", len(rs.seed))
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(rs.seed), canon)), nil
}

// relayBaseURL is the private relay this Identity Agent enrols with, or empty.
func (s *CoreServer) relayBaseURL() string { return s.relayOperator(privateRelay) }

// relayOperator is the relay configured for kind: the persisted setting first,
// then the environment. The open-source core bundles no operator.
func (s *CoreServer) relayOperator(kind relayKind) string {
	if s.DataStore != nil {
		if saved, err := s.DataStore.GetSettings(); err == nil && saved != nil {
			v := saved.RelayOperator
			if kind.mode == relayproto.ModePublic {
				v = saved.PublicRelayOperator
			}
			if strings.TrimSpace(v) != "" {
				return strings.TrimRight(strings.TrimSpace(v), "/")
			}
		}
	}
	return strings.TrimRight(strings.TrimSpace(os.Getenv(kind.env)), "/")
}

// publicRelayName is the name asked for at the public relay, if any.
func (s *CoreServer) publicRelayName() string {
	if s.DataStore != nil {
		if saved, err := s.DataStore.GetSettings(); err == nil && saved != nil {
			return strings.TrimSpace(saved.PublicRelayName)
		}
	}
	return ""
}

// relayEnrolment is what a relay session is made from: the enrolment
// identifier, its signed key log and its key.
type relayEnrolment struct {
	record storedRelayEnrollment
	seed   []byte
	kel    []byte
}

// loadRelayEnrolment reuses the enrolment recorded for this operator, or mints
// one. Reusing it is what keeps the address stable across restarts: the relay
// knows the address by the enrolment identifier.
//
// A machine nobody has claimed yet still gets a root seed of its own here
// (ensureRootSeed), so it can be reached to be claimed.
func (s *CoreServer) loadRelayEnrolment(kind relayKind, base string) (*relayEnrolment, error) {
	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		return nil, fmt.Errorf("no root seed to derive an enrolment key from: %w", err)
	}
	if stored, found, lerr := loadRelayEnrollment(s.DataDir, kind.record); lerr != nil {
		log.Printf("[relay] the recorded %s enrolment could not be read (%v); minting a fresh one, "+
			"which changes this Identity Agent's %s address", kind.mode, lerr, kind.mode)
	} else if found && stored.BaseURL == base {
		if e, rerr := reuseRelayEnrolment(rootSeed, stored); rerr == nil {
			log.Printf("[relay] reusing the %s enrolment recorded for %s (%s)", kind.mode, base, stored.AID)
			return e, nil
		} else {
			log.Printf("[relay] the recorded %s enrolment cannot be used (%v); minting a fresh one, "+
				"which changes this Identity Agent's %s address", kind.mode, rerr, kind.mode)
		}
	}

	if s.KeriDriver == nil {
		return nil, fmt.Errorf("no KERI engine to mint an enrolment identifier with")
	}
	aid, _, seed, idx, err := s.mintPairwiseIn(kind.pool, kind.name)
	if err != nil {
		return nil, fmt.Errorf("mint an enrolment identifier: %w", err)
	}
	pubB64, ok := getPairwiseKey(aid)
	if !ok {
		pubB64 = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	rec := storedRelayEnrollment{BaseURL: base, AID: aid, RelationshipIndex: idx, PublicKey: pubB64}
	if kel, ok := getPairwiseKEL(aid); ok {
		rec.KEL = kel
	}
	stream, err := signedInceptionKEL(aid, rec.KEL, seed)
	if err != nil {
		return nil, fmt.Errorf("produce the enrolment identifier's key log: %w", err)
	}
	if serr := saveRelayEnrollment(s.DataDir, kind.record, rec); serr != nil {
		log.Printf("[relay] WARNING: could not record the %s enrolment, so a restart will mint another "+
			"and this Identity Agent's address will change: %v", kind.mode, serr)
	}
	return &relayEnrolment{record: rec, seed: seed, kel: stream}, nil
}

// reuseRelayEnrolment rebuilds an enrolment from its record. The key is
// re-derived from the root seed, never stored, and is checked against the key
// recorded: a root seed that changed since would otherwise sign as an
// identifier whose log names a different key, and every admission would fail
// with no explanation.
func reuseRelayEnrolment(rootSeed []byte, stored *storedRelayEnrollment) (*relayEnrolment, error) {
	seed, err := backup.DerivePairwiseSeed(rootSeed, stored.RelationshipIndex, 0)
	if err != nil {
		return nil, fmt.Errorf("re-derive the enrolment key: %w", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if stored.PublicKey != "" && stored.PublicKey != pubB64 {
		return nil, fmt.Errorf("the key re-derived from this root seed is not the one %s was made with", stored.AID)
	}
	stream, err := signedInceptionKEL(stored.AID, stored.KEL, seed)
	if err != nil {
		return nil, fmt.Errorf("produce %s's key log: %w", stored.AID, err)
	}
	// Put back what makes the identifier resolvable after a restart.
	registerPairwiseKey(stored.AID, pubB64)
	if len(stored.KEL) > 0 {
		registerPairwiseKEL(stored.AID, stored.KEL)
	}
	return &relayEnrolment{record: *stored, seed: seed, kel: stream}, nil
}

// relationshipRoutes are what a private address may reach on this Identity
// Agent: an identity's artifacts, its message endpoint and pairwise key
// registration. Each is drawn from publicRoutes, which a test holds.
var relationshipRoutes = map[string]bool{
	"GET /oobi/{aid}":            true,
	"GET /public/oobi/{aid}":     true,
	"GET /{aid}/oobi":            true,
	"GET /{aid}/did.json":        true,
	"GET /public/{aid}/did.json": true,
	"GET /{aid}/kel":             true,
	"GET /{aid}/keri.cesr":       true,
	"POST /_register":            true,
	"POST /public/_register":     true,
	"POST /didcomm":              true,
}

// privateAddressMayReach is this Identity Agent's own rule for a request that
// arrived on a private address (ADR-048 §6). The relay applies a rule too, but
// a relay is not trusted to decide what reaches the Identity Agent.
func (s *CoreServer) privateAddressMayReach(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
		return false
	}
	method := r.Method
	probe := r
	if method == http.MethodHead {
		method = http.MethodGet
		probe = r.Clone(r.Context())
		probe.Method = http.MethodGet
	}
	// TestEveryRelationshipRouteIsPublic holds that each of these is a public
	// route, so a private address never reaches more than a stranger may.
	return relationshipRoutes[method+" "+matchedRoutePattern(s.router, probe)]
}

// startRelay brings up the relay the ingress mode calls for, if one is
// configured, and keeps trying until it is reached.
//
// It runs in its own goroutine off Start: the local server must not wait on the
// network.
func (s *CoreServer) startRelay() {
	s.mu.Lock()
	s.relayGen++
	gen := s.relayGen
	s.mu.Unlock()
	s.runRelay(gen)
}

// runRelay is startRelay for one generation: if the settings change while it
// is still enrolling, a newer start has overtaken it and it installs nothing.
func (s *CoreServer) runRelay(gen int) {
	var kind relayKind
	switch s.resolveIngressMode() {
	case IngressModeRelay:
		kind = privateRelay
	case IngressModePublic:
		kind = publicRelay
	default:
		return
	}
	base := s.relayOperator(kind)
	if base == "" {
		if kind.mode == relayproto.ModePublic {
			log.Printf("[relay] public mode is chosen but no public relay is configured")
		}
		return
	}
	e, err := s.loadRelayEnrolment(kind, base)
	if err != nil {
		log.Printf("[relay] %s relay %s not brought up: %v", kind.mode, base, err)
		return
	}

	raid, name := e.record.AID, ""
	if kind.mode == relayproto.ModePublic {
		// A public address is the identity's own, so it serves the identity.
		if s.DataStore != nil {
			if id, err := s.DataStore.GetIdentity(); err == nil && id != nil && id.AID != "" {
				raid = id.AID
			}
		}
		name = s.publicRelayName()
	}
	sessionSigner, err := keri.NewSoftwareSigner(e.seed, true)
	if err != nil {
		log.Printf("[relay] could not load the enrolment key: %v", err)
		return
	}
	kel := e.kel
	rm := relay.NewManager(relay.Config{
		BaseURL: base, Mode: kind.mode, EnrollmentAID: e.record.AID,
		KEL: func() []byte { return kel }, Session: sessionSigner,
		Requests: &relayEnrollmentSigner{seed: e.seed}, RAID: raid, Name: name,
		Handler: s.router, PrivateMayReach: s.privateAddressMayReach,
		TLS: s.relayTLS, HTTPClient: s.relayClient,
	})
	rm.Remember(e.record.Allocations)
	rm.OnChange(func(string, bool) { s.EndpointService.Refresh() })
	rm.OnAllocated(func(held []relay.Allocation) {
		// Read back first: the record also holds what was asked of the relay
		// since (a domain waiting for its DNS proof, say).
		rec := e.record
		if stored, found, err := loadRelayEnrollment(s.DataDir, kind.record); err == nil && found && stored.AID == rec.AID {
			rec = *stored
		}
		rec.Allocations = held
		if err := saveRelayEnrollment(s.DataDir, kind.record, rec); err != nil {
			log.Printf("[relay] WARNING: could not remember this Identity Agent's relay addresses, "+
				"so a restart may move them: %v", err)
		}
	})

	// Installed under the lock Stop reads it with. Enrolling is slow, so the
	// server may already have stopped; then stop what was just built.
	s.mu.Lock()
	if !s.running || s.relayGen != gen {
		s.mu.Unlock()
		return
	}
	s.RelayManager = rm
	s.mu.Unlock()
	s.EndpointService.SetRelayManager(rm)

	// Keep trying. A relay that cannot be reached at start-up (the network is
	// down, the machine just woke) is reached later without a restart.
	backoff := 5 * time.Second
	for {
		s.mu.Lock()
		current := s.relayGen == gen
		s.mu.Unlock()
		if !current {
			return
		}
		err := rm.Start(s.AppCtx)
		if err == nil {
			return
		}
		if rm.GetStatus().State == relay.StateFailed {
			// Trying again cannot change it; it waits for the settings to.
			log.Printf("[relay] %s refused: %s", base, rm.GetStatus().Reason)
			return
		}
		log.Printf("[relay] could not reach %s yet, trying again in %s: %v", base, backoff, err)
		select {
		case <-s.AppCtx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}

// relayedAddress is the address a request arrived at, when it came through a
// relay: the URL this Identity Agent holds for the allocation the stream's
// preamble names, taken from its own records. A private address is a path at
// the relay, so links this Identity Agent writes into a response must carry
// it; nothing a caller sends (a Host or X-Forwarded-Prefix header) decides it.
func (s *CoreServer) relayedAddress(r *http.Request) (string, bool) {
	p, ok := relayproto.PreambleFrom(r.Context())
	if !ok {
		return "", false
	}
	s.mu.Lock()
	rm := s.RelayManager
	s.mu.Unlock()
	if rm == nil {
		return "", false
	}
	a := rm.Lookup(p.Allocation)
	if a == nil || a.URL == "" {
		return "", false
	}
	return strings.TrimRight(a.URL, "/"), true
}
