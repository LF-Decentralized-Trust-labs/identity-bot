package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
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
	"identity-agent-core/secureenclave"
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
// enrolment key, as a plain Ed25519 signature over relayproto.CanonicalBody
// (ADR-049).
type relayEnrollmentSigner struct {
	// seed is the 32-byte Ed25519 seed for the enrolment identifier, never the
	// root seed.
	seed []byte
}

func (rs *relayEnrollmentSigner) SignCanonical(enrollmentAID string, body map[string]interface{}) (string, error) {
	canon, err := relayproto.CanonicalBody(body)
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

// unclaimed reports whether this Identity Agent holds no identity yet.
func (s *CoreServer) unclaimed() bool {
	if s.DataStore == nil {
		return true
	}
	id, err := s.DataStore.GetIdentity()
	return err == nil && (id == nil || id.AID == "")
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
// The enrolment key derives from the root seed. A machine nobody has claimed
// yet, and that has never held a seed, gets one of its own here so it can be
// reached to be claimed. Any other machine uses the seed it has, and the relay
// waits if it cannot be read: a relay is never a reason to make a new one.
func (s *CoreServer) loadRelayEnrolment(kind relayKind, base string) (*relayEnrolment, error) {
	rootSeed, err := secureenclave.LoadRootSeed(s.DataDir)
	if errors.Is(err, secureenclave.ErrNoRootSeed) && s.unclaimed() {
		rootSeed, err = ensureRootSeed(s.DataDir)
	}
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

// arrivedByRelay reports whether r reached this Identity Agent through a
// relay. An address at a relay carries the protocol and never a page, so
// nothing that answers in HTML answers it.
func arrivedByRelay(r *http.Request) bool {
	_, ok := relayproto.PreambleFrom(r.Context())
	return ok
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
	return relayproto.IsPrivateRoute(method + " " + matchedRoutePattern(s.router, probe))
}

// startRelay brings up the relay the ingress mode calls for, if one is
// configured, and keeps trying until it is reached.
//
// It runs in its own goroutine off Start: the local server must not wait on the
// network.
func (s *CoreServer) startRelay() {
	ctx, gen := s.nextRelayGeneration()
	s.runRelay(ctx, gen)
}

// relayRetryWait is the first wait before trying an unreachable relay again;
// it doubles up to five minutes.
var relayRetryWait = 5 * time.Second

// relayFailure is why a relay generation has no relay: what a screen shows
// when there is nothing running to ask.
type relayFailure struct {
	gen          int
	code, reason string
}

// nextRelayGeneration ends whatever relay start or relay is running, and
// begins a new generation with its own context. Anything the old generation
// is still doing is cancelled, and it can install nothing.
func (s *CoreServer) nextRelayGeneration() (context.Context, int) {
	parent := s.AppCtx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	if s.relayCancel != nil {
		s.relayCancel()
	}
	s.relayGen++
	gen := s.relayGen
	s.relayCancel = cancel
	s.relayFailure = nil
	old := s.RelayManager
	s.RelayManager = nil
	if s.EndpointService != nil {
		s.EndpointService.SetRelayManager(nil)
	}
	s.mu.Unlock()
	if old != nil {
		old.Stop()
	}
	return ctx, gen
}

// relayGaveUp records why generation gen has no relay, if it is still the
// current one.
func (s *CoreServer) relayGaveUp(gen int, code, reason string) {
	log.Printf("[relay] not brought up: %s", reason)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.relayGen == gen {
		s.relayFailure = &relayFailure{gen: gen, code: code, reason: reason}
	}
}

// runRelay brings up generation gen's relay. If a newer generation begins
// while it is still enrolling, ctx is cancelled and it installs nothing.
func (s *CoreServer) runRelay(ctx context.Context, gen int) {
	kind, uses := relayKindFor(s.resolveIngressMode())
	if !uses {
		return
	}
	base := s.relayOperator(kind)
	if base == "" {
		s.relayGaveUp(gen, "no_relay", "No relay is configured for this mode.")
		return
	}
	e, err := s.loadRelayEnrolment(kind, base)
	if err != nil {
		s.relayGaveUp(gen, "no_enrolment", "This Identity Agent could not make its relay enrolment: "+err.Error())
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
		s.relayGaveUp(gen, "no_enrolment", "The relay enrolment key could not be loaded: "+err.Error())
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
		// Through the record's lock: the owner's routes change the same record
		// (a domain waiting for its DNS proof, say).
		if err := s.updateRelayRecord(kind, func(rec *storedRelayEnrollment) {
			if rec.AID == e.record.AID {
				rec.Allocations = held
			}
		}); err != nil {
			log.Printf("[relay] WARNING: could not remember this Identity Agent's relay addresses, "+
				"so a restart may move them: %v", err)
		}
	})

	// Installed under the lock Stop reads it with, and only while this is still
	// the current generation: a newer one has stopped whatever it replaced and
	// must not find this installed behind it.
	s.mu.Lock()
	if !s.running || s.relayGen != gen || ctx.Err() != nil {
		s.mu.Unlock()
		rm.Stop()
		return
	}
	s.RelayManager = rm
	if s.EndpointService != nil {
		s.EndpointService.SetRelayManager(rm)
	}
	s.mu.Unlock()

	// Keep trying. A relay that cannot be reached at start-up (the network is
	// down, the machine just woke) is reached later without a restart.
	backoff := relayRetryWait
	for {
		err := rm.Start(ctx)
		if err == nil || ctx.Err() != nil || errors.Is(err, relay.ErrStopped) {
			return
		}
		if st := rm.GetStatus(); st.State == relay.StateFailed {
			// Trying again cannot change it; it waits for the settings to.
			log.Printf("[relay] %s refused: %s", base, st.Reason)
			return
		}
		log.Printf("[relay] could not reach %s yet, trying again in %s: %v", base, backoff, err)
		select {
		case <-ctx.Done():
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
	rm := s.currentRelay()
	if rm == nil {
		return "", false
	}
	a := rm.Lookup(p.Allocation)
	if a == nil || a.URL == "" {
		return "", false
	}
	return strings.TrimRight(a.URL, "/"), true
}
