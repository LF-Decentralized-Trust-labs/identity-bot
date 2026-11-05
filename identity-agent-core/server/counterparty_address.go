package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"path/filepath"
	"sync"

	"identity-agent-core/endpoint"
)

// What a counterparty is given to reach this agent (ADR-048 §6).
//
// Two kinds of route write an address into something. One pairs the owner's
// own device, on the owner's network: the owner is not a counterparty, and the
// address that device can use is the direct one. The other hands something to
// somebody else — an invitation, an OOBI, an introduction — and that names a
// relay address and never this agent's direct address. With no relay address a
// Direct-mode agent names its direct listener instead, which is path-scoped,
// answers only for identifiers on its allowlist, and serves no invitation.

// directListenerBase is where the direct listener is reached, and false unless
// the agent is in Direct mode and a listener is configured.
func (s *CoreServer) directListenerBase() (string, bool) {
	if s.resolveIngressMode() != IngressModeDirect {
		return "", false
	}
	return endpoint.DirectAdvertisedURL()
}

// oobiForCounterparty is the OOBI link to give a counterparty for aid: at the
// relay address when one is held, else on the direct listener of a Direct-mode
// agent, whose allowlist then admits aid. False when neither exists.
func (s *CoreServer) oobiForCounterparty(r *http.Request, aid string) (string, bool) {
	if base, ok := s.relayAddressBase(r); ok {
		return fmt.Sprintf("%s/public/oobi/%s", base, aid), true
	}
	base, ok := s.directListenerBase()
	if !ok {
		return "", false
	}
	s.mu.Lock()
	al := s.allowlistOrNone()
	s.mu.Unlock()
	if err := al.Allow(aid); err != nil {
		return "", false
	}
	return fmt.Sprintf("%s/%s/oobi", base, aid), true
}

// maxOobiIdentifiers bounds the pairwise identifiers /api/oobi makes. Each is a
// key, a log and a witness event that can never be taken back, and the route is
// reachable by any local program.
const maxOobiIdentifiers = 512

const oobiOffersFileName = "oobi-offers.json"

// oobiOffers remembers which pairwise identifier was made for which
// counterparty, so asking again for the same one gives the same identifier.
type oobiOffers struct {
	mu   sync.Mutex
	path string
	Made int               `json:"made"`
	For  map[string]string `json:"for"`
}

var errTooManyOobiIdentifiers = errors.New("the limit of identifiers made for OOBIs is reached")

func loadOobiOffers(dataDir string) *oobiOffers {
	o := &oobiOffers{path: filepath.Join(dataDir, oobiOffersFileName), For: map[string]string{}}
	if raw, err := os.ReadFile(o.path); err == nil {
		_ = json.Unmarshal(raw, o)
		if o.For == nil {
			o.For = map[string]string{}
		}
	}
	return o
}

func (o *oobiOffers) saveLocked() error {
	raw, err := json.Marshal(o)
	if err != nil {
		return err
	}
	tmp := o.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, o.path)
}

// identifierFor returns the identifier already made for counterparty, if it can
// still be served, else makes one with mint. A counterparty of "" is not
// recognisable and always gets a new one.
func (o *oobiOffers) identifierFor(counterparty string, servable func(string) bool, mint func() (string, error)) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if counterparty != "" {
		if aid, ok := o.For[counterparty]; ok && servable(aid) {
			return aid, nil
		}
	}
	if o.Made >= maxOobiIdentifiers {
		return "", errTooManyOobiIdentifiers
	}
	aid, err := mint()
	if err != nil {
		return "", err
	}
	o.Made++
	if counterparty != "" {
		o.For[counterparty] = aid
	}
	if err := o.saveLocked(); err != nil {
		return aid, fmt.Errorf("remember the identifier made for this counterparty: %w", err)
	}
	return aid, nil
}

func (s *CoreServer) oobiOffersOrLoad() *oobiOffers {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oobiOffersHeld == nil {
		s.oobiOffersHeld = loadOobiOffers(s.DataDir)
	}
	return s.oobiOffersHeld
}

var errNoRelayAddress = errors.New("no relay address is held: what a counterparty is given names a relay address and never this agent's direct address (ADR-048 §6)")

// writeNoRelayAddress refuses a route that would hand a counterparty an address
// when there is no relay address to hand.
func writeNoRelayAddress(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "No relay address", errNoRelayAddress.Error())
}

// heldRelayBase is the relay address this agent holds, for code that has no
// request to read one from.
func (s *CoreServer) heldRelayBase() (string, bool) {
	if rm := s.currentRelay(); rm != nil {
		if u := strings.TrimRight(rm.URL(), "/"); u != "" {
			return u, true
		}
	}
	return "", false
}
