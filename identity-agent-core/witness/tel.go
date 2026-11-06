package witness

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	keri "github.com/grapeid/keri-go"
)

// A witness serves the transaction log of the registries an identity it
// witnesses has founded, so that someone who is not that identity can read
// whether a credential was issued and whether it has since been revoked.
//
// WHAT THE LOG IS. A registry's events (its inception, each issuance, each
// revocation) are made by the issuer and sealed in the issuer's key log. A
// witness only stores and serves them: it never authors one. An event is
// stored only if the key log it holds for that issuer carries the seal of
// exactly that event, so the issuer, whose key log nobody else can append to,
// is the only party who can have put it there.
//
// NO PER-CREDENTIAL SURFACE. The log is asked for by issuer and a place in the
// issuer's key log (since_sn), never by credential or by registry. Asking by
// credential would tell the witness who is checking whom; asking for the whole
// log tells it only that someone reads this issuer's log, and what one reader
// takes out of it stays with the reader.
//
// FRESHNESS. AnchoredSN is how far through the issuer's key log this witness
// holds. Every event of the log anchored at or before it that the issuer gave
// this witness is in the answer. A reader holding the key log further on than
// that knows this witness is behind, and one holding a seal that no served
// event answers knows an event is being kept back.

// TELAnswer is what a witness says about an issuer's registry logs.
type TELAnswer struct {
	IssuerAID string `json:"issuer_aid"`
	// SinceSN echoes the request: events anchored after this place in the
	// issuer's key log are given. -1 asks for all of it.
	SinceSN int `json:"since_sn"`
	// AnchoredSN is the last event of the issuer's key log this witness holds.
	AnchoredSN int        `json:"anchored_sn"`
	Events     []TELEvent `json:"events"`
}

// TELLimits bound a submission so that a route open to anybody costs bounded work.
const (
	MaxTELEventsPerSubmission = 256
	maxTELEventBytes          = 8 << 10
)

// AnchoredTEL checks registry events against the key log of the issuer they
// claim to come from, and returns them with the place in that key log whose
// seal vouches for each. It is the one check, used by a witness before it
// stores events and by a verifier before it believes what a witness served.
//
// kelRaw is the issuer's key log as published, event by event, and must already
// have been verified as a log (signatures included): a seal in a log that is
// not the issuer's proves nothing. held is what is already known to be good
// (nil for a verifier, who starts from nothing).
//
// All or nothing: one event that fails refuses the batch, because a batch that
// is half believed is a log with parts missing.
//
// An event is accepted only when
//   - it verifies against its own digest (keri-go);
//   - a registry inception names this issuer, and every other event belongs to
//     a registry whose inception is in held or in the batch;
//   - the issuer's key log seals exactly this event: the subject, the event's
//     number in its own log, and its digest;
//   - each credential's events chain: an issuance, then at most a revocation.
func AnchoredTEL(issuer string, kelRaw [][]byte, raws [][]byte, held []TELEvent) ([]TELEvent, error) {
	type sealKey struct {
		subject string
		sn      uint64
		said    string
	}
	anchors := map[sealKey]int{}
	for _, raw := range kelRaw {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
		}
		seals, _ := ev.Seals()
		for _, s := range seals {
			k := sealKey{s.Identifier, s.SN, s.SAID}
			if at, seen := anchors[k]; !seen || int(ev.SN) < at {
				anchors[k] = int(ev.SN)
			}
		}
	}

	known := map[string]TELEvent{} // by event identifier
	registries := map[string]bool{}
	for _, h := range held {
		known[h.SAID] = h
		if h.Ilk == "vcp" {
			registries[h.Registry] = true
		}
	}

	var fresh []TELEvent
	parsed := make([]TELEvent, 0, len(raws))
	for i, raw := range raws {
		if len(raw) == 0 || len(raw) > maxTELEventBytes {
			return nil, fmt.Errorf("registry event %d is empty or larger than any event is", i)
		}
		ev, err := keri.VerifyTELEvent(raw)
		if err != nil {
			return nil, fmt.Errorf("registry event %d does not verify: %w", i, err)
		}
		te := TELEvent{
			IssuerAID: issuer, SAID: ev.SAID, Registry: ev.Registry, Ilk: ev.Ilk, Subject: ev.Subject,
			SN: ev.SN, RawB64: base64.StdEncoding.EncodeToString(raw),
		}
		if ev.Ilk == "vcp" {
			var body struct {
				II string `json:"ii"`
			}
			if json.Unmarshal(raw, &body) != nil || body.II != issuer {
				return nil, fmt.Errorf("registry %s was not founded by %s", ev.Subject, issuer)
			}
			if ev.SN != 0 {
				return nil, fmt.Errorf("registry %s begins at %d, not 0", ev.Subject, ev.SN)
			}
			te.Registry = ev.Subject
		} else if ev.Ilk != "iss" && ev.Ilk != "rev" {
			return nil, fmt.Errorf("registry event %d is a %q, which a witness does not keep", i, ev.Ilk)
		}
		at, sealed := anchors[sealKey{te.Subject, uint64(te.SN), te.SAID}]
		if !sealed {
			return nil, fmt.Errorf("the key log of %s holds no seal of %s %s, so it is not the issuer's", issuer, ev.Ilk, ev.SAID)
		}
		te.AnchorSN = at
		parsed = append(parsed, te)
	}
	for _, te := range parsed {
		if te.Ilk == "vcp" {
			registries[te.Registry] = true
		}
	}
	// Per credential: the whole chain, held and new, must hold together.
	byCred := map[string][]TELEvent{}
	for _, h := range held {
		if h.Ilk != "vcp" {
			byCred[h.Subject] = append(byCred[h.Subject], h)
		}
	}
	for _, te := range parsed {
		if _, dup := known[te.SAID]; dup {
			continue
		}
		known[te.SAID] = te
		fresh = append(fresh, te)
		if te.Ilk == "vcp" {
			continue
		}
		if !registries[te.Registry] {
			return nil, fmt.Errorf("%s %s is in registry %s, whose inception by %s is not held", te.Ilk, te.SAID, te.Registry, issuer)
		}
		byCred[te.Subject] = append(byCred[te.Subject], te)
	}
	for subject, evs := range byCred {
		sort.Slice(evs, func(a, b int) bool { return evs[a].SN < evs[b].SN })
		chain := make([][]byte, 0, len(evs))
		for _, e := range evs {
			if e.Registry != evs[0].Registry {
				return nil, fmt.Errorf("the events of %s name two registries", subject)
			}
			raw, _ := base64.StdEncoding.DecodeString(e.RawB64)
			chain = append(chain, raw)
		}
		if _, err := keri.CredentialStatus(subject, chain); err != nil {
			return nil, fmt.Errorf("the events of %s do not hold together: %w", subject, err)
		}
	}
	return fresh, nil
}

// ReceiveTEL stores registry events an issuer it witnesses has made, each only
// after the key log held for that issuer is shown to seal it. It authors
// nothing. Returns how many events were new.
func (s *Service) ReceiveTEL(issuerAID string, rawB64 []string) (int, error) {
	if len(rawB64) == 0 || len(rawB64) > MaxTELEventsPerSubmission {
		return 0, fmt.Errorf("rejected: a submission is between 1 and %d events", MaxTELEventsPerSubmission)
	}
	kelRaw, err := s.heldKelRaw(issuerAID)
	if err != nil {
		return 0, err
	}
	raws := make([][]byte, 0, len(rawB64))
	for i, b := range rawB64 {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return 0, fmt.Errorf("rejected: registry event %d is not base64", i)
		}
		raws = append(raws, raw)
	}
	s.telMu.Lock()
	defer s.telMu.Unlock()
	held, err := s.Store.GetTELEvents(issuerAID)
	if err != nil {
		return 0, err
	}
	fresh, err := AnchoredTEL(issuerAID, kelRaw, raws, held)
	if err != nil {
		return 0, fmt.Errorf("rejected: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, ev := range fresh {
		ev.StoredAt = now
		if err := s.Store.StoreTELEvent(ev); err != nil {
			return 0, err
		}
	}
	return len(fresh), nil
}

// heldKelRaw is the key log this witness holds for an identity, as published.
// "not_witnessing" when none is held, which is also what an unwitnessed
// identity is told, so the route cannot be used to learn who is witnessed.
func (s *Service) heldKelRaw(aid string) ([][]byte, error) {
	kel, err := s.Store.GetKelEvents(aid)
	if err != nil {
		return nil, err
	}
	if len(kel) == 0 {
		return nil, fmt.Errorf("not_witnessing")
	}
	out := make([][]byte, 0, len(kel))
	for _, e := range kel {
		if e.RawBytesB64 == "" {
			continue // kept before bytes were: readable, cannot be checked
		}
		raw, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
		if err == nil {
			out = append(out, raw)
		}
	}
	return out, nil
}

// ServeTEL is the registry logs of an issuer, the events anchored after
// sinceSN in the issuer's key log (-1 for all), and how far this witness holds
// that key log. The events are exactly what the issuer published. "not_held"
// when this witness holds no key log for the issuer.
func (s *Service) ServeTEL(issuerAID string, sinceSN int) (TELAnswer, error) {
	last, err := s.Store.LastKelSeq(issuerAID)
	if err != nil {
		return TELAnswer{}, err
	}
	if n, _ := s.Store.CountKelEvents(issuerAID); n == 0 {
		return TELAnswer{}, fmt.Errorf("not_held")
	}
	all, err := s.Store.GetTELEvents(issuerAID)
	if err != nil {
		return TELAnswer{}, err
	}
	out := TELAnswer{IssuerAID: issuerAID, SinceSN: sinceSN, AnchoredSN: last, Events: []TELEvent{}}
	for _, ev := range all {
		if ev.AnchorSN > sinceSN {
			out.Events = append(out.Events, ev)
		}
	}
	return out, nil
}
