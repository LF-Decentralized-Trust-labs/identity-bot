package witness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
// FRESHNESS. LatestKelSN is how far through the issuer's key log this witness
// holds. Every event of the log anchored at or before it that the issuer gave
// this witness is in the answer. A reader holding the key log further on than
// that knows this witness is behind, and one holding a seal that no served
// event answers knows an event is being kept back.

// TELAnswer is what a witness says about an issuer's registry logs
// (SEAM-13 §2). It is the wire form: Events are the KERI TEL events exactly as
// the issuer published them (t, d, ri, i, dt, and p for a revocation), so a
// reader hands each one to its own KERI library and needs nothing of ours.
//
//   - AID is the issuer.
//   - RegistryPrefix is the issuer's registry. An issuer with several has them
//     all in Registries, in the order they were founded, and RegistryPrefix is
//     the first, which never changes as more are founded; each event names its
//     own registry in "ri". Registries is left out when there is only one, so
//     the common answer is exactly the contract's shape.
//   - Events are those anchored after the since_sn asked for (-1, or none given,
//     is all of them), including each registry's inception, which is what makes
//     the registry the issuer's.
//   - AnchoredSN is the issuer's key-log position of the latest event held in
//     the log, whatever since_sn asked: the place the registry log is held to.
//   - LatestKelSN is how far this witness holds the issuer's key log. A reader
//     holding the key log further on than this knows the witness is behind.
type TELAnswer struct {
	AID            string            `json:"aid"`
	RegistryPrefix string            `json:"registry_prefix"`
	Registries     []string          `json:"registries,omitempty"`
	Events         []json.RawMessage `json:"events"`
	AnchoredSN     int               `json:"anchored_sn"`
	LatestKelSN    int               `json:"latest_kel_sn"`
}

// TELHead is the short form of an answer (SEAM-13 §2): where the log is held
// to and the digest of the latest event, enough to learn whether anything is
// new without fetching it. EventDigest is the identifier of the most recently
// anchored event held. Provisional with the seam's OQ-2.
type TELHead struct {
	AnchoredSN  int    `json:"anchored_sn"`
	LatestKelSN int    `json:"latest_kel_sn"`
	EventDigest string `json:"event_digest"`
}

// ErrNoTEL is a witness holding no registry log for the issuer asked about
// (SEAM-13 §5 T-1). The route answers 404 {"error":"no_tel"}.
var ErrNoTEL = errors.New("no_tel")

// ErrBadSubmission is a registry-event submission that is wrong whoever it is
// for and whether or not this witness holds a log for the issuer: no events,
// too many, or not base64. ErrTELNotAccepted is every other way a submission
// can fail, which is the same answer for an issuer this witness holds no log
// for and for one it does (a route open to anybody must not say which
// identities a witness witnesses).
var (
	ErrBadSubmission  = errors.New("bad submission")
	ErrTELNotAccepted = errors.New("not accepted")
)

// NotAnchoredError is an event the issuer's key log does not seal: the
// evidence that whoever supplied it is not the issuer's witness-held record
// (SEAM-13 §5 T-3). It is a different thing from an event that is malformed, or
// from an answer from a witness behind the key log.
type NotAnchoredError struct {
	Issuer, Ilk, SAID string
}

func (e *NotAnchoredError) Error() string {
	return fmt.Sprintf("the key log of %s holds no seal of %s %s, so it is not the issuer's", e.Issuer, e.Ilk, e.SAID)
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
//   - the issuer's key log seals exactly this event, in an interaction (ixn)
//     event and no other kind: the subject, the event's
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
		if ev.Ilk != "ixn" {
			// KERI lets any event carry seals in "a" (keripy reads a TEL
			// anchor from a rotation too), so the protocol does not require
			// ixn here. This contract does: every registry event is sealed by
			// an interaction (the engine's IxnRawBytesB64), and accepting a seal
			// from an establishment event would let a rotation's data field
			// vouch for a registry event no issuer of ours writes there.
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
			return nil, &NotAnchoredError{Issuer: issuer, Ilk: ev.Ilk, SAID: ev.SAID}
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
		return 0, fmt.Errorf("%w: a submission is between 1 and %d events", ErrBadSubmission, MaxTELEventsPerSubmission)
	}
	// Everything that does not depend on what this witness holds is checked
	// before anything that does.
	raws := make([][]byte, 0, len(rawB64))
	for i, b := range rawB64 {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return 0, fmt.Errorf("%w: registry event %d is not base64", ErrBadSubmission, i)
		}
		raws = append(raws, raw)
	}
	kelRaw, err := s.heldKelRaw(issuerAID)
	if err != nil {
		if err.Error() == "not_witnessing" {
			return 0, ErrTELNotAccepted
		}
		return 0, err
	}
	s.telMu.Lock()
	defer s.telMu.Unlock()
	held, err := s.Store.GetTELEvents(issuerAID)
	if err != nil {
		return 0, err
	}
	fresh, err := AnchoredTEL(issuerAID, kelRaw, raws, held)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrTELNotAccepted, err)
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

// ServeTEL is the registry logs of an issuer: the events anchored after
// sinceSN in the issuer's key log (-1 for all), and how far this witness holds
// that key log. The events are exactly what the issuer published. ErrNoTEL when
// this witness holds no registry log for the issuer.
func (s *Service) ServeTEL(issuerAID string, sinceSN int) (TELAnswer, error) {
	all, err := s.Store.GetTELEvents(issuerAID)
	if err != nil {
		return TELAnswer{}, err
	}
	if len(all) == 0 {
		return TELAnswer{}, ErrNoTEL
	}
	last, err := s.Store.LastKelSeq(issuerAID)
	if err != nil {
		return TELAnswer{}, err
	}
	out := TELAnswer{AID: issuerAID, LatestKelSN: last, Events: []json.RawMessage{}}
	seen := map[string]bool{}
	for _, ev := range all {
		if ev.AnchorSN > out.AnchoredSN {
			out.AnchoredSN = ev.AnchorSN
		}
		if ev.Ilk == "vcp" && !seen[ev.Registry] {
			seen[ev.Registry] = true
			out.Registries = append(out.Registries, ev.Registry)
		}
		if ev.AnchorSN <= sinceSN {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(ev.RawB64)
		if err != nil || !json.Valid(raw) {
			return TELAnswer{}, fmt.Errorf("a held registry event is unreadable")
		}
		out.Events = append(out.Events, json.RawMessage(raw))
	}
	if len(out.Registries) > 0 {
		out.RegistryPrefix = out.Registries[0]
	} else {
		out.RegistryPrefix = all[0].Registry
	}
	if len(out.Registries) < 2 {
		out.Registries = nil
	}
	return out, nil
}

// ServeTELHead is where an issuer's registry log is held to, and the digest of
// the latest event in it. ErrNoTEL when none is held.
func (s *Service) ServeTELHead(issuerAID string) (TELHead, error) {
	all, err := s.Store.GetTELEvents(issuerAID)
	if err != nil {
		return TELHead{}, err
	}
	if len(all) == 0 {
		return TELHead{}, ErrNoTEL
	}
	last, err := s.Store.LastKelSeq(issuerAID)
	if err != nil {
		return TELHead{}, err
	}
	tip := all[len(all)-1] // in the order of the key-log events that anchor them
	return TELHead{AnchoredSN: tip.AnchorSN, LatestKelSN: last, EventDigest: tip.SAID}, nil
}

// PublishTEL sends registry events this agent made, in the order they were
// made, to each of the witnesses its key log names (designated, by witness
// key). It is how an outside verifier comes to find them (SEAM-13 §3).
//
// A witness stores an event only if the key log it holds seals it, and refuses
// a batch with any event it cannot place, so a witness that has not yet been
// given the key-log event that anchors the first refuses the whole batch. The
// batch is therefore tried whole and, if refused, one event at a time in order
// until the first refusal, so what can be placed is and a single bad event
// does not hold back the ones before it.
//
// Returns how many of the designated witnesses now hold every event. A
// designated witness this agent has no address for counts as not holding them.
func (s *Service) PublishTEL(ctx context.Context, issuerAID string, raws [][]byte, designated []string) (held int, err error) {
	if len(raws) == 0 || len(designated) == 0 {
		return 0, nil
	}
	rootAID := issuerAID
	if id, _ := s.Contacts.GetIdentity(); id != nil {
		rootAID = id.AID
	}
	targets, err := s.witnessesToReach(ClassifyAID(issuerAID, rootAID), issuerAID, designated)
	if err != nil {
		return 0, err
	}
	want := map[string]bool{}
	for _, k := range designated {
		want[k] = true
	}
	encoded := make([]string, 0, len(raws))
	for _, r := range raws {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(r))
	}
	send := func(t witnessTarget, evs []string) error {
		body, _ := json.Marshal(map[string]interface{}{"events": evs})
		url := witnessBase(t.URL) + witnessPathPrefix(t.Commercial) + "/witness/tel/" + issuerAID
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, err := s.PostEvent(s.ownersLocalAllowed(cctx, url), url, body)
		return err
	}
	var lastErr error
	for _, t := range targets {
		if t.WitnessKey == "" || !want[t.WitnessKey] {
			continue
		}
		delete(want, t.WitnessKey)
		complete := true
		for from := 0; from < len(encoded) && complete; from += MaxTELEventsPerSubmission {
			to := from + MaxTELEventsPerSubmission
			if to > len(encoded) {
				to = len(encoded)
			}
			if err := send(t, encoded[from:to]); err == nil {
				continue
			} else {
				lastErr = err
			}
			// Refused as a batch: place what can be placed, in order.
			for _, one := range encoded[from:to] {
				if e := send(t, []string{one}); e != nil {
					lastErr, complete = e, false
					break
				}
			}
		}
		if complete {
			held++
		}
	}
	if held < len(designated) && lastErr == nil {
		lastErr = fmt.Errorf("no address is known for %d of the %d witnesses", len(want), len(designated))
	}
	return held, lastErr
}
