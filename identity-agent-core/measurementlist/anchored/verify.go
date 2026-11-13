package anchored

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/measurementlist"
)

// Floors are what this device already holds, and never goes below: the highest
// list sequence accepted and the hash (the credential's SAID) of the list
// accepted at it, and the newest place of the publisher's history it has held.
type Floors struct {
	ListSequence int64
	ListDigest   string
	// HasKeyHistory says KeyHistorySN and KeyHistorySAID are set.
	HasKeyHistory  bool
	KeyHistorySN   int
	KeyHistorySAID string
	// NewestPublishedAt is the newest published_at of any list accepted, in
	// seconds since the epoch (0: none). "Now" for every date check is never
	// earlier than it, so a host that sets its clock back cannot reopen an
	// expired list or a closed window.
	NewestPublishedAt int64
}

// NoEarlierThanTheFloor is now, or the newest published_at already accepted if
// that is later.
func (f Floors) NoEarlierThanTheFloor(now time.Time) time.Time {
	if f.NewestPublishedAt > now.Unix() {
		return time.Unix(f.NewestPublishedAt, 0).UTC()
	}
	return now
}

// Result is a verified list, and where the publisher's history stood when it
// was verified (the new key-history floor).
type Result struct {
	List           *measurementlist.List
	CredentialSAID string
	Tip            Tip
}

// logEvent is one event of the publisher's history as Verify reads it.
type logEvent struct {
	msg   []byte
	raw   []byte
	ilk   string
	sn    int
	said  string
	seals []seal
}

type seal struct{ i, s, d string }

type sealWire struct {
	I *string `json:"i"`
	S *string `json:"s"`
	D *string `json:"d"`
}

func hexSN(n int) string { return strconv.FormatInt(int64(n), 16) }

// readLog splits the messages into events and reads each one's event seals: an
// anchor that is exactly {i, s, d}, three strings (but see below). Any other anchor is data the
// identity keeps for its own purposes (who owns it, a handover's steps, the keys
// it is messaged at): it names no event of the registry, so it can neither
// withhold one nor vouch for one, and is not read. Every event seal, wherever
// it sits, must be matched by an event of the registry.
func readLog(msgs [][]byte, registry string) ([]logEvent, error) {
	out := make([]logEvent, 0, len(msgs))
	for n, m := range msgs {
		raw, err := keri.EventOfMessage(m)
		if err != nil {
			return nil, fmt.Errorf("%w: message %d: %v", ErrBadHistory, n, err)
		}
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: message %d: %v", ErrBadHistory, n, err)
		}
		le := logEvent{msg: m, raw: raw, ilk: ev.Ilk, sn: int(ev.SN), said: ev.SAID}
		if ev.SN != uint64(n) {
			return nil, fmt.Errorf("%w: message %d is at sequence %d", ErrBadHistory, n, ev.SN)
		}
		switch ev.Ilk {
		case "icp", "rot", "ixn":
		default:
			return nil, fmt.Errorf("%w: event %d is a %q, which a publisher's history does not hold", ErrBadHistory, n, ev.Ilk)
		}
		var body struct {
			A []json.RawMessage `json:"a"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("%w: event %d: %v", ErrBadHistory, n, err)
		}
		for _, a := range body.A {
			var generic map[string]json.RawMessage
			var w sealWire
			if json.Unmarshal(a, &generic) != nil || len(generic) != 3 || json.Unmarshal(a, &w) != nil ||
				w.I == nil || w.S == nil || w.D == nil {
				continue
			}
			// A seal of an identifier by itself at sequence 0 (the owner named at
			// founding, a credential issued outside any registry) seals no event of
			// the registry: an issuance's and a revocation's seals never have i
			// equal to d. The registry's own inception does, which is why the
			// registry is excepted.
			if *w.S == "0" && *w.I == *w.D && *w.I != registry {
				continue
			}
			le.seals = append(le.seals, seal{*w.I, *w.S, *w.D})
		}
		out = append(out, le)
	}
	return out, nil
}

// Verify accepts a list only if every requirement of the package holds. The
// replies are the witnesses' answers to the question just asked (freshness is
// a required input, so a caller cannot skip it), now is the time of this
// decision, and floors are what the device already holds.
func Verify(b *Bundle, pin Pin, replies []TipReply, floors Floors, now time.Time) (*Result, error) {
	return VerifyAsking(b, pin, func(string, []string, int) ([]TipReply, error) { return replies, nil }, floors, now)
}

// Asker asks the publisher's designated witnesses for their tip, now, and
// returns what came back. It is told whom to ask by the key history Verify has
// just validated, so the question cannot go to witnesses the history does not
// name. Each question must carry a fresh random nonce (Resolver does).
type Asker func(aid string, designated []string, threshold int) ([]TipReply, error)

// VerifyAsking is Verify for a caller that has no answers yet: freshness is
// still required, and the witnesses are asked only once the history has been
// found genuine, with the witnesses that history designates.
func VerifyAsking(b *Bundle, pin Pin, ask Asker, floors Floors, now time.Time) (*Result, error) {
	return VerifyAskingAlso(b, pin, ask, nil, floors, now)
}

// VerifyAskingAlso is VerifyAsking that also asks the person's peer watchers
// (peers may be nil: nobody else is asked). A peer's answer can only refuse a
// bundle, never vouch for one: see CheckPeers.
func VerifyAskingAlso(b *Bundle, pin Pin, ask Asker, peers PeerAsker, floors Floors, now time.Time) (*Result, error) {
	if ask == nil {
		return nil, fmt.Errorf("%w: nobody to ask", ErrNotFresh)
	}
	if err := pin.check(); err != nil {
		return nil, err
	}
	if b == nil || b.Publisher != pin.Publisher || b.Registry != pin.Registry {
		return nil, ErrWrongPublisher
	}
	if len(b.KEL) == 0 {
		return nil, fmt.Errorf("%w: no key history", ErrMalformed)
	}

	// 2. The history is genuine.
	if !bytes.HasPrefix(b.KEL[0], pin.InceptionEvent) {
		return nil, fmt.Errorf("%w: its inception is not the pinned one", ErrWrongPublisher)
	}
	res, err := keri.ValidateSignedKEL(b.KEL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadHistory, err)
	}
	if res.Identifier != pin.Publisher {
		return nil, ErrWrongPublisher
	}
	log, err := readLog(b.KEL, pin.Registry)
	if err != nil {
		return nil, err
	}

	// 4. Witnessed: the identity has witnesses and every event has its threshold
	// of them. An identity with none is "fully witnessed" to the library, and
	// would then be vouched for by nobody.
	for i, w := range res.Witnessing {
		if len(w.Witnesses) == 0 || w.Threshold < 1 || !w.Met {
			return nil, fmt.Errorf("%w: event %d", ErrNotWitnessed, i)
		}
	}

	// 1. Fresh: where the witnesses say the history ends.
	last := res.Witnessing[len(res.Witnessing)-1]
	replies, err := ask(pin.Publisher, last.Witnesses, int(last.Threshold))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotFresh, err)
	}
	tip, err := AgreedTip(pin.Publisher, last.Witnesses, int(last.Threshold), replies)
	if err != nil {
		return nil, err
	}
	have := log[len(log)-1]
	switch {
	case have.sn < tip.SN:
		return nil, fmt.Errorf("%w: it ends at %d and the witnesses hold %d", ErrBehind, have.sn, tip.SN)
	case have.sn > tip.SN:
		return nil, fmt.Errorf("%w: it ends at %d and the witnesses hold %d", ErrAhead, have.sn, tip.SN)
	case have.said != tip.SAID:
		return nil, &Duplicity{SN: tip.SN, Held: tip.SAID, Offered: have.said, Message: have.msg}
	}

	// ... and no contact of the person's holds more of it, or other.
	if peers != nil {
		if err := checkPeers(log, peers(pin.Publisher)); err != nil {
			return nil, err
		}
	}

	// ... and extends what this device already holds.
	if floors.HasKeyHistory {
		if floors.KeyHistorySN < 0 || floors.KeyHistorySAID == "" {
			return nil, fmt.Errorf("%w: the key-history floor this device holds is not a place", ErrMalformed)
		}
		if floors.KeyHistorySN >= len(log) {
			return nil, fmt.Errorf("%w: this device has seen it as far as %d", ErrBehind, floors.KeyHistorySN)
		}
		if log[floors.KeyHistorySN].said != floors.KeyHistorySAID {
			return nil, &Duplicity{SN: floors.KeyHistorySN, Held: floors.KeyHistorySAID,
				Offered: log[floors.KeyHistorySN].said, Message: log[floors.KeyHistorySN].msg}
		}
	}

	// 3. The anchor: every TEL event, sealed; every seal, matched.
	type placed struct {
		ev  *keri.TELEvent
		pos int // the KEL event that seals it
	}
	sealAt := map[seal]int{}
	for _, le := range log {
		for _, s := range le.seals {
			if _, dup := sealAt[s]; dup {
				return nil, fmt.Errorf("%w: a seal appears twice", ErrForeignSeal)
			}
			sealAt[s] = le.sn
		}
	}
	var events []placed
	matched := map[seal]bool{}
	for i, raw := range b.TEL {
		ev, err := keri.VerifyTELEvent(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: event %d: %v", ErrBadTEL, i, err)
		}
		s := seal{ev.Subject, hexSN(ev.SN), ev.SAID}
		pos, ok := sealAt[s]
		if !ok {
			return nil, fmt.Errorf("%w: %s event %d", ErrUnsealed, ev.Ilk, i)
		}
		if matched[s] {
			return nil, fmt.Errorf("%w: an event appears twice", ErrBadTEL)
		}
		matched[s] = true
		events = append(events, placed{ev, pos})
	}
	for s := range sealAt {
		if !matched[s] {
			return nil, fmt.Errorf("%w: a seal for %s at %s", ErrWithheld, s.i, s.s)
		}
	}

	// the registry
	var vcp *placed
	for i := range events {
		if events[i].ev.Ilk == "vcp" {
			if vcp != nil {
				return nil, fmt.Errorf("%w: more than one registry inception", ErrBadRegistry)
			}
			vcp = &events[i]
		}
	}
	if vcp == nil {
		return nil, fmt.Errorf("%w: no registry inception", ErrBadRegistry)
	}
	if vcp.ev.SAID != pin.Registry || vcp.ev.Issuer != pin.Publisher || vcp.ev.SN != 0 ||
		len(vcp.ev.Traits) != 1 || vcp.ev.Traits[0] != "NB" || len(vcp.ev.Backers) != 0 || vcp.ev.BackerThreshold != "0" {
		return nil, ErrBadRegistry
	}

	// each credential's own log, in the order the history sealed it
	type chain struct{ iss, rev *placed }
	chains := map[string]*chain{}
	var order []string
	for i := range events {
		ev := &events[i]
		if ev.ev.Ilk == "vcp" {
			continue
		}
		if ev.ev.Registry != pin.Registry {
			return nil, fmt.Errorf("%w: an event of another registry", ErrBadTEL)
		}
		if ev.pos <= vcp.pos {
			return nil, fmt.Errorf("%w: an event is sealed before the registry exists", ErrBadTEL)
		}
		c := chains[ev.ev.Subject]
		if c == nil {
			c = &chain{}
			chains[ev.ev.Subject] = c
			order = append(order, ev.ev.Subject)
		}
		switch {
		case ev.ev.Ilk == "iss" && ev.ev.SN == 0 && c.iss == nil:
			c.iss = ev
		case ev.ev.Ilk == "rev" && ev.ev.SN == 1 && c.rev == nil:
			c.rev = ev
		default:
			return nil, fmt.Errorf("%w: a credential's log is out of shape", ErrBadTEL)
		}
	}
	creds := map[string]*keri.Credential{}
	for i, raw := range b.Credentials {
		c, err := keri.VerifyCredential(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: credential %d: %v", ErrBadList, i, err)
		}
		if c.Issuer != pin.Publisher || c.SchemaSAID != pin.SchemaSAID || c.Registry != pin.Registry ||
			c.Recipient != "" || c.Salt != "" || len(c.Edges) != 0 || len(c.Rules) != 0 {
			return nil, fmt.Errorf("%w: credential %d", ErrBadList, i)
		}
		if _, dup := creds[c.SAID]; dup {
			return nil, fmt.Errorf("%w: a credential appears twice", ErrBadList)
		}
		creds[c.SAID] = c
	}

	// 5, 6. Which list is the newest not withdrawn.
	var newest *keri.Credential
	newestPos := -1
	for _, id := range order {
		c := chains[id]
		if c.iss == nil {
			return nil, fmt.Errorf("%w: a withdrawal with no issuance", ErrBadTEL)
		}
		cred, ok := creds[id]
		if !ok {
			return nil, fmt.Errorf("%w: the credential for an issuance is not in the bundle", ErrWithheld)
		}
		telEvents := [][]byte{c.iss.ev.Raw}
		if c.rev != nil {
			if c.rev.pos <= c.iss.pos || c.rev.ev.Prior != c.iss.ev.SAID {
				return nil, fmt.Errorf("%w: a withdrawal that does not follow its issuance", ErrBadTEL)
			}
			telEvents = append(telEvents, c.rev.ev.Raw)
		}
		status, err := keri.CredentialStatus(id, telEvents)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadTEL, err)
		}
		if status == keri.StatusRevoked {
			continue
		}
		if c.iss.pos > newestPos {
			newest, newestPos = cred, c.iss.pos
		}
	}
	for id := range creds {
		if chains[id] == nil {
			return nil, fmt.Errorf("%w: a credential no issuance covers", ErrUnsealed)
		}
	}
	if newest == nil {
		return nil, ErrNoList
	}

	// 7. The content, held to the rules of a signed list.
	content, err := measurementlist.ContentOfAttributes(newest.Attributes)
	if err != nil {
		return nil, err
	}
	list, err := measurementlist.FromContent(content, newest.SAID, measurementlist.Rules{
		MinSequence: floors.ListSequence, SeenDigest: floors.ListDigest, Now: floors.NoEarlierThanTheFloor(now)})
	if err != nil {
		return nil, err
	}
	return &Result{List: list, CredentialSAID: newest.SAID, Tip: tip}, nil
}

// PeerTip is what one of the person's peer watchers says it holds of the
// publisher's key history: the newest place it has seen and that event's SAID
// (SN -1 and empty: it holds nothing). It is a claim by a contact, not a
// signed answer of the publisher's witnesses.
type PeerTip struct {
	Peer string
	SN   int
	SAID string
}

// PeerAsker asks the person's peer watchers for the publisher's tip.
type PeerAsker func(publisher string) []PeerTip

// checkPeers is the second source of "what is the latest state". The witnesses
// the bundle's own history names are the only ones the checker can ask, so a
// device whose floor predates a rotation that replaced every one of them can be
// served a stale bundle, and answered by witnesses whose keys are retired: no
// check of the bundle can see that (a limit of KERI, ADR-078). A peer that
// holds more of the history, or another event at a place the bundle holds,
// shows it. A peer that holds nothing, or less, says nothing and is ignored:
// it may never have been asked to watch the publisher.
//
// A peer's word refuses and never accepts. A contact that lies can make a
// device refuse a list (and is asked again later); it cannot make it take one.
func checkPeers(log []logEvent, tips []PeerTip) error {
	have := log[len(log)-1]
	for _, t := range tips {
		switch {
		case t.SN < 0 || t.SAID == "":
		case t.SN > have.sn:
			return fmt.Errorf("%w: a contact of yours holds the publisher's history to place %d and the bundle ends at %d", ErrBehind, t.SN, have.sn)
		case log[t.SN].said != t.SAID:
			return &Duplicity{SN: t.SN, Held: t.SAID, Offered: log[t.SN].said, Message: log[t.SN].msg}
		}
	}
	return nil
}
