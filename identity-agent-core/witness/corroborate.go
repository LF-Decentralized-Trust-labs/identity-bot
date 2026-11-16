package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/internal/boundedread"
)

// Asking somebody other than the claimant whether a presented key log is the
// whole history, the way KERI does.
//
// Checking a presented key log establishes authorship: every event is signed by
// the key the log itself puts in force. What it cannot establish is that the
// log is COMPLETE. A log is a chain, and a chain with its last link removed is
// still a valid chain, so somebody who rotated away from a key and kept the
// rotation to themselves can present the earlier log and sign with the old
// key. Everything verifies; the identity has moved on and the verifier cannot
// tell.
//
// Two things close it, and KERI uses both:
//
//   - RECEIPTS. Each establishment event must carry receipts, signed over the
//     event's bytes, from at least as many of the witnesses in force at that
//     event as it set as its threshold (bt, "toad"), tracking br and ba across
//     rotations. This is what shows the event was witnessed at all. It cannot
//     show the event is the LAST one: every receipt a witness ever issued stays
//     valid for ever.
//   - A LIVE ANSWER SIGNED BY THE WITNESS. A designated witness is asked now
//     how far it holds the log, and the answer is believed only as a key state
//     notice (the reply /ksn/{witness}, see KeyStateRoute) dated now and signed by
//     the witness's own key. A witness holding more than was presented, or a
//     different event at a place, is the withheld rotation or a fork. An answer
//     anybody could have typed (the key log over plain HTTP) is not evidence
//     either way, so nothing here rests on one.
//
// WHY THE CLAIMANT'S OWN ADDRESS IS NOT ENOUGH. The OOBI in a claim names the
// claimant's own Identity Agent, so somebody withholding a rotation from the presented
// copy would withhold it from the served copy too.
//
// WHERE A WITNESS IS FOUND. An event designates a witness by its key,
// deliberately, so a receipt can be checked without resolving the witness's own
// history. A key is not an address. The registry of witness operators
// (BootstrapWitness) says where to ask, as a hint only: the witness's own
// signed /loc/scheme reply is read from there (VerifyWitnessLocation) and
// decides where it is reached, and whatever then answers must sign as the
// witness's key. A server at a registered address that is not the witness
// cannot, so it is ignored. A wrong address can only fail to answer; it cannot
// lie.
//
// This is used by the Identity Agent when it checks a claim, and by anybody
// outside the core who has to answer the same question (a verifier of a founded
// organisation), so there is one implementation of it.

// Corroboration is what asking the witnesses established.
type Corroboration struct {
	// Asked is how many designated witnesses gave a signed, current key state
	// notice for the identifier.
	Asked int
	// Held is how many of those state the presented log's newest event as
	// theirs: the same place, the same digest. Only these corroborate.
	Held int
	// Empty is how many answered, signed, that they hold nothing for this
	// identifier, as a witness does for one it has never seen. Reachable is not
	// confirming.
	Empty int
	// Behind is how many answered, signed, with some of the history but less
	// than was claimed.
	Behind int
	// Failed is how many designated witnesses could not be asked: no address
	// for the key, no answer, or an answer not signed by that key.
	Failed int
	// Designated is how many the log names at all.
	Designated int
	// Required is how many witnesses must hold the newest event: the
	// threshold the log's last establishment event set, and at least one.
	Required int
	// ReceiptsMet is whether every establishment event of the presented log
	// has receipts, from the witnesses in force at it, to its threshold.
	ReceiptsMet bool
	// Unreceipted lists the places of the establishment events that fall short
	// (or whose witness list cannot be read), in order.
	Unreceipted []int
	// Contradicted means a witness holds a longer history than the one
	// presented (the withheld-rotation case), a different event where one was
	// presented (a fork), or a validly signed second event at a place of the
	// presented log (duplicity, see SignedRivals).
	Contradicted bool
	// Why explains a contradiction, for the refusal message.
	Why string
	// Unverified is why the presented log was not even asked about: it is not a
	// signed key log (an event whose signature does not verify, a chain that does
	// not hold) or it is the log of an identifier other than ownerAID. Nothing a
	// witness says can corroborate a log that is not a log of that identifier.
	Unverified string
	// Answers is one entry per designated witness that was asked, in the order
	// the log designates them, so a caller can check what each one holds
	// further than this does. A witness that could not be asked is not here
	// (it is counted in Failed).
	Answers []WitnessAnswer
}

// WitnessAnswer is one designated witness's reply.
type WitnessAnswer struct {
	// Key is the designated witness key, and URL the address that answered.
	Key, URL string
	// State is the witness's signed key state notice.
	State witnessproto.KeyState
	// Shown is the event the witness handed over when its notice stated more
	// than was presented, or another event at a place of it: what that notice is
	// believed by (see corroborateThrough). Nil when the notice stated no such
	// thing.
	Shown map[string]interface{}
	// Replica is the log the witness serves for the identifier. It is what the
	// witness says, unsigned; it is read only for receipts (which prove
	// themselves) and for the conflicting events below, never as a statement
	// of what the witness holds.
	Replica []map[string]interface{}
	// Conflicting is what the witness kept as evidence that the identity
	// signed two different events at one place (duplicity), as the witness
	// served it. It is not believed as served: a validly signed rival among
	// it is a contradiction, and the rest is reported in Ignored.
	Conflicting []map[string]interface{}
	// Ignored is how many of the entries in Conflicting were not a validly
	// signed second event at a place of the presented log (see
	// SignedRivals), and so counted for nothing.
	Ignored int
}

// Corroborated is the question a caller actually wants answered: the log is
// receipted to its threshold at every establishment event, at least as many
// witnesses as that threshold say, signed and now, that the newest event is
// theirs, and none contradicts it.
//
// A witness that is reachable but holds nothing confirms nothing, so it is the
// witnesses that hold the newest event that count, not the ones that answered.
func (c Corroboration) Corroborated() bool {
	return c.Unverified == "" && c.ReceiptsMet && c.Required > 0 && c.Held >= c.Required && !c.Contradicted
}

// WitnessKeysIn reads the witness keys an inception event designates.
//
// KERI's `b` field, on the establishment event. Absent or empty means the
// identity named no witnesses, which is a real answer: nobody was ever asked to
// watch, so nobody can be asked now.
func WitnessKeysIn(kel []map[string]interface{}) []string {
	// From the verified bytes, never from event_json text beside them: that
	// text is not covered by the check on the claim, and blanking its "b" would
	// otherwise leave nobody to ask.
	ev, _, ok := InceptionOf(kel)
	if !ok {
		return nil
	}
	raw, _ := ev["b"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if k, _ := v.(string); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// Corroborate checks a presented log, itself and as the log of ownerAID (Corroboration.Unverified says if it is not), against the witnesses in force at its end, each found by its designated key (pool is the registry of
// witness operators: BootstrapPool() in the Identity Agent, or the registry a
// verifier loads, and gives only a place to start looking). client may be nil.
//
// Failure to reach a witness is NOT a contradiction. A witness that is down,
// or that this machine has no route to, leaves the history uncorroborated,
// which is a different answer from refuted; the caller decides what to do about
// it. Conflating the two would make every network fault look like an attack.
func Corroborate(client *http.Client, pool []BootstrapWitness, ownerAID string, presented []map[string]interface{}) Corroboration {
	return CorroborateThrough(client, pool, ownerAID, presented, WitnessKeysInForce(presented))
}

// WitnessKeysInForce reads the witness keys in force at the end of a presented
// log: the inception's, changed by each rotation's cuts and adds (br, ba). These
// are the witnesses to ask now, and the ones whose answers the threshold of the
// last establishment event counts. A log whose witness list cannot be followed
// to its end falls back to the inception's.
func WitnessKeysInForce(presented []map[string]interface{}) []string {
	rebuilt, ok := drivers.RecordsFromVerifiedBytes(presented)
	if !ok || len(rebuilt) == 0 {
		return WitnessKeysIn(presented)
	}
	in, ok := drivers.ValidateKELInputFromRecords("", rebuilt)
	if !ok {
		return WitnessKeysIn(presented)
	}
	var held []string
	for _, raw := range in.RawEvents {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return WitnessKeysIn(presented)
		}
		held, _ = drivers.WitnessesAfter(held, ev)
	}
	return held
}

// CorroborateThrough is Corroborate for a caller that has worked out which
// witnesses are in force from the whole log (after rotations) rather than from
// the inception alone. keys are witness keys, and are resolved the same way.
func CorroborateThrough(client *http.Client, pool []BootstrapWitness, ownerAID string, presented []map[string]interface{}, keys []string) Corroboration {
	return corroborateThrough(client, pool, ownerAID, presented, keys, time.Now())
}

// corroborationDeadline is how long all the witnesses together are given to
// answer. They are asked at once, so a few that never answer cost this once, not
// once each; a witness that has not answered by then has failed to answer.
var corroborationDeadline = 20 * time.Second

// maxWitnessesAsked bounds how many witnesses one check asks. A key log names its
// own witnesses (and a caller of CorroborateThrough chooses them), so without a
// bound a log naming thousands would make thousands of requests per claim. Real
// logs name a handful; any beyond this are counted as not answering.
const maxWitnessesAsked = 64

// witnessTimeout is how long one request to one witness may take when the caller
// gave no client of its own.
const witnessTimeout = 8 * time.Second

// oneWitnessAnswer is what asking one designated witness produced.
type oneWitnessAnswer struct {
	base        string
	state       witnessproto.KeyState
	shown       map[string]interface{}
	replica     []map[string]interface{}
	conflicting []map[string]interface{}
	err         error
}

// A notice that states a longer history than was presented, or another event at a
// place of it, is a claim and no more: any witness can type one. It becomes a
// contradiction when the witness shows an event that is validly signed by the
// identity's own keys, which a witness cannot make. departure is the place of the
// event to ask for, or -1 when the notice departs from nothing.
func departure(state witnessproto.KeyState, presented []map[string]interface{}) int {
	tip := len(presented) - 1
	switch {
	case state.SN > tip:
		return tip + 1
	case state.SN >= 0 && state.SAID != eventDigestOf(presented[state.SN]):
		return state.SN
	}
	return -1
}

// signedKeyLog is the presented log as a verified signed key log, and why it is not
// one when it is not: it must verify, and be the log of ownerAID.
func signedKeyLog(ownerAID string, presented []map[string]interface{}) (*keri.SignedKELResult, string) {
	msgs, err := drivers.SignedMessagesFromRecords(presented)
	if err != nil {
		return nil, "the presented log cannot be checked as a signed key log: " + err.Error()
	}
	log, err := keri.ValidateSignedKEL(msgs)
	if err != nil {
		return nil, "the presented log is not a valid signed key log: " + err.Error()
	}
	if log.Identifier != ownerAID {
		return nil, fmt.Sprintf("the presented log is the log of %s, not of %s", log.Identifier, ownerAID)
	}
	return log, ""
}

// showsLongerHistory is whether rec is a validly signed event that follows the
// presented log's newest event: what a witness holding more of the log than was
// presented can show, and what one that only says so cannot.
func showsLongerHistory(log *keri.SignedKELResult, tip int, rec map[string]interface{}) bool {
	if rec == nil {
		return false
	}
	msgs, err := drivers.SignedMessagesFromRecords([]map[string]interface{}{rec})
	if err != nil || len(msgs) != 1 {
		return false
	}
	ev, err := keri.ParseEvent(msgs[0])
	if err != nil || ev.Identifier != log.Identifier || ev.SN != uint64(tip+1) {
		return false
	}
	_, err = keri.VerifyEvent(log.StateAt(uint64(tip)), msgs[0])
	return err == nil
}

func corroborateThrough(client *http.Client, pool []BootstrapWitness, ownerAID string, presented []map[string]interface{}, keys []string, now time.Time) Corroboration {
	carried := receiptsCarriedBy(presented)
	// Rebuilt from the bytes the verdict on the claim covers, so nothing served
	// beside them (a top-level "d", event_json) can say what the claim shows. A
	// log that cannot be rebuilt was not verified by its bytes and cannot be
	// corroborated.
	rebuilt, ok := drivers.RecordsFromVerifiedBytes(presented)
	// Each witness once: asking one twice must not count it twice.
	seen := map[string]bool{}
	var distinct []string
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			distinct = append(distinct, k)
		}
	}
	keys = distinct
	out := Corroboration{Designated: len(keys)}
	if !ok || len(rebuilt) == 0 {
		out.Unverified = "the presented log carries no signed bytes, so it cannot be checked"
		return out
	}
	presented = rebuilt
	// The log is checked here, not left to the caller: this is the function an
	// outside verifier calls, and a witness's confirmation of a log nobody
	// checked, or of another identifier's, confirms nothing.
	log, why := signedKeyLog(ownerAID, presented)
	if log == nil {
		out.Unverified = why
		return out
	}
	if len(keys) == 0 {
		return out
	}
	tip := len(presented) - 1
	tipSAID := eventDigestOf(presented[tip])
	receipts := carried

	// All the witnesses at once, under one deadline.
	ctx, cancel := context.WithTimeout(context.Background(), corroborationDeadline)
	defer cancel()
	answers := make([]oneWitnessAnswer, len(keys))
	var wg sync.WaitGroup
	for i, key := range keys {
		if i >= maxWitnessesAsked {
			answers[i] = oneWitnessAnswer{err: fmt.Errorf("more witnesses than are asked at once")}
			continue
		}
		wg.Add(1)
		go func(i int, key string) {
			defer wg.Done()
			answers[i] = askWitness(ctx, client, pool, key, ownerAID, presented, now)
		}(i, key)
	}
	wg.Wait()

	for i, key := range keys {
		a := answers[i]
		if a.err != nil {
			out.Failed++
			continue
		}
		state := a.state
		rivals, ignored := SignedRivals(presented, a.conflicting)
		// A notice stating more, or another event, counts only with the event it
		// states. Without it the witness has said something and shown nothing, so
		// it has not answered; it cannot refuse a claim by typing a number.
		departs := departure(state, presented) >= 0
		shownLonger := state.SN > tip && showsLongerHistory(log, tip, a.shown)
		shownRival := state.SN >= 0 && state.SN <= tip && state.SAID != eventDigestOf(presented[state.SN]) &&
			a.shown != nil && isSignedRival(log, a.shown)
		if departs && rivals == 0 && !shownLonger && !shownRival {
			out.Failed++
			continue
		}
		out.Asked++
		out.Answers = append(out.Answers, WitnessAnswer{Key: key, URL: a.base, State: state, Shown: a.shown,
			Replica: a.replica, Conflicting: a.conflicting, Ignored: ignored})
		for _, rec := range a.replica {
			if said := eventDigestOf(rec); said != "" {
				receipts[said] = append(receipts[said], receiptsOf(rec, i+1)...)
			}
		}

		// DUPLICITY. A witness that kept a second, different event at a place
		// the identity had already used is holding proof the identity signed two
		// histories. That is the one thing a witness is for (ADR-031). It is
		// proof only when the second event is validly signed: anything else a
		// witness hands back (garbage, the held event itself, an event signed
		// by a key already rotated away from) proves nothing, and a witness
		// that is broken or hostile must not be able to refuse an honest claim
		// by sending it.
		if rivals > 0 {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness holds %d validly signed conflicting event(s) for %s: evidence that identity signed two different histories",
				rivals, ownerAID)
			return out
		}
		// A witness showing a validly signed event beyond the presented log is
		// the withheld rotation: the claimant showed a prefix and signed with a
		// key the identity has moved on from.
		if shownLonger {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness states it holds %d events for %s and shows the event after the %d the claim "+
					"presented, validly signed, so the claim is signed against a history that identity has already moved on from",
				state.SN+1, ownerAID, len(presented))
			return out
		}
		// A validly signed different event where the claim shows one is a fork,
		// not a confirmation.
		if shownRival {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness shows a validly signed different event %d for %s than the claim presented", state.SN, ownerAID)
			return out
		}
		switch {
		case state.SN < 0:
			out.Empty++
		case state.SN < tip:
			out.Behind++
		case state.SAID == tipSAID:
			out.Held++
		}
	}

	out.ReceiptsMet, out.Unreceipted, out.Required = receiptsToThreshold(ownerAID, presented, receipts)
	if out.Required < 1 {
		out.Required = 1
	}
	return out
}

// askWitness finds one witness and asks it, as one step so that all of them can
// be asked at once: the registry hint, the witness's signed location, its signed
// key state notice, the copy of the log it serves (read only for what proves
// itself), and, when its notice departs from the presented log, the event it
// states.
func askWitness(ctx context.Context, client *http.Client, pool []BootstrapWitness, key, ownerAID string, presented []map[string]interface{}, now time.Time) oneWitnessAnswer {
	hint := ""
	for _, b := range pool {
		if b.WitnessKey == key && b.URL != "" {
			hint = strings.TrimRight(b.URL, "/")
			break
		}
	}
	if hint == "" {
		return oneWitnessAnswer{err: fmt.Errorf("no address is known for %s", key)}
	}
	c, ours := witnessClient(client, hint)
	if ours {
		// A client made for this one question is not kept: its idle connections
		// would otherwise outlive it, one set for every witness of every claim.
		defer c.CloseIdleConnections()
	}
	base := LocateWitness(ctx, c, hint, key)
	state, err := FetchKeyState(ctx, c, base, key, ownerAID, presented, now)
	if err != nil {
		return oneWitnessAnswer{err: err}
	}
	out := oneWitnessAnswer{base: base, state: state}
	// What the witness serves as its copy is not believed, but a receipt proves
	// itself and a signed rival proves itself.
	out.replica, out.conflicting, _ = FetchReplica(ctx, c, base, ownerAID, presented)
	if at := departure(state, presented); at >= 0 {
		// Asked twice: a witness that states more and is then refused the read by
		// a rate limit or a passing fault would otherwise count as having shown
		// nothing, and a withheld rotation could be waved through on that.
		for try := 0; try < 2 && out.shown == nil; try++ {
			out.shown, _ = FetchEvent(ctx, c, base, ownerAID, at, presented)
		}
	}
	return out
}

// witnessClient is the client to ask the witness registered at hint with. One the
// caller gave is used as it is but follows no redirect. With none, the guarded
// client: it dials no loopback, link-local, private or reserved address and uses
// no proxy, unless the registry wrote the witness's own address as a local one.
// A witness must be asked where the registry or its own signed location says, and
// never be sent on somewhere by a redirect.
//
// ours is whether the client was made here, so that its idle connections can be
// closed when the question is answered.
func witnessClient(client *http.Client, hint string) (c *http.Client, ours bool) {
	if client == nil {
		return GuardedClient(witnessTimeout, LiteralIsLocal(hostOf(hint))), true
	}
	cp := *client
	cp.CheckRedirect = refuseRedirects
	return &cp, false
}

// receiptsCarriedBy reads the witness receipts a presented log's records carry,
// by the digest of the event each is of. Nothing in them is trusted: each is
// checked against its event and the witnesses in force when it is counted.
func receiptsCarriedBy(records []map[string]interface{}) map[string][]drivers.WitnessReceipt {
	out := map[string][]drivers.WitnessReceipt{}
	for _, rec := range records {
		if said := eventDigestOf(rec); said != "" {
			out[said] = append(out[said], receiptsOf(rec, 0)...)
		}
	}
	return out
}

// receiptsOf reads the "witness_receipts" of one served record, each marked with
// its source: 0 for the presented log, one number for each witness asked.
func receiptsOf(rec map[string]interface{}, source int) []drivers.WitnessReceipt {
	list, _ := rec["witness_receipts"].([]interface{})
	var out []drivers.WitnessReceipt
	for _, e := range list {
		m, _ := e.(map[string]interface{})
		w, _ := m["witness"].(string)
		sig, _ := m["cesr_signature"].(string)
		if w != "" && sig != "" {
			out = append(out, drivers.WitnessReceipt{WitnessAID: w, CesrSignature: sig, Source: source})
		}
	}
	return out
}

// receiptsToThreshold is whether every establishment event of the log has
// receipts, from witnesses in force at it, to the threshold it set: counted by
// drivers.WitnessingByEvent, which counts only designated witnesses, once each,
// whose signature over the event's bytes verifies, and is the one counter the
// core, the page and conversation bundles share. The threshold of the last
// establishment event is returned for the live question.
func receiptsToThreshold(aid string, log []map[string]interface{}, receipts map[string][]drivers.WitnessReceipt) (met bool, short []int, lastThreshold int) {
	in, ok := drivers.ValidateKELInputFromRecords(aid, log)
	if !ok {
		return false, []int{0}, 0
	}
	in.Receipts = receipts
	rows := drivers.WitnessingByEvent(in)
	met = true
	for _, raw := range in.RawEvents {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return false, append(short, -1), 0
		}
		if !ev.Establishment() {
			continue
		}
		row, found := rows[ev.SAID]
		if !found || !row.Known {
			met = false
			short = append(short, int(ev.SN))
			continue
		}
		lastThreshold = row.Threshold
		if !row.Met {
			met = false
			short = append(short, int(ev.SN))
		}
	}
	return met, short, lastThreshold
}

// SignedRivals counts, in what a witness handed back as conflicting, the
// entries that prove duplicity of the presented log, and those that do not.
//
// An entry proves it only when it is an event of the log's identifier, is a
// DIFFERENT event from the one the log holds at its place, and verifies
// (keri.VerifyEvent) against the key state the presented log has before that
// place: the test the witness itself applies before it keeps a conflict
// (signedRival, shared). Anything else is ignored: an event that cannot be
// read, the held event itself, an event of another identifier, one at a place
// the log does not reach, and one signed by a key the log had already rotated
// away from at that place. presented is the log as rebuilt from its verified
// bytes; if it cannot be judged as a signed log nothing can be shown against
// it and every entry is ignored.
func SignedRivals(presented, conflicting []map[string]interface{}) (valid, ignored int) {
	if len(conflicting) == 0 {
		return 0, 0
	}
	var log *keri.SignedKELResult
	if msgs, err := drivers.SignedMessagesFromRecords(presented); err == nil {
		if l, err := keri.ValidateSignedKEL(msgs); err == nil {
			log = l
		}
	}
	for _, rec := range conflicting {
		if log != nil && isSignedRival(log, rec) {
			valid++
		} else {
			ignored++
		}
	}
	return valid, ignored
}

func isSignedRival(log *keri.SignedKELResult, rec map[string]interface{}) bool {
	if rec == nil {
		return false
	}
	msgs, err := drivers.SignedMessagesFromRecords([]map[string]interface{}{rec})
	if err != nil || len(msgs) != 1 {
		return false
	}
	rawB64, _ := rec["raw_bytes_b64"].(string)
	raw, err := drivers.DecodeRawBytes(rawB64)
	if err != nil {
		return false
	}
	ev, _, held, ok := signedRival(log, raw, msgs[0])
	return ok && ev.SAID != held.Digest()
}

// eventDigestOf is the event identifier of one record on either side. From the
// raw bytes when the record carries them; otherwise from its top-level "d",
// which is what a witness serves (it keeps the event's parsed fields, not its
// bytes). The presented log has been rebuilt from its verified bytes before this
// is asked of it, so on that side "d" can only be what the bytes say.
func eventDigestOf(rec map[string]interface{}) string {
	if said, _ := drivers.EventIDOfRecord(rec); said != "" {
		return said
	}
	d, _ := rec["d"].(string)
	return d
}

// FetchReplica reads one witness's copy of an identity's key log, and the
// conflicting events it kept as evidence of duplicity.
//
// The witness answers a stranger as for a log it does not hold (MayRead), so the
// read carries the inception event of the log being checked, which the claimant
// had to present and which this witness can compare with its own. That is the
// sanctioned path for a verifier that is neither the identity nor its delegator.
func FetchReplica(ctx context.Context, client *http.Client, base, aid string, presented []map[string]interface{}) (kel, conflicting []map[string]interface{}, err error) {
	var out struct {
		KEL         []map[string]interface{} `json:"kel"`
		Conflicting []map[string]interface{} `json:"conflicting"`
	}
	if err := getWitness(ctx, client, base, "/witness/kel/"+aid, presented, &out); err != nil {
		return nil, nil, err
	}
	return out.KEL, out.Conflicting, nil
}

// FetchEvent reads the event at place sn of an identity's key log from one
// witness, as its controller published and signed it. It is a candidate, to be
// checked against the log it should extend.
func FetchEvent(ctx context.Context, client *http.Client, base, aid string, sn int, presented []map[string]interface{}) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := getWitness(ctx, client, base, "/witness/kel/"+aid+"/event/"+strconv.Itoa(sn), presented, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// witnessPrefixes are where a witness's routes are served: a commercial witness
// at the root, an Identity Agent acting as a witness under /api. Both are tried
// rather than guessed, because guessing wrong reads as "witness unreachable" and
// silently weakens the check.
var witnessPrefixes = []string{"", "/api"}

// getWitness is the one GET to a witness: each prefix in turn, bounded, status
// 200, decoded into out. presented, when it has an inception, is sent as the
// proof that lets a verifier who is neither the identity nor its delegator read.
func getWitness(ctx context.Context, client *http.Client, base, route string, presented []map[string]interface{}, out interface{}) error {
	var lastErr error
	for _, prefix := range witnessPrefixes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+prefix+route, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if proof, ok := InceptionProof(presented); ok {
			req.Header.Set(HeaderInception, proof)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, rerr := boundedread.All(resp.Body, boundedread.Document)
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}
		if err := json.Unmarshal(body, out); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no witness route answered")
	}
	return lastErr
}

// LocateWitness is the address to ask the witness whose key is key, given the
// registry's hint for where to look. The witness's own signed /loc/scheme
// reply, fetched from the hint, says where it is reached now, and is taken only
// when it is signed by that key and is not an internal address. When it is not
// served, does not verify, or is internal, the hint itself is asked: that is
// safe, because what answers there is believed only if it signs as the key
// (FetchKeyState), so a wrong address cannot lie.
//
// An internal address (loopback, link-local, private, shared, reserved, or a
// name that resolves to one) is refused as a location because the witness, not
// the registry, wrote it: a witness could otherwise aim this machine at its own
// services. A registry that itself writes a local address as the hint is
// the operator's own choice, and its signed location may be local too.
func LocateWitness(ctx context.Context, client *http.Client, hint, key string) string {
	var ans witnessproto.SignedReply
	if err := getWitness(ctx, client, hint, "/witness/loc/"+key, nil, &ans); err != nil {
		return hint
	}
	loc, err := witnessproto.VerifyWitnessLocation(ans, key)
	if err != nil {
		return hint
	}
	if !LiteralIsLocal(hostOf(hint)) {
		u, err := url.Parse(loc.URL)
		if err != nil || LiteralIsLocal(u.Hostname()) || resolvesInternalBy(ctx, u.Hostname()) {
			return hint
		}
	}
	return loc.URL
}

// resolvesInternalBy is ResolvesInternal, given up on when ctx is: a name whose
// resolver never answers is treated as internal, so it cannot hold the check past
// its deadline.
func resolvesInternalBy(ctx context.Context, host string) bool {
	done := make(chan bool, 1)
	go func() { done <- ResolvesInternal(host) }()
	select {
	case internal := <-done:
		return internal
	case <-ctx.Done():
		return true
	}
}

// FetchKeyState asks the witness whose key is key, at base, for its key state
// notice for aid, and returns it only if it is signed by that key and dated now
// (VerifyKeyStateNotice). The read carries the inception of the log being
// checked, as FetchReplica does, so a witness that answers a stranger as for a
// log it does not hold can recognise a verifier presenting the log.
func FetchKeyState(ctx context.Context, client *http.Client, base, key, aid string, presented []map[string]interface{}, now time.Time) (witnessproto.KeyState, error) {
	var ans witnessproto.SignedReply
	if err := getWitness(ctx, client, base, "/witness/ksn/"+aid, presented, &ans); err != nil {
		return witnessproto.KeyState{}, err
	}
	return witnessproto.VerifyKeyStateNotice(ans, key, aid, now)
}
