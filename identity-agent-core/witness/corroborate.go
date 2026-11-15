package witness

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
//     notice (the reply /ksn/{aid}, see KeyStateRoute) dated now and signed by
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
	State KeyState
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
	return c.ReceiptsMet && c.Required > 0 && c.Held >= c.Required && !c.Contradicted
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

// Corroborate checks a presented log against the witnesses in force at its end, each found by its designated key (pool is the registry of
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

func corroborateThrough(client *http.Client, pool []BootstrapWitness, ownerAID string, presented []map[string]interface{}, keys []string, now time.Time) Corroboration {
	carried := receiptsCarriedBy(presented)
	// Rebuilt from the bytes the verdict on the claim covers, so nothing served
	// beside them (a top-level "d", event_json) can say what the claim shows. A
	// log that cannot be rebuilt was not verified by its bytes and cannot be
	// corroborated.
	rebuilt, ok := drivers.RecordsFromVerifiedBytes(presented)
	out := Corroboration{Designated: len(keys)}
	if len(keys) == 0 || !ok || len(rebuilt) == 0 {
		return out
	}
	presented = rebuilt
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	tip := len(presented) - 1
	tipSAID := eventDigestOf(presented[tip])
	receipts := carried

	for _, key := range keys {
		hint := ""
		for _, b := range pool {
			if b.WitnessKey == key && b.URL != "" {
				hint = strings.TrimRight(b.URL, "/")
				break
			}
		}
		if hint == "" {
			out.Failed++
			continue
		}
		base := LocateWitness(client, hint, key)
		state, err := FetchKeyState(client, base, key, ownerAID, presented, now)
		if err != nil {
			out.Failed++
			continue
		}
		// What the witness serves as its copy is not believed, but a receipt
		// proves itself and a signed rival proves itself.
		replica, conflicting, _ := FetchReplica(client, base, ownerAID, presented)
		out.Asked++
		rivals, ignored := SignedRivals(presented, conflicting)
		out.Answers = append(out.Answers, WitnessAnswer{Key: key, URL: base, State: state, Replica: replica,
			Conflicting: conflicting, Ignored: ignored})
		for _, rec := range replica {
			if said := eventDigestOf(rec); said != "" {
				receipts[said] = append(receipts[said], receiptsOf(rec)...)
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
		// A witness stating, signed, that it holds MORE of this identity's
		// history than was presented is the withheld rotation: the claimant
		// showed a prefix and signed with a key the identity has moved on from.
		if state.SN > tip {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness states it holds %d events for %s but the claim presented %d, so the claim "+
					"is signed against a history that identity has already moved on from",
				state.SN+1, ownerAID, len(presented))
			return out
		}
		// A different event where the claim shows one is a fork, not a
		// confirmation.
		if state.SN >= 0 && state.SAID != eventDigestOf(presented[state.SN]) {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness states a different event %d for %s than the claim presented", state.SN, ownerAID)
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

// receiptsCarriedBy reads the witness receipts a presented log's records carry,
// by the digest of the event each is of. Nothing in them is trusted: each is
// checked against its event and the witnesses in force when it is counted.
func receiptsCarriedBy(records []map[string]interface{}) map[string][]drivers.WitnessReceipt {
	out := map[string][]drivers.WitnessReceipt{}
	for _, rec := range records {
		if said := eventDigestOf(rec); said != "" {
			out[said] = append(out[said], receiptsOf(rec)...)
		}
	}
	return out
}

// receiptsOf reads the "witness_receipts" of one served record.
func receiptsOf(rec map[string]interface{}) []drivers.WitnessReceipt {
	list, _ := rec["witness_receipts"].([]interface{})
	var out []drivers.WitnessReceipt
	for _, e := range list {
		m, _ := e.(map[string]interface{})
		w, _ := m["witness"].(string)
		sig, _ := m["cesr_signature"].(string)
		if w != "" && sig != "" {
			out = append(out, drivers.WitnessReceipt{WitnessAID: w, CesrSignature: sig})
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
func FetchReplica(client *http.Client, base, aid string, presented []map[string]interface{}) (kel, conflicting []map[string]interface{}, err error) {
	// Commercial witnesses serve at the root; an Identity Agent acting as a witness
	// serves the same route under /api. Try both rather than guess, because
	// guessing wrong reads as "witness unreachable" and silently weakens the
	// check.
	var lastErr error
	for _, path := range []string{"/witness/kel/", "/api/witness/kel/"} {
		req, err := http.NewRequest(http.MethodGet, base+path+aid, nil)
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
		var out struct {
			KEL         []map[string]interface{} `json:"kel"`
			Conflicting []map[string]interface{} `json:"conflicting"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			lastErr = err
			continue
		}
		return out.KEL, out.Conflicting, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no witness route answered")
	}
	return nil, nil, lastErr
}

// witnessPrefixes are where a witness's routes are served: a commercial witness
// at the root, an Identity Agent acting as a witness under /api. Both are tried
// rather than guessed, because guessing wrong reads as "witness unreachable" and
// silently weakens the check.
var witnessPrefixes = []string{"", "/api"}

// getSigned fetches one signed reply from a witness, trying each prefix.
func getSigned(client *http.Client, base, route string, headers map[string]string) (SignedReply, error) {
	var lastErr error
	for _, prefix := range witnessPrefixes {
		req, err := http.NewRequest(http.MethodGet, base+prefix+route, nil)
		if err != nil {
			lastErr = err
			continue
		}
		for k, v := range headers {
			req.Header.Set(k, v)
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
		var ans SignedReply
		if err := json.Unmarshal(body, &ans); err != nil {
			lastErr = err
			continue
		}
		return ans, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no witness route answered")
	}
	return SignedReply{}, lastErr
}

// LocateWitness is the address to ask the witness whose key is key, given the
// registry's hint for where to look. The witness's own signed /loc/scheme
// reply, fetched from the hint, says where it is reached now, and is taken only
// when it is signed by that key. When it is not served, or does not verify, the
// hint itself is asked: that is safe, because what answers there is believed
// only if it signs as the key (FetchKeyState), so a wrong address cannot lie.
func LocateWitness(client *http.Client, hint, key string) string {
	ans, err := getSigned(client, hint, "/witness/loc/"+key, nil)
	if err != nil {
		return hint
	}
	loc, err := VerifyWitnessLocation(ans, key)
	if err != nil {
		return hint
	}
	return loc.URL
}

// FetchKeyState asks the witness whose key is key, at base, for its key state
// notice for aid, and returns it only if it is signed by that key and dated now
// (VerifyKeyStateNotice). The read carries the inception of the log being
// checked, as FetchReplica does, so a witness that answers a stranger as for a
// log it does not hold can recognise a verifier presenting the log.
func FetchKeyState(client *http.Client, base, key, aid string, presented []map[string]interface{}, now time.Time) (KeyState, error) {
	headers := map[string]string{}
	if proof, ok := InceptionProof(presented); ok {
		headers[HeaderInception] = proof
	}
	ans, err := getSigned(client, base, "/witness/ksn/"+aid, headers)
	if err != nil {
		return KeyState{}, err
	}
	return VerifyKeyStateNotice(ans, key, aid, now)
}
