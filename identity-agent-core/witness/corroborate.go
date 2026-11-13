package witness

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/internal/boundedread"
)

// Asking somebody other than the claimant whether a presented key log is the
// whole history.
//
// Checking a presented key log establishes authorship: every event is signed by
// the key the log itself puts in force. What it cannot establish is that the
// log is COMPLETE. A log is a chain, and a chain with its last link removed is
// still a valid chain, so somebody who rotated away from a key and kept the
// rotation to themselves can present the earlier log and sign with the old
// key. Everything verifies; the identity has moved on and the verifier cannot
// tell.
//
// The only thing that closes it is a party who saw the events as they happened:
// the witnesses the log itself designates in its inception.
//
// WHY THE CLAIMANT'S OWN ADDRESS IS NOT ENOUGH. The OOBI in a claim names the
// claimant's own agent, so somebody withholding a rotation from the presented
// copy would withhold it from the served copy too.
//
// WHY A WITNESS IS NOT FOUND BY WHAT IT SAYS ABOUT ITSELF. An event designates
// a witness by its key, deliberately, so a receipt can be checked without
// resolving the witness's own history. A key is not an address. Turning it into
// somewhere to ask is a local lookup in the registry of witness operators
// (BootstrapWitness.WitnessKey), never an answer a server gives about itself:
// any server can claim any identity. A designated key the registry does not
// know cannot be asked and counts as failed.
//
// This is used by the Identity Agent when it checks a claim, and by anybody
// outside the core who has to answer the same question (a verifier of a founded
// organisation), so there is one implementation of it.

// Corroboration is what asking the witnesses established.
type Corroboration struct {
	// Asked is how many designated witnesses were reachable and answered.
	Asked int
	// Held is how many of those hold the presented events: at least the
	// sequence claimed, with the same digests. Only these corroborate.
	Held int
	// Empty is how many answered, but with no events for this identifier, as a
	// witness does for one it has never seen. Reachable is not confirming.
	Empty int
	// Behind is how many answered with some of the history but less than was
	// claimed.
	Behind int
	// Failed is how many designated witnesses could not be asked: no address
	// for the key in the registry, or no answer.
	Failed int
	// Designated is how many the log names at all.
	Designated int
	// Contradicted means a witness holds a longer history than the one
	// presented (the withheld-rotation case), a different event where one was
	// presented (a fork), or evidence of duplicity (see Conflicting).
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
	// Key is the designated witness key, and URL the address the registry gives
	// that key.
	Key, URL string
	// Replica is the log the witness holds for the identifier.
	Replica []map[string]interface{}
	// Conflicting is what the witness kept as evidence that the identity
	// signed two different events at one place (duplicity). Non-empty is a
	// contradiction: witnesses exist to detect exactly this.
	Conflicting []map[string]interface{}
}

// Corroborated is the question a caller actually wants answered.
//
// A witness that is reachable but holds nothing confirms nothing, so it is the
// witnesses that hold the events that count, not the ones that answered.
func (c Corroboration) Corroborated() bool { return c.Held > 0 && !c.Contradicted }

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

// Corroborate checks a presented log against the witnesses its inception
// designates, each found by its designated key in pool (the registry:
// BootstrapPool() in the Identity Agent, or the registry a verifier loads).
// client may be nil.
//
// Failure to reach a witness is NOT a contradiction. A witness that is down,
// or that this machine has no route to, leaves the history uncorroborated,
// which is a different answer from refuted; the caller decides what to do about
// it. Conflating the two would make every network fault look like an attack.
func Corroborate(client *http.Client, pool []BootstrapWitness, ownerAID string, presented []map[string]interface{}) Corroboration {
	return CorroborateThrough(client, pool, ownerAID, presented, WitnessKeysIn(presented))
}

// CorroborateThrough is Corroborate for a caller that has worked out which
// witnesses are in force from the whole log (after rotations) rather than from
// the inception alone. keys are witness keys, and are resolved the same way.
func CorroborateThrough(client *http.Client, pool []BootstrapWitness, ownerAID string, presented []map[string]interface{}, keys []string) Corroboration {
	// Rebuilt from the bytes the verdict on the claim covers, so nothing served
	// beside them (a top-level "d", event_json) can say what the claim shows. A
	// log that cannot be rebuilt was not verified by its bytes and cannot be
	// corroborated.
	rebuilt, ok := drivers.RecordsFromVerifiedBytes(presented)
	out := Corroboration{Designated: len(keys)}
	if len(keys) == 0 || !ok {
		return out
	}
	presented = rebuilt
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}

	for _, key := range keys {
		var base string
		for _, b := range pool {
			if b.WitnessKey == key && b.URL != "" {
				base = strings.TrimRight(b.URL, "/")
				break
			}
		}
		if base == "" {
			out.Failed++
			continue
		}
		replica, conflicting, err := FetchReplica(client, base, ownerAID, presented)
		if err != nil {
			out.Failed++
			continue
		}
		out.Asked++
		out.Answers = append(out.Answers, WitnessAnswer{Key: key, URL: base, Replica: replica, Conflicting: conflicting})

		// DUPLICITY. A witness that kept a second, different event at a place
		// the identity had already used is holding proof the identity signed two
		// histories. That is the one thing a witness is for (ADR-031).
		if len(conflicting) > 0 {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness holds %d conflicting event(s) for %s: evidence that identity signed two different histories",
				len(conflicting), ownerAID)
			return out
		}
		// A witness holding MORE of this identity's history than was presented
		// is the withheld rotation: the claimant showed a prefix and signed with
		// a key the identity has moved on from.
		if len(replica) > len(presented) {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness holds %d events for %s but the claim presented %d, so the claim "+
					"is signed against a history that identity has already moved on from",
				len(replica), ownerAID, len(presented))
			return out
		}
		// A different event where the claim shows one is a fork, not a
		// confirmation.
		if at, differs := firstDigestMismatch(presented, replica); differs {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness holds a different event %d for %s than the claim presented", at, ownerAID)
			return out
		}
		switch {
		case len(replica) == 0:
			out.Empty++
		case len(replica) < len(presented):
			out.Behind++
		case !holdsDigests(presented, replica):
			out.Behind++
		default:
			out.Held++
		}
	}
	return out
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

// firstDigestMismatch finds an event where both sides give a readable digest
// and they differ.
func firstDigestMismatch(presented, replica []map[string]interface{}) (int, bool) {
	for i := 0; i < len(presented) && i < len(replica); i++ {
		a, b := eventDigestOf(presented[i]), eventDigestOf(replica[i])
		if a != "" && b != "" && a != b {
			return i, true
		}
	}
	return 0, false
}

// holdsDigests reports whether the witness gives, for EVERY event the claim
// shows, the same readable digest at the same place. An event whose digest
// cannot be read on either side is not held: unreadable is not confirming.
func holdsDigests(presented, replica []map[string]interface{}) bool {
	if len(replica) < len(presented) {
		return false
	}
	for i, p := range presented {
		want, got := eventDigestOf(p), eventDigestOf(replica[i])
		if want == "" || got == "" || got != want {
			return false
		}
	}
	return true
}

// FetchReplica reads one witness's copy of an identity's key log, and the
// conflicting events it kept as evidence of duplicity.
//
// The witness answers a stranger as for a log it does not hold (MayRead), so the
// read carries the inception event of the log being checked, which the claimant
// had to present and which this witness can compare with its own. That is the
// sanctioned path for a verifier that is neither the identity nor its delegator.
func FetchReplica(client *http.Client, base, aid string, presented []map[string]interface{}) (kel, conflicting []map[string]interface{}, err error) {
	// Commercial witnesses serve at the root; an agent acting as a witness
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
