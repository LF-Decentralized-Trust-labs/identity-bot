package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/internal/boundedread"
	"identity-agent-core/witness"
)

// Asking somebody other than the claimant whether this history is the whole
// history.
//
// Checking a presented key log establishes authorship: every event is signed by
// the key the log itself puts in force. What it cannot establish is that the
// log is COMPLETE. A log is a chain, and a chain with its last link removed is
// still a valid chain — so somebody who held a key, rotated away from it, and
// kept the rotation to themselves can present the earlier log and sign with the
// old key. Everything verifies. The identity has moved on and the verifier
// cannot tell.
//
// The only thing that closes it is a party who saw the events as they happened.
// That is what a witness is for, and it is why an identity designates witnesses
// in the one event where designation is possible.
//
// WHY THE CLAIMANT'S OWN ADDRESS IS NOT ENOUGH. The obvious move is to fetch the
// log from the OOBI in the claim and compare. That proves nothing: the OOBI
// names the claimant's own agent, so somebody withholding a rotation from the
// presented copy would withhold it from the served copy too. The fetch has to
// go to a party the claimant does not control, and the log itself says who
// those are — the witness keys designated in its inception.
//
// WHAT A WITNESS KEY IS NOT is an address. An event designates the key receipts
// verify against, deliberately, so a receipt can be checked without first
// resolving the witness's own history. Turning that key into somewhere to ask
// is a local lookup, through the same registry this agent already uses to pick
// witnesses for identities of its own.

// corroboration is what asking the witnesses established.
type corroboration struct {
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
	// for the key, or no answer.
	Failed int
	// Designated is how many the log names at all.
	Designated int
	// Contradicted means a witness holds a longer history than the one
	// presented — the withheld-rotation case, and the reason this exists.
	Contradicted bool
	// Why explains a contradiction, for the refusal message.
	Why string
}

// Corroborated is the question a caller actually wants answered.
//
// A witness that is reachable but holds nothing confirms nothing, so it is the
// witnesses that hold the events that count, not the ones that answered.
func (c corroboration) Corroborated() bool { return c.Held > 0 && !c.Contradicted }

// witnessKeysIn reads the witness keys an inception event designates.
//
// KERI's `b` field, on the establishment event. Absent or empty means the
// identity named no witnesses, which is a real answer: nobody was ever asked to
// watch, so nobody can be asked now.
func witnessKeysIn(kel []map[string]interface{}) []string {
	// From the verified bytes, never from event_json text beside them: that
	// text is not covered by the check on the claim, and blanking its "b" would
	// otherwise leave nobody to ask.
	ev, _, ok := witness.InceptionOf(kel)
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

// eventCountIn counts the events in a log, however it is carried.
func eventCountIn(kel []map[string]interface{}) int { return len(kel) }

// askTheWitnesses checks a presented log against the parties it says were
// watching.
//
// Failure to reach a witness is NOT a contradiction. A witness that is down,
// or that this machine has no route to, leaves the history uncorroborated —
// which is a different answer from refuted, and the caller decides what to do
// about it. Conflating the two would make every network fault look like an
// attack, and would make a machine with no internet unable to be set up at all.
func (s *CoreServer) askTheWitnesses(ownerAID string, presented []map[string]interface{}) corroboration {
	keys := witnessKeysIn(presented)
	out := corroboration{Designated: len(keys)}
	if len(keys) == 0 {
		return out
	}

	// A designated key is not an address. Resolve it through the registry this
	// agent already uses; a key it does not recognise cannot be asked.
	pool := witness.BootstrapPool()
	client := &http.Client{Timeout: 8 * time.Second}

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
		replica, err := fetchWitnessReplica(client, base, ownerAID, presented)
		if err != nil {
			out.Failed++
			continue
		}
		out.Asked++

		// THE CHECK. A witness holding MORE of this identity's history than was
		// presented is the withheld rotation: the claimant showed a prefix and
		// signed with a key the identity has moved on from.
		if len(replica) > eventCountIn(presented) {
			out.Contradicted = true
			out.Why = fmt.Sprintf(
				"a witness holds %d events for %s but the claim presented %d, so the claim "+
					"is signed against a history that identity has already moved on from",
				len(replica), ownerAID, eventCountIn(presented))
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
		case len(replica) < eventCountIn(presented):
			out.Behind++
		case !holdsDigests(presented, replica):
			out.Behind++
		default:
			out.Held++
		}
	}
	return out
}

// claimedEventDigest is the said of an event as a log carries it: the event itself, its
// event_json text, or its raw bytes. Empty when it cannot be read.
func claimedEventDigest(entry map[string]interface{}) string {
	if d, _ := entry["d"].(string); d != "" {
		return d
	}
	var parsed map[string]interface{}
	if b64, _ := entry["raw_bytes_b64"].(string); b64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
			_ = json.Unmarshal(raw, &parsed)
		}
	} else if body, _ := entry["event_json"].(string); body != "" {
		_ = json.Unmarshal([]byte(body), &parsed)
	}
	d, _ := parsed["d"].(string)
	return d
}

// firstDigestMismatch finds an event where both sides give a digest and they
// differ.
func firstDigestMismatch(presented, replica []map[string]interface{}) (int, bool) {
	for i := 0; i < len(presented) && i < len(replica); i++ {
		a, b := claimedEventDigest(presented[i]), claimedEventDigest(replica[i])
		if a != "" && b != "" && a != b {
			return i, true
		}
	}
	return 0, false
}

// holdsDigests reports whether the witness gives, for each event the claim
// shows with a digest, the same digest at the same place.
func holdsDigests(presented, replica []map[string]interface{}) bool {
	for i, p := range presented {
		if want := claimedEventDigest(p); want != "" && claimedEventDigest(replica[i]) != want {
			return false
		}
	}
	return true
}

// fetchWitnessReplica reads one witness's copy of an identity's key log.
//
// The witness answers a stranger as for a log it does not hold (witness.MayRead),
// so the read carries the inception event of the log being checked, which the
// claimant had to present and which this witness can compare with its own. That
// is the sanctioned path for a verifier that is neither the identity nor its
// delegator.
func fetchWitnessReplica(client *http.Client, base, aid string, presented []map[string]interface{}) ([]map[string]interface{}, error) {
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
		if proof, ok := witness.InceptionProof(presented); ok {
			req.Header.Set(witness.HeaderInception, proof)
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
			KEL []map[string]interface{} `json:"kel"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			lastErr = err
			continue
		}
		return out.KEL, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no witness route answered")
	}
	return nil, lastErr
}
