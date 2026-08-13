package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
	// Designated is how many the log names at all.
	Designated int
	// Contradicted means a witness holds a longer history than the one
	// presented — the withheld-rotation case, and the reason this exists.
	Contradicted bool
	// Why explains a contradiction, for the refusal message.
	Why string
}

// Corroborated is the question a caller actually wants answered.
func (c corroboration) Corroborated() bool { return c.Asked > 0 && !c.Contradicted }

// witnessKeysIn reads the witness keys an inception event designates.
//
// KERI's `b` field, on the establishment event. Absent or empty means the
// identity named no witnesses, which is a real answer: nobody was ever asked to
// watch, so nobody can be asked now.
func witnessKeysIn(kel []map[string]interface{}) []string {
	for _, entry := range kel {
		ev := keriEventBody(entry)
		if ev == nil {
			continue
		}
		if t, _ := ev["t"].(string); t != "icp" && t != "dip" {
			continue
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
	return nil
}

// keriEventBody gets at the actual KERI event, whichever shape it arrived in.
//
// A log travels in two forms and both reach here. A witness serves parsed
// events, so the fields are at the top level. This agent's own store keeps
// records — the event as text under event_json, alongside the signature and the
// canonical bytes — because a KERI event's serialisation is ordered and putting
// it through a map loses that.
//
// Reading only one shape is how this silently found no witnesses at all: the
// keys were there, one level down, and every history came back "0 witnesses
// named" rather than failing in a way anybody would notice.
func keriEventBody(entry map[string]interface{}) map[string]interface{} {
	if entry == nil {
		return nil
	}
	if _, ok := entry["t"].(string); ok {
		return entry
	}
	if body, ok := entry["event_json"].(string); ok && body != "" {
		var parsed map[string]interface{}
		if json.Unmarshal([]byte(body), &parsed) == nil {
			return parsed
		}
	}
	return nil
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
			continue
		}
		replica, err := fetchWitnessReplica(client, base, ownerAID)
		if err != nil {
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
	}
	return out
}

// fetchWitnessReplica reads one witness's copy of an identity's key log.
func fetchWitnessReplica(client *http.Client, base, aid string) ([]map[string]interface{}, error) {
	// Commercial witnesses serve at the root; an agent acting as a witness
	// serves the same route under /api. Try both rather than guess, because
	// guessing wrong reads as "witness unreachable" and silently weakens the
	// check.
	var lastErr error
	for _, path := range []string{"/witness/kel/", "/api/witness/kel/"} {
		resp, err := client.Get(base + path + aid)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
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
