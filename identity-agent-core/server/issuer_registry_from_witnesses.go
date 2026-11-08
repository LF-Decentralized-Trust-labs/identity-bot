package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/witness"

	keri "github.com/grapeid/keri-go"
)

// A credential from an issuer outside this agent is proved the way one of its
// own is (keriengine checkIssuanceProved, and the revocation check): from the
// credential's registry log, whose events the issuer's verified key log seals.
// This agent does not hold that log, so it asks the issuer's witnesses, whom
// the issuer's key log names, for it.
//
// WHAT REACHES THE WITNESS. The question is "the registry logs of issuer X,
// from the start", plus the inception event of X's key log (the proof that
// lets a party who is neither X nor its delegator read, see witness.MayRead).
// It does not carry the credential, its registry, or which credential is being
// checked, and it is not signed, so it does not carry who is asking either. The
// witness learns that someone, from the network address of the request,
// reads the logs of X. What the reader takes out of the whole log is not seen.
//
// WHAT IS BELIEVED. Nothing a witness says is taken as said. Every event is
// checked by witness.AnchoredTEL, the check the witness itself applies before
// storing one, against the issuer's key log this agent has already verified; a
// revocation a witness invented is not sealed there and refuses the whole
// answer. A witness that is behind this agent's copy of the key log, or whose
// answer leaves out an event the key log seals for the credential (a revocation
// kept back), is not believed either. Failing to reach any witness leaves the
// credential unproved ("not checked"), never proved and never revoked.

const maxTELAnswerBytes = 8 << 20

// rejectedWitnessFor is how long a witness that served an unsealed event is not
// asked about that issuer again.
const rejectedWitnessFor = 24 * time.Hour

var rejectedWitnesses = struct {
	sync.Mutex
	until map[string]time.Time
}{until: map[string]time.Time{}}

func witnessRejected(issuer, key string) bool {
	rejectedWitnesses.Lock()
	defer rejectedWitnesses.Unlock()
	t, ok := rejectedWitnesses.until[issuer+"|"+key]
	return ok && time.Now().Before(t)
}

func rejectWitness(issuer, key string) {
	rejectedWitnesses.Lock()
	defer rejectedWitnesses.Unlock()
	rejectedWitnesses.until[issuer+"|"+key] = time.Now().Add(rejectedWitnessFor)
}

// telDuplicity is what a witness did that makes it possible the issuer is
// showing different histories to different parties, or that the witness is
// lying (SEAM-13 §5 T-3).
type telDuplicity struct {
	Issuer     string
	WitnessKey string
	Reason     string
	// Conflict is set when the witnesses disagree with each other, and no one
	// of them is shown to have served an unsealed event.
	Conflict bool
}

const checkPossibleDuplicity = "possible_duplicity"

// fold puts the finding into a verification result: the credential is not
// verified, the check is named, and the error says which witness and why. Safe
// on nil.
func (d *telDuplicity) fold(res *drivers.DriverVerifyCredentialResponse) {
	if d == nil || res == nil {
		return
	}
	if res.Checks == nil {
		res.Checks = map[string]interface{}{}
	}
	res.Verified = false
	res.Checks[checkPossibleDuplicity] = true
	if d.Conflict {
		res.Errors = append(res.Errors, fmt.Sprintf(
			"possible duplicity: the witnesses of %s (%s) do not agree on the credential's registry log (%s); no log was accepted",
			d.Issuer, d.WitnessKey, d.Reason))
		return
	}
	res.Errors = append(res.Errors, fmt.Sprintf(
		"possible duplicity: witness %s of %s served a registry log the issuer's key log does not seal (%s); that log and witness were rejected",
		d.WitnessKey, d.Issuer, d.Reason))
}

// currentWitnessKeys is the witness set the issuer's key log has in force at its
// end: the inception's, with each rotation's cuts and additions applied.
func currentWitnessKeys(kelRaw [][]byte) []string {
	var set []string
	has := func(k string) int {
		for i, v := range set {
			if v == k {
				return i
			}
		}
		return -1
	}
	for _, raw := range kelRaw {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
		}
		switch ev.Ilk {
		case "icp", "dip":
			set = append([]string(nil), ev.Witnesses...)
		case "rot", "drt":
			for _, c := range ev.WitnessCut {
				if i := has(c); i >= 0 {
					set = append(set[:i], set[i+1:]...)
				}
			}
			for _, a := range ev.WitnessAdd {
				if has(a) < 0 {
					set = append(set, a)
				}
			}
		}
	}
	return set
}

// keyLogBytes is the published bytes of each event of a key log given as
// records. A record without bytes is skipped: it can be read and not checked.
func keyLogBytes(kel []map[string]interface{}) [][]byte {
	out := make([][]byte, 0, len(kel))
	for _, rec := range kel {
		b64, _ := rec["raw_bytes_b64"].(string)
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) > 0 {
			out = append(out, raw)
		}
	}
	return out
}

// A witness answer, and whose it is.
type witnessAnswer struct {
	key  string
	base string
	ans  witness.TELAnswer
}

// maxCatchUpRounds bounds how many times one check extends the issuer's key log.
const maxCatchUpRounds = 8

// keyLogSN is the sequence number of the last event of a key log (-1 for none).
func keyLogSN(kelRaw [][]byte) int {
	last := -1
	for _, raw := range kelRaw {
		if ev, err := keri.ParseEvent(raw); err == nil && int(ev.SN) > last {
			last = int(ev.SN)
		}
	}
	return last
}

// catchUpKeyLog extends the issuer's key log from the witnesses that say they
// hold more of it. A witness's latest_kel_sn is only a reason to look: what is
// kept is the longest log that verifies end to end, event by event, from the
// signatures the log itself puts in force (drivers.ValidateKELFromBytes), so a
// witness cannot lengthen the log by saying it is longer. The log given back is
// the one given when nothing verified.
func catchUpKeyLog(client *http.Client, issuer string, kel []map[string]interface{}, answers []witnessAnswer) []map[string]interface{} {
	clientFor := func(string) *http.Client { return client }
	for round := 0; round < maxCatchUpRounds; round++ {
		have := keyLogSN(keyLogBytes(kel))
		var best []map[string]interface{}
		for _, a := range answers {
			if a.ans.LatestKelSN <= have {
				continue
			}
			later := askWitnessForLaterEventsWith(clientFor, a.base, issuer, kel)
			if len(kel)+len(later) <= max(len(kel), len(best)) {
				continue
			}
			events := append(append([]map[string]interface{}{}, kel...), later...)
			in, ok := drivers.ValidateKELInputFromRecords(issuer, events)
			if !ok {
				continue
			}
			if val, err := drivers.ValidateKELFromBytes(in); err != nil || !val.KelVerified {
				continue
			}
			best = events
		}
		if best == nil {
			return kel
		}
		kel = best
	}
	return kel
}

// registryLogFromWitnesses is the events of one credential in its registry, in
// order, as the issuer's witnesses serve them, checked. Nil when no witness
// gave a log that holds up, which is "not checked", never "not revoked". The
// second result is set when one served events the key log does not seal. The
// third is the issuer's key log as it now stands: the one given, or a longer
// one this check verified, which the caller must check the credential against
// (a revocation anchored after the log it held is sealed only in the longer).
//
// THE KEY LOG THIS IS CHECKED AGAINST IS CAUGHT UP FIRST. The verifier's copy
// of the issuer's key log is only as new as the last time anything refreshed
// it, and nothing on this path does. Every witness is asked; when any says it
// holds the key log further than this agent does, the key log is extended from
// those witnesses and verified (catchUpKeyLog) before any answer is weighed. If
// a witness holds further than could be verified, the check ends as not
// checked: its answer cannot be tested against a log this agent cannot reach,
// and a revocation may be in it. Of the witnesses whose answer holds up, the
// one that anchors furthest is taken (SEAM-13 section 2 and T-2); one whose
// answer fails anchoring against the caught-up log is T-3: rejected and
// reported as possible duplicity. A verifier whose copy and every witness are
// all behind together cannot know it; that is what asking several witnesses is
// for.
//
// READING A WITNESS DIRECTLY IS THE FALLBACK. SEAM-13 sends this question to
// the blinded registry service (T-inv-6, section 4) and reads a witness
// directly only when that service cannot be reached. That is why the question
// below reveals as little as it does (see the top of this file).
func (s *CoreServer) registryLogFromWitnesses(client *http.Client, issuer, registry, credential string, issuerKel []map[string]interface{}) ([]string, *telDuplicity, []map[string]interface{}) {
	kelRaw := keyLogBytes(issuerKel)
	if len(kelRaw) == 0 {
		return nil, nil, issuerKel
	}
	kel := issuerKel
	pool := witness.BootstrapPool()
	asked := map[string]bool{}
	var answers []witnessAnswer
	askAll := func(raw [][]byte) {
		for _, key := range currentWitnessKeys(raw) {
			if asked[key] {
				continue
			}
			base := ""
			for _, b := range pool {
				if b.WitnessKey == key && b.URL != "" {
					base = strings.TrimRight(b.URL, "/")
					break
				}
			}
			if base == "" || witnessRejected(issuer, key) {
				continue
			}
			asked[key] = true
			if ans, err := fetchRegistryLogs(client, base, issuer, kel); err == nil {
				answers = append(answers, witnessAnswer{key: key, base: base, ans: ans})
			}
		}
	}
	askAll(kelRaw)

	claimed := -1
	for _, a := range answers {
		claimed = max(claimed, a.ans.LatestKelSN)
	}
	if claimed > keyLogSN(kelRaw) {
		kel = catchUpKeyLog(client, issuer, kel, answers)
		kelRaw = keyLogBytes(kel)
		askAll(kelRaw) // a rotation in what was caught up may name witnesses not yet asked
	}
	lastSN := keyLogSN(kelRaw)
	for _, a := range answers {
		if a.ans.LatestKelSN > lastSN {
			return nil, nil, kel // holds the key log further than could be verified: not checked
		}
	}

	sealed := map[string]bool{} // digests the key log seals for this credential
	for _, raw := range kelRaw {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
		}
		seals, _ := ev.Seals()
		for _, sl := range seals {
			if sl.Identifier == credential {
				sealed[sl.SAID] = true
			}
		}
	}

	// Each witness whose answer holds up is one vote for a log: the credential's
	// events it served and the key-log position it says it holds. The log is
	// proven complete only when as many witnesses as the issuer's key log
	// requires (its witness threshold) vote for the same one. Witnesses that did
	// not answer, or are behind, count for nothing, so fewer than the threshold
	// leaves the credential "could not check", never "not revoked" (SEAM-13 T-4).
	type vote struct {
		key      string
		sn       int
		events   []string // the credential's events, in order
		anchor   int
		complete bool
	}
	var dup *telDuplicity
	var votes []vote
	for _, a := range answers {
		if a.ans.LatestKelSN < lastSN {
			continue // behind the key log this agent holds
		}
		raws := make([][]byte, 0, len(a.ans.Events))
		for _, ev := range a.ans.Events {
			raws = append(raws, []byte(ev))
		}
		checked, err := witness.AnchoredTEL(issuer, kelRaw, raws, nil)
		if err != nil {
			var unsealed *witness.NotAnchoredError
			if errors.As(err, &unsealed) {
				// As far on as the key log, and still serving what it does not
				// seal: not an honest gap.
				rejectWitness(issuer, a.key)
				if dup == nil {
					dup = &telDuplicity{Issuer: issuer, WitnessKey: a.key, Reason: err.Error()}
				}
			}
			continue
		}
		// The registry's inception was required, and checked as the issuer's,
		// by AnchoredTEL for any event in it. What goes on is the credential's
		// own events: the engine reads them as one credential's log.
		var mine []witness.TELEvent
		anchor := -1
		for _, ev := range checked {
			anchor = max(anchor, ev.AnchorSN)
			if ev.Subject == credential && ev.Registry == registry {
				mine = append(mine, ev)
			}
		}
		have := map[string]bool{}
		for _, ev := range mine {
			have[ev.SAID] = true
		}
		complete := len(mine) > 0
		for said := range sealed {
			if !have[said] {
				complete = false // the key log seals an event of this credential the answer left out
			}
		}
		sort.Slice(mine, func(x, y int) bool { return mine[x].SN < mine[y].SN })
		v := vote{key: a.key, sn: a.ans.LatestKelSN, anchor: anchor, complete: complete}
		for _, ev := range mine {
			v.events = append(v.events, ev.RawB64)
		}
		votes = append(votes, v)
	}

	byLog := map[string][]vote{}
	for _, v := range votes {
		id := fmt.Sprintf("%d|%s", v.sn, strings.Join(v.events, ","))
		byLog[id] = append(byLog[id], v)
	}
	if len(byLog) > 1 {
		// Witnesses as far on as the key log, and not agreeing on what the
		// credential's log is: one of them is wrong, or the issuer shows
		// different histories. Not a verdict either way.
		var keys []string
		for _, v := range votes {
			keys = append(keys, v.key)
		}
		if dup == nil {
			dup = &telDuplicity{Issuer: issuer, WitnessKey: strings.Join(keys, ","), Conflict: true,
				Reason: "the witnesses disagree on the credential's registry log or on how far the key log goes"}
		}
		return nil, dup, kel
	}
	need := keyLogToad(kelRaw)
	for _, group := range byLog {
		if len(group) >= need && group[0].complete {
			return group[0].events, dup, kel
		}
	}
	// A good log from one witness does not erase what another served.
	return nil, dup, kel
}

// keyLogToad is the number of the issuer's witnesses that must agree, from its
// key log: the threshold (bt) of the last establishment event that carries one.
// At least one: an answer from no witness proves nothing.
func keyLogToad(kelRaw [][]byte) int {
	toad := 0
	for _, raw := range kelRaw {
		if ev, err := keri.ParseEvent(raw); err == nil && ev.Establishment() && ev.HasTOAD {
			toad = int(ev.TOAD)
		}
	}
	return max(toad, 1)
}

// fetchRegistryLogs reads an issuer's whole registry log from one witness. The
// request carries the issuer's inception (witness.HeaderInception) and nothing
// that identifies the asker or the credential.
func fetchRegistryLogs(client *http.Client, base, issuer string, issuerKel []map[string]interface{}) (witness.TELAnswer, error) {
	var lastErr error
	for _, path := range []string{"/witness/tel/", "/api/witness/tel/"} {
		req, err := http.NewRequest(http.MethodGet, base+path+url.PathEscape(issuer)+"?since_sn=-1", nil)
		if err != nil {
			lastErr = err
			continue
		}
		if proof, ok := witness.InceptionProof(issuerKel); ok {
			req.Header.Set(witness.HeaderInception, proof)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, rerr := boundedread.All(resp.Body, maxTELAnswerBytes)
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}
		var ans witness.TELAnswer
		if err := json.Unmarshal(body, &ans); err != nil {
			lastErr = err
			continue
		}
		if ans.AID != issuer {
			lastErr = fmt.Errorf("the answer is about another identity")
			continue
		}
		return ans, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no witness route answered")
	}
	return witness.TELAnswer{}, lastErr
}

var telClient = &http.Client{Timeout: 8 * time.Second}
