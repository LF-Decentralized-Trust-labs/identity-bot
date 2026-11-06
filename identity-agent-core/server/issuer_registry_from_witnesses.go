package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/drivers"
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

// registryLogFromWitnesses is the events of one credential in its registry, in
// order, as the issuer's witnesses
// serve them, checked. Nil when no witness gave a log that holds up; the second
// result is set when one served events the key log does not seal.
func (s *CoreServer) registryLogFromWitnesses(client *http.Client, issuer, registry, credential string, issuerKel []map[string]interface{}) ([]string, *telDuplicity) {
	kelRaw := keyLogBytes(issuerKel)
	if len(kelRaw) == 0 {
		return nil, nil
	}
	var dup *telDuplicity
	lastSN := -1
	sealed := map[string]bool{} // digests the key log seals for this credential
	for _, raw := range kelRaw {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
		}
		if int(ev.SN) > lastSN {
			lastSN = int(ev.SN)
		}
		seals, _ := ev.Seals()
		for _, sl := range seals {
			if sl.Identifier == credential {
				sealed[sl.SAID] = true
			}
		}
	}
	pool := witness.BootstrapPool()
	for _, key := range currentWitnessKeys(kelRaw) {
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
		ans, err := fetchRegistryLogs(client, base, issuer, issuerKel)
		if err != nil || ans.LatestKelSN < lastSN {
			continue // unreachable, or behind the key log this agent already holds
		}
		raws := make([][]byte, 0, len(ans.Events))
		for _, ev := range ans.Events {
			raws = append(raws, []byte(ev))
		}
		checked, err := witness.AnchoredTEL(issuer, kelRaw, raws, nil)
		if err != nil {
			var unsealed *witness.NotAnchoredError
			if errors.As(err, &unsealed) && ans.LatestKelSN <= lastSN {
				// Not behind, not ahead, and still serving what this key log
				// does not seal: not an honest gap.
				rejectWitness(issuer, key)
				if dup == nil {
					dup = &telDuplicity{Issuer: issuer, WitnessKey: key, Reason: err.Error()}
				}
			}
			continue
		}
		// The registry's inception was required, and checked as the issuer's,
		// by AnchoredTEL for any event in it. What goes on is the credential's
		// own events: the engine reads them as one credential's log.
		var mine []witness.TELEvent
		for _, ev := range checked {
			if ev.Subject == credential && ev.Registry == registry {
				mine = append(mine, ev)
			}
		}
		if len(mine) == 0 {
			continue
		}
		have := map[string]bool{}
		for _, ev := range mine {
			have[ev.SAID] = true
		}
		complete := true
		for said := range sealed {
			if !have[said] {
				complete = false // the key log seals an event of this credential the answer left out
			}
		}
		if !complete {
			continue
		}
		sort.Slice(mine, func(a, b int) bool { return mine[a].SN < mine[b].SN })
		var res []string
		for _, ev := range mine {
			res = append(res, ev.RawB64)
		}
		return res, dup // a good log from another witness does not erase what the first one served
	}
	return nil, dup
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTELAnswerBytes))
		resp.Body.Close()
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
