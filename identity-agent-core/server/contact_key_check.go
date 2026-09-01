package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"identity-agent-core/store"
)

// Checking a counterparty's key history at the moment it is relied on.
//
// It used to be checked once, when two agents first met, and never again —
// EnsureKeriContact returns early for anyone it already knows. A key event log
// is append-only and grows: people rotate keys, events accumulate, and none of
// it was looked at a second time. So an agent kept authenticating against a
// snapshot, which means a legitimate rotation was invisible to it and so was an
// illegitimate one.
//
// That mattered more once exchanges began authenticating against the recorded
// key, because it made a stale snapshot load-bearing.
//
// So the check happens when the key is used. What it establishes is narrow and
// worth stating plainly: that this key history is internally consistent, every
// event signed, and the identifier genuinely derived from its own inception.
// It says nothing about who anybody is. It is the floor that makes a claim
// about an identity worth evaluating at all, not evidence for the claim.

// kelCheck is what checking a counterparty's key history concluded.
type kelCheck string

const (
	// kelVerifiedNow — checked here, just now, and it holds.
	kelVerifiedNow kelCheck = "verified"
	// kelFailed — checked, and something is wrong. Refuse.
	kelFailed kelCheck = "failed"
	// kelUnchecked — could not be checked on this device. Not the same as
	// passing, and it must never be reported as though it were: on a phone
	// there is no engine to check with, so an agent that treated silence as
	// success would be claiming an answer it never obtained.
	kelUnchecked kelCheck = "unchecked"
)

// kelCheckCache keeps a recent result so that using a contact several times in
// a row does not re-fetch their log each time. Short, because the point is
// freshness — long enough to cover one interaction, not long enough to make
// this the old behaviour under a new name.
var kelCheckCache = struct {
	sync.Mutex
	m map[string]kelCheckResult
}{m: map[string]kelCheckResult{}}

const kelCheckFreshness = 5 * time.Minute

type kelCheckResult struct {
	State     kelCheck
	Key       string
	Reason    string
	CheckedAt time.Time
	// Witnessed reports whether every event in the log carried receipts from
	// the threshold of witnesses the identity designated.
	//
	// Carried separately from State because it answers a different question.
	// State says the log is sound and signed by its controller; this says
	// somebody other than the controller stood behind it, which is the only
	// thing that makes a SECOND, conflicting log detectable. A caller reading a
	// current key can proceed without it; a caller about to accept a change to
	// what an identity commits to cannot, because the whole risk there is being
	// shown an old or forked history by whoever served it.
	Witnessed bool
	// WitnessThreshold is how many receipts the identity asked for. Zero means
	// it designated nobody, so it can never be witnessed — which is a different
	// situation from falling short, and the two must not be conflated.
	WitnessThreshold int
}

// contactKeyForUse re-checks a contact's key history and returns the key that
// should be relied on now.
//
// The key comes back from the check rather than from the stored record on
// purpose: if they have rotated, the current key is the one their log now ends
// with, and returning the stored one would authenticate against a key they have
// retired.
func (s *CoreServer) contactKeyForUse(aid string) kelCheckResult {
	kelCheckCache.Lock()
	if hit, ok := kelCheckCache.m[aid]; ok && time.Since(hit.CheckedAt) < kelCheckFreshness {
		kelCheckCache.Unlock()
		return hit
	}
	kelCheckCache.Unlock()

	result := s.checkContactKEL(aid)

	kelCheckCache.Lock()
	kelCheckCache.m[aid] = result
	kelCheckCache.Unlock()
	return result
}

func (s *CoreServer) checkContactKEL(aid string) kelCheckResult {
	now := time.Now().UTC()
	stored, err := s.DataStore.GetContact(aid)
	if err != nil || stored == nil {
		return kelCheckResult{State: kelUnchecked, Reason: "no record of this identity", CheckedAt: now}
	}

	// No engine on this device — a phone. Report that honestly rather than
	// falling back to the recorded key and calling it checked.
	if s.KeriDriver == nil {
		return kelCheckResult{
			State: kelUnchecked, Key: stored.PublicKey,
			Reason: "this device has no key engine, so nothing was checked here", CheckedAt: now,
		}
	}
	if stored.OobiURL == "" {
		return kelCheckResult{
			State: kelUnchecked, Key: stored.PublicKey,
			Reason: "no address on file to fetch their key history from", CheckedAt: now,
		}
	}

	events, ferr := fetchKELFromOOBI(stored.OobiURL)
	if ferr != nil {
		// Unreachable is not the same as wrong. Refusing outright would make
		// any counterparty's outage look like an attack, so this is reported as
		// unchecked and the caller decides what that is worth.
		return kelCheckResult{
			State: kelUnchecked, Key: stored.PublicKey,
			Reason: fmt.Sprintf("could not fetch their key history: %v", ferr), CheckedAt: now,
		}
	}
	if len(events) == 0 {
		return kelCheckResult{
			State: kelUnchecked, Key: stored.PublicKey,
			Reason: "their address published no key history", CheckedAt: now,
		}
	}

	val, verr := s.KeriDriver.ValidateKEL(aid, events)
	if verr != nil {
		return kelCheckResult{
			State: kelUnchecked, Key: stored.PublicKey,
			Reason: fmt.Sprintf("the check could not run: %v", verr), CheckedAt: now,
		}
	}
	if !val.KelVerified {
		reason := "their key history did not check out"
		if len(val.ValidationErrors) > 0 {
			reason = val.ValidationErrors[0]
		}
		return kelCheckResult{State: kelFailed, Reason: reason, CheckedAt: now}
	}

	// VERIFIED WITH NO KEY IS NOT VERIFIED.
	//
	// Falling back to the stored key here would write KelVerified: true beside a
	// key the validator did not produce — and that record is the one the owner's
	// key is read from when nothing is sealed. A validator that ever answered
	// "verified" without a current key would launder a caller-chosen key into
	// the one place that is trusted for saying who the owner is.
	//
	// Not reachable today: both validators derive the key from the inception
	// event they just checked. Closed anyway, because the cost is a line and the
	// failure would be silent and total.
	key := val.CurrentPublicKey
	if key == "" {
		return kelCheckResult{
			State: kelFailed, CheckedAt: now,
			Reason: "their key history checked out but named no current key, which is not " +
				"something this agent can act on",
		}
	}
	// Record what was found, so the current key survives a restart and so
	// anything reading the history later sees the latest check rather than the
	// first one.
	_ = s.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: aid, KEL: events, KelVerified: true, CurrentPublicKey: key,
		EventsValidated: val.EventsValidated, ValidatedAt: now.Format(time.RFC3339),
	})
	return kelCheckResult{
		State: kelVerifiedNow, Key: key, CheckedAt: now,
		Witnessed: val.Witnessed, WitnessThreshold: val.WitnessThreshold,
	}
}

func fetchKELFromOOBI(oobiURL string) ([]map[string]interface{}, error) {
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(oobiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("their address answered %d", resp.StatusCode)
	}
	var body struct {
		KEL []map[string]interface{} `json:"kel"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.KEL, nil
}
