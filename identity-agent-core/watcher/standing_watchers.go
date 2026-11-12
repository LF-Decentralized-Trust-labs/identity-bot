package watcher

import (
	"context"
	"encoding/json"

	"identity-agent-core/drivers"
)

// Several standing watchers, for coverage.
//
// watcher_config "standing_watchers" holds extra standing watchers beside the
// default (default_l2_url), as a JSON list of {"url"}. Any one honest watcher
// that holds what the controller published is enough to show a fork, so more
// watchers make it likelier that one does. Nothing counts watchers to decide a
// refusal: a contact is refused on proof of duplicity, from a single watcher's
// evidence (proof_of_duplicity.go), and a watcher that withholds, cannot be
// reached or cannot back up its answer is the same as no watcher.
//
// watcher_config "entity_kind" is "individual" (the default) or "organisation".

const (
	configStandingWatchers = "standing_watchers"
	configEntityKind       = "entity_kind"

	EntityIndividual   = "individual"
	EntityOrganisation = "organisation"

	// An organisation is advised to ask at least this many standing watchers, and
	// is expected to have this many (5 to 7), so that one being down or lying
	// leaves others able to show a fork. It is coverage, not a vote.
	OrgMinWatchers         = 2
	OrgRecommendedWatchers = 5
)

// StandingWatcher is one standing watcher.
type StandingWatcher struct {
	URL string `json:"url"`
}

// StandingWatchers is the default watcher followed by the extra ones, each URL once.
func (s *Service) StandingWatchers() []StandingWatcher {
	out := []StandingWatcher{{URL: s.DefaultL2URL()}}
	if s.Store != nil {
		if raw, _ := s.Store.GetConfig(configStandingWatchers); raw != "" {
			var extra []StandingWatcher
			if json.Unmarshal([]byte(raw), &extra) == nil {
				for _, w := range extra {
					dup := false
					for _, o := range out {
						dup = dup || o.URL == w.URL
					}
					if w.URL != "" && !dup {
						out = append(out, StandingWatcher{URL: w.URL})
					}
				}
			}
		}
	}
	return out
}

// SetStandingWatchers keeps the extra standing watchers (the default is not listed here).
func (s *Service) SetStandingWatchers(ws []StandingWatcher) error {
	b, err := json.Marshal(ws)
	if err != nil {
		return err
	}
	return s.Store.SetConfig(configStandingWatchers, string(b))
}

// EntityKind is "individual" unless the owner is an organisation.
func (s *Service) EntityKind() string {
	if s.Store != nil {
		if v, _ := s.Store.GetConfig(configEntityKind); v == EntityOrganisation {
			return EntityOrganisation
		}
	}
	return EntityIndividual
}

// StandingPolicyMet says whether the standing watchers give the entity the
// coverage it is advised: individuals have no minimum (the default plus peers);
// an organisation asks at least OrgMinWatchers.
func (s *Service) StandingPolicyMet() bool {
	return s.EntityKind() != EntityOrganisation || len(s.StandingWatchers()) >= OrgMinWatchers
}

type standingAnswer struct {
	w       StandingWatcher
	outcome string // match, mismatch, unknown, unavailable; then, for a mismatch once judged: fork, faulty, ahead, behind, superseded
	resp    *DigestResponse
	proof   *proof
	// later is a watcher that agrees at the presented tip yet holds an event after
	// it: the presented log may be stale.
	later bool
}

// askStanding asks every standing watcher for its digest at seq.
func (s *Service) askStanding(ctx context.Context, aid string, seq int, digest string, result *VerifyKelResult) []standingAnswer {
	var out []standingAnswer
	for _, w := range s.StandingWatchers() {
		resp, latency, err := s.L2.QueryDigest(ctx, w.URL, aid, seq)
		a := standingAnswer{w: w, outcome: "unknown", resp: resp}
		if err != nil {
			a.outcome = "unavailable"
			a.resp = nil
			s.emit("kel_l2_query_latency", map[string]interface{}{
				"url": w.URL, "error": err.Error(), "latency_ms": latency.Milliseconds(),
			})
		} else {
			switch {
			case resp.Digest == nil:
			case *resp.Digest == digest:
				a.outcome = "match"
				// A watcher that agrees at the tip may hold events after it. The
				// digest at the next place says so, and the log it then shows
				// either carries a later key state or is judged like any other.
				if next, _, err := s.L2.QueryDigest(ctx, w.URL, aid, seq+1); err == nil && next.Digest != nil {
					a.later = true
				}
			default:
				a.outcome = "mismatch"
			}
		}
		out = append(out, a)
	}
	return out
}

// judge settles a watcher's mismatch by asking it for its log and proving what
// differs. A mismatch that cannot be proven stays "mismatch": the watcher
// disagrees, nothing shows who is right, and that is shown, not acted on.
func (s *Service) judge(ctx context.Context, in VerifyKelInput, a *standingAnswer) {
	if a.outcome != "mismatch" && !a.later {
		return
	}
	if len(in.Signed) == 0 {
		a.proof = &proof{Kind: proofUnprovable, Reason: "the presented log came without its signed bytes: " + in.NotSigned}
		return
	}
	theirs, err := s.L2.FetchLog(ctx, a.w.URL, in.AID)
	if err != nil {
		a.proof = &proof{Kind: proofUnprovable, Reason: "the watcher would not show its log: " + err.Error()}
		return
	}
	p := judgeWatcherLog(in.AID, in.Signed, theirs)
	a.proof = &p
	if a.later && p.Kind != proofAhead && p.Kind != proofSuperseded && p.Kind != proofFork && p.Kind != proofWatcherFaulty {
		return // it agrees where it matters, and nothing later changes that
	}
	switch p.Kind {
	case proofFork:
		a.outcome = "fork"
		p.Evidence.Watcher = a.w.URL
	case proofWatcherFaulty:
		a.outcome = "faulty"
	case proofAhead:
		a.outcome = "ahead"
		p.LatestRecords = recordsFor(in.Signed, in.KEL, theirs, p.LatestMessages)
	case proofSuperseded:
		a.outcome = "superseded"
		p.LatestRecords = recordsFor(in.Signed, in.KEL, theirs, p.LatestMessages)
	case proofWatcherBehind:
		a.outcome = "behind"
	}
}

// recordsFor is an adopted log's messages as records: each is the presented
// log's own record where the presented log holds that event, otherwise the
// watcher's.
func recordsFor(presented [][]byte, presentedRecs []map[string]interface{}, theirs *WatcherLog, messages [][]byte) []map[string]interface{} {
	by := map[string]map[string]interface{}{}
	for i, m := range theirs.Messages {
		if i < len(theirs.Records) {
			by[string(m)] = theirs.Records[i]
		}
	}
	for i, m := range presented {
		if i < len(presentedRecs) {
			by[string(m)] = presentedRecs[i]
		}
	}
	out := make([]map[string]interface{}, 0, len(messages))
	for _, m := range messages {
		rec, ok := by[string(m)]
		if !ok {
			return nil
		}
		out = append(out, rec)
	}
	// Whatever the watcher served beside the bytes (parsed fields, event text) is
	// not covered by the signatures, so each record is rebuilt from the verified
	// bytes alone.
	rebuilt, ok := drivers.RecordsFromVerifiedBytes(out)
	if !ok {
		return nil
	}
	return rebuilt
}
