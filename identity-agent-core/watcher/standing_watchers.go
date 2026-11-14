package watcher

import (
	"context"
	"encoding/json"
	"log"
	"sync"

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
// An organisation is advised several (at least two, and five to seven); that is
// advice about reach (ADR-075), and nothing here counts or enforces it.

const configStandingWatchers = "standing_watchers"

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

type standingAnswer struct {
	w       StandingWatcher
	outcome string // match, mismatch, unknown, unavailable; then, for a mismatch once judged: fork, faulty, ahead, behind, superseded
	resp    *DigestResponse
	proof   *proof
	// later is a watcher that agrees at the presented tip yet holds an event after
	// it: the presented log may be stale.
	later bool
	// rival is a watcher that agrees at the presented tip yet says, in its signed
	// answer, that it holds a rival branch at or below it.
	rival bool
}

// askStanding asks every standing watcher for its digest at seq, all at once,
// so a slow watcher costs its own time and not the sum of the others'. The
// answers are in the order the watchers are listed.
func (s *Service) askStanding(ctx context.Context, aid string, seq int, digest string) []standingAnswer {
	ws := s.StandingWatchers()
	out := make([]standingAnswer, len(ws))
	var wg sync.WaitGroup
	for i, w := range ws {
		wg.Add(1)
		go func(i int, w StandingWatcher) {
			defer wg.Done()
			out[i] = s.askOneStanding(ctx, w, aid, seq, digest)
		}(i, w)
	}
	wg.Wait()
	return out
}

func (s *Service) askOneStanding(ctx context.Context, w StandingWatcher, aid string, seq int, digest string) standingAnswer {
	resp, latency, err := s.L2.QueryDigest(ctx, w.URL, aid, seq)
	a := standingAnswer{w: w, outcome: "unknown", resp: resp}
	if err != nil {
		a.outcome = "unavailable"
		a.resp = nil
		s.emit("kel_l2_query_latency", map[string]interface{}{
			"url": w.URL, "error": err.Error(), "latency_ms": latency.Milliseconds(),
		})
		return a
	}
	switch {
	case resp.Digest == nil:
	case *resp.Digest == digest:
		a.outcome = "match"
		a.rival = resp.RivalAtOrBelow
		// A watcher that agrees at the tip may hold events after it. The
		// digest at the next place says so, and the log it then shows
		// either carries a later key state or is judged like any other.
		if next, _, err := s.L2.QueryDigest(ctx, w.URL, aid, seq+1); err == nil && next.Digest != nil {
			a.later = true
		}
	default:
		a.outcome = "mismatch"
	}
	return a
}

// judge settles a watcher's mismatch by asking it for its log and proving what
// differs. A mismatch that cannot be proven stays "mismatch": the watcher
// disagrees, nothing shows who is right, and that is shown, not acted on.
func (s *Service) judge(ctx context.Context, in VerifyKelInput, a *standingAnswer) {
	if a.outcome != "mismatch" && !a.later && !a.rival {
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
	if (a.later || a.rival) && p.Kind != proofAhead && p.Kind != proofSuperseded && p.Kind != proofFork && p.Kind != proofWatcherFaulty {
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
		log.Printf("[watcher] a watcher's later log could not be rebuilt from its signed bytes; its key state is not adopted as records")
		return nil
	}
	return rebuilt
}

// aheadLog is a log some source holds that goes on from what was presented: the
// kept log (url empty) or a standing watcher's.
type aheadLog struct {
	messages [][]byte
	url      string
}

// reconcileAhead picks the log to go on with from every log that is ahead of
// the presented one, comparing them with each other, because choosing the
// longest would let a thief win by holding the longer branch. Two ahead logs
// that conflict and both verify are proof of a fork, and that is returned; one
// that supersedes the other by recovery wins; one that is only a part of the
// other is the shorter.
func reconcileAhead(aid string, cands []aheadLog) (best *aheadLog, fork *proof, forkURL string) {
	for i := range cands {
		c := cands[i]
		if best == nil {
			best = &c
			continue
		}
		p := judgeWatcherLog(aid, best.messages, &WatcherLog{Messages: c.messages})
		switch p.Kind {
		case proofFork:
			p.Evidence.Watcher = c.url
			if p.Evidence.Watcher == "" {
				p.Evidence.Watcher = best.url
			}
			return nil, &p, p.Evidence.Watcher
		case proofAhead, proofSuperseded:
			best = &aheadLog{messages: p.LatestMessages, url: c.url}
		}
	}
	return best, nil, ""
}
