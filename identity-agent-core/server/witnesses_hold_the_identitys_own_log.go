package server

import (
	"context"
	"identity-agent-core/drivers"
	"identity-agent-core/witness"
	"sync"
	"time"
)

// The identity's witnesses are kept up to date with its key log.
//
// Every Identity Agent does this, whether or not it anchors a record: after it
// appends to its log, and on every tick, so no witness is left with a gap it
// would have to hold the next event back for. An Identity Agent that anchors
// its record through a record identity asks for that identity's log to be
// sent in the same pass.

// witnessState is the one witnessing worker.
type witnessState struct {
	// One witnessing worker at a time: a request while it runs is coalesced
	// into one more pass, which reads the key logs as they are then, so the
	// newest anchoring is always sent and never overtaken by an older one.
	witnessOnce sync.Once
	witnessKick chan struct{}
	witnessMu   sync.Mutex
	witnessJob  witnessJob
}

type witnessJob struct {
	owner, record string
	witnesses     []string
	toad          int
}

// witnessRecord brings the record identity's witnesses up to date: first with
// this identity's own key log, so they hold its approval of the record
// identity, in order, then with the record identity's. A witness that holds
// the approval witnesses the record identity from its inception. Nothing to
// do where it names none.
func (s *CoreServer) witnessRecord(ownerAID, recordAID string, witnesses []string, toad int) {
	if len(witnesses) == 0 || s.WitnessService == nil {
		return
	}
	s.witnessing.witnessMu.Lock()
	job := witnessJob{owner: ownerAID, record: recordAID, witnesses: witnesses, toad: toad}
	// A request for the identity's own log alone does not drop a record
	// identity a pass is already due to send.
	if job.record == "" {
		job.record = s.witnessing.witnessJob.record
	}
	s.witnessing.witnessJob = job
	s.witnessing.witnessMu.Unlock()
	s.witnessing.witnessOnce.Do(func() {
		s.witnessing.witnessKick = make(chan struct{}, 1)
		s.anchorStopMu.Lock()
		stop := s.anchorStop
		s.anchorStopMu.Unlock()
		s.inBackground(func(ctx context.Context) { s.keepWitnessing(ctx, stop) })
	})
	select {
	case s.witnessing.witnessKick <- struct{}{}:
	default: // a pass is already due, and will read the newest
	}
}

// keepWitnessing runs one witnessing pass per request, one at a time.
func (s *CoreServer) keepWitnessing(running context.Context, stop <-chan struct{}) {
	for {
		// stop is nil when the worker was started after the anchoring loop
		// stopped, and a nil channel never closes, so it also ends with the
		// server's background work.
		select {
		case <-stop:
			return
		case <-running.Done():
			return
		case <-s.witnessing.witnessKick:
		}
		s.witnessing.witnessMu.Lock()
		job := s.witnessing.witnessJob
		s.witnessing.witnessMu.Unlock()
		ctx, cancel := context.WithTimeout(running, time.Minute)
		s.WitnessService.BringUpToDate(ctx, job.owner, s.signedEventsOf(job.owner), job.witnesses, job.toad)
		if job.record != "" {
			s.WitnessService.BringUpToDate(ctx, job.record, s.signedEventsOf(job.record), job.witnesses, job.toad)
		}
		cancel()
	}
}

// signedEventsOf is an identity's key log as published and signed.
func (s *CoreServer) signedEventsOf(aid string) []witness.SignedEvent {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		return nil
	}
	out := make([]witness.SignedEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, witness.SignedEvent{RawBytesB64: ev.RawBytesB64, CesrSignature: ev.CesrSignature})
	}
	return out
}

// witnessOwnLog brings the identity's witnesses up to date with its own key
// log: every Identity Agent, whether or not it anchors a record, after it
// appends to its log and on every tick, so no witness is left with a gap it
// would have to hold the next event back for.
func (s *CoreServer) witnessOwnLog() {
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok || s.DataStore == nil {
		return
	}
	owner, err := s.DataStore.GetIdentity()
	if err != nil || owner == nil {
		return
	}
	if witnesses, toad, err := keeper.WitnessConfig(owner.AID); err == nil && len(witnesses) > 0 {
		s.witnessRecord(owner.AID, "", witnesses, toad)
	}
}
