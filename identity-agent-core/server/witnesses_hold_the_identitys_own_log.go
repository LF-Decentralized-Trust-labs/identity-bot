package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"identity-agent-core/drivers"
	"identity-agent-core/recovery"
	"identity-agent-core/witness"
	"log"
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
	// sendMu is held while a key log is read and sent to its witnesses, and by
	// whatever must know no send is in flight: discarding unsigned events asks
	// the witnesses what they hold and sets the events aside under it, so a
	// send that read them cannot reach a witness between the answer and the
	// discard.
	sendMu sync.Mutex
	// witnessJobs is what each pass brings up to date, one job per identity
	// asked for: the identity kept here, and any root it was moved on from.
	witnessJobs map[string]witnessJob
	// movedOnTries is how often, and until when not again, the witnesses of a
	// root this core rotated away from have been tried and not held its log.
	movedOnTries map[string]movedOnTry
	// movedOnEnded are the roots whose witnessing finished in this run, marked
	// under witnessMu before the job goes, so a pass that read the root map
	// before it finished cannot add the job back.
	movedOnEnded map[string]bool
	// afterMovedOnRead is called by a test between a pass reading the root map
	// and acting on it.
	afterMovedOnRead func()
}

type movedOnTry struct {
	attempts  int
	notBefore time.Time
}

// A witness of a root that was moved on from may be gone for good, and it is
// not contacted for ever: each pass that finds the log not held waits longer
// than the one before, up to movedOnLongestBackoff, and after
// movedOnGiveUpAfter such passes this core stops and records that it did.
var (
	movedOnBackoff        = 30 * time.Second
	movedOnLongestBackoff = time.Hour
	movedOnGiveUpAfter    = 12
)

// witnessClock is the time the backoff is judged by; a test replaces it.
var witnessClock = time.Now

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
	s.addWitnessJob(ownerAID, recordAID, witnesses, toad, false)
}

// addWitnessJob is witnessRecord; with movedOn it adds nothing for a root whose
// witnessing has ended, judged under the lock the job is added under.
func (s *CoreServer) addWitnessJob(ownerAID, recordAID string, witnesses []string, toad int, movedOn bool) {
	if len(witnesses) == 0 || s.WitnessService == nil {
		return
	}
	s.witnessing.witnessMu.Lock()
	if movedOn && s.witnessing.movedOnEnded[ownerAID] {
		s.witnessing.witnessMu.Unlock()
		return
	}
	job := witnessJob{owner: ownerAID, record: recordAID, witnesses: witnesses, toad: toad}
	// A request for the identity's own log alone does not drop a record
	// identity a pass is already due to send.
	if job.record == "" {
		job.record = s.witnessing.witnessJobs[ownerAID].record
	}
	if s.witnessing.witnessJobs == nil {
		s.witnessing.witnessJobs = map[string]witnessJob{}
	}
	s.witnessing.witnessJobs[ownerAID] = job
	s.witnessing.witnessMu.Unlock()
	s.kickWitnessing()
}

// kickWitnessing asks the witnessing worker for one more pass, starting it
// the first time.
func (s *CoreServer) kickWitnessing() {
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
		jobs := make([]witnessJob, 0, len(s.witnessing.witnessJobs))
		for _, job := range s.witnessing.witnessJobs {
			jobs = append(jobs, job)
		}
		s.witnessing.witnessMu.Unlock()
		movedOn := s.rootsMovedOnToWitness()
		ctx, cancel := context.WithTimeout(running, time.Minute)
		done := map[string]bool{}
		for _, job := range jobs {
			events, held := s.sendLogToWitnesses(ctx, job.owner, job.witnesses, job.toad)
			done[job.owner] = true
			if job.record != "" {
				s.sendLogToWitnesses(ctx, job.record, job.witnesses, job.toad)
				done[job.record] = true
			}
			if entry, ok := movedOn[job.owner]; ok {
				// An old root's rotation is held once the witnesses its
				// threshold asks for hold it; one of three gone for good is
				// not a reason to go on trying, or to give up.
				held = held || s.WitnessService.HoldsThreshold(job.owner, events, job.witnesses, job.toad)
				// A try counts as not held only once no send to these
				// witnesses is in flight and their own tips say so; while
				// one is, nothing is concluded and the job stays.
				settled := true
				if !held {
					held, settled = s.WitnessService.HeldThrough(ctx, job.owner, events, job.witnesses, job.toad)
				}
				if settled {
					s.endOrDelayMovedOn(entry, held)
				}
			}
		}
		// The key log is where each witness needs it to be before it will take
		// a registry event that log seals, for every identity that issues,
		// pairwise ones included.
		s.witnessIssuersOfWaitingEvents(ctx, done)
		s.pushRegistryEvents(ctx)
		cancel()
	}
}

// sendLogToWitnesses reads an identity's key log and brings its witnesses up to
// date with it, as one step under sendMu: what was read is what is sent, and
// nothing that must know no send is in flight can overlap it. It returns the
// log it sent and whether the witnesses hold it.
func (s *CoreServer) sendLogToWitnesses(ctx context.Context, aid string, witnesses []string, toad int) ([]witness.SignedEvent, bool) {
	s.witnessing.sendMu.Lock()
	defer s.witnessing.sendMu.Unlock()
	events := s.signedEventsOf(aid)
	return events, s.WitnessService.BringUpToDate(ctx, aid, events, witnesses, toad)
}

// signedEventsOf is an identity's key log as published and signed.
func (s *CoreServer) signedEventsOf(aid string) []witness.SignedEvent {
	events, err := s.DataStore.GetEvents(aid)
	if err != nil {
		return nil
	}
	out := make([]witness.SignedEvent, 0, len(events))
	for _, ev := range events {
		out = append(out, witness.SignedEvent{RawBytesB64: ev.RawBytesB64,
			CesrSignature: ev.CesrSignature, Signatures: ev.ControllerSignatures()})
	}
	return out
}

// designationAfter is the witnesses an identity's key log designates, and the
// threshold it asks of them, once ev is in it. Read from the log by the same
// rule everything else uses (witnessesAfter), so an identity founded when the
// registry listed more witnesses keeps reaching, and counting receipts from,
// every one it designates. ev may already be in the log, or be the next event
// to go in; it is applied once either way. A nil ev reads the log as it stands.
func (s *CoreServer) designationAfter(aid string, ev map[string]interface{}) ([]string, int) {
	if s.DataStore == nil {
		return nil, 0
	}
	events, _ := s.DataStore.GetEvents(aid)
	evD, _ := ev["d"].(string)
	var current []string
	toad := 0
	apply := func(parsed map[string]interface{}) {
		if next, ok := witnessesAfter(current, parsed); ok {
			current = next
			toad = thresholdOf(parsed["bt"])
		}
	}
	for _, e := range events {
		raw, _ := base64.StdEncoding.DecodeString(e.RawBytesB64)
		var parsed map[string]interface{}
		if json.Unmarshal(raw, &parsed) != nil {
			continue
		}
		if d, _ := parsed["d"].(string); evD != "" && d == evD {
			break
		}
		apply(parsed)
	}
	if ev != nil {
		apply(ev)
	}
	if toad < 0 {
		toad = 0
	}
	return current, toad
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
	s.dropJobsOfOtherIdentities(owner.AID)
	s.witnessLogOf(keeper, owner.AID, false)
	s.witnessRootsMovedOn(keeper)
	// A pairwise identity's registry events may be waiting for its own
	// witnesses, whether or not the owner names any.
	if s.WitnessService != nil {
		if p, err := s.DataStore.PendingTELPushes(1); err == nil && len(p) > 0 {
			s.kickWitnessing()
		}
	}
}

// dropJobsOfOtherIdentities removes the own-log job of an identity that is no
// longer the one kept here (a restore replaced it in this process), so it is
// not sent on every pass until restart. A root moved on from has its own job
// and stays while that is open.
func (s *CoreServer) dropJobsOfOtherIdentities(kept string) {
	// The runs are read before the map: a run writes its map entry before it
	// forgets itself, so a root that is in neither list here had its entry
	// written and is in the map read next, never in neither.
	running := s.rootsInAnUnfinishedRun()
	open := s.rootsMovedOnToWitness()
	s.witnessing.witnessMu.Lock()
	defer s.witnessing.witnessMu.Unlock()
	for aid := range s.witnessing.witnessJobs {
		_, moved := open[aid]
		if aid != kept && !moved && !running[aid] {
			delete(s.witnessing.witnessJobs, aid)
		}
	}
}

// rootsInAnUnfinishedRun are the old roots of the break-glass runs begun and
// not finished. The identity record moves to the new root partway through a
// run and the root map entry is written at its end, so for that while the old
// root is neither the identity kept here nor yet a root moved on from, and its
// job is not dropped.
func (s *CoreServer) rootsInAnUnfinishedRun() map[string]bool {
	out := map[string]bool{}
	runs, err := recovery.RunningRootAIDRotations(s.DataDir)
	if err != nil {
		return out
	}
	for _, run := range runs {
		out[run.OldRootAID] = true
	}
	return out
}

// beginWitnessing is what a start does: a root this core gave up on is tried
// again, because its rotation is what tells that root's witnesses the old key is
// retired, and the tries already counted are forgotten.
func (s *CoreServer) beginWitnessing() {
	s.witnessing.witnessMu.Lock()
	s.witnessing.movedOnTries = nil
	s.witnessing.movedOnEnded = nil
	s.witnessing.witnessMu.Unlock()
	if s.DataDir == "" {
		return
	}
	if err := recovery.ClearRootAIDWitnessingGaveUp(s.DataDir); err != nil {
		log.Printf("[witness] could not reopen the witnessing of the roots given up on: %v", err)
	}
}

// rootsMovedOnToWitness are the roots this core rotated away from by
// break-glass whose witnesses are still to be brought up to date, by old root.
// Only an entry the signed rotation wrote counts: break-glass was ungated, and
// wrote this file with no signature on the rotation, before 746602a8
// (2026-06-21), and an install from then would otherwise start sending
// witnesses the possibly unsigned logs of those old roots on every tick.
func (s *CoreServer) rootsMovedOnToWitness() map[string]recovery.RootAIDMapEntry {
	out := map[string]recovery.RootAIDMapEntry{}
	if s.DataDir == "" {
		return out
	}
	moved, err := recovery.LoadRootAIDMap(s.DataDir)
	if err != nil {
		return out
	}
	for _, entry := range moved.Entries {
		if entry.WitnessingIsOpen() {
			out[entry.OldRootAID] = entry
		}
	}
	return out
}

// witnessRootsMovedOn brings up to date the witnesses of every root this core
// rotated away from by break-glass, until they hold the rotation. The identity
// kept here is the new root by then, so the pass above does not reach the old
// one, whose last event is the rotation. A witness that already holds the log
// is not asked again, a root that names no witness has nothing to send, and
// one whose witnesses never hold the log is given up on (movedOnGiveUpAfter).
func (s *CoreServer) witnessRootsMovedOn(keeper drivers.KELKeeper) {
	open := s.rootsMovedOnToWitness()
	s.witnessing.witnessMu.Lock()
	hook := s.witnessing.afterMovedOnRead
	s.witnessing.witnessMu.Unlock()
	if hook != nil {
		hook()
	}
	for aid, entry := range open {
		s.witnessing.witnessMu.Lock()
		waiting := witnessClock().Before(s.witnessing.movedOnTries[aid].notBefore)
		s.witnessing.witnessMu.Unlock()
		if waiting {
			continue
		}
		witnesses, toad, err := keeper.WitnessConfig(aid)
		if err != nil {
			continue
		}
		if len(witnesses) == 0 {
			s.endMovedOn(entry, false)
			continue
		}
		s.addWitnessJob(aid, "", witnesses, toad, true)
	}
}

// endOrDelayMovedOn is what a pass that tried a moved-on root's witnesses
// concludes: they hold the log and the job ends, or they do not and it is tried
// again later, or no more.
func (s *CoreServer) endOrDelayMovedOn(entry recovery.RootAIDMapEntry, held bool) {
	if held {
		s.endMovedOn(entry, false)
		return
	}
	s.witnessing.witnessMu.Lock()
	if s.witnessing.movedOnTries == nil {
		s.witnessing.movedOnTries = map[string]movedOnTry{}
	}
	try := s.witnessing.movedOnTries[entry.OldRootAID]
	try.attempts++
	gaveUp := try.attempts >= movedOnGiveUpAfter
	wait := movedOnBackoff
	for i := 1; i < try.attempts && wait < movedOnLongestBackoff; i++ {
		wait *= 2
	}
	if wait > movedOnLongestBackoff {
		wait = movedOnLongestBackoff
	}
	try.notBefore = witnessClock().Add(wait)
	// The job leaves the list now and is added again only after notBefore, so
	// passes that other work asks for do not count as tries.
	delete(s.witnessing.witnessJobs, entry.OldRootAID)
	s.witnessing.movedOnTries[entry.OldRootAID] = try
	s.witnessing.witnessMu.Unlock()
	if gaveUp {
		log.Printf("[witness] the witnesses of %s, which this core rotated away from, still do not hold its log after %d tries; giving up",
			entry.OldRootAID, try.attempts)
		s.endMovedOn(entry, true)
	}
}

// endMovedOn ends the job that sends a moved-on root's log to its witnesses and
// records, in the root map, why it ended.
func (s *CoreServer) endMovedOn(entry recovery.RootAIDMapEntry, gaveUp bool) {
	s.witnessing.witnessMu.Lock()
	if s.witnessing.movedOnEnded == nil {
		s.witnessing.movedOnEnded = map[string]bool{}
	}
	s.witnessing.movedOnEnded[entry.OldRootAID] = true
	delete(s.witnessing.witnessJobs, entry.OldRootAID)
	delete(s.witnessing.movedOnTries, entry.OldRootAID)
	s.witnessing.witnessMu.Unlock()
	if err := recovery.RecordRootAIDWitnessing(s.DataDir, entry.OldRootAID, entry.AuthorizationEventSAID, gaveUp, time.Now()); err != nil {
		log.Printf("[witness] could not record how the witnessing of %s ended: %v", entry.OldRootAID, err)
	}
}

// witnessLogOf brings the witnesses of aid up to date with its log: the
// identity kept here, or, with movedOn, a root it was just moved on from, whose
// job is not added once its witnessing has ended.
func (s *CoreServer) witnessLogOf(keeper drivers.KELKeeper, aid string, movedOn bool) {
	if witnesses, toad, err := keeper.WitnessConfig(aid); err == nil && len(witnesses) > 0 {
		s.addWitnessJob(aid, "", witnesses, toad, movedOn)
	}
}
