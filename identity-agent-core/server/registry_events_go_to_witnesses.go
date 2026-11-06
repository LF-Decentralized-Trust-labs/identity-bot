package server

import (
	"context"
	"encoding/base64"
	"log"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A registry event this identity makes (a registry's inception, an issuance, a
// revocation) is sent to the witnesses its key log names, so that someone
// outside can read it from them (SEAM-13 §3: POST /witness/tel/{issuer_aid}).
// Without it a credential this agent issues can be checked only by someone who
// was handed the log.
//
// IT NEVER FAILS AN ISSUANCE. The event is first kept, with its anchor, as
// always (keepTELCommit); sending it is a consequence of that and is not part
// of it. A witness that cannot be reached, or does not yet hold the key-log
// event that anchors the registry event (it refuses an event it cannot see
// sealed), only means the event stays in an outbox (store.TELPush).
//
// HOW IT IS RETRIED. The outbox is drained by the witnessing worker straight
// after it has brought the witnesses' copy of the key log up to date, which is
// when the first attempt can succeed, and again on every tick (the worker is
// kicked from the tick), for as long as anything waits. An event leaves the
// outbox when every witness the key log names holds it; sending one a witness
// already has is a no-op there. After telPushGiveUpAfter an event is dropped
// with a log line: the log itself is kept either way, and a verifier who is
// handed it still has it.

const (
	telPushGiveUpAfter = 14 * 24 * time.Hour
	telPushBatch       = 256
)

// queueTELPush records an event just kept for sending and asks the witnessing
// worker to run. A failure to queue is logged and nothing more: the event is
// kept, and what is not queued is not lost, only not yet findable from outside.
func (s *CoreServer) queueTELPush(aid, said, kind string, raw []byte) {
	if s.DataStore == nil {
		return
	}
	err := s.DataStore.EnqueueTELPush(store.TELPush{
		IssuerAID: aid, SAID: said, Kind: kind, RawB64: base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		log.Printf("[witness] registry event %s was kept but could not be queued for the witnesses: %v", said, err)
		return
	}
	s.witnessOwnLog()
}

// backfillRegistryEvents queues, once, every registry event this agent kept
// before the outbox existed, so the witnesses of each issuer come to hold the
// whole of its log and not only what it makes from now on. It is the same
// queue as any other event, so it is retried, and sending an event a witness
// already holds is a no-op there; running it twice would only queue what is
// already queued, and the mark kept in the store stops it being run again.
// Every issuer is covered, a pairwise identity's registry as much as the
// owner's (SEAM-13 section 2). A registry kept without its inception's bytes
// cannot be sent and is left out.
func (s *CoreServer) backfillRegistryEvents() {
	if s.DataStore == nil {
		return
	}
	if done, err := s.DataStore.TELBackfillDone(); err != nil || done {
		return
	}
	regs, err := s.DataStore.ListRegistries()
	if err != nil {
		log.Printf("[witness] registry events made earlier could not be listed: %v", err)
		return
	}
	for _, r := range regs {
		if r.VcpRawB64 == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(r.VcpRawB64)
		if err != nil {
			continue
		}
		ev, err := keri.VerifyTELEvent(raw)
		if err != nil {
			continue
		}
		queue := []store.TELPush{{IssuerAID: r.IssuerAID, SAID: ev.SAID, Kind: "vcp", RawB64: r.VcpRawB64}}
		events, err := s.DataStore.GetRegistryTEL(r.RegistrySAID)
		if err != nil {
			log.Printf("[witness] the log of registry %s could not be read: %v", r.RegistrySAID, err)
			return // not marked done: the next start tries again
		}
		for _, e := range events {
			queue = append(queue, store.TELPush{IssuerAID: r.IssuerAID, SAID: e.SAID, Kind: e.Kind, RawB64: e.RawB64})
		}
		for _, p := range queue {
			if err := s.DataStore.EnqueueTELPush(p); err != nil {
				log.Printf("[witness] event %s could not be queued: %v", p.SAID, err)
				return
			}
		}
	}
	if err := s.DataStore.MarkTELBackfillDone(); err != nil {
		log.Printf("[witness] could not record that earlier registry events were queued: %v", err)
	}
	s.witnessOwnLog()
}

// witnessIssuersOfWaitingEvents brings the witnesses of every identity that
// has a registry event waiting up to date with that identity's key log: the
// owner's, and a pairwise identity's too, whose TEL is served by that
// identity's own witnesses (SEAM-13 section 2). A witness refuses a registry
// event whose sealing key-log event it does not hold.
func (s *CoreServer) witnessIssuersOfWaitingEvents(ctx context.Context, already map[string]bool) {
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok || s.DataStore == nil || s.WitnessService == nil {
		return
	}
	pending, err := s.DataStore.PendingTELPushes(telPushBatch)
	if err != nil {
		return
	}
	for _, p := range pending {
		if already[p.IssuerAID] {
			continue
		}
		already[p.IssuerAID] = true
		witnesses, toad, err := keeper.WitnessConfig(p.IssuerAID)
		if err != nil || len(witnesses) == 0 {
			continue
		}
		s.WitnessService.BringUpToDate(ctx, p.IssuerAID, s.signedEventsOf(p.IssuerAID), witnesses, toad)
	}
}

// pushRegistryEvents sends what waits in the outbox to the issuer's witnesses.
// It reports to the log and returns; nothing waits on it.
func (s *CoreServer) pushRegistryEvents(ctx context.Context) {
	keeper, ok := s.KeriDriver.(drivers.KELKeeper)
	if !ok || s.DataStore == nil || s.WitnessService == nil {
		return
	}
	if n, err := s.DataStore.DropStaleTELPushes(time.Now().Add(-telPushGiveUpAfter).UTC().Format(time.RFC3339Nano)); err == nil && n > 0 {
		log.Printf("[witness] gave up sending %d registry events that waited more than %s", n, telPushGiveUpAfter)
	}
	pending, err := s.DataStore.PendingTELPushes(telPushBatch)
	if err != nil || len(pending) == 0 {
		return
	}
	byIssuer := map[string][]store.TELPush{}
	var order []string
	for _, p := range pending {
		if _, seen := byIssuer[p.IssuerAID]; !seen {
			order = append(order, p.IssuerAID)
		}
		byIssuer[p.IssuerAID] = append(byIssuer[p.IssuerAID], p)
	}
	for _, issuer := range order {
		events := byIssuer[issuer]
		designated, _, err := keeper.WitnessConfig(issuer)
		if err != nil || len(designated) == 0 {
			continue // nobody to send to yet
		}
		var raws [][]byte
		var saids []string
		for _, p := range events {
			raw, err := base64.StdEncoding.DecodeString(p.RawB64)
			if err != nil {
				continue
			}
			if _, err := keri.VerifyTELEvent(raw); err != nil {
				continue
			}
			raws = append(raws, raw)
			saids = append(saids, p.SAID)
		}
		held, err := s.WitnessService.PublishTEL(ctx, issuer, raws, designated)
		if held >= len(designated) {
			_ = s.DataStore.FinishTELPushes(issuer, saids)
			continue
		}
		reason := "no witness answered"
		if err != nil {
			reason = err.Error()
		}
		_ = s.DataStore.FailedTELPush(issuer, saids, reason)
		log.Printf("[witness] %d of %d witnesses hold the registry events of %s; will retry: %s", held, len(designated), issuer, reason)
	}
}
