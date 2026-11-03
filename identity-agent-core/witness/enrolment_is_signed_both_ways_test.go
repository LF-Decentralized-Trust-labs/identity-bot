package witness

import (
	"context"
	"testing"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

// A request to witness for someone changes nothing, and tells nobody anything,
// unless the requester's own key signed it, bound to the OOBI the answer goes to.
func TestAWitnessRequestIsActedOnOnlyIfTheRequesterSignedIt(t *testing.T) {
	const aid = "ERequester0000000000000000000000000000000003"
	pub, seed := identityKey(t)
	_, otherSeed := identityKey(t)
	oobi := "http://127.0.0.1:5050/public/oobi/" + aid
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{
			aid: {AID: aid, Status: "accepted", ContactCategory: "trusted", PublicKey: pub},
		},
		identity: &store.IdentityState{AID: "EWitness0000000000000000000000000000000000004"},
	}
	cap := &capturePoster{}
	w := agentService(t, mc.identity.AID, mc)
	w.PostEvent = cap.post

	sign := func(seed []byte, oobi, id string, at time.Time) WitnessRequest {
		stamp := at.UTC().Format(time.RFC3339Nano)
		sig, _ := login.SignString(RequestStatement(aid, w.Identity(), oobi, id, false, stamp), seed)
		return WitnessRequest{RequesterAID: aid, RequesterOOBI: oobi, BackendType: BackendDesktop, RequestID: id, Stamp: stamp, Signature: sig}
	}
	unsigned := WitnessRequest{RequesterAID: aid, RequesterOOBI: oobi, BackendType: BackendDesktop}
	for name, req := range map[string]WitnessRequest{
		"unsigned":    unsigned,
		"another key": sign(otherSeed, oobi, "r1", time.Now()),
		"stale":       sign(seed, oobi, "r1", time.Now().Add(-time.Hour)),
		"an oobi it did not sign": func() WitnessRequest {
			r := sign(seed, oobi, "r1", time.Now())
			r.RequesterOOBI = "http://attacker.test/public/oobi/" + aid
			return r
		}(),
		"another request id": func() WitnessRequest { r := sign(seed, oobi, "r1", time.Now()); r.RequestID = "r2"; return r }(),
	} {
		res := w.ProcessInboundRequest(context.Background(), req)
		if res.Accepted || res.Reason != "unsigned_request" {
			t.Fatalf("a request %s was not refused as unsigned: %+v", name, res)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if meta, _ := w.Store.GetContactMeta(aid); meta != nil && (meta.WitnessingFor || meta.EnrolledAt != "") {
		t.Fatalf("a refused request enrolled the requester: %+v", meta)
	}
	if tasks, _ := mc.GetTasks(); len(tasks) != 0 {
		t.Fatalf("a refused request left tasks behind: %+v", tasks)
	}
	if len(cap.posts) != 0 {
		t.Fatalf("a refused request made this agent post to %s", cap.posts[0].URL)
	}

	good := sign(seed, oobi, "r1", time.Now())
	if res := w.ProcessInboundRequest(context.Background(), good); !res.Accepted {
		t.Fatalf("the requester's own signed request was refused: %s", res.Reason)
	}
	if res := w.ProcessInboundRequest(context.Background(), good); res.Accepted || res.Reason != "unsigned_request" {
		t.Fatalf("a replay of the same signed request was acted on: %+v", res)
	}
}

// An answer is acted on only for the exact request it answers: one this agent
// sent and has not completed.
func TestAnAnswerMustNameTheRequestItAnswers(t *testing.T) {
	for name, id := range map[string]string{"no request named": "", "a request never sent": "forged", "a request to another": "other"} {
		s, mc, key, seed := asked(t)
		mc.tasks = append(mc.tasks, store.TaskRecord{ID: "other", Type: "witness_request_sent", Status: "pending", ContactAID: "EElse"})
		if err := s.ApplyAcceptCallback(answerTo(id, witnessAID, askerAID, key, "accepted", seed, time.Now())); err == nil {
			t.Fatalf("an answer with %s was acted on", name)
		}
		nothingChanged(t, s, mc, witnessAID)
	}

	s, mc, key, seed := asked(t)
	cb := answerTo("sent", witnessAID, askerAID, key, "accepted", seed, time.Now())
	cb.RequestID = "forged" // not what the witness signed
	if err := s.ApplyAcceptCallback(cb); err == nil {
		t.Fatal("an answer whose request id was altered after signing was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)

	if err := s.ApplyAcceptCallback(answerTo("sent", witnessAID, askerAID, key, "accepted", seed, time.Now())); err != nil {
		t.Fatalf("the real answer to the real request was refused: %v", err)
	}
	if err := s.ApplyAcceptCallback(answerTo("sent", witnessAID, askerAID, key, "accepted", seed, time.Now().Add(time.Second))); err == nil {
		t.Fatal("a second answer to a completed request was acted on")
	}
}
