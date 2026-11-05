package witness

import (
	"context"
	"fmt"
	"testing"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

// An unsigned request is refused plainly whatever the decision would have
// been: no task, no enrolment, and nothing posted to the address it names.
func TestAnUnsignedRequestIsRefusedEvenWhereItWouldBeDeclined(t *testing.T) {
	const witnessID = "EWitness0000000000000000000000000000000000009"
	pub, _ := identityKey(t)
	attacker := "http://169.254.169.254/public/oobi/EVictim"
	cases := map[string]func(mc *memContacts, aid string){
		"unknown_contact": func(mc *memContacts, aid string) {},
		"contact_category_ineligible": func(mc *memContacts, aid string) {
			mc.contacts[aid] = store.ContactRecord{AID: aid, Status: "accepted", ContactCategory: "general", PublicKey: pub}
		},
		"capacity_full": func(mc *memContacts, aid string) {
			mc.contacts[aid] = store.ContactRecord{AID: aid, Status: "accepted", ContactCategory: "trusted", PublicKey: pub}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			aid := "ERequester" + name
			mc := &memContacts{contacts: map[string]store.ContactRecord{}, identity: &store.IdentityState{AID: witnessID}}
			setup(mc, aid)
			cap := &capturePoster{}
			w := agentService(t, witnessID, mc)
			w.PostEvent = cap.post
			if name == "capacity_full" {
				for i := 0; i < MaxOutgoingWitnessing; i++ {
					if err := w.Store.SaveContactMeta(ContactMeta{ContactAID: fmt.Sprintf("EOther%d", i), WitnessingFor: true}); err != nil {
						t.Fatal(err)
					}
				}
			}
			res := w.ProcessInboundRequest(context.Background(), WitnessRequest{
				RequesterAID: aid, RequesterOOBI: attacker, BackendType: BackendDesktop, RequestID: "victims-request",
			})
			want := "unsigned_request"
			if name == "unknown_contact" {
				want = "requester_key_unknown"
			}
			if res.Accepted || res.TaskID != "" || res.Reason != want {
				t.Fatalf("an unsigned request was processed: %+v", res)
			}
			time.Sleep(50 * time.Millisecond)
			if tasks, _ := mc.GetTasks(); len(tasks) != 0 {
				t.Fatalf("an unsigned request wrote tasks: %+v", tasks)
			}
			if len(cap.posts) != 0 {
				t.Fatalf("an unsigned request made this agent post to %s", cap.posts[0].URL)
			}
		})
	}
}

// A request whose backend type was changed after signing is not acted on.
func TestTheBackendTypeIsSigned(t *testing.T) {
	const aid = "ERequesterBackend00000000000000000000000000001"
	pub, seed := identityKey(t)
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{aid: {AID: aid, Status: "accepted", ContactCategory: "trusted", PublicKey: pub}},
		identity: &store.IdentityState{AID: "EWitness0000000000000000000000000000000000010"},
	}
	w := agentService(t, mc.identity.AID, mc)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	sig, _ := login.SignString(RequestStatement(aid, w.Identity(), "", BackendDesktop, "r", false, stamp), seed)
	req := WitnessRequest{RequesterAID: aid, BackendType: BackendMobile, RequestID: "r", Stamp: stamp, Signature: sig}
	if res := w.ProcessInboundRequest(context.Background(), req); res.Reason != "unsigned_request" {
		t.Fatalf("a request with a changed backend type was acted on: %+v", res)
	}
}

// A requester whose key is not held is refused with a reason that says so.
func TestARequesterWithNoKnownKeyIsToldSo(t *testing.T) {
	const aid = "ERequesterNoKey0000000000000000000000000000001"
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{aid: {AID: aid, Status: "accepted", ContactCategory: "trusted"}},
		identity: &store.IdentityState{AID: "EWitness0000000000000000000000000000000000011"},
	}
	w := agentService(t, mc.identity.AID, mc)
	if res := w.ProcessInboundRequest(context.Background(), WitnessRequest{RequesterAID: aid}); res.Reason != "requester_key_unknown" {
		t.Fatalf("got %+v", res)
	}
}

// The reason in an answer is signed: one changed in transit is refused.
func TestTheReasonInAnAnswerIsSigned(t *testing.T) {
	s, mc, key, seed := asked(t)
	cb := answerTo("sent", witnessAID, askerAID, key, "declined", seed, time.Now())
	cb.Reason = "send them your password"
	if err := s.ApplyAcceptCallback(cb); err == nil {
		t.Fatal("an answer with an altered reason was acted on")
	}
	nothingChanged(t, s, mc, witnessAID)
}

// A request sent more than a day ago is not answered late.
func TestALateAnswerIsRefused(t *testing.T) {
	s, mc, key, seed := asked(t)
	old := time.Now().Add(-requestLifetime - time.Minute).UTC().Format(time.RFC3339)
	mc.tasks[0].CreatedAt = old
	if err := s.ApplyAcceptCallback(answerTo("sent", witnessAID, askerAID, key, "accepted", seed, time.Now())); err == nil {
		t.Fatal("an answer to a request sent over a day ago was acted on")
	}
	if c, _ := mc.GetContact(witnessAID); c != nil && c.IsWitness {
		t.Fatal("a late answer enrolled the witness")
	}
}

// failingTasks fails to save a task once told to.
type failingTasks struct {
	*memContacts
	fail bool
}

func (f *failingTasks) SaveTask(t store.TaskRecord) error {
	if f.fail {
		return fmt.Errorf("disk full")
	}
	return f.memContacts.SaveTask(t)
}

// If the request cannot be marked done, the enrolment is undone and the same
// answer can still be used.
func TestAnEnrolmentIsUndoneIfTheRequestCannotBeCompleted(t *testing.T) {
	key, seed := witnessKey()
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{witnessAID: {AID: witnessAID, Status: "accepted", ContactCategory: "trusted"}},
		identity: &store.IdentityState{AID: askerAID},
		tasks: []store.TaskRecord{{ID: "sent", Type: "witness_request_sent", Status: "pending", ContactAID: witnessAID,
			CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339()}},
	}
	ft := &failingTasks{memContacts: mc}
	s := agentService(t, askerAID, mc)
	s.Contacts = ft
	s.RecordContactCapability(witnessAID, BackendDesktop, key, "")

	ft.fail = true
	if err := s.ApplyAcceptCallback(answerTo("sent", witnessAID, askerAID, key, "accepted", seed, time.Now())); err == nil {
		t.Fatal("the answer reported success though the request could not be completed")
	}
	nothingChanged(t, s, mc, witnessAID)

	ft.fail = false
	if err := s.ApplyAcceptCallback(answerTo("sent", witnessAID, askerAID, key, "accepted", seed, time.Now().Add(time.Second))); err != nil {
		t.Fatalf("the answer could not be used again after the failure: %v", err)
	}
	if c, _ := mc.GetContact(witnessAID); c == nil || !c.IsWitness {
		t.Fatal("the witness was not enrolled on the retry")
	}
}

// AskToCoverDelegatesOf sends the id of a request it has recorded.
func TestAskingToCoverDelegatesSendsARealRequestID(t *testing.T) {
	const wid = "EWitnessAsked0000000000000000000000000000000001"
	mc := &memContacts{
		contacts: map[string]store.ContactRecord{wid: {AID: wid, Status: "accepted", ContactCategory: "trusted", OobiURL: "http://127.0.0.1:5051/public/oobi/" + wid}},
		identity: &store.IdentityState{AID: askerAID},
	}
	cap := &capturePoster{}
	s := agentService(t, askerAID, mc)
	s.PostEvent = cap.post
	c, _ := mc.GetContact(wid)
	if _, err := s.sendRecordedRequest(context.Background(), c, true); err != nil {
		t.Fatal(err)
	}
	req := cap.lastRequest(t)
	tasks, _ := mc.GetTasks()
	if req.RequestID == "" || len(tasks) != 1 || tasks[0].ID != req.RequestID {
		t.Fatalf("request id %q does not name the recorded request: %+v", req.RequestID, tasks)
	}
}
