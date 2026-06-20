package witness

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/store"
)

type capturePoster struct {
	mu    sync.Mutex
	posts []struct {
		URL  string
		Body []byte
	}
}

func (c *capturePoster) post(ctx context.Context, url string, body []byte) (map[string]interface{}, error) {
	c.mu.Lock()
	c.posts = append(c.posts, struct {
		URL  string
		Body []byte
	}{url, append([]byte(nil), body...)})
	c.mu.Unlock()
	return map[string]interface{}{"ok": true}, nil
}

func (c *capturePoster) lastAccept() AcceptCallback {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.posts) - 1; i >= 0; i-- {
		if strings.Contains(c.posts[i].URL, "/api/witness/accept") {
			var cb AcceptCallback
			_ = json.Unmarshal(c.posts[i].Body, &cb)
			return cb
		}
	}
	return AcceptCallback{}
}

func agentService(t *testing.T, aid string, mc *memContacts) *Service {
	t.Helper()
	st := setupTestSQLite(t)
	s := NewService(st, mc, nil, BackendDesktop)
	s.OurAID = func() string { return aid }
	s.OurOOBI = func() string { return "http://127.0.0.1:5050/public/oobi/" + aid }
	return s
}

func TestMutualEnrollmentPostBack(t *testing.T) {
	aidA := "EAgentA00000000000000000000000000001"
	aidB := "EAgentB00000000000000000000000000002"

	mcA := &memContacts{
		contacts: map[string]store.ContactRecord{
			aidB: {AID: aidB, Alias: "B", Status: "accepted", ContactType: "trusted",
				OobiURL: "http://127.0.0.1:5051/public/oobi/" + aidB},
		},
		identity: &store.IdentityState{AID: aidA},
	}
	mcB := &memContacts{
		contacts: map[string]store.ContactRecord{
			aidA: {AID: aidA, Alias: "A", Status: "accepted", ContactType: "trusted",
				OobiURL: "http://127.0.0.1:5050/public/oobi/" + aidA},
		},
		identity: &store.IdentityState{AID: aidB},
	}

	cap := &capturePoster{}
	sA := agentService(t, aidA, mcA)
	sB := agentService(t, aidB, mcB)
	sA.PostEvent = cap.post
	sB.PostEvent = cap.post

	// A sends outbound request to B.
	if err := sA.SendWitnessRequest(context.Background(), aidB); err != nil {
		t.Fatal(err)
	}

	// B receives the enrollment request and POSTs accept back to A.
	result := sB.ProcessInboundRequest(context.Background(), WitnessRequest{
		RequesterAID: aidA, RequesterOOBI: sA.OurOOBI(), BackendType: BackendDesktop,
	})
	if !result.Accepted {
		t.Fatalf("B should accept A: %s", result.Reason)
	}

	time.Sleep(50 * time.Millisecond)
	cb := cap.lastAccept()
	if cb.Decision != "accepted" || cb.RequesterAID != aidA || cb.ResponderAID != aidB {
		t.Fatalf("POST-back wrong: %+v", cb)
	}
	if !strings.HasSuffix(cap.posts[len(cap.posts)-1].URL, "/api/witness/accept") {
		t.Fatalf("expected accept URL, got %s", cap.posts[len(cap.posts)-1].URL)
	}

	// A receives the accept callback — B is now A's witness.
	if err := sA.ApplyAcceptCallback(cb); err != nil {
		t.Fatal(err)
	}
	cB, _ := mcA.GetContact(aidB)
	if cB == nil || !cB.IsWitness {
		t.Fatal("A must enroll B as witness-for-us after accept")
	}

	metaB, _ := sB.Store.GetContactMeta(aidA)
	if metaB == nil || !metaB.WitnessingFor {
		t.Fatal("B must witness-for A after inbound accept")
	}
}

func TestInboundDeclinePostsBack(t *testing.T) {
	aidA := "EAgentA00000000000000000000000000003"
	aidU := "EUnknown00000000000000000000000000004"
	mcB := &memContacts{
		contacts: map[string]store.ContactRecord{},
		identity: &store.IdentityState{AID: "EAgentB00000000000000000000000000005"},
	}
	cap := &capturePoster{}
	sB := agentService(t, mcB.identity.AID, mcB)
	sB.PostEvent = cap.post

	result := sB.ProcessInboundRequest(context.Background(), WitnessRequest{
		RequesterAID: aidU, RequesterOOBI: "http://127.0.0.1:5050/public/oobi/" + aidA, BackendType: BackendDesktop,
	})
	if result.Accepted {
		t.Fatal("unknown contact must decline")
	}
	time.Sleep(50 * time.Millisecond)
	cb := cap.lastAccept()
	if cb.Decision != "declined" {
		t.Fatalf("want declined POST-back, got %+v", cb)
	}
}

func TestApplyAcceptCallbackCompletesTask(t *testing.T) {
	aidA := "EAgentA00000000000000000000000000006"
	aidB := "EAgentB00000000000000000000000000007"
	mcA := &memContacts{
		contacts: map[string]store.ContactRecord{
			aidB: {AID: aidB, Status: "accepted", ContactType: "trusted"},
		},
		identity: &store.IdentityState{AID: aidA},
		tasks: []store.TaskRecord{{
			ID: "t1", Type: "witness_request_sent", Status: "pending", ContactAID: aidB,
			CreatedAt: NowRFC3339(), UpdatedAt: NowRFC3339(),
		}},
	}
	sA := agentService(t, aidA, mcA)
	if err := sA.ApplyAcceptCallback(AcceptCallback{
		RequesterAID: aidA, ResponderAID: aidB, Decision: "accepted", BackendType: BackendDesktop,
	}); err != nil {
		t.Fatal(err)
	}
	tasks, _ := mcA.GetTasks()
	if len(tasks) != 1 || tasks[0].Status != "completed" {
		t.Fatalf("task=%+v", tasks)
	}
}