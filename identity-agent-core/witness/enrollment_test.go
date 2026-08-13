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

// acceptURL is where the accept was posted.
//
// The accept specifically, not whatever was posted last. Two services post here
// independently — one sending a request, the other accepting it — so which
// arrives last is not something the code decides, and asserting on it was
// asserting an ordering that does not exist. It held while the timings happened
// to line up and failed every run under the race detector.
//
// Through the lock, like everything else here. The test used to index c.posts
// directly while a service was still appending to it, which is a data race
// whether or not it was ever caught.
func (c *capturePoster) acceptURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.posts) - 1; i >= 0; i-- {
		if strings.Contains(c.posts[i].URL, "/api/witness/accept") {
			return c.posts[i].URL
		}
	}
	return ""
}

// lastURL is where the most recent post went, for saying what happened instead
// when something expected did not.
func (c *capturePoster) lastURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.posts) == 0 {
		return ""
	}
	return c.posts[len(c.posts)-1].URL
}

// waitForAccept waits until the accept has actually been posted.
//
// It used to be a 50ms sleep, which is a guess about how long another goroutine
// takes. That guess held until the race detector slowed everything down, and
// then the test asserted on the request that came before the accept and failed
// every run — so -race could not be used on this package at all, which is the
// one package whose work happens in background goroutines and therefore the one
// where a real race would hide.
//
// Waiting for the thing being asserted is both faster in the ordinary case and
// correct in the slow one.
func (c *capturePoster) waitForAccept(t *testing.T) AcceptCallback {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if cb := c.lastAccept(); cb.Decision != "" {
			return cb
		}
		if time.Now().After(deadline) {
			t.Fatalf("no accept was posted within 5s; last post went to %q", c.lastURL())
		}
		time.Sleep(2 * time.Millisecond)
	}
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
			aidB: {AID: aidB, Alias: "B", Status: "accepted", ContactCategory: "trusted",
				OobiURL: "http://127.0.0.1:5051/public/oobi/" + aidB},
		},
		identity: &store.IdentityState{AID: aidA},
	}
	mcB := &memContacts{
		contacts: map[string]store.ContactRecord{
			aidA: {AID: aidA, Alias: "A", Status: "accepted", ContactCategory: "trusted",
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

	cb := cap.waitForAccept(t)
	if cb.Decision != "accepted" || cb.RequesterAID != aidA || cb.ResponderAID != aidB {
		t.Fatalf("POST-back wrong: %+v", cb)
	}
	if !strings.HasSuffix(cap.acceptURL(), "/api/witness/accept") {
		t.Fatalf("the accept did not go to the accept route, it went to %q", cap.acceptURL())
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
			aidB: {AID: aidB, Status: "accepted", ContactCategory: "trusted"},
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
