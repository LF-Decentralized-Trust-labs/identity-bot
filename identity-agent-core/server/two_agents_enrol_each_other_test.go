package server

import (
	"context"
	"testing"
	"time"

	"identity-agent-core/store"
	"identity-agent-core/witness"
)

// Enrolment between two Identity Agents, over real HTTP: one asks, the other
// answers with a signed acceptance on a separate connection, and the asker
// enrols it. The answer can arrive before the request's own response does, so
// this is where an answer refused as unsolicited would show.
func TestTwoAgentsEnrolEachOtherOverTheWire(t *testing.T) {
	a, b := startPeer(t, "a"), startPeer(t, "b")
	aidA, aidB := "EAgentA0000000000000000000000000000000000001", "EAgentB0000000000000000000000000000000000002"
	for _, p := range []struct {
		peer *peerAgent
		aid  string
	}{{a, aidA}, {b, aidB}} {
		aid, base := p.aid, p.peer.base
		p.peer.svc.OurAID = func() string { return aid }
		p.peer.svc.OurOOBI = func() string { return base + "/public/oobi/" + aid }
	}
	// Each has the other as a trusted contact, with the witness key its OOBI
	// published.
	meet := func(self *peerAgent, other *peerAgent, otherAID string) {
		if err := self.svc.Contacts.SaveContact(store.ContactRecord{
			AID: otherAID, Alias: otherAID[:8], Status: "accepted", ContactCategory: "trusted",
			OobiURL: other.base + "/public/oobi/" + otherAID,
		}); err != nil {
			t.Fatal(err)
		}
		self.svc.RecordContactCapability(otherAID, witness.BackendDesktop, other.witnessKey, "individual")
	}
	meet(a, b, aidB)
	meet(b, a, aidA)

	if err := a.svc.SendWitnessRequest(context.Background(), aidB); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, _ := a.svc.Contacts.GetContact(aidB); c != nil && c.IsWitness {
			break
		}
		if time.Now().After(deadline) {
			tasks, _ := a.svc.Contacts.GetTasks()
			t.Fatalf("B's signed acceptance never enrolled it as A's witness; A's tasks: %+v", tasks)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if meta, _ := b.svc.Store.GetContactMeta(aidA); meta == nil || !meta.WitnessingFor {
		t.Fatal("B does not witness for A after accepting")
	}
}
