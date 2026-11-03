package server

import (
	"encoding/json"
	"testing"

	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

// The address a stranger's request records is kept only if it names that
// stranger and is not a private address; the request is recorded either way.
func TestAStrangersAddressIsKeptOnlyIfItNamesTheStrangerAndIsNotPrivate(t *testing.T) {
	const aid = "EStrangerWhoNamesItself"
	cases := map[string]struct {
		oobi string
		kept bool
	}{
		"its own address":      {"https://peer.example/oobi/" + aid, true},
		"another AID":          {"https://peer.example/oobi/EVictim", false},
		"no AID at all":        {"https://peer.example/", false},
		"a loopback address":   {"http://127.0.0.1:8080/oobi/" + aid, false},
		"localhost":            {"http://localhost/oobi/" + aid, false},
		"a private address":    {"http://10.0.0.5/oobi/" + aid, false},
		"the metadata address": {"http://169.254.169.254/oobi/" + aid, false},
		"shared address space": {"http://100.64.0.1/oobi/" + aid, false},
		"not a web address":    {"file:///etc/passwd/" + aid, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := witnessWithSeed(t, 1)
			body, _ := json.Marshal(map[string]string{"oobi_url": c.oobi})
			if err := s.recordConnectionRequest(aid, &didcomm.JWM{Type: didcomm.TypeContactRequest, Body: body}); err != nil {
				t.Fatal(err)
			}
			rec, _ := s.DataStore.GetContact(aid)
			if rec == nil || rec.Status != "pending_inbound" {
				t.Fatalf("the request was not recorded as pending: %+v", rec)
			}
			if kept := rec.OobiURL != ""; kept != c.kept {
				t.Fatalf("address %q: kept=%v, want %v (recorded %q)", c.oobi, kept, c.kept, rec.OobiURL)
			}
			if rec.ContactSource != "inbound" {
				t.Fatalf("a stranger's contact is not marked as its own doing: %q", rec.ContactSource)
			}
		})
	}
}

// A stranger's own acknowledgement cannot accept it: only the owner does.
func TestAStrangerCannotAcceptItself(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	_ = s.DataStore.SaveContact(store.ContactRecord{AID: "ESTRANGER", Status: "pending_inbound"})
	body, _ := json.Marshal(contactExchange{Kind: "acceptance"})
	if err := (contactAck{}).Perform(s, InboundMessage{FromAID: "ESTRANGER", Body: body}); err == nil {
		t.Fatal("the acknowledgement of a stranger that asked to connect was not refused")
	}
	after, _ := s.DataStore.GetContact("ESTRANGER")
	if after.Status != "pending_inbound" {
		t.Fatalf("a stranger accepted itself: status %q", after.Status)
	}
}
