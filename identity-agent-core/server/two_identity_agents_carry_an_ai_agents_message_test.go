package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentpeer"
	"identity-agent-core/store"
)

// Two cores, each with its own keys and a real envelope between them: one
// Identity Agent sends the message of an AI agent it holds to the other,
// which hands it, checked, to whoever keeps its AI agents' conversations, and
// refuses it when nobody does. The directory the receiver publishes arrives the
// same way.
func TestTwoIdentityAgentsCarryAnAIAgentsMessageAndADirectory(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	a, b := agentWithDerivedIdentity(t), agentWithDerivedIdentity(t)
	// The fixture names both "EOURS"; they are two Identity Agents.
	ida, _ := a.DataStore.GetIdentity()
	idb, _ := b.DataStore.GetIdentity()
	ida.AID, idb.AID = "EALPHA", "EBETA"
	if err := a.DataStore.SaveIdentity(*ida); err != nil {
		t.Fatal(err)
	}
	if err := b.DataStore.SaveIdentity(*idb); err != nil {
		t.Fatal(err)
	}
	serve := func(s *CoreServer) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, io.LimitReader(r.Body, 0))
			s.handleDIDCommInbound(w, r)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	sa, sb := serve(a), serve(b)
	know := func(me *CoreServer, other *CoreServer, otherAID, endpoint string) {
		keys, err := other.keySetFor(otherAID)
		if err != nil {
			t.Fatal(err)
		}
		did, _ := keys.DID()
		didcommMu.Lock()
		defer didcommMu.Unlock()
		peers, _ := me.loadPeers()
		peers[otherAID] = peerRecord{AID: otherAID, DID: *did, Endpoint: endpoint, AddedAt: time.Now()}
		if err := me.savePeers(peers); err != nil {
			t.Fatal(err)
		}
	}
	know(a, b, "EBETA", sb.URL)
	know(b, a, "EALPHA", sa.URL)
	for _, c := range []struct {
		s        *CoreServer
		aid, url string
	}{{a, "EBETA", sb.URL}, {b, "EALPHA", sa.URL}} {
		if err := c.s.DataStore.SaveContact(store.ContactRecord{AID: c.aid, Alias: "the other one", Status: "accepted", OobiURL: c.url + "/oobi"}); err != nil {
			t.Fatal(err)
		}
	}

	var taken []agentpeer.Statement
	st := agentpeer.Statement{Kind: agentpeer.KindAsk, FromAgent: "EREVIEWREQ", ToAgent: "EREVIEWER", MessageID: "m-live-1"}
	// Nobody keeps AI agents' conversations at the receiver: the send goes, and
	// nothing is taken (and the sender is told nothing of why).
	if err := a.SendAgentPeerMessage("EBETA", st, "please review"); err != nil {
		t.Fatalf("the send itself failed: %v", err)
	}
	b.OnAgentPeerMessage(func(_ string, st agentpeer.Statement, _ agentpeer.Message) error {
		taken = append(taken, st)
		return nil
	})
	st.MessageID = "m-live-2"
	if err := a.SendAgentPeerMessage("EBETA", st, "please review"); err != nil {
		t.Fatal(err)
	}
	if len(taken) != 1 || taken[0].FromAID != "EALPHA" || taken[0].ToAID != "EBETA" || taken[0].ToAgent != "EREVIEWER" || taken[0].MessageID != "m-live-2" {
		t.Fatalf("the keeper was given %+v", taken)
	}
	// The core keeps no copy of the words: whether the owner's rule takes a
	// message is the keeper's, and a copy here would be a second plaintext of
	// one the rule refused, readable by every controller, with no limit.
	held, err := b.DataStore.GetNotifications("", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range held {
		if n.Kind == "agent-peer-message" || strings.Contains(n.Payload, "please review") ||
			strings.Contains(n.SignedMessage, "please review") {
			t.Fatalf("the core kept a copy of a message between AI agents: %+v", n)
		}
	}
	// Not a contact on the sending side: nothing goes out.
	if err := a.SendAgentPeerMessage("ESTRANGER", st, "hi"); err == nil {
		t.Fatal("a message went to an Identity Agent that is not a contact")
	}

	// The receiving Identity Agent tells the sender which of its AI agents it may reach.
	var lists []agentpeer.Directory
	a.OnAgentPeerDirectory(func(from string, d agentpeer.Directory) error {
		if from != "EBETA" {
			t.Errorf("a directory kept as from %s", from)
		}
		lists = append(lists, d)
		return nil
	})
	if err := b.SendAgentPeerDirectory("EALPHA", agentpeer.Directory{Agents: []agentpeer.DirectoryEntry{{AID: "EREVIEWER", Name: "reviewer"}}}); err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || len(lists[0].Agents) != 1 || lists[0].Agents[0].Name != "reviewer" {
		t.Fatalf("the directory kept for EBETA: %+v", lists)
	}
}
