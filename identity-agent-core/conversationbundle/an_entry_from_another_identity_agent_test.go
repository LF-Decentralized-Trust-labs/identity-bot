package conversationbundle

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/agentpeer"
	"identity-agent-core/didcomm"
)

// checkWith runs the entry checks with the given Identity Agents' messaging keys
// as well as this one's, as a key log would give them.
func checkWith(t *testing.T, c *conversation, b *Bundle, others map[string]*didcomm.DID) *verifier {
	t.Helper()
	mine, err := c.keys.DID()
	if err != nil {
		t.Fatal(err)
	}
	v := newVerifier()
	v.b, v.hashes, v.signedOnce, v.answered, v.notes = b, map[int]string{}, map[string]int{}, map[string]bool{}, map[string]bool{}
	v.dids = map[string]*didcomm.DID{rootAID: mine}
	for aid, d := range others {
		v.dids[aid] = d
	}
	v.checkEntries()
	return v
}

// peerFaultsOf is what the entry checks found, leaving out that the AI agent it is
// addressed to was not shown delegated from the root: this harness carries no
// key logs, and that check is the same for any entry.
func peerFaultsOf(v *verifier) []Fault {
	var out []Fault
	for _, f := range v.r.Faults {
		if !strings.Contains(f.Why, "it is addressed to") {
			out = append(out, f)
		}
	}
	return out
}

// An ask from an AI agent another Identity Agent holds is an entry of this
// Identity Agent's own conversation: countersigned by this Identity Agent, and
// carrying the other's signed statement, which is checked with the other's keys.
func TestAnEntryFromAnotherIdentityAgentsAIAgentIsCheckedWithThatIdentityAgentsKeys(t *testing.T) {
	c := newConversation(t)
	theirs, err := didcomm.GenerateKeySet("EBETA")
	if err != nil {
		t.Fatal(err)
	}
	theirDID, _ := theirs.DID()
	from := agentmessage.Peer("EBETA", "EREV")

	// signedWords is what the other Identity Agent signed; recordedWords is what
	// this Identity Agent recorded, and carries.
	build := func(signedWords, recordedWords string, edit func(*agentmessage.Record)) *Bundle {
		m, err := agentpeer.Seal(theirs, agentpeer.Statement{Kind: agentpeer.KindAsk, ToAID: rootAID, FromAgent: "EREV", ToAgent: "EWORKER",
			MessageID: "m_rev_1"}, signedWords, c.now)
		if err != nil {
			t.Fatal(err)
		}
		salt, _ := base64.RawURLEncoding.DecodeString(m.Salt)
		st, err := agentpeer.ReadStatement(m.Signed, theirDID)
		if err != nil {
			t.Fatal(err)
		}
		rec := agentmessage.Record{MessageID: "m_rev_1", Conversation: "c1", Seq: 1, Kind: agentmessage.KindAsk, From: from, To: "EWORKER",
			BodyHash: st.Fingerprint, Depth: 1, OpenedBy: from, IATime: c.now.UTC().Format(time.RFC3339Nano),
			PeerProof: &m.Signed}
		if edit != nil {
			edit(&rec)
		}
		env, err := agentmessage.Countersign(c.keys, rec)
		if err != nil {
			t.Fatal(err)
		}
		return &Bundle{Format: Format, Conversation: "c1", Root: rootAID, Entries: []Entry{{Envelope: env, Body: encodeWords(recordedWords), Salt: base64.StdEncoding.EncodeToString(salt)}}}
	}
	keys := map[string]*didcomm.DID{"EBETA": theirDID}
	words := "please review branch fix-1"

	if v := checkWith(t, c, build(words, words, nil), keys); len(peerFaultsOf(v)) != 0 {
		t.Fatalf("a good entry faulted: %+v", peerFaultsOf(v))
	}
	if v := checkWith(t, c, build(words, words, nil), nil); len(peerFaultsOf(v)) == 0 {
		t.Fatal("an entry from another Identity Agent held with none of that Identity Agent's keys")
	}
	stranger, _ := didcomm.GenerateKeySet("EBETA")
	strangerDID, _ := stranger.DID()
	if v := checkWith(t, c, build(words, words, nil), map[string]*didcomm.DID{"EBETA": strangerDID}); len(peerFaultsOf(v)) == 0 {
		t.Fatal("an entry held against keys the sending Identity Agent did not sign with")
	}
	if v := checkWith(t, c, build("other words", words, nil), keys); len(peerFaultsOf(v)) == 0 {
		t.Fatal("an entry saying words the sending Identity Agent did not sign held")
	}
	if v := checkWith(t, c, build(words, words, func(r *agentmessage.Record) { r.To = "EOTHER" }), keys); len(peerFaultsOf(v)) == 0 {
		t.Fatal("an entry for another AI agent than the one signed for held")
	}
}

func encodeWords(w string) string { return base64.StdEncoding.EncodeToString([]byte(w)) }

func peerGrant(caps []string, limits map[string]interface{}) *credential {
	c, _ := json.Marshal(caps)
	attrs := map[string]json.RawMessage{"capabilities": c}
	if limits != nil {
		l, _ := json.Marshal(limits)
		attrs["resource_constraints"] = l
	}
	return &credential{said: "Egrant_a", holder: "EA", attrs: attrs, issued: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
}

// An AI agent this Identity Agent holds may ask one another Identity Agent holds
// only under agent.message.peer naming that contact: agent.message.send, however
// wide, never reaches another Identity Agent.
func TestAnAskToAnotherIdentityAgentRestsOnThePeerCapability(t *testing.T) {
	to := agentmessage.Peer("EBETA", "EREV")
	opening := openingEntry("EA", to)
	named := map[string]interface{}{
		agentpeer.CapabilityMessagePeer:    map[string]interface{}{agentpeer.ConstraintContact: []string{"EBETA"}},
		agentmessage.CapabilityMessageOpen: map[string]interface{}{"per_hour": 6},
	}
	check := func(g *credential) string {
		v := newVerifier()
		v.checkAskAllowed("entry 1", g, opening, []byte("words"))
		return openingFaults(v)
	}
	if f := check(peerGrant([]string{agentpeer.CapabilityMessagePeer}, named)); f != "" {
		t.Fatalf("an opening under a grant naming the contact and a rate was refused: %s", f)
	}
	// The wide grant inside one Identity Agent does not reach another.
	wide := peerGrant([]string{agentmessage.CapabilityMessageAgent}, nil)
	if f := check(wide); !strings.Contains(f, "another Identity Agent") {
		t.Fatalf("agent.message.send reached another Identity Agent: %q", f)
	}
	// Another contact's name, or no rate, is not permission.
	other := map[string]interface{}{
		agentpeer.CapabilityMessagePeer:    map[string]interface{}{agentpeer.ConstraintContact: []string{"EGAMMA"}},
		agentmessage.CapabilityMessageOpen: map[string]interface{}{"per_hour": 6},
	}
	if f := check(peerGrant([]string{agentpeer.CapabilityMessagePeer}, other)); f == "" {
		t.Fatal("a grant naming another contact reached this one")
	}
	norate := map[string]interface{}{agentpeer.CapabilityMessagePeer: map[string]interface{}{agentpeer.ConstraintContact: []string{"EBETA"}}}
	if f := check(peerGrant([]string{agentpeer.CapabilityMessagePeer}, norate)); f == "" {
		t.Fatal("an opening with no stated rate was allowed")
	}
}
