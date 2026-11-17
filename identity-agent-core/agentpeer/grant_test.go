package agentpeer

import (
	"testing"

	"identity-agent-core/iacrypto"
)

func TestAGrantMustNameTheContact(t *testing.T) {
	g := func(c map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{CapabilityMessagePeer: c}
	}
	if CheckPeerGrant(map[string]interface{}{}, "O", "a") == nil {
		t.Fatal("no constraint was treated as permission")
	}
	if CheckPeerGrant(g(map[string]interface{}{ConstraintContact: []interface{}{"X"}}), "O", "a") == nil {
		t.Fatal("a grant naming another contact reached O")
	}
	ok := g(map[string]interface{}{ConstraintContact: []interface{}{"O"}})
	if err := CheckPeerGrant(ok, "O", "a"); err != nil {
		t.Fatal(err)
	}
	narrow := g(map[string]interface{}{ConstraintContact: []interface{}{"O"}, ConstraintAgent: []interface{}{"a"}})
	if CheckPeerGrant(narrow, "O", "b") == nil {
		t.Fatal("an AI agent outside the grant's list was reached")
	}
}

func TestADirectoryNamesEachAIAgentOnceWithAPlainName(t *testing.T) {
	ok := Directory{Agents: []DirectoryEntry{{AID: "E1", Name: "reviewer", Role: "reviews"}, {AID: "E2", Name: "builder"}}}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]Directory{
		"a name with an @":  {Agents: []DirectoryEntry{{AID: "E1", Name: "boss@alias"}}},
		"a text override":   {Agents: []DirectoryEntry{{AID: "E1", Name: "a\u202eb"}}},
		"a line break":      {Agents: []DirectoryEntry{{AID: "E1", Name: "a\nb"}}},
		"an empty name":     {Agents: []DirectoryEntry{{AID: "E1", Name: ""}}},
		"the same name":     {Agents: []DirectoryEntry{{AID: "E1", Name: "x"}, {AID: "E2", Name: "X"}}},
		"the same AI agent": {Agents: []DirectoryEntry{{AID: "E1", Name: "x"}, {AID: "E1", Name: "y"}}},
		"a space in an id":  {Agents: []DirectoryEntry{{AID: "E 1", Name: "x"}}},
	} {
		if d.Check() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

var fp = iacrypto.Blake3QB64Must([]byte("x"))

func TestAnIdentifierHasNoSlashSoAPartyAndAMessageIdReadOnlyOneWay(t *testing.T) {
	for _, id := range []string{"EHOLDER/EAGENT", "x/e1"} {
		st := Statement{Kind: KindAsk, FromAID: "EA", ToAID: "EB", FromAgent: "EX", ToAgent: "EY", MessageID: "m", Fingerprint: fp, SentAt: now.Format(sentAtLayout)}
		st.MessageID = id
		if st.Check() == nil {
			t.Errorf("a message id %q was accepted", id)
		}
		st.MessageID, st.FromAgent = "m", id
		if st.Check() == nil {
			t.Errorf("an AI agent %q was accepted", id)
		}
	}
}

// A narrowing constraint that is badly shaped never widens the grant: an AI agent
// given as text, as an empty list or as a list of anything but text is a
// refusal, not "every AI agent the contact holds".
func TestABadlyShapedConstraintFailsClosed(t *testing.T) {
	for name, c := range map[string]map[string]interface{}{
		"the agent constraint given as text":          {ConstraintContact: []interface{}{"O"}, ConstraintAgent: "ONLY"},
		"the agent constraint given as an empty list": {ConstraintContact: []interface{}{"O"}, ConstraintAgent: []interface{}{}},
		"the agent constraint as a list of numbers":   {ConstraintContact: []interface{}{"O"}, ConstraintAgent: []interface{}{1}},
		"the agent constraint with an empty entry":    {ConstraintContact: []interface{}{"O"}, ConstraintAgent: []interface{}{""}},
		"a contact given as text":                     {ConstraintContact: "O"},
		"a contact given as an empty list":            {ConstraintContact: []interface{}{}},
		"a constraint nobody defined":                 {ConstraintContact: []interface{}{"O"}, "also": []interface{}{"x"}},
	} {
		limits := map[string]interface{}{CapabilityMessagePeer: c}
		if CheckPeerGrant(limits, "O", "ESOMEONEELSE") == nil {
			t.Errorf("%s widened the grant", name)
		}
		if CheckPeerGrantShape(limits) == nil {
			t.Errorf("%s was accepted as a shape", name)
		}
	}
	if CheckPeerGrantShape(map[string]interface{}{CapabilityMessagePeer: "yes"}) == nil {
		t.Error("a grant entry that is not an object was accepted")
	}
	if CheckPeerGrantShape(map[string]interface{}{}) != nil {
		t.Error("a grant without the capability is not misshapen")
	}
}
