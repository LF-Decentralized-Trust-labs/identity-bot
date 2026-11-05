package conversationbundle

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
)

// An AI agent may open a conversation toward another AI agent its grant allows
// (ADR-047, Amendment 3). These test the checks that rule adds to the
// verifier, on the entries themselves: the signatures are covered by
// agentmessage's own tests and the published vectors.

func openingGrant(said, holder string, to ...string) *credential {
	caps, _ := json.Marshal([]string{agentmessage.CapabilityMessageAgent})
	attrs := map[string]json.RawMessage{"capabilities": caps}
	if len(to) > 0 {
		limits, _ := json.Marshal(map[string]interface{}{
			agentmessage.CapabilityMessageAgent: map[string]interface{}{"to": to},
			agentmessage.CapabilityMessageOpen:  map[string]interface{}{"per_hour": 6},
		})
		attrs["resource_constraints"] = limits
	}
	return &credential{said: said, holder: holder, attrs: attrs, issued: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
}

func openingEntry(from, to string) agentmessage.Record {
	return agentmessage.Record{MessageID: "m1", Seq: 1, Kind: agentmessage.KindAsk, From: from, To: to, OpenedBy: from, Depth: 1,
		GrantSAID: "Egrant_a", IATime: "2026-11-02T10:00:00Z",
		Statement: &agentmessage.Statement{Kind: agentmessage.KindAsk, From: from, To: to}}
}

func openingFaults(v *verifier) string {
	var s []string
	for _, f := range v.r.Faults {
		s = append(s, f.Where+": "+f.Why)
	}
	return strings.Join(s, "\n")
}

func newVerifier() *verifier {
	return &verifier{r: &Report{}, creds: map[string]*credential{}, entries: map[string]agentmessage.Record{}}
}

func TestAnAIAgentsAskToAnotherAIAgentOpensAConversation(t *testing.T) {
	v := newVerifier()
	v.checkOpening("entry 1", openingEntry("EA", "EB"))
	if len(v.r.Faults) != 0 || v.opener.MessageID != "m1" {
		t.Fatalf("an AI agent's opening ask was refused or not remembered: %s", openingFaults(v))
	}
}

func TestAnOpeningThatIsNotAnAskToAnAIAgentIsRefused(t *testing.T) {
	for name, change := range map[string]func(*agentmessage.Record){
		"to a person":                 func(r *agentmessage.Record) { r.To = agentmessage.Person("EP") },
		"as a reply":                  func(r *agentmessage.Record) { r.Kind = agentmessage.KindReply },
		"from one who did not open":   func(r *agentmessage.Record) { r.OpenedBy = "EC" },
		"acting on an earlier one":    func(r *agentmessage.Record) { r.Statement.InReplyTo = "m0" },
		"at the depth of a person":    func(r *agentmessage.Record) { r.Depth = 0 },
		"with no proof from a sender": func(r *agentmessage.Record) { r.Statement = nil },
	} {
		v := newVerifier()
		rec := openingEntry("EA", "EB")
		change(&rec)
		v.checkOpening("entry 1", rec)
		if len(v.r.Faults) == 0 {
			t.Errorf("a conversation was opened %s", name)
		}
	}
}

func TestAnAskThatActsOnNoMessageIsOnlyTheFirstEntry(t *testing.T) {
	v := newVerifier()
	late := openingEntry("EA", "EB")
	late.Seq = 2
	v.checkThread("entry 2", late)
	if len(v.r.Faults) == 0 {
		t.Fatal("an ask that acts on no message was taken as the second entry of a conversation")
	}
	v = newVerifier()
	v.checkThread("entry 1", openingEntry("EA", "EB"))
	if len(v.r.Faults) != 0 {
		t.Fatalf("the opening ask was refused for naming no message: %s", openingFaults(v))
	}
}

// A chain reaches no further than the AI agent that started it, as for a
// person: B may be allowed to ask C, but not in a conversation A opened if A
// could not have asked C.
func TestAnAskInAnAIAgentsConversationReachesNoFurtherThanItsOpener(t *testing.T) {
	v := newVerifier()
	v.creds["Egrant_a"] = openingGrant("Egrant_a", "EA", "EB")
	v.checkOpening("entry 1", openingEntry("EA", "EB"))
	ask := func(to string) agentmessage.Record {
		return agentmessage.Record{MessageID: "m3", Seq: 3, Kind: agentmessage.KindAsk, From: "EB", To: to, GrantSAID: "Egrant_b", IATime: "2026-11-02T10:01:00Z"}
	}
	args := func(to string) []byte { return agentmessage.AskArgs(to, "words") }
	v.checkOpenerReach("entry 3", ask("EB2"), args("EB2"))
	if !strings.Contains(openingFaults(v), "opener") {
		t.Fatalf("an ask beyond what the opener could reach was accepted: %q", openingFaults(v))
	}
	v = newVerifier()
	v.creds["Egrant_a"] = openingGrant("Egrant_a", "EA", "EB", "EC")
	v.checkOpening("entry 1", openingEntry("EA", "EB"))
	v.checkOpenerReach("entry 3", ask("EC"), args("EC"))
	if len(v.r.Faults) != 0 {
		t.Fatalf("an ask the opener could have made was refused: %s", openingFaults(v))
	}
}

func TestAnOpenersRevokedGrantEndsItsConversation(t *testing.T) {
	v := newVerifier()
	g := openingGrant("Egrant_a", "EA")
	revoked := time.Date(2026, 11, 2, 10, 0, 30, 0, time.UTC)
	g.revoked = &revoked
	v.creds["Egrant_a"] = g
	v.checkOpening("entry 1", openingEntry("EA", "EB"))
	later := agentmessage.Record{MessageID: "m3", Seq: 3, Kind: agentmessage.KindAsk, From: "EB", To: "EC", GrantSAID: "Egrant_b", IATime: "2026-11-02T10:01:00Z"}
	v.checkOpenerReach("entry 3", later, agentmessage.AskArgs("EC", "words"))
	if !strings.Contains(openingFaults(v), "was not in force") {
		t.Fatalf("an ask after its opener's grant was revoked was accepted: %q", openingFaults(v))
	}
}

// An opening is admitted only under a grant that names, outright, whom it may
// open toward and how often: a grant with no constraint on "to" reads as
// unconstrained for an ordinary ask, and must not for an opening.
func TestAnOpeningNeedsAGrantThatNamesWhomAndHowOften(t *testing.T) {
	ask := func(g *credential) *verifier {
		v := newVerifier()
		v.checkAskAllowed("entry 1", g, openingEntry("EA", "EB"), []byte("words"))
		return v
	}
	if v := ask(openingGrant("Egrant_a", "EA", "EB")); len(v.r.Faults) != 0 {
		t.Fatalf("an opening under a grant naming EB and a rate was refused: %s", openingFaults(v))
	}
	for name, g := range map[string]*credential{
		"no constraint on to": openingGrant("Egrant_a", "EA"),
		"another agent named": openingGrant("Egrant_a", "EA", "EC"),
		"no count per hour":   withoutRate(openingGrant("Egrant_a", "EA", "EB")),
	} {
		if v := ask(g); !strings.Contains(openingFaults(v), "does not let it") {
			t.Errorf("an opening was accepted under a grant with %s: %q", name, openingFaults(v))
		}
	}
	// An ordinary ask inside a conversation is unchanged by this rule.
	v := newVerifier()
	reply := openingEntry("EA", "EB")
	reply.Statement.InReplyTo = "m0"
	v.checkAskAllowed("entry 3", openingGrant("Egrant_a", "EA"), reply, []byte("words"))
	if len(v.r.Faults) != 0 {
		t.Fatalf("an ask that acts on a message was held to the opening rule: %s", openingFaults(v))
	}
}

func withoutRate(g *credential) *credential {
	limits, _ := json.Marshal(map[string]interface{}{agentmessage.CapabilityMessageAgent: map[string]interface{}{"to": []string{"EB"}}})
	g.attrs["resource_constraints"] = limits
	return g
}
