package conversationbundle

import (
	"strings"
	"testing"

	"identity-agent-core/agentmessage"
)

// A conversation closes only when its opener says so, or its owner stops it,
// and the close is an entry of the chain, so a trail shows who closed it. The
// verifier holds each of those: who may close, reopen or raise the limit, that
// nothing is asked once it is closed, and that an answer after the close is
// kept and is no fault.
func TestACloseIsTheOpenersOrTheOwnersAndNothingIsAskedAfterIt(t *testing.T) {
	const opener, other = "agent-a", "agent-c"
	owner := &agentmessage.PersonRef{AID: "EOWNER", Standing: "owner"}
	signer := &agentmessage.PersonRef{AID: "ESIGNER", Standing: "signer"}
	control := func(kind, from string) agentmessage.Record {
		return agentmessage.Record{MessageID: "m-" + kind, Kind: kind, From: from, OpenedBy: opener}
	}
	byPerson := func(kind string, p *agentmessage.PersonRef) agentmessage.Record {
		r := control(kind, agentmessage.Person(p.AID))
		r.PersonProof, r.Person = &agentmessage.PersonProof{}, p
		return r
	}
	faults := func(f func(v *verifier)) []Fault {
		r := &Report{}
		v := &verifier{r: r, entries: map[string]agentmessage.Record{}, answered: map[string]bool{}}
		f(v)
		return r.Faults
	}
	wantFault := func(name string, got []Fault, contains string) {
		t.Helper()
		if len(got) != 1 || !strings.Contains(got[0].Why, contains) {
			t.Fatalf("%s: want one fault containing %q, got %v", name, contains, got)
		}
	}
	wantNone := func(name string, got []Fault) {
		t.Helper()
		if len(got) != 0 {
			t.Fatalf("%s: refused: %v", name, got)
		}
	}

	wantNone("a body's close acts on no message", faults(func(v *verifier) { v.checkThread("e", control(agentmessage.KindClose, opener)) }))
	wantNone("the opener closes", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindClose, opener), nil) }))
	wantNone("the owner closes what another opened", faults(func(v *verifier) { v.checkControl("e", byPerson(agentmessage.KindClose, owner), nil) }))
	wantFault("someone else closes", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindClose, other), nil) }), "is neither")
	wantFault("a signer who did not open it closes", faults(func(v *verifier) { v.checkControl("e", byPerson(agentmessage.KindClose, signer), nil) }), "is neither")
	wantFault("the owner reopens what another opened", faults(func(v *verifier) {
		v.closed = true
		v.checkControl("e", byPerson(agentmessage.KindReopen, owner), nil)
	}), "only by the one who opened")
	wantFault("a close of a closed conversation", faults(func(v *verifier) {
		v.checkControl("e", control(agentmessage.KindClose, opener), nil)
		v.checkControl("e", control(agentmessage.KindClose, opener), nil)
	}), "already closed")
	wantFault("a reopen of an open conversation", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindReopen, opener), nil) }), "was not closed")
	wantNone("close then reopen then ask", faults(func(v *verifier) {
		v.checkControl("e", control(agentmessage.KindClose, opener), nil)
		v.checkControl("e", control(agentmessage.KindReopen, opener), nil)
		v.checkControl("e", agentmessage.Record{Kind: agentmessage.KindAsk, From: opener}, nil)
	}))
	wantFault("an ask after the close", faults(func(v *verifier) {
		v.checkControl("e", control(agentmessage.KindClose, opener), nil)
		v.checkControl("e", agentmessage.Record{Kind: agentmessage.KindAsk, From: opener}, nil)
	}), "closed and not reopened")
	wantNone("an answer after the close is kept", faults(func(v *verifier) {
		v.checkControl("e", control(agentmessage.KindClose, opener), nil)
		v.checkControl("e", agentmessage.Record{Kind: agentmessage.KindReply, From: other}, nil)
	}))
	wantNone("the opener raises the limit", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindLimit, opener), []byte("80")) }))
	wantFault("another raises the limit", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindLimit, other), []byte("80")) }), "only by the one who opened")
	wantFault("a limit past the ceiling", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindLimit, opener), []byte("401")) }), "not one a conversation may have")
	wantFault("a limit that is not a raise", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindLimit, opener), []byte("40")) }), "not one a conversation may have")
	wantFault("a close that carries words", faults(func(v *verifier) { v.checkControl("e", control(agentmessage.KindClose, opener), []byte("bye")) }), "carries no words")
}
