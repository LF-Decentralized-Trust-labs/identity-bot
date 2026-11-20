package ownership

import (
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers/signedlog"
)

// Every log here is made by the real engine (keri-go through signedlog) and
// signed by the key KERI says must sign it, so what Check reads is what a
// verifier would be handed.

// pair is an owner identity X that names a witness, an Identity Agent M that
// names X in its inception and names a witness, and X's log before and after
// it seals M's inception.
type pair struct {
	m              *maker
	wm, wx         VectorWitness
	machine        *signedlog.Log
	bare, anchored *signedlog.Log
}

func newPair(t *testing.T) pair {
	m := newMaker(t)
	p := pair{m: m, wm: m.witness("of-the-machine"), wx: m.witness("of-the-owner")}
	p.bare = signedlog.InceptWith(t, m.keys("owner", 3), witnessedBy(p.wx))
	p.machine = signedlog.InceptWith(t, m.keys("machine", 4), witnessedBy(p.wm, m.names(p.bare)))
	p.anchored = p.bare.Fork().Seal(m.anchors(p.machine, 0))
	return p
}

func check(mv, ov VectorLog, others ...VectorLog) Result {
	return VectorCase{Machine: mv, Owner: ov, OtherLogs: others}.Check()
}

func want(t *testing.T, got Result, g Grade, why Reason) {
	t.Helper()
	if got.Grade != g || got.Reason != why {
		t.Fatalf("got %s (%s): %s; want %s (%s)", got.Grade, got.Reason, got.Detail, g, why)
	}
}

func TestAnIdentityAgentIsOwnedWhenItsOwnersLogSealsItsInception(t *testing.T) {
	p := newPair(t)
	got := check(handed(p.machine), handed(p.anchored))
	want(t, got, OwnedAnchored, NotFromWitnesses)
	if !got.Owned() || got.Machine != p.machine.AID || got.Owner != p.bare.AID ||
		got.Event != p.machine.AID || got.EventSN != 0 || got.AnchoredBy != p.anchored.SAID(1) {
		t.Fatalf("the result does not say what was sealed and where: %+v", got)
	}
	// Without the owner's interaction the same Identity Agent is only named.
	want(t, check(handed(p.machine), handed(p.bare)), NamedNotOwned, NamedNotAnchored)
}

func TestALookAlikeThatNamesTheOwnerIsNamedNotOwned(t *testing.T) {
	p := newPair(t)
	lookAlike := signedlog.InceptWith(t, p.m.keys("look-alike", 2), witnessedBy(p.wm, p.m.names(p.bare)))
	if lookAlike.AID == p.machine.AID {
		t.Fatal("control: the look-alike is the machine")
	}
	got := check(handed(lookAlike), handed(p.anchored))
	want(t, got, NamedNotOwned, NamedNotAnchored)
	if got.Owned() {
		t.Fatal("a look-alike was treated as owned")
	}
}

// A seal that names the right Identity Agent and the wrong event, or the
// right event at the wrong place, merely matches in part and is not an anchor.
func TestASealThatDoesNotNameTheEventExactlyIsNotAnAnchor(t *testing.T) {
	p := newPair(t)
	for name, seal := range map[string]json.RawMessage{
		"another digest":          p.m.seal(p.machine.AID, 0, p.bare.AID),
		"another sequence number": p.m.seal(p.machine.AID, 1, p.machine.AID),
	} {
		got := check(handed(p.machine), handed(p.bare.Fork().Seal(seal)))
		if got.Grade != NamedNotOwned || got.Reason != NamedNotAnchored {
			t.Errorf("%s: got %s (%s)", name, got.Grade, got.Reason)
		}
	}
}

func TestADelegationApprovalIsNotAnAnchor(t *testing.T) {
	p := newPair(t)
	delegate := signedlog.InceptDelegated(t, p.m.keys("delegate", 2), p.bare.AID)
	approving := p.bare.Fork().Seal(p.m.seal(delegate.AID, 0, delegate.AID))
	want(t, check(handed(delegate), handed(approving)), Refused, Delegated)

	// And an approval written before the anchor does not count as the first
	// anchor, once the delegate's log shows what was sealed.
	after := approving.Fork().Seal(p.m.anchors(p.machine, 0))
	want(t, check(handed(p.machine), handed(after)), Refused, LogUnchecked)
	want(t, check(handed(p.machine), handed(after), handed(delegate)), OwnedAnchored, NotFromWitnesses)
}

func TestALogThatBeginsWithADelegatedInceptionIsNeverOwned(t *testing.T) {
	p := newPair(t)
	delegated := signedlog.InceptDelegated(t, p.m.keys("delegate-naming", 2), p.bare.AID, p.m.names(p.bare))
	sealing := p.bare.Fork().Seal(p.m.seal(delegated.AID, 0, delegated.AID))
	got := check(handed(delegated), handed(sealing))
	want(t, got, NamedNotOwned, Delegated)

	if _, err := AnchorSeal(delegated.Raws[0]); err == nil {
		t.Fatal("an anchor seal was built for a delegated inception")
	}
}

func TestAnAnchorIsReadOnlyFromAnInteractionEvent(t *testing.T) {
	p := newPair(t)
	inRotation := p.bare.Fork().RotateSealing(p.m.anchors(p.machine, 0))
	want(t, check(handed(p.machine), handed(inRotation)), NamedNotOwned, NamedNotAnchored)

	if _, err := AnchorSeal(p.anchored.Raws[1]); err == nil {
		t.Fatal("an anchor seal was built for an interaction event")
	}
}

func TestTheAnchorSealIsKERIsEventSealWithALowercaseHexSequenceNumber(t *testing.T) {
	p := newPair(t)
	seal, err := AnchorSeal(p.machine.Raws[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"i":"` + p.machine.AID + `","s":"0","d":"` + p.machine.AID + `"}`; string(seal) != want {
		t.Fatalf("the founding seal is %s, want %s", seal, want)
	}
	// Sequence number 26 is written 1a.
	later, err := EventSeal(p.machine.AID, 26, "EEventAtPlaceTwentySix")
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"i":"` + p.machine.AID + `","s":"1a","d":"EEventAtPlaceTwentySix"}`; string(later) != want {
		t.Fatalf("got %s, want %s", later, want)
	}
	// keri-go reads it back as the event seal it is.
	ev, err := keri.ParseEvent(p.anchored.Raws[1])
	if err != nil {
		t.Fatal(err)
	}
	seals, err := SealsOfInteraction(ev)
	if err != nil || len(seals) != 1 || seals[0] != (keri.Seal{Identifier: p.machine.AID, SN: 0, SAID: p.machine.AID}) {
		t.Fatalf("read back %v %v", seals, err)
	}
}

func TestAnOwnerThatLeftAndCameBackIsOwnedOnlyFromTheEventWhereItCameBack(t *testing.T) {
	p := newPair(t)
	another := signedlog.Incept(t, p.m.keys("another-owner", 2))
	left := p.machine.Fork().RotateSealing(p.m.names(another))
	want(t, check(handed(left), handed(p.anchored)), Refused, NotNamed)

	back := left.Fork().RotateSealing(p.m.names(p.bare), p.m.names(another))
	got := check(handed(back), handed(p.anchored))
	want(t, got, NamedNotOwned, NamedNotAnchored)
	if got.EventSN != 2 || got.Event != back.SAID(2) {
		t.Fatalf("the owner entered at event %d, want the rotation at 2", got.EventSN)
	}

	got = check(handed(back), handed(p.anchored.Fork().Seal(p.m.anchors(back, 2))))
	want(t, got, OwnedAnchored, NotFromWitnesses)
	if got.EventSN != 2 {
		t.Fatalf("owned from event %d, want 2", got.EventSN)
	}
}

// A rotation that carries no owner seals leaves the set as it was, so the
// owner named at the inception is still the owner and its anchor stands.
func TestARotationThatNamesNoOwnersLeavesTheOwnerSetAsItWas(t *testing.T) {
	p := newPair(t)
	rotated := p.machine.Fork().Rotate().Interact("work").Rotate()
	got := check(handed(rotated), handed(p.anchored))
	want(t, got, OwnedAnchored, NotFromWitnesses)
	if got.EventSN != 0 {
		t.Fatalf("the owner entered at event %d, want the inception", got.EventSN)
	}
}

func TestASecondMachineAnchoredInOneOwnerLogIsNamedNotOwned(t *testing.T) {
	p := newPair(t)
	second := signedlog.InceptWith(t, p.m.keys("second-machine", 2), witnessedBy(p.wm, p.m.names(p.bare)))
	both := p.anchored.Fork().Seal(p.m.anchors(second, 0))

	want(t, check(handed(second), handed(both), handed(p.machine)), NamedNotOwned, SecondMachine)
	// The first anchored is still owned, and stays the only one.
	want(t, check(handed(p.machine), handed(both)), OwnedAnchored, NotFromWitnesses)
}

func TestASealOfAnIdentifierWhoseLogWasNotSuppliedCannotBeChecked(t *testing.T) {
	p := newPair(t)
	second := signedlog.InceptWith(t, p.m.keys("second-machine", 2), witnessedBy(p.wm, p.m.names(p.bare)))
	both := p.anchored.Fork().Seal(p.m.anchors(second, 0))
	want(t, check(handed(second), handed(both)), Refused, LogUnchecked)

	// A copy of that log that stops short of the sealed event answers nothing.
	rotated := p.machine.Fork().Rotate()
	sealsLater := p.bare.Fork().Seal(p.m.seal(rotated.AID, 1, rotated.SAID(1))).Seal(p.m.anchors(second, 0))
	want(t, check(handed(second), handed(sealsLater), handed(p.machine)), Refused, LogUnchecked)
}

func TestAnAnchorARecoveryRemovedNoLongerCounts(t *testing.T) {
	p := newPair(t)
	recovered := p.bare.Fork().Rotate() // at the place the anchoring interaction held

	// Knowing the earlier copy, the verifier says the anchor was removed.
	want(t, check(handed(p.machine), handed(recovered, p.anchored)), NamedNotOwned, AnchorRemoved)
	// Without it, the recovered log simply does not anchor.
	want(t, check(handed(p.machine), handed(recovered)), NamedNotOwned, NamedNotAnchored)
	// The old copy, against the recovered one the verifier kept, is refused.
	want(t, check(handed(p.machine), handed(p.anchored, recovered)), Refused, StaleCopy)

	// Anchored again in a new interaction event, it is owned again.
	again := recovered.Fork().Seal(p.m.anchors(p.machine, 0))
	got := check(handed(p.machine), handed(again, p.anchored))
	want(t, got, OwnedAnchored, NotFromWitnesses)
	if got.AnchoredBy != again.SAID(2) {
		t.Fatalf("anchored by %s, want the new interaction", got.AnchoredBy)
	}
}

func TestALaterCopyThatDoesNotCarryOnFromTheOneKeptIsRefused(t *testing.T) {
	p := newPair(t)
	longer := p.anchored.Fork().Interact("later")
	want(t, check(handed(p.machine), handed(p.anchored, longer)), Refused, StaleCopy)
	// The other way round the kept copy is simply earlier, and nothing is wrong.
	want(t, check(handed(p.machine), handed(longer, p.anchored)), OwnedAnchored, NotFromWitnesses)

	rotated := p.machine.Fork().Rotate()
	want(t, check(handed(p.machine, rotated), handed(p.anchored)), Refused, StaleCopy)
}

func TestADuplicitousOwnerLogOwnsNothing(t *testing.T) {
	p := newPair(t)
	fork := p.bare.Fork().Interact("a second history")
	got := check(handed(p.machine), handed(p.anchored, fork))
	want(t, got, Refused, Duplicity)
	if got.Owned() {
		t.Fatal("a duplicitous owner log owned a machine")
	}
	// Whichever copy is presented and whichever kept.
	second := signedlog.InceptWith(t, p.m.keys("second-machine", 2), witnessedBy(p.wm, p.m.names(p.bare)))
	other := p.bare.Fork().Seal(p.m.anchors(second, 0))
	want(t, check(handed(second), handed(other, p.anchored)), Refused, Duplicity)

	// A recovery rotation over a branch that itself holds a later
	// establishment event is no repair: the controller signed both.
	established := p.anchored.Fork().Rotate()
	want(t, check(handed(p.machine), handed(p.bare.Fork().Rotate(), established)), Refused, Duplicity)
}

// Two establishment events of the Identity Agent at one place are duplicity,
// and no recovery replaces one.
func TestADuplicitousMachineLogIsNotOwned(t *testing.T) {
	p := newPair(t)
	another := signedlog.Incept(t, p.m.keys("another-owner", 2))
	one := p.machine.Fork().Rotate()
	two := p.machine.Fork().RotateSealing(p.m.names(p.bare), p.m.names(another))
	want(t, check(handed(one, two), handed(p.anchored)), Refused, Duplicity)
}

func TestConfirmedNeedsReceiptsOnBothEventsAndBothLogsFromTheirWitnesses(t *testing.T) {
	p := newPair(t)
	onMachine, onOwner := p.m.receipt(p.wm, p.machine, 0), p.m.receipt(p.wx, p.anchored, 1)

	want(t, check(fetched(p.machine, onMachine), fetched(p.anchored, onOwner)), OwnedConfirmed, ReasonNone)

	want(t, check(fetched(p.machine, nil), fetched(p.anchored, onOwner)), OwnedAnchored, ReceiptsShort)
	want(t, check(fetched(p.machine, onMachine), fetched(p.anchored, nil)), OwnedAnchored, ReceiptsShort)
	// A receipt of the owner's inception is not a receipt of the anchoring event.
	want(t, check(fetched(p.machine, onMachine), fetched(p.anchored, p.m.receipt(p.wx, p.anchored, 0))), OwnedAnchored, ReceiptsShort)
	// A receipt by a witness the log does not name counts for nothing.
	stranger := p.m.receipt(p.wm, p.anchored, 1)
	want(t, check(fetched(p.machine, onMachine), fetched(p.anchored, stranger)), OwnedAnchored, ReceiptsShort)
}

func TestConfirmedIsNeverReportedForACopyTheCheckedPartyHandedOver(t *testing.T) {
	p := newPair(t)
	onMachine, onOwner := p.m.receipt(p.wm, p.machine, 0), p.m.receipt(p.wx, p.anchored, 1)
	mine := func(l *signedlog.Log, r map[string][]VectorReceipt) VectorLog {
		v := handed(l)
		v.Receipts = r
		return v
	}
	for name, logs := range map[string][2]VectorLog{
		"the owner's log handed over":   {fetched(p.machine, onMachine), mine(p.anchored, onOwner)},
		"the machine's log handed over": {mine(p.machine, onMachine), fetched(p.anchored, onOwner)},
		"both handed over":              {mine(p.machine, onMachine), mine(p.anchored, onOwner)},
	} {
		got := check(logs[0], logs[1])
		if got.Grade != OwnedAnchored || got.Reason != NotFromWitnesses {
			t.Errorf("%s: got %s (%s)", name, got.Grade, got.Reason)
		}
	}
	// The zero Log claims nothing about where it came from.
	if (Log{}).Source != FromTheCheckedParty {
		t.Fatal("a log that does not say where it came from must count as handed over")
	}
}

func TestALogThatNamesNoWitnessesIsAnchoredAndNeverConfirmed(t *testing.T) {
	m := newMaker(t)
	owner := signedlog.Incept(t, m.keys("owner", 2))
	machine := signedlog.InceptWith(t, m.keys("machine", 2), keri.InceptionInput{Data: []json.RawMessage{m.names(owner)}})
	owner.Seal(m.anchors(machine, 0))
	want(t, check(fetched(machine, nil), fetched(owner, nil)), OwnedAnchored, ReceiptsShort)
}

func TestALogThatDoesNotVerifyIsRefused(t *testing.T) {
	p := newPair(t)
	broken := func(l *signedlog.Log) VectorLog {
		v := handed(l)
		last := []byte(v.Messages[len(v.Messages)-1])
		i := len(last) - 5 // inside the last signature
		if last[i] == 'A' {
			last[i] = 'B'
		} else {
			last[i] = 'A'
		}
		v.Messages[len(v.Messages)-1] = string(last)
		return v
	}
	want(t, check(broken(p.machine), handed(p.anchored)), Refused, LogInvalid)
	want(t, check(handed(p.machine), broken(p.anchored)), Refused, LogInvalid)
	want(t, check(VectorLog{}, handed(p.anchored)), Refused, LogInvalid)
	want(t, check(handed(p.machine), VectorLog{}), Refused, LogInvalid)

	// A rotation signed by keys the log never committed to.
	stolen := p.anchored.Fork().RotateTo(signedlog.NewKeys(t, 2))
	want(t, check(handed(p.machine), handed(stolen)), Refused, LogInvalid)

	// An owner the Identity Agent's log does not name at all.
	stranger := signedlog.Incept(t, p.m.keys("another-owner", 2)).Seal(p.m.anchors(p.machine, 0))
	want(t, check(handed(p.machine), handed(stranger)), Refused, NotNamed)
}
