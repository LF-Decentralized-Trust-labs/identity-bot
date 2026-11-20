package drivers_test

import (
	"errors"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
)

// judged puts the event of theirs at place sn to mine, which holds another
// event there, both ways of judging.
func judged(t *testing.T, mine, theirs *signedlog.Log, sn int) (one, both drivers.TakenPlace) {
	t.Helper()
	log, err := keri.ValidateSignedKEL(mine.Messages())
	if err != nil {
		t.Fatal(err)
	}
	other, err := keri.ValidateSignedKEL(theirs.Messages())
	if err != nil {
		t.Fatal(err)
	}
	message := theirs.Messages()[sn]
	ev, err := keri.ParseEvent(theirs.Raws[sn])
	if err != nil {
		t.Fatal(err)
	}
	var refusal *keri.ValidationError
	if _, err := log.Admit(message); !errors.As(err, &refusal) || !refusal.Has(keri.FaultPlaceTaken) {
		t.Fatalf("control: the event was not refused as a second event at a taken place: %v", err)
	}
	one, _ = drivers.JudgeAtTakenPlace(log, mine.Messages(), ev, message)
	both, _ = drivers.JudgeCopiesAtTakenPlace(log, mine.Messages(), other, theirs.Messages(), ev, message)
	return one, both
}

func TestARecoveryIsARepairOnlyIfTheRetiredCopyAdmitsIt(t *testing.T) {
	base := signedlog.Incept(t, signedlog.NewKeys(t, 4))
	recovered := base.Fork().Rotate()

	// The retired branch holds interactions only: a repair, judged either way.
	one, both := judged(t, recovered, base.Fork().Interact("one").Interact("two"), 1)
	if one != drivers.TakenRetired || both != drivers.TakenRetired {
		t.Fatalf("a recovery over interactions: %v and %v, want retired by both", one, both)
	}

	// The retired branch goes on to an establishment event, which no recovery
	// replaces. Judged from the one log it still looks retired; with the other
	// copy in hand it is the fork it is.
	one, both = judged(t, recovered, base.Fork().Interact("one").Rotate(), 1)
	if one != drivers.TakenRetired {
		t.Fatalf("control: judged against one log this reads %v", one)
	}
	if both != drivers.TakenFork {
		t.Fatalf("a recovery over a branch that holds a later rotation: %v, want a fork", both)
	}

	// Two interactions at one place are a fork either way.
	one, both = judged(t, base.Fork().Interact("a"), base.Fork().Interact("b"), 1)
	if one != drivers.TakenFork || both != drivers.TakenFork {
		t.Fatalf("two interactions at one place: %v and %v", one, both)
	}
}
