package store

import (
	"errors"
	"testing"

	"identity-agent-core/drivers/signedlog"
)

func record(l *signedlog.Log, verified bool) ContactKELRecord {
	return ContactKELRecord{AID: l.AID, KEL: l.Records(), KelVerified: verified,
		EventsValidated: l.Len(), CurrentPublicKey: l.Key()}
}

type contactLogs interface {
	SaveContactKEL(ContactKELRecord) error
	GetContactKEL(string) (*ContactKELRecord, error)
}

func bothStores(t *testing.T, each func(t *testing.T, st contactLogs)) {
	file, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sqlite, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]contactLogs{"file": file, "sqlite": sqlite} {
		t.Run(name, func(t *testing.T) { each(t, st) })
	}
}

// The real owner history is K1 -> K2 -> K3 and this machine holds all of it.
// Someone holding only the retired K2 signs events of their own after the K2
// rotation: a log the engine verifies (see the drivers test of the same
// scenario), as long as the real one and with a key of its own at the tip. A
// count of events cannot tell it from the real log; its events can.
func TestAForkSignedByARetiredKeyDoesNotReplaceTheHeldLog(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK2 := signedlog.Incept(t, keys).Rotate()
	real := atK2.Fork().Rotate()
	sameLength := atK2.Fork().Interact("mine")
	longer := atK2.Fork().Interact("mine").Interact("and more")

	bothStores(t, func(t *testing.T, st contactLogs) {
		if err := st.SaveContactKEL(record(real, true)); err != nil {
			t.Fatal(err)
		}
		for name, fork := range map[string]*signedlog.Log{"as long": sameLength, "longer": longer} {
			if fork.Len() < real.Len() {
				t.Fatalf("test setup: the %s fork is shorter than the real log", name)
			}
			if err := st.SaveContactKEL(record(fork, true)); !errors.Is(err, ErrLogDoesNotExtend) {
				t.Fatalf("a fork that is %s as the held log replaced it, err=%v", name, err)
			}
		}
		// A caller-supplied count is not a reason to believe anything.
		inflated := record(sameLength, true)
		inflated.EventsValidated = 99
		if err := st.SaveContactKEL(inflated); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("an inflated EventsValidated got a fork in, err=%v", err)
		}
		got, _ := st.GetContactKEL(real.AID)
		if got == nil || got.CurrentPublicKey != keys.Pub(2) || len(got.KEL) != real.Len() {
			t.Fatalf("the held log changed: %+v", got)
		}
	})
}

// The older rule, which still holds: a log that stops earlier does not replace
// the one held, verified or not, and a log that carries on from it, or is it,
// does.
func TestAVerifiedLogOnlyMovesForward(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK1 := signedlog.Incept(t, keys)
	atK2 := atK1.Fork().Rotate()
	atK3 := atK2.Fork().Rotate()
	beyond := atK3.Fork().Interact("later")

	bothStores(t, func(t *testing.T, st contactLogs) {
		if err := st.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveContactKEL(record(atK2, true)); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("a shorter log replaced the held one, err=%v", err)
		}
		if err := st.SaveContactKEL(record(atK2, false)); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("an unverified shorter record replaced the held log, err=%v", err)
		}
		// Nothing but a verdict and a key, no events at all.
		if err := st.SaveContactKEL(ContactKELRecord{AID: atK3.AID}); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("an empty record replaced the held log, err=%v", err)
		}
		if got, _ := st.GetContactKEL(atK3.AID); got == nil || got.CurrentPublicKey != keys.Pub(2) {
			t.Fatalf("held log changed: %+v", got)
		}
		if err := st.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatalf("the same log again was refused: %v", err)
		}
		if err := st.SaveContactKEL(record(beyond, true)); err != nil {
			t.Fatalf("a log carrying on from the held one was refused: %v", err)
		}
	})
}

// A machine that holds only K1 -> K2 can be taken forward by the genuine log.
func TestAnOlderHeldLogIsReplacedByTheGenuineLongerOne(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK2 := signedlog.Incept(t, keys).Rotate()
	atK3 := atK2.Fork().Rotate()
	bothStores(t, func(t *testing.T, st contactLogs) {
		if err := st.SaveContactKEL(record(atK2, true)); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveContactKEL(record(atK3, true)); err != nil {
			t.Fatalf("the genuine longer log was refused: %v", err)
		}
	})
}

// A verified log is not given up for an unverified copy of itself. If it were,
// nothing would be checked against what is held any more, and a fork could come
// in behind it: the three steps below, in order, in each store.
//
// Fails when the `!offered.KelVerified` refusal in refuseAnEarlierLog
// (store/store.go) is removed: step 2 is accepted, and step 3 then replaces the
// log with the fork, whose tip is the retired K2.
func TestAnUnverifiedCopyDoesNotOpenTheWayForAFork(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK2 := signedlog.Incept(t, keys).Rotate()
	real := atK2.Fork().Rotate()
	fork := atK2.Fork().Interact("mine").Interact("also mine")

	bothStores(t, func(t *testing.T, st contactLogs) {
		// 1. The real K1 -> K2 -> K3 log, verified.
		if err := st.SaveContactKEL(record(real, true)); err != nil {
			t.Fatal(err)
		}
		// 2. The same events, marked unverified.
		if err := st.SaveContactKEL(record(real, false)); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("an unverified copy replaced the verified log, err=%v", err)
		}
		// 3. A verified fork of it from the retired K2.
		if err := st.SaveContactKEL(record(fork, true)); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("a fork got in behind an unverified copy, err=%v", err)
		}
		got, _ := st.GetContactKEL(real.AID)
		if got == nil || !got.KelVerified || got.CurrentPublicKey != keys.Pub(2) || len(got.KEL) != real.Len() {
			t.Fatalf("the held log changed: %+v", got)
		}
	})
}
