package store

import (
	"errors"
	"testing"

	"identity-agent-core/drivers/signedlog"
)

// A recovery rotation (ADR-061 section 10) takes the place of interactions a
// stolen current key signed, signed by the keys the log committed to next. It
// is how the owner takes the identity back, and the log it leaves may be as
// long as the one held, or shorter. A machine holding the thief's interactions
// takes it; a fork that only replaces interactions with interactions it still
// refuses. Fails when the held log is replaced only by a log carrying it
// further.
func TestARecoveryReplacesTheInteractionsItSupersedes(t *testing.T) {
	keys := signedlog.NewKeys(t, 3)
	atK1 := signedlog.Incept(t, keys)
	stolen := atK1.Fork().Interact("the thief's").Interact("and another")
	recovered := atK1.Fork().Rotate()                               // shorter than stolen
	recoveredAsLong := atK1.Fork().Rotate().Interact("the owner's") // as long

	for name, recovery := range map[string]*signedlog.Log{"shorter": recovered, "as long": recoveredAsLong} {
		t.Run(name, func(t *testing.T) {
			bothStores(t, func(t *testing.T, st contactLogs) {
				if err := st.SaveContactKEL(record(stolen, true)); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveContactKEL(record(recovery, true)); err != nil {
					t.Fatalf("the recovery did not replace the thief's interactions: %v", err)
				}
				got, _ := st.GetContactKEL(recovery.AID)
				if got == nil || len(got.KEL) != recovery.Len() || got.CurrentPublicKey != keys.Pub(1) {
					t.Fatalf("the held log is not the recovered one: %+v", got)
				}
			})
		})
	}
}

// Interactions in place of interactions are a fork, not a recovery: the same
// current key signed both, and nothing says which is the owner's.
func TestInteractionsInPlaceOfInteractionsDoNotReplaceTheHeldLog(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	atK1 := signedlog.Incept(t, keys)
	held := atK1.Fork().Interact("one")
	fork := atK1.Fork().Interact("another")

	bothStores(t, func(t *testing.T, st contactLogs) {
		if err := st.SaveContactKEL(record(held, true)); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveContactKEL(record(fork, true)); !errors.Is(err, ErrLogDoesNotExtend) {
			t.Fatalf("an equal-length fork of interactions replaced the held log: %v", err)
		}
	})
}
