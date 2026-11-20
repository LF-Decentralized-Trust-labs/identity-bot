package store

import (
	"strings"
	"testing"

	"identity-agent-core/drivers/signedlog"
)

// A restored database never ends with two events at one place in an owner
// log: the merged log is always one whole verified log.
func TestARestoredDatabaseNeverEndsWithTwoEventsAtOnePlaceInAnOwnerLog(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	founded := signedlog.Incept(t, keys)
	short := founded.Fork().Interact("a")
	long := short.Fork().Interact("a2").Interact("a3")
	other := founded.Fork().Interact("b")
	otherLong := other.Fork().Interact("b2").Interact("b3").Interact("b4")

	// A store holding log, written through reservations or, for a log from
	// before they were kept, without.
	holding := func(t *testing.T, log *signedlog.Log, reserved bool) *SQLiteStore {
		_, s := openStore(t)
		mintedOwner(t, s, founded, 1)
		if reserved {
			extended(t, s, log, machineOne)
			return s
		}
		for _, ev := range ownerLogEvents(log) {
			if err := s.SaveEvent(ev); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	wholeLog := func(t *testing.T, s *SQLiteStore, want *signedlog.Log) {
		t.Helper()
		events, err := s.GetEvents(founded.AID)
		if err != nil {
			t.Fatal(err)
		}
		if !isVerifiedLogOf(founded.AID, events) {
			t.Fatalf("the merged log is not one verified log: %v", digestsOf(t, s, founded.AID))
		}
		if got, w := digestsOf(t, s, founded.AID), digestsIn(want); strings.Join(got, ",") != strings.Join(w, ",") {
			t.Fatalf("the merged log is %v, want %v", got, w)
		}
	}

	t.Run("a backup that carries the held log on is taken", func(t *testing.T) {
		into := holding(t, short, true)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, long, true))); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, long)
		res, _ := into.OwnerLogReservations(founded.AID)
		if len(res) != 3 || res[2].State != OwnerLogDone {
			t.Fatalf("the reservations are %+v", res)
		}
	})
	t.Run("an older backup does not wind the held log back", func(t *testing.T) {
		into := holding(t, long, true)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, short, true))); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, long)
	})
	t.Run("a different event reserved at one place refuses the restore", func(t *testing.T) {
		into := holding(t, long, true)
		err := into.ImportSnapshot(snapshotOf(t, holding(t, otherLong, true)))
		if err == nil || !strings.Contains(err.Error(), "reserved a different event") {
			t.Fatalf("the restore was not refused: %v", err)
		}
		wholeLog(t, into, long)
	})
	t.Run("of two logs that part, the longer stands whole and the identity is marked", func(t *testing.T) {
		// The held log is the longer: a row-by-row restore would put the
		// backup's event at place 1 under the held events after it.
		into := holding(t, long, false)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, other, false))); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, long)
		if id, _, _ := into.MachineOwnerIdentity(founded.AID); id.DuplicitousAt == nil || *id.DuplicitousAt != 1 {
			t.Fatalf("the parting was not recorded: %+v", id)
		}

		// The backup's is the longer: it replaces the held one from where
		// they part, and nothing of the held one is left after it.
		into = holding(t, long, false)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, otherLong, false))); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, otherLong)
		if id, _, _ := into.MachineOwnerIdentity(founded.AID); id.DuplicitousAt == nil || *id.DuplicitousAt != 1 {
			t.Fatalf("the parting was not recorded: %+v", id)
		}
	})
	t.Run("a backup's log that does not verify does not replace the held one", func(t *testing.T) {
		into := holding(t, short, false)
		from := holding(t, long, false)
		if _, err := from.db.Exec(`UPDATE kel SET cesr_signature = (SELECT cesr_signature FROM kel WHERE seq_num = 0)
			WHERE seq_num = 3`); err != nil {
			t.Fatal(err)
		}
		if err := into.ImportSnapshot(snapshotOf(t, from)); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, short)
	})
	t.Run("what was recorded beside the identity is not undone by an older backup", func(t *testing.T) {
		into := holding(t, short, true)
		older := snapshotOf(t, holding(t, founded, true))
		if err := into.GiveUpMachineOwnerIdentity(founded.AID, machineOne); err != nil {
			t.Fatal(err)
		}
		if err := into.ImportSnapshot(older); err != nil {
			t.Fatal(err)
		}
		id, _, _ := into.MachineOwnerIdentity(founded.AID)
		if id.GivenUpFor != machineOne || id.AnchoredM != machineOne || id.Kind != "individual" {
			t.Fatalf("after the restore the identity reads %+v", id)
		}
	})
	t.Run("an owner identity only the backup holds is restored with its log", func(t *testing.T) {
		_, into := openStore(t)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, long, true))); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, long)
		if id, found, _ := into.MachineOwnerIdentity(founded.AID); !found || id.AnchoredM != machineOne || id.KeyIndex != 1 {
			t.Fatalf("the identity reads %+v (found=%v)", id, found)
		}
	})
	t.Run("one owner identity anchoring two Identity Agents refuses the restore", func(t *testing.T) {
		into := holding(t, founded, true)
		from := holding(t, founded, true)
		if _, err := into.ReserveOwnerLogPlace(reservationFor(short), machineOne); err != nil {
			t.Fatal(err)
		}
		if _, err := from.db.Exec(`UPDATE machine_owner_identities SET anchored_m = ?`, machineTwo); err != nil {
			t.Fatal(err)
		}
		if err := into.ImportSnapshot(snapshotOf(t, from)); err == nil {
			t.Fatal("the restore was not refused")
		}
	})
}
