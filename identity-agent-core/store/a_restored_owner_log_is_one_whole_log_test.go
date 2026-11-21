package store

import (
	"encoding/base64"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
)

// A restored database never ends with two events at one place in an owner
// log: the merged log is always one whole verified log.
func TestARestoredDatabaseNeverEndsWithTwoEventsAtOnePlaceInAnOwnerLog(t *testing.T) {
	keys := signedlog.NewKeys(t, 2)
	founded := signedlog.Incept(t, keys)
	short := anchoring(t, founded.Fork(), machineOne, 0)
	long := anchoring(t, anchoring(t, short.Fork(), machineOne, 1), machineOne, 2)
	other := anchoring(t, founded.Fork(), machineOne, 5)
	otherLong := anchoring(t, anchoring(t, anchoring(t, other.Fork(), machineOne, 6), machineOne, 7), machineOne, 8)

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
	t.Run("a different event done at one place marks the identity and the held log stands", func(t *testing.T) {
		into := holding(t, long, true)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, otherLong, true))); err != nil {
			t.Fatalf("the restore was refused: %v", err)
		}
		wholeLog(t, into, long)
		if id, _, _ := into.MachineOwnerIdentity(founded.AID); id.DuplicitousAt == nil || *id.DuplicitousAt != 1 {
			t.Fatalf("the parting was not recorded: %+v", id)
		}
		reservationsAre(t, into, founded.AID, long)
	})
	t.Run("of two logs that part, the held one stands whole and the identity is marked", func(t *testing.T) {
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

		// The backup's is the longer: the held one still stands, whole.
		into = holding(t, long, false)
		if err := into.ImportSnapshot(snapshotOf(t, holding(t, otherLong, false))); err != nil {
			t.Fatal(err)
		}
		wholeLog(t, into, long)
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
	t.Run("of two Identity Agents recorded as anchored, the one whose reservation stands is kept", func(t *testing.T) {
		into := holding(t, founded, true)
		from := holding(t, founded, true)
		if _, err := into.ReserveOwnerLogPlace(reservationFor(short), machineOne); err != nil {
			t.Fatal(err)
		}
		if _, err := from.db.Exec(`UPDATE machine_owner_identities SET anchored_m = ?`, machineTwo); err != nil {
			t.Fatal(err)
		}
		if err := into.ImportSnapshot(snapshotOf(t, from)); err != nil {
			t.Fatalf("the restore was refused: %v", err)
		}
		if id, _, _ := into.MachineOwnerIdentity(founded.AID); id.AnchoredM != machineOne || id.DuplicitousAt != nil {
			t.Fatalf("the identity reads %+v", id)
		}
	})
}

// reservationsAre checks that the reservations held in aid's log are those
// of l's events after its founding, all done, and nothing else.
func reservationsAre(t *testing.T, s *SQLiteStore, aid string, l *signedlog.Log) {
	n := l.Len()
	t.Helper()
	res, err := s.OwnerLogReservations(aid)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != n-1 {
		t.Fatalf("%d reservations are held, want %d: %+v", len(res), n-1, res)
	}
	for i, r := range res {
		want := reservationFor(l.Cut(i + 2))
		if r.SN != i+1 || r.RawB64 != want.RawB64 || r.State != OwnerLogDone {
			t.Fatalf("the reservation at %d is %+v, want the done reservation of %s", r.SN, r, want.Digest)
		}
	}
}

// A restore is never refused for what two databases say about an owner
// identity's log. The device that restores an older backup, anchors, and
// then restores a newer backup that anchored differently at the same place
// gets everything the newer backup holds, and the owner identity is marked
// as having two events at that place.
func TestARestoreIsNotLockedOutByTwoAnchorsAtOnePlace(t *testing.T) {
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	anchoredFirst := anchoring(t, founded.Fork(), machineOne, 0)
	anchoredHere := anchoring(t, founded.Fork(), machineOne, 1)

	// The first device: a backup before it anchored, and one after, with a
	// contact and a credential.
	_, first := openStore(t)
	mintedOwner(t, first, founded, 1)
	older := snapshotOf(t, first)
	extended(t, first, anchoredFirst, machineOne)
	if err := first.SaveContact(ContactRecord{AID: "EContactFromTheNewerBackup", Alias: "Newer"}); err != nil {
		t.Fatal(err)
	}
	if err := first.SaveCredential(CredentialRecord{SAID: "ECredentialFromTheNewerBackup", Status: "issued"}); err != nil {
		t.Fatal(err)
	}
	newer := snapshotOf(t, first)

	// This device restores the older backup and anchors at the same place.
	_, here := openStore(t)
	if err := here.ImportSnapshot(older); err != nil {
		t.Fatal(err)
	}
	extended(t, here, anchoredHere, machineOne)

	for try := 1; try <= 2; try++ {
		if err := here.ImportSnapshot(newer); err != nil {
			t.Fatalf("restore %d of the newer backup was refused: %v", try, err)
		}
		if c, err := here.GetContact("EContactFromTheNewerBackup"); err != nil || c == nil {
			t.Fatalf("the contact was not restored: %v", err)
		}
		if c, err := here.GetCredential("ECredentialFromTheNewerBackup"); err != nil || c == nil {
			t.Fatalf("the credential was not restored: %v", err)
		}
		id, _, _ := here.MachineOwnerIdentity(founded.AID)
		if id.DuplicitousAt == nil || *id.DuplicitousAt != 1 || id.AnchoredM != machineOne {
			t.Fatalf("the owner identity reads %+v", id)
		}
		if got, want := digestsOf(t, here, founded.AID), digestsIn(anchoredHere); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("the log is %v, want this device's %v", got, want)
		}
		reservationsAre(t, here, founded.AID, anchoredHere)
	}
}

// Each way two databases can disagree about one place in an owner log is
// settled without refusing the restore.
func TestTwoDatabasesThatDisagreeAboutAnOwnerLogAreSettled(t *testing.T) {
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	a := anchoring(t, founded.Fork(), machineOne, 0)
	b := anchoring(t, founded.Fork(), machineTwo, 0)

	// done keeps l's events after the founding; waiting reserves l's last
	// event and keeps nothing.
	done := func(t *testing.T, l *signedlog.Log, m string) *SQLiteStore {
		_, s := openStore(t)
		mintedOwner(t, s, founded, 1)
		extended(t, s, l, m)
		return s
	}
	waiting := func(t *testing.T, l *signedlog.Log, m string) *SQLiteStore {
		_, s := openStore(t)
		mintedOwner(t, s, founded, 1)
		if _, err := s.ReserveOwnerLogPlace(reservationFor(l), m); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// broken spoils the signature of the event at place 1.
	broken := func(t *testing.T, s *SQLiteStore) *SQLiteStore {
		if _, err := s.db.Exec(`UPDATE kel SET cesr_signature = (SELECT cesr_signature FROM kel WHERE seq_num = 0)
			WHERE seq_num = 1`); err != nil {
			t.Fatal(err)
		}
		return s
	}
	restore := func(t *testing.T, into, from *SQLiteStore) MachineOwnerIdentity {
		t.Helper()
		if err := into.ImportSnapshot(snapshotOf(t, from)); err != nil {
			t.Fatalf("the restore was refused: %v", err)
		}
		id, _, _ := into.MachineOwnerIdentity(founded.AID)
		return id
	}
	logIs := func(t *testing.T, s *SQLiteStore, l *signedlog.Log) {
		t.Helper()
		if got, want := digestsOf(t, s, founded.AID), digestsIn(l); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("the log is %v, want %v", got, want)
		}
	}
	waitingIs := func(t *testing.T, s *SQLiteStore, l *signedlog.Log) {
		t.Helper()
		res, _ := s.OwnerLogReservations(founded.AID)
		want := reservationFor(l)
		if len(res) != 1 || res[0].RawB64 != want.RawB64 || res[0].State != OwnerLogReserved {
			t.Fatalf("the reservations are %+v, want %s waiting", res, want.Digest)
		}
	}

	t.Run("both done with different events, each verified: marked, this device's stands", func(t *testing.T) {
		into := done(t, a, machineOne)
		id := restore(t, into, done(t, b, machineTwo))
		if id.DuplicitousAt == nil || *id.DuplicitousAt != 1 || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, a)
		reservationsAre(t, into, founded.AID, a)
	})
	t.Run("done in the backup, only reserved here: the done one is taken", func(t *testing.T) {
		into := waiting(t, b, machineTwo)
		id := restore(t, into, done(t, a, machineOne))
		if id.DuplicitousAt != nil || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, a)
		reservationsAre(t, into, founded.AID, a)
	})
	t.Run("done here, only reserved in the backup: the done one stays", func(t *testing.T) {
		into := done(t, a, machineOne)
		id := restore(t, into, waiting(t, b, machineTwo))
		if id.DuplicitousAt != nil || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, a)
		reservationsAre(t, into, founded.AID, a)
	})
	t.Run("done in a backup whose log is not taken, only reserved here: the done one waits", func(t *testing.T) {
		// The backup's log does not verify, so this device's stands, and the
		// place after its tip is reserved in both. The backup's reservation
		// was signed and kept there, so it may have been sent: it is the one
		// that waits to be finished, with the same bytes.
		into := waiting(t, anchoring(t, founded.Fork(), machineOne, 3), machineOne)
		id := restore(t, into, broken(t, done(t, a, machineOne)))
		if id.DuplicitousAt != nil || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, founded)
		waitingIs(t, into, a)
	})
	t.Run("both only reserved with different events: this device's stays", func(t *testing.T) {
		into := waiting(t, a, machineOne)
		id := restore(t, into, waiting(t, b, machineTwo))
		if id.DuplicitousAt != nil || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, founded)
		waitingIs(t, into, a)
	})
	t.Run("only reserved in the backup: it is taken", func(t *testing.T) {
		_, into := openStore(t)
		mintedOwner(t, into, founded, 1)
		id := restore(t, into, waiting(t, b, machineTwo))
		if id.DuplicitousAt != nil || id.AnchoredM != machineTwo {
			t.Fatalf("the identity reads %+v", id)
		}
		waitingIs(t, into, b)
	})
	t.Run("the backup's log does not verify: nothing is marked and this device's stands", func(t *testing.T) {
		into := done(t, a, machineOne)
		id := restore(t, into, broken(t, done(t, b, machineTwo)))
		if id.DuplicitousAt != nil || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, a)
		reservationsAre(t, into, founded.AID, a)
	})
	t.Run("this device's log does not verify: nothing is marked and the backup's is taken", func(t *testing.T) {
		into := broken(t, done(t, a, machineOne))
		id := restore(t, into, done(t, b, machineTwo))
		if id.DuplicitousAt != nil || id.AnchoredM != machineTwo {
			t.Fatalf("the identity reads %+v", id)
		}
		logIs(t, into, b)
		reservationsAre(t, into, founded.AID, b)
	})
	t.Run("neither verifies: nothing is marked and this device's stands", func(t *testing.T) {
		into := broken(t, done(t, a, machineOne))
		id := restore(t, into, broken(t, done(t, b, machineTwo)))
		if id.DuplicitousAt != nil || id.AnchoredM != machineOne {
			t.Fatalf("the identity reads %+v", id)
		}
		events, _ := into.GetEvents(founded.AID)
		if d, _ := drivers.EventIDOfRawB64(events[1].RawBytesB64); len(events) != 2 || d != a.SAID(1) {
			t.Fatalf("the log holds %d events", len(events))
		}
	})
	t.Run("a log only the backup holds is taken only if it verifies", func(t *testing.T) {
		_, into := openStore(t)
		id := restore(t, into, broken(t, done(t, a, machineOne)))
		if events, _ := into.GetEvents(founded.AID); len(events) != 0 {
			t.Fatalf("a log that does not verify was taken: %d events", len(events))
		}
		if res, _ := into.OwnerLogReservations(founded.AID); len(res) != 0 {
			t.Fatalf("its reservations were taken: %+v", res)
		}
		if id.KeyIndex != 1 {
			t.Fatalf("the identity reads %+v", id)
		}
	})
}

// tamperedReservations are bytes a reservation at place 1 of founded's log
// can hold that are not the interaction the row says they are, each with the
// digest the row would state for them.
func tamperedReservations(t *testing.T, founded *signedlog.Log) map[string][2]string {
	t.Helper()
	at := func(l *signedlog.Log, i int) (string, string) {
		raw := base64.StdEncoding.EncodeToString(l.Raws[i])
		return raw, l.SAID(i)
	}
	out := map[string][2]string{}
	stranger := anchoring(t, signedlog.Incept(t, signedlog.NewKeys(t, 2)), machineOne, 0)
	raw, d := at(stranger, 1)
	out["another identifier"] = [2]string{raw, d}
	raw, d = at(anchoring(t, anchoring(t, founded.Fork(), machineOne, 0), machineOne, 1), 2)
	out["another place"] = [2]string{raw, d}
	raw, d = at(founded.Fork().Rotate(), 1)
	out["a rotation"] = [2]string{raw, d}
	raw, d = at(anchoring(t, founded.Fork(), machineTwo, 0), 1)
	out["a seal naming another Identity Agent"] = [2]string{raw, d}
	// The bytes of a true anchor with the digest field changed: the digest
	// stated is not the digest of the bytes.
	real := anchoring(t, founded.Fork(), machineOne, 0)
	forged := "EForgedDigestForgedDigestForgedDigestForged0"
	bytes := strings.Replace(string(real.Raws[1]), real.SAID(1), forged, 1)
	out["a digest that is not the digest of its bytes"] = [2]string{
		base64.StdEncoding.EncodeToString([]byte(bytes)), forged}
	// A true anchor with something after it, and its digest derived again
	// over the longer bytes, so that the digest stated is theirs.
	for name, tail := range map[string]string{"a newline after the event": "\n",
		"spaces after the event": "   ", "an empty object after the event": "{}", "junk after the event": "junk"} {
		raw, d := paddedWithItsDigest(t, real.Raws[1], real.SAID(1), tail)
		out[name] = [2]string{base64.StdEncoding.EncodeToString(raw), d}
	}
	return out
}

// paddedWithItsDigest is an event's bytes with tail after them and the
// digest field set to the digest computed over the padded bytes.
func paddedWithItsDigest(t *testing.T, raw []byte, said, tail string) ([]byte, string) {
	t.Helper()
	padded := append(append([]byte{}, raw...), tail...)
	d, err := keri.ComputeSAID(padded)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(padded), said, d, 1)), d
}

// Padded bytes whose digest is that of the padded bytes are not one
// canonical event, and Anchors refuses them, as it does every tampered row
// but the one that is a true anchor of another Identity Agent, which is
// refused by whoever knows which Identity Agent is meant.
func TestAReservationOfBytesThatAreNotOneCanonicalEventIsRefused(t *testing.T) {
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	for name, bad := range tamperedReservations(t, founded) {
		if name == "a seal naming another Identity Agent" {
			continue
		}
		r := OwnerLogReservation{OwnerAID: founded.AID, SN: 1, PriorDigest: founded.SAID(0), Digest: bad[1], RawB64: bad[0]}
		if _, err := r.Anchors(); err == nil {
			t.Errorf("%s: Anchors accepted it", name)
		}
	}
}

// A reservation in a backup is taken only if its bytes are the interaction
// it describes, anchoring the Identity Agent the backup records: nothing on
// this device wrote it, and its bytes are what the key would sign.
func TestARestoredReservationThatIsNotWhatItSaysIsNotTaken(t *testing.T) {
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	for name, bad := range tamperedReservations(t, founded) {
		t.Run(name, func(t *testing.T) {
			_, into := openStore(t)
			mintedOwner(t, into, founded, 1)
			_, from := openStore(t)
			mintedOwner(t, from, founded, 1)
			if _, err := from.ReserveOwnerLogPlace(reservationFor(anchoring(t, founded.Fork(), machineOne, 0)), machineOne); err != nil {
				t.Fatal(err)
			}
			if _, err := from.db.Exec(`UPDATE owner_log_reservations SET event_bytes_b64 = ?, digest = ?`,
				bad[0], bad[1]); err != nil {
				t.Fatal(err)
			}
			if err := into.ImportSnapshot(snapshotOf(t, from)); err != nil {
				t.Fatalf("the restore was refused: %v", err)
			}
			if res, _ := into.OwnerLogReservations(founded.AID); len(res) != 0 {
				t.Fatalf("a reservation that is not what it says was taken: %+v", res)
			}
		})
	}
}
