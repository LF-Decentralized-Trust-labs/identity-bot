package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
	"identity-agent-core/sqlitedb"
)

const (
	machineOne = "EMachineOneMachineOneMachineOneMachineOne000"
	machineTwo = "EMachineTwoMachineTwoMachineTwoMachineTwo000"
)

// anchoring is l with an interaction appended that anchors event n of the
// Identity Agent m, as the writer of an owner log writes one: one event seal.
// Different n give different events at one place.
func anchoring(t *testing.T, l *signedlog.Log, m string, n int) *signedlog.Log {
	t.Helper()
	seal, err := drivers.EventSeal(m, fmt.Sprintf("%x", n), m)
	if err != nil {
		t.Fatal(err)
	}
	return l.Seal(seal)
}

// ownerLogEvents is a test log as the rows the store keeps.
func ownerLogEvents(l *signedlog.Log) []EventRecord {
	out := make([]EventRecord, 0, l.Len())
	for i, raw := range l.Raws {
		_, ilk := drivers.EventIDOfRawB64(base64.StdEncoding.EncodeToString(raw))
		out = append(out, EventRecord{
			AID: l.AID, SequenceNumber: i, EventType: ilk, EventJSON: string(raw),
			RawBytesB64: base64.StdEncoding.EncodeToString(raw), CesrSignature: l.Sigs[i],
		})
	}
	return out
}

// reservationFor is the reservation of the last event of l.
func reservationFor(l *signedlog.Log) OwnerLogReservation {
	evs := ownerLogEvents(l)
	last, before := evs[len(evs)-1], evs[len(evs)-2]
	digest, _ := drivers.EventIDOfRawB64(last.RawBytesB64)
	prior, _ := drivers.EventIDOfRawB64(before.RawBytesB64)
	return OwnerLogReservation{OwnerAID: l.AID, SN: last.SequenceNumber, PriorDigest: prior,
		Digest: digest, RawB64: last.RawBytesB64}
}

// mintedOwner keeps a founded owner identity and its founding, as a mint does.
func mintedOwner(t *testing.T, s *SQLiteStore, l *signedlog.Log, index int) {
	t.Helper()
	if err := s.RememberMachineOwnerIdentity(l.AID, index, "individual"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveEvent(ownerLogEvents(l)[0]); err != nil {
		t.Fatal(err)
	}
}

// extended reserves and keeps every event of l after those the store holds.
func extended(t *testing.T, s *SQLiteStore, l *signedlog.Log, m string) {
	t.Helper()
	held, err := s.GetEvents(l.AID)
	if err != nil {
		t.Fatal(err)
	}
	for n := len(held) + 1; n <= l.Len(); n++ {
		upTo := l.Cut(n)
		if _, err := s.ReserveOwnerLogPlace(reservationFor(upTo), m); err != nil {
			t.Fatal(err)
		}
		if err := s.KeepOwnerLogEvent(ownerLogEvents(upTo)[n-1]); err != nil {
			t.Fatal(err)
		}
	}
}

func digestsOf(t *testing.T, s *SQLiteStore, aid string) []string {
	t.Helper()
	events, err := s.GetEvents(aid)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ev := range events {
		d, _ := drivers.EventIDOfRawB64(ev.RawBytesB64)
		out = append(out, d)
	}
	return out
}

func digestsIn(l *signedlog.Log) []string {
	var out []string
	for _, ev := range ownerLogEvents(l) {
		d, _ := drivers.EventIDOfRawB64(ev.RawBytesB64)
		out = append(out, d)
	}
	return out
}

// A place reserved for one event is never reserved for another: the second
// request is answered with the first reservation, and that is all a caller
// may sign.
func TestAPlaceIsReservedForOneEventForGood(t *testing.T) {
	_, s := openStore(t)
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	mintedOwner(t, s, founded, 1)
	first := reservationFor(anchoring(t, founded.Fork(), machineOne, 0))
	second := reservationFor(anchoring(t, founded.Fork(), machineOne, 1))

	got, err := s.ReserveOwnerLogPlace(first, machineOne)
	if err != nil || got.Digest != first.Digest || got.State != OwnerLogReserved {
		t.Fatalf("the first reservation: %+v, %v", got, err)
	}
	got, err = s.ReserveOwnerLogPlace(second, machineOne)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != first.Digest || got.RawB64 != first.RawB64 {
		t.Fatalf("a second event was reserved at a reserved place: %+v", got)
	}
	all, _ := s.OwnerLogReservations(founded.AID)
	if len(all) != 1 || all[0].Digest != first.Digest {
		t.Fatalf("the reservations are %+v", all)
	}
	// And only the reserved bytes are kept there.
	if err := s.KeepOwnerLogEvent(ownerLogEvents(anchoring(t, founded.Fork(), machineOne, 1))[1]); err == nil {
		t.Fatal("an event that was not the one reserved was kept at the reserved place")
	}
	if got := digestsOf(t, s, founded.AID); len(got) != 1 {
		t.Fatalf("the log now holds %v", got)
	}
}

// An event is kept in an owner log only at a place reserved for it, and only
// signed.
func TestAnOwnerLogEventIsKeptOnlyWhereItWasReserved(t *testing.T) {
	_, s := openStore(t)
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	mintedOwner(t, s, founded, 1)
	next := anchoring(t, founded.Fork(), machineOne, 0)
	ev := ownerLogEvents(next)[1]

	if err := s.KeepOwnerLogEvent(ev); err == nil {
		t.Fatal("an event was kept at a place nobody reserved")
	}
	if _, err := s.ReserveOwnerLogPlace(reservationFor(next), machineOne); err != nil {
		t.Fatal(err)
	}
	unsigned := ev
	unsigned.CesrSignature = ""
	if err := s.KeepOwnerLogEvent(unsigned); err == nil {
		t.Fatal("an unsigned event was kept")
	}
	// A different event, validly signed, at the place reserved for this one.
	if err := s.KeepOwnerLogEvent(ownerLogEvents(anchoring(t, founded.Fork(), machineOne, 1))[1]); err == nil {
		t.Fatal("a different event was kept at the place reserved for another")
	}
	if got := digestsOf(t, s, founded.AID); len(got) != 1 {
		t.Fatalf("the log holds %v", got)
	}
	if err := s.KeepOwnerLogEvent(ev); err != nil {
		t.Fatal(err)
	}
	if err := s.KeepOwnerLogEvent(ev); err != nil {
		t.Fatalf("keeping the same event again: %v", err)
	}
	all, _ := s.OwnerLogReservations(founded.AID)
	if len(all) != 1 || all[0].State != OwnerLogDone {
		t.Fatalf("the reservation is %+v", all)
	}
	if got := digestsOf(t, s, founded.AID); len(got) != 2 {
		t.Fatalf("the log holds %v", got)
	}
}

// A reservation is refused where its place does not follow the kept log, or
// while an earlier one still waits for its event.
func TestAReservationFollowsTheKeptLog(t *testing.T) {
	_, s := openStore(t)
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	mintedOwner(t, s, founded, 1)
	two := anchoring(t, anchoring(t, founded.Fork(), machineOne, 0), machineOne, 1)

	if _, err := s.ReserveOwnerLogPlace(reservationFor(two), machineOne); !errors.Is(err, ErrOwnerLogPlaceNotNext) {
		t.Fatalf("a place two past the tip was reserved: %v", err)
	}
	if _, err := s.ReserveOwnerLogPlace(reservationFor(two.Cut(2)), machineOne); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveOwnerLogPlace(reservationFor(two), machineOne); !errors.Is(err, ErrOwnerLogPlaceNotNext) {
		t.Fatalf("a second place was reserved while the first still waits: %v", err)
	}
	stranger := anchoring(t, signedlog.Incept(t, signedlog.NewKeys(t, 2)), machineOne, 0)
	if _, err := s.ReserveOwnerLogPlace(reservationFor(stranger), machineOne); !errors.Is(err, ErrNotAnOwnerIdentity) {
		t.Fatalf("a place was reserved in a log this device does not own: %v", err)
	}
}

// One owner identity anchors one Identity Agent, and one that was given up or
// is known to be duplicitous anchors nothing.
func TestAnOwnerIdentityReservesForOneIdentityAgentOnly(t *testing.T) {
	_, s := openStore(t)
	founded := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	mintedOwner(t, s, founded, 1)
	one := anchoring(t, founded.Fork(), machineOne, 0)
	extended(t, s, one, machineOne)

	two := anchoring(t, one.Fork(), machineOne, 1)
	if _, err := s.ReserveOwnerLogPlace(reservationFor(anchoring(t, one.Fork(), machineTwo, 0)), machineTwo); !errors.Is(err, ErrOwnerLogNamesAnother) {
		t.Fatalf("a second Identity Agent was reserved for: %v", err)
	}
	if id, _, _ := s.MachineOwnerIdentity(founded.AID); id.AnchoredM != machineOne {
		t.Fatalf("it anchors %q", id.AnchoredM)
	}
	// A later event of the same Identity Agent is not a second one.
	if _, err := s.ReserveOwnerLogPlace(reservationFor(two), machineOne); err != nil {
		t.Fatal(err)
	}

	givenUp := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	mintedOwner(t, s, givenUp, 2)
	if err := s.GiveUpMachineOwnerIdentity(givenUp.AID, machineOne); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReserveOwnerLogPlace(reservationFor(anchoring(t, givenUp.Fork(), machineOne, 0)), machineOne); !errors.Is(err, ErrOwnerIdentityGivenUp) {
		t.Fatalf("a given-up owner identity reserved a place: %v", err)
	}
	if err := s.GiveUpMachineOwnerIdentity(givenUp.AID, machineTwo); err == nil {
		t.Fatal("an owner identity was given up for a second Identity Agent")
	}

	forked := signedlog.Incept(t, signedlog.NewKeys(t, 2))
	mintedOwner(t, s, forked, 3)
	if err := s.MarkMachineOwnerIdentityDuplicitous(forked.AID, 4); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkMachineOwnerIdentityDuplicitous(forked.AID, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkMachineOwnerIdentityDuplicitous(forked.AID, 7); err != nil {
		t.Fatal(err)
	}
	if id, _, _ := s.MachineOwnerIdentity(forked.AID); id.DuplicitousAt == nil || *id.DuplicitousAt != 2 {
		t.Fatalf("the first place of duplicity is %v", id.DuplicitousAt)
	}
	if _, err := s.ReserveOwnerLogPlace(reservationFor(anchoring(t, forked.Fork(), machineOne, 0)), machineOne); !errors.Is(err, ErrOwnerIdentityDuplicitous) {
		t.Fatalf("a duplicitous owner identity reserved a place: %v", err)
	}
}

// The kind is kept with the index at mint, and a later call does not change
// either.
func TestTheKindIsKeptWithTheIndexAtMint(t *testing.T) {
	_, s := openStore(t)
	if err := s.RememberMachineOwnerIdentity("EOwner", 7, "organisation"); err != nil {
		t.Fatal(err)
	}
	if err := s.RememberMachineOwnerIdentity("EOwner", 9, "individual"); err != nil {
		t.Fatal(err)
	}
	id, found, err := s.MachineOwnerIdentity("EOwner")
	if err != nil || !found || id.KeyIndex != 7 || id.Kind != "organisation" {
		t.Fatalf("kept %+v (found=%v, %v)", id, found, err)
	}
	if idx, found, _ := s.MachineOwnerIndex("EOwner"); !found || idx != 7 {
		t.Fatalf("the index is %d", idx)
	}
	all, err := s.MachineOwnerIdentities()
	if err != nil || len(all) != 1 || all[0].Kind != "organisation" {
		t.Fatalf("listed %+v, %v", all, err)
	}
}

// A reservation is written with the journal flushed at commit, and the
// connection it used goes back with the settings every connection has.
func TestAReservationIsWrittenThroughToDisk(t *testing.T) {
	_, s := openStore(t)
	var during, full int
	err := s.durably(func(tx *sql.Tx) error {
		if err := tx.QueryRow("PRAGMA synchronous").Scan(&during); err != nil {
			return err
		}
		return tx.QueryRow("PRAGMA fullfsync").Scan(&full)
	})
	if err != nil {
		t.Fatal(err)
	}
	if during != 2 || full != 1 {
		t.Fatalf("inside the transaction synchronous is %d and fullfsync %d, want 2 (FULL) and 1", during, full)
	}
	settings, err := sqlitedb.InForce(s.DB(), 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, got := range settings {
		if got != "5000 wal 1 1" {
			t.Fatalf("connection %d was left with %q", i, got)
		}
	}
}

// A durable transaction that reads before it writes is not refused because
// another connection wrote in between: it holds the write lock from its
// start, and the other writer waits for it.
func TestADurableTransactionIsNotRefusedByAWriteMadeWhileItReads(t *testing.T) {
	_, s := openStore(t)
	other := make(chan error, 1)
	err := s.durably(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM owner_log_reservations`).Scan(&n); err != nil {
			return err
		}
		go func() {
			_, err := s.DB().Exec(`INSERT INTO machine_owner_identities (aid, key_index) VALUES ('EOther', 1)`)
			other <- err
		}()
		// Long enough for the other write to land, were it let in.
		select {
		case err := <-other:
			other <- err
		case <-time.After(300 * time.Millisecond):
		}
		_, err := tx.Exec(`INSERT INTO machine_owner_identities (aid, key_index) VALUES ('EThis', 2)`)
		return err
	})
	if err != nil {
		t.Fatalf("the durable transaction was refused: %v", err)
	}
	if err := <-other; err != nil {
		t.Fatalf("the other write, made after it: %v", err)
	}
}

// An install made before owner logs were extended gains the columns and the
// table, and what it already held is kept as it was.
func TestAnInstallFromBeforeOwnerLogsWereExtendedUpgrades(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "id.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := applyMigrationsUpTo(db, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO machine_owner_identities (aid, key_index) VALUES ('EOld', 5)`); err != nil {
		t.Fatal(err)
	}
	if err := ApplyIdentityMigrations(db); err != nil {
		t.Fatal(err)
	}
	s := &SQLiteStore{db: db}
	id, found, err := s.MachineOwnerIdentity("EOld")
	if err != nil || !found || id.KeyIndex != 5 || id.Kind != "" || id.AnchoredM != "" ||
		id.GivenUpFor != "" || id.DuplicitousAt != nil {
		t.Fatalf("the earlier row reads %+v (found=%v, %v)", id, found, err)
	}
	if got, err := s.OwnerLogReservations("EOld"); err != nil || len(got) != 0 {
		t.Fatalf("the reservations table: %v, %v", got, err)
	}
}
