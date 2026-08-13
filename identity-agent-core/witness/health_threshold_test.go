package witness

import (
	"testing"
	"time"

	"identity-agent-core/store"
)

// The tolerance is a length of time, not a count of failures. A bare count
// reads as if it means something on its own, and silently changes meaning when
// the heartbeat interval moves.
func TestTheOfflineToleranceIsExpressedInTime(t *testing.T) {
	if OfflineTolerance < 24*time.Hour {
		t.Fatalf("a witness is written off after %v; a machine that reboots, moves house or "+
			"loses power for a day should be waited for, not replaced", OfflineTolerance)
	}
	if got := time.Duration(OfflineFailureThreshold) * HeartbeatInterval; got != OfflineTolerance {
		t.Fatalf("the failure count works out to %v, which is not the stated tolerance %v",
			got, OfflineTolerance)
	}
}

// A witness that comes back is relied on again. The key log designated it the
// whole time, so resuming costs nothing — and without this, dropping was
// automatic while restoring needed a fresh enrolment, so one bad night cost a
// witness permanently.
func TestAWitnessThatComesBackIsReliedOnAgain(t *testing.T) {
	s, mc := testService(t)
	mc.contacts["EFriend"] = store.ContactRecord{
		AID: "EFriend", Status: "accepted", ContactCategory: "general", IsWitness: true,
	}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: "EFriend", BackendType: BackendDesktop, WitnessStatus: StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}

	// Long enough to be written off.
	for i := 0; i < OfflineFailureThreshold; i++ {
		s.RecordHeartbeatResult("EFriend", false)
	}
	c, _ := s.Contacts.GetContact("EFriend")
	if c.IsWitness {
		t.Fatal("a witness silent for the whole tolerance was still being relied on")
	}

	// And then it answers.
	s.RecordHeartbeatResult("EFriend", true)
	c, _ = s.Contacts.GetContact("EFriend")
	if !c.IsWitness {
		t.Fatal("a witness that came back was not resumed, so one outage cost it permanently")
	}
	meta, err := s.Store.GetContactMeta("EFriend")
	if err != nil || meta == nil {
		// Said plainly rather than dereferenced. Absent is a real answer here —
		// no row is reported as (nil, nil) — and discarding it turned a missing
		// row into a panic that took the whole package down and pointed at
		// witnesses instead of at the store.
		t.Fatalf("no health record for a witness that has one: %v", err)
	}
	if meta.WitnessStatus != StatusOnline || meta.OfflineCount != 0 {
		t.Fatalf("its health was not reset: status=%s count=%d", meta.WitnessStatus, meta.OfflineCount)
	}
}

// A short outage must not drop anything. This is the case the previous
// one-hour threshold got wrong.
func TestAShortOutageDoesNotDropAWitness(t *testing.T) {
	s, mc := testService(t)
	mc.contacts["EFriend"] = store.ContactRecord{
		AID: "EFriend", Status: "accepted", ContactCategory: "general", IsWitness: true,
	}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: "EFriend", BackendType: BackendDesktop, WitnessStatus: StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}

	// Four hours of silence — the old threshold was one hour.
	for i := 0; i < int(4*time.Hour/HeartbeatInterval); i++ {
		s.RecordHeartbeatResult("EFriend", false)
	}
	c, _ := s.Contacts.GetContact("EFriend")
	if !c.IsWitness {
		t.Fatal("four hours offline cost a witness; a reboot or a power cut should not")
	}
}

// Recovery must clear the count, or intermittent failures accumulate over
// months and eventually write off a witness that is mostly fine.
func TestIntermittentFailuresDoNotAccumulate(t *testing.T) {
	s, mc := testService(t)
	mc.contacts["EFriend"] = store.ContactRecord{
		AID: "EFriend", Status: "accepted", ContactCategory: "general", IsWitness: true,
	}
	if err := s.Store.SaveContactMeta(ContactMeta{
		ContactAID: "EFriend", BackendType: BackendDesktop, WitnessStatus: StatusOnline,
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < OfflineFailureThreshold*3; i++ {
		s.RecordHeartbeatResult("EFriend", false)
		s.RecordHeartbeatResult("EFriend", true) // answered again
	}
	c, _ := s.Contacts.GetContact("EFriend")
	if !c.IsWitness {
		t.Fatal("a witness that answered every other check was written off")
	}
}
