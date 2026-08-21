package server

import (
	"strings"
	"testing"
)

// The owner is told where they will actually see it.
//
// A holder being asked for a share is the one property this design has that no
// other configuration does: a theft becomes an event the owner hears about
// rather than one they never do. That was a line in a server log, which is not
// a warning — it is a warning nobody reads — while the agent already had
// somewhere to put one.
func TestTheOwnerIsToldWhereTheyWillSeeIt(t *testing.T) {
	s := agentWithNoIdentity(t)

	s.tellTheOwnerAShareWasAskedFor("EPairwiseForSomebody")

	notes, err := s.DataStore.GetNotifications("unread", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("expected the owner to be told once, found %d notifications", len(notes))
	}
	n := notes[0]
	if n.Status != "unread" {
		t.Fatalf("it arrived already read: %q", n.Status)
	}
	// It has to say what to do, because somebody holding a share for a friend
	// has no idea what this means otherwise.
	if !strings.Contains(strings.ToLower(n.Body), "not something you expected") {
		t.Fatalf("it does not say what to do about it: %q", n.Body)
	}
	if n.Payload != "EPairwiseForSomebody" {
		t.Fatalf("it does not say which holding was asked about: %q", n.Payload)
	}
}

// A notification that cannot be written does not break the recovery.
//
// Refusing to answer a share request because a notification failed would turn
// a delivery problem into a broken recovery, which is the wrong trade by a
// distance.
func TestAFailedNotificationDoesNotBreakAnything(t *testing.T) {
	s := &CoreServer{} // no store at all
	s.tellTheOwnerAShareWasAskedFor("EAnything")
}
