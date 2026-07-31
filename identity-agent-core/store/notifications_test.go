package store

import (
	"testing"
)

// notificationStore is the slice of Store these tests exercise.
//
// Narrower than Store on purpose. FileStore does not satisfy the full Store
// interface today — it is missing DeleteShareAction, and nothing notices because
// nothing assigns it to a Store — so a test written against Store would only
// ever run against SQLite while appearing to cover both.
type notificationStore interface {
	SaveNotification(n Notification) error
	GetNotification(id string) (*Notification, error)
	GetNotifications(status string, limit int) ([]Notification, error)
	SetNotificationStatus(id, status string) error
}

// Both implementations, because a method that behaves differently depending on
// which one is wired is a bug nobody finds until the day the other is used.
func eachStore(t *testing.T, run func(t *testing.T, s notificationStore)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		s, err := NewSQLiteStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		run(t, s)
	})
	t.Run("file", func(t *testing.T) {
		s, err := NewFileStore(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		run(t, s)
	})
}

func sample(id string) Notification {
	return Notification{
		ID: id, FromAID: "EHOST", ToAID: "EOWNER",
		Kind: "subscription", Severity: NotificationWarning,
		Title: "Your instance stops on 14 August", Body: "A payment failed.",
		Verified: true,
	}
}

func TestANotificationIsStoredAndReadBack(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		if err := s.SaveNotification(sample("n1")); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetNotification("n1")
		if err != nil || got == nil {
			t.Fatalf("not found: %v %v", got, err)
		}
		if got.Title != "Your instance stops on 14 August" || got.FromAID != "EHOST" {
			t.Errorf("came back different: %+v", got)
		}
		if !got.Verified {
			t.Error("verified did not survive the round trip")
		}
		if got.Status != NotificationUnread {
			t.Errorf("a new notification was not unread: %q", got.Status)
		}
	})
}

// A notification with no id could never be marked read, so it would sit in the
// list forever with no way to act on it.
func TestANotificationWithoutAnIDIsRefused(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		if err := s.SaveNotification(Notification{Title: "orphan"}); err == nil {
			t.Error("a notification with no id was accepted")
		}
	})
}

func TestReadAndDismissedAreDifferentStates(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		s.SaveNotification(sample("n1"))

		if err := s.SetNotificationStatus("n1", NotificationRead); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetNotification("n1")
		if got.Status != NotificationRead {
			t.Fatalf("status is %q", got.Status)
		}
		if got.ReadAt == "" {
			t.Error("nothing recorded when it was read")
		}

		if err := s.SetNotificationStatus("n1", NotificationDismissed); err != nil {
			t.Fatal(err)
		}
		got, _ = s.GetNotification("n1")
		if got.Status != NotificationDismissed {
			t.Errorf("dismissing a read notification left it %q", got.Status)
		}
	})
}

func TestAnUnknownStatusIsRefused(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		s.SaveNotification(sample("n1"))
		if err := s.SetNotificationStatus("n1", "archived"); err == nil {
			t.Error("an invented status was accepted")
		}
	})
}

// Silence here would let a client show something as read that is still unread,
// until the next refresh put it back.
func TestMarkingSomethingThatIsNotThereIsAnError(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		if err := s.SetNotificationStatus("never-existed", NotificationRead); err == nil {
			t.Error("marking a notification that does not exist reported success")
		}
	})
}

// The list is what has happened, so the most recent thing is what somebody is
// looking for. (The signing queue orders the other way — that is work to get
// through, and the oldest is the one to do first.)
func TestNotificationsComeBackNewestFirst(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		for _, tc := range []struct{ id, at string }{
			{"old", "2026-01-01T00:00:00Z"},
			{"newest", "2026-03-01T00:00:00Z"},
			{"middle", "2026-02-01T00:00:00Z"},
		} {
			n := sample(tc.id)
			n.ReceivedAt = tc.at
			if err := s.SaveNotification(n); err != nil {
				t.Fatal(err)
			}
		}

		list, err := s.GetNotifications("", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 3 {
			t.Fatalf("expected 3, got %d", len(list))
		}
		if list[0].ID != "newest" || list[2].ID != "old" {
			t.Errorf("wrong order: %s, %s, %s", list[0].ID, list[1].ID, list[2].ID)
		}
	})
}

func TestUnreadCanBeAskedForOnItsOwn(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		s.SaveNotification(sample("n1"))
		s.SaveNotification(sample("n2"))
		s.SetNotificationStatus("n1", NotificationRead)

		unread, err := s.GetNotifications(NotificationUnread, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(unread) != 1 || unread[0].ID != "n2" {
			t.Errorf("unread filter returned %d: %+v", len(unread), unread)
		}

		all, _ := s.GetNotifications("", 0)
		if len(all) != 2 {
			t.Errorf("an empty status should mean everything, got %d", len(all))
		}
	})
}

// A message redelivered after being read must not come back unread, and must
// not be able to rewrite what it said. Otherwise a sender could change the text
// of something a person had already acted on.
func TestARedeliveryCannotRewriteWhatWasSaidOrReopenIt(t *testing.T) {
	eachStore(t, func(t *testing.T, s notificationStore) {
		s.SaveNotification(sample("n1"))
		s.SetNotificationStatus("n1", NotificationRead)

		changed := sample("n1")
		changed.Title = "Something else entirely"
		changed.Status = NotificationUnread
		if err := s.SaveNotification(changed); err != nil {
			t.Fatal(err)
		}

		got, _ := s.GetNotification("n1")
		if got.Title != "Your instance stops on 14 August" {
			t.Errorf("a redelivery rewrote the text: %q", got.Title)
		}
		if got.Status != NotificationRead {
			t.Errorf("a redelivery marked a read notification unread again: %q", got.Status)
		}
	})
}
