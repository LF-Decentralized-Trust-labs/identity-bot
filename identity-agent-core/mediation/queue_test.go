package mediation

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"identity-agent-core/limits"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func small() limits.Limits {
	l := limits.Defaults()
	l.QueueMessages, l.QueueBytes, l.QueueSharePercent = 10, 1000, 100
	return l
}

func msg(i int, conv, sender string, n int) Message {
	return Message{ID: fmt.Sprintf("m%d", i), Conversation: conv, Sender: sender, Recipient: "r", Sealed: bytes.Repeat([]byte{1}, n)}
}

// A sealed copy is deleted once it is delivered and kept, and not before.
func TestTheQueueDeletesWordsOnceDeliveredAndKept(t *testing.T) {
	q := New(small(), nil)
	if err := q.Enqueue(msg(1, "c", "s", 100)); err != nil {
		t.Fatal(err)
	}
	if err := q.Delivered("m1"); err != nil || q.Len() != 1 || q.Bytes() != 100 {
		t.Fatalf("delivered alone must keep the copy: len %d bytes %d err %v", q.Len(), q.Bytes(), err)
	}
	if len(q.Held("r")) != 0 {
		t.Fatal("a delivered message is offered to the recipient again")
	}
	if err := q.Kept("m1"); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 0 || q.Bytes() != 0 {
		t.Fatalf("the copy outlived being delivered and kept: len %d bytes %d", q.Len(), q.Bytes())
	}
	if err := q.Kept("m1"); !errors.Is(err, ErrNothingHeld) {
		t.Fatalf("got %v", err)
	}
	// Kept first, then delivered, deletes just the same.
	q.Enqueue(msg(2, "c", "s", 10))
	q.Kept("m2")
	if q.Len() != 1 {
		t.Fatal("kept alone deleted the copy")
	}
	q.Delivered("m2")
	if q.Len() != 0 {
		t.Fatal("the copy outlived being kept and delivered")
	}
}

// At the bound a new message is refused with the reason, and every message
// already accepted is still held, byte for byte.
func TestAtTheBoundANewMessageIsRefusedAndNoAcceptedOneIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name string
		l    limits.Limits
		size int
	}{
		{"count", small(), 1},
		{"bytes", func() limits.Limits { l := small(); l.QueueBytes = 50; return l }(), 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := New(tc.l, nil)
			var accepted []string
			for i := 0; i < 20; i++ {
				m := msg(i, fmt.Sprintf("c%d", i), fmt.Sprintf("s%d", i), tc.size)
				err := q.Enqueue(m)
				var r *Refusal
				switch {
				case err == nil:
					accepted = append(accepted, m.ID)
				case errors.As(err, &r) && r.Reason == ReasonFull:
				default:
					t.Fatalf("message %d: %v", i, err)
				}
			}
			want := tc.l.QueueMessages
			if tc.name == "bytes" {
				want = 5
			}
			if len(accepted) != want || q.Len() != want {
				t.Fatalf("accepted %d, held %d, want %d", len(accepted), q.Len(), want)
			}
			held := q.Held("r")
			for i, id := range accepted {
				if held[i].ID != id || len(held[i].Sealed) != tc.size {
					t.Fatalf("an accepted message was dropped or changed: %v", id)
				}
			}
		})
	}
}

func TestOneConversationOrSenderCannotFillTheQueue(t *testing.T) {
	l := small()
	l.QueueSharePercent = 30
	q := New(l, nil)
	for i := 0; i < 3; i++ {
		if err := q.Enqueue(msg(i, "busy", fmt.Sprintf("s%d", i), 1)); err != nil {
			t.Fatal(err)
		}
	}
	var r *Refusal
	if err := q.Enqueue(msg(3, "busy", "other", 1)); !errors.As(err, &r) || r.Reason != ReasonConversation {
		t.Fatalf("got %v", err)
	}
	for i := 10; i < 13; i++ {
		q.Enqueue(msg(i, fmt.Sprintf("c%d", i), "loud", 1))
	}
	if err := q.Enqueue(msg(13, "c13", "loud", 1)); !errors.As(err, &r) || r.Reason != ReasonSender {
		t.Fatalf("got %v", err)
	}
	if err := q.Enqueue(msg(14, "quiet", "quiet", 1)); err != nil {
		t.Fatalf("a quiet pair was crowded out: %v", err)
	}
}

// The share is in bytes as well as messages: a few large messages cannot take
// more of the queue than their share while the count is far from its own.
func TestOneConversationOrSenderCannotTakeMoreThanItsShareOfBytes(t *testing.T) {
	l := small()             // 1000 bytes, 10 messages
	l.QueueSharePercent = 30 // 300 bytes, 3 messages
	var r *Refusal

	q := New(l, nil)
	for i, n := range []int{150, 149} {
		if err := q.Enqueue(msg(i, "busy", fmt.Sprintf("s%d", i), n)); err != nil {
			t.Fatal(err)
		}
	}
	// 299 held in two messages: one byte more is the share exactly, two is over.
	if err := q.Enqueue(msg(2, "busy", "s2", 2)); !errors.As(err, &r) || r.Reason != ReasonConversation {
		t.Fatalf("a conversation past its byte share got %v", err)
	}
	if err := q.Enqueue(msg(3, "busy", "s3", 1)); err != nil {
		t.Fatalf("a conversation filling its byte share exactly was refused: %v", err)
	}
	if q.Len() != 3 || q.Bytes() != 300 {
		t.Fatalf("a refusal changed what is held: %d messages, %d bytes", q.Len(), q.Bytes())
	}
	if err := q.Enqueue(msg(4, "quiet", "quiet", 300)); err != nil {
		t.Fatalf("another conversation was crowded out: %v", err)
	}

	// The same for a sender across conversations.
	q = New(l, nil)
	for i, n := range []int{150, 149} {
		if err := q.Enqueue(msg(i, fmt.Sprintf("c%d", i), "loud", n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Enqueue(msg(2, "c2", "loud", 2)); !errors.As(err, &r) || r.Reason != ReasonSender {
		t.Fatalf("a sender past its byte share got %v", err)
	}
	if err := q.Enqueue(msg(3, "c3", "loud", 1)); err != nil {
		t.Fatalf("a sender filling its byte share exactly was refused: %v", err)
	}

	// Bytes come back to the share when a message is deleted.
	if err := q.Discard("m0"); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(msg(5, "c5", "loud", 150)); err != nil {
		t.Fatalf("a deleted message's bytes were not returned to its sender's share: %v", err)
	}
}

// After seven days the sealed copy is deleted and the sender is told.
func TestAMessageHeldSevenDaysIsRefusedBackAndDeleted(t *testing.T) {
	c := &clock{time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	q := New(small(), c.now)
	q.Enqueue(msg(1, "c", "s", 10))
	c.t = c.t.Add(7*24*time.Hour - time.Second)
	if n, _ := q.Expire(); len(n) != 0 {
		t.Fatalf("expired early: %v", n)
	}
	c.t = c.t.Add(time.Second)
	got, _ := q.Expire()
	if len(got) != 1 || got[0].Sender != "s" || got[0].Reason != "the recipient was not reachable for 7 days" {
		t.Fatalf("got %+v", got)
	}
	if q.Len() != 0 || q.Bytes() != 0 {
		t.Fatal("the sealed copy was not deleted")
	}
}
