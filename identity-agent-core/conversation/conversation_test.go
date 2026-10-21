package conversation

import (
	"context"
	"errors"
	"sync"
	"testing"

	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

func entryBuilder(t *testing.T, conv, from, to, kind string, body []byte) Build {
	ks, err := didcomm.GenerateKeySet("EIA")
	if err != nil {
		t.Fatal(err)
	}
	return func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
		rec := agentmessage.Record{MessageID: NewID("m_"), Conversation: conv, Seq: seq, PrevHash: prev,
			Kind: kind, From: from, To: to, BodyHash: agentmessage.HashBody(body), OpenedBy: "person:EP"}
		env, err := agentmessage.Countersign(ks, rec)
		return env, rec, err
	}
}

// Entries chain, in order, each naming the hash of the one before; and the
// words are kept where the store keeps them, under the digest the entry holds.
func TestEntriesChainAndKeepTheirWords(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	open := &Conversation{OpenedBy: "person:EP", FirstAgent: "EA"}
	e1, err := s.Append(ctx, "c1", open, []byte("hello"), []string{"EA"}, nil, entryBuilder(t, "c1", "person:EP", "EA", agentmessage.KindAsk, []byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	e2, err := s.Append(ctx, "c1", nil, []byte("hi"), nil, nil, entryBuilder(t, "c1", "EA", "person:EP", agentmessage.KindReply, []byte("hi")))
	if err != nil {
		t.Fatal(err)
	}
	if e1.Seq != 1 || e2.Seq != 2 || e2.Hash == e1.Hash {
		t.Fatalf("entries out of order: %d %d", e1.Seq, e2.Seq)
	}
	r2, _ := agentmessage.Read(e2.Envelope)
	if r2.PrevHash != e1.Hash {
		t.Fatal("the second entry does not name the first's hash")
	}
	c, _ := s.Get("c1")
	if c.HeadHash != e2.Hash || c.Turns != 2 {
		t.Fatalf("the conversation's head is not its last entry: %+v", c)
	}
	words, err := s.Contents().Get(ctx, e1.ContentRef)
	if err != nil || string(words) != "hello" {
		t.Fatalf("the words were not kept: %q %v", words, err)
	}
	if !s.IsParty("c1", "EA") || s.IsParty("c1", "EB") {
		t.Fatal("who is in the conversation is wrong")
	}
}

// What is queued for a body stays queued until its receipt, so a body that
// asks again before acknowledging is given it again.
func TestAMessageWaitsUntilItsReceipt(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	defer s.Close()
	ctx := context.Background()
	e, err := s.Append(ctx, "c1", &Conversation{OpenedBy: "person:EP", FirstAgent: "EA"}, []byte("x"), []string{"EA"}, nil,
		entryBuilder(t, "c1", "person:EP", "EA", agentmessage.KindAsk, []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if w, _ := s.Waiting("EA", 10); len(w) != 1 || w[0].MessageID != e.MessageID {
			t.Fatalf("collection %d: %v", i, w)
		}
	}
	if ok, _ := s.Delivered(e.MessageID, "EA", "m_receipt"); !ok {
		t.Fatal("the receipt did not mark it delivered")
	}
	if w, _ := s.Waiting("EA", 10); len(w) != 0 {
		t.Fatal("a message still waited after its receipt")
	}
	if ok, _ := s.Delivered(e.MessageID, "EA", "m_again"); ok {
		t.Fatal("a second receipt was taken as the first")
	}
}

// Two writers at once cannot give two entries the same place: the chain does
// not fork.
func TestTheChainDoesNotForkUnderConcurrentWriters(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	defer s.Close()
	ctx := context.Background()
	if _, err := s.Append(ctx, "c1", &Conversation{OpenedBy: "person:EP", FirstAgent: "EA"}, []byte("0"), nil, nil,
		entryBuilder(t, "c1", "person:EP", "EA", agentmessage.KindAsk, []byte("0"))); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := []byte{byte('a' + i)}
			if _, err := s.Append(ctx, "c1", nil, b, nil, nil, entryBuilder(t, "c1", "EA", "person:EP", agentmessage.KindReceipt, b)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	entries, _ := s.Entries("c1", 0)
	prev := ""
	for i, e := range entries {
		r, _ := agentmessage.Read(e.Envelope)
		if e.Seq != i+1 || r.PrevHash != prev {
			t.Fatalf("entry %d forked the chain", i+1)
		}
		prev = e.Hash
	}
	if len(entries) != 9 {
		t.Fatalf("expected 9 entries, got %d", len(entries))
	}
}

// An entry built for the wrong place is refused rather than written.
func TestAnEntryBuiltForAnotherPlaceIsRefused(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	defer s.Close()
	ctx := context.Background()
	if _, err := s.Append(ctx, "c1", &Conversation{OpenedBy: "person:EP", FirstAgent: "EA"}, []byte("0"), nil, nil,
		entryBuilder(t, "c1", "person:EP", "EA", agentmessage.KindAsk, []byte("0"))); err != nil {
		t.Fatal(err)
	}
	wrong := func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
		return entryBuilder(t, "c1", "EA", "person:EP", agentmessage.KindReply, []byte("x"))(seq+5, prev)
	}
	if _, err := s.Append(ctx, "c1", nil, []byte("x"), nil, nil, wrong); err == nil {
		t.Fatal("an entry built for another place was written")
	}
	if _, err := s.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a missing conversation was found")
	}
}

// An ask is answered once by each party it was put to.
func TestAnAskIsAnsweredOnce(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	defer s.Close()
	ctx := context.Background()
	ask, err := s.Append(ctx, "c1", &Conversation{OpenedBy: "person:EP", FirstAgent: "EA"}, []byte("q"), []string{"EA"}, nil,
		entryBuilder(t, "c1", "person:EP", "EA", agentmessage.KindAsk, []byte("q")))
	if err != nil {
		t.Fatal(err)
	}
	answer := func(kind string, body []byte) error {
		ks, _ := didcomm.GenerateKeySet("EIA")
		_, err := s.Append(ctx, "c1", nil, body, nil, nil, func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
			rec := agentmessage.Record{MessageID: NewID("m_"), Conversation: "c1", Seq: seq, PrevHash: prev,
				Kind: kind, From: "EA", To: "person:EP", InReplyTo: ask.MessageID, BodyHash: agentmessage.HashBody(body)}
			env, err := agentmessage.Countersign(ks, rec)
			return env, rec, err
		})
		return err
	}
	if err := answer(agentmessage.KindReply, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := answer(agentmessage.KindFailure, []byte("b")); !errors.Is(err, ErrAlreadyAnswered) {
		t.Fatalf("a second answer to one ask was recorded: %v", err)
	}
	if !s.Answered(ask.MessageID, "EA") {
		t.Fatal("the answer is not seen")
	}
}

// A receipt neither counts as a turn nor keeps a conversation open.
func TestAReceiptDoesNotKeepAConversationOpen(t *testing.T) {
	s, _ := OpenStore(t.TempDir())
	defer s.Close()
	ctx := context.Background()
	if _, err := s.Append(ctx, "c1", &Conversation{OpenedBy: "person:EP", FirstAgent: "EA"}, []byte("q"), nil, nil,
		entryBuilder(t, "c1", "person:EP", "EA", agentmessage.KindAsk, []byte("q"))); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Get("c1")
	if _, err := s.Append(ctx, "c1", nil, []byte("r"), nil, nil,
		entryBuilder(t, "c1", "EA", "person:EP", agentmessage.KindReceipt, []byte("r"))); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Get("c1")
	if after.Turns != before.Turns || !after.LastAt.Equal(before.LastAt) {
		t.Fatalf("a receipt counted, or moved the conversation's last activity: %+v -> %+v", before, after)
	}
}
