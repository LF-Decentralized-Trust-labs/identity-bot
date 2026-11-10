package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// broadcastFrom is a service with one enrolled witness that receipts whatever it is sent (as
// the witness at place 0), the rotation it is sent, and the means to see what was kept.
func broadcastFrom(t *testing.T, hook func(string, map[string]interface{}) ([]string, int, error)) (*Service, *keepingContacts, []byte, string) {
	t.Helper()
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := iacrypto.NonTransferableAIDQB64(pub)
	// The witness is known by its own key, so the one that answers is the one asked.
	mc.contacts[key] = store.ContactRecord{AID: key, OobiURL: "http://w.test", IsWitness: true}
	_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: key, WitnessKey: key, IsCommercial: true})
	const said = "ERotationCutsEveryone0123456789ABCDEFGHIJKLMN"
	raw := []byte(`{"v":"KERI10JSON000000_","t":"rot","d":"` + said + `","i":"ERoot","s":"1"}`)
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		if !strings.HasPrefix(url, "http://w.test/") {
			// The bootstrap witness a root is topped up with is not the one under test.
			return nil, errors.New("not answering")
		}
		sig, err := drivers.SignEventReceipt(raw, priv.Seed(), 0)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"witness_aid": key, "cesr_signature": sig}, nil
	}
	s.DesignationAfter = hook
	t.Cleanup(func() { s.Stop() })
	return s, kc, raw, said
}

func settled(t *testing.T, s *Service, kc *keepingContacts, said string, wantKept int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		kc.mu.Lock()
		n := len(kc.kept)
		kc.mu.Unlock()
		if n >= wantKept {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
}

// After a rotation that cuts every witness, the log's threshold is its own (0)
// and a cut witness's receipt is not in the list in force, so it is neither
// kept nor counted: not the floor, not an unchecked list.
func TestAfterACutAllRotationTheCutWitnessesReceiptsDoNotCount(t *testing.T) {
	s, kc, raw, said := broadcastFrom(t, func(string, map[string]interface{}) ([]string, int, error) {
		return []string{}, 0, nil
	})
	if err := s.BroadcastEvent(context.Background(), "ERoot", raw, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	settled(t, s, kc, said, 1)
	f, _ := s.Store.GetFinalization(said)
	if f == nil || f.Threshold != 0 {
		t.Fatalf("finalization %+v, want the log's own threshold 0", f)
	}
	if f.ReceiptCount != 0 || len(kc.kept) != 0 {
		t.Fatalf("a cut witness's receipt was kept (%d) or counted (%d)", len(kc.kept), f.ReceiptCount)
	}
}

// A log that cannot be read: the receipt is kept and nothing is counted.
func TestAReceiptIsKeptButNotCountedWhenTheLogCannotBeRead(t *testing.T) {
	s, kc, raw, said := broadcastFrom(t, func(string, map[string]interface{}) ([]string, int, error) {
		return nil, 0, errors.New("damaged")
	})
	if err := s.BroadcastEvent(context.Background(), "ERoot", raw, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	settled(t, s, kc, said, 1)
	kc.mu.Lock()
	kept := len(kc.kept)
	kc.mu.Unlock()
	f, _ := s.Store.GetFinalization(said)
	if kept != 1 {
		t.Fatalf("kept %d receipts, want 1", kept)
	}
	if f == nil || f.ReceiptCount != 0 || f.State == FinalizeFinalized {
		t.Fatalf("a receipt was counted against a list nobody could read: %+v", f)
	}
}

// The same for the one witness a caller submits to.
func TestSubmittingToAWitnessCountsNothingWhenTheLogCannotBeRead(t *testing.T) {
	s, kc, raw, said := broadcastFrom(t, func(string, map[string]interface{}) ([]string, int, error) {
		return nil, 0, errors.New("damaged")
	})
	now := NowRFC3339()
	_ = s.Store.SaveFinalization(FinalizationState{EventSAID: said, SignerAID: "ERoot", State: FinalizePending, Threshold: 1, StartedAt: now, UpdatedAt: now})
	if _, err := s.SubmitToWitness(context.Background(), "http://w.test/witness/event", "ERoot", raw, "0Bsig"); err != nil {
		t.Fatal(err)
	}
	if len(kc.kept) != 1 {
		t.Fatalf("kept %d receipts, want 1", len(kc.kept))
	}
	if f, _ := s.Store.GetFinalization(said); f.ReceiptCount != 0 || f.State == FinalizeFinalized {
		t.Fatalf("counted against a list nobody could read: %+v", f)
	}
}

// And after a cut-all rotation a submitted receipt is refused outright, with no
// workaround: the hook's empty list is what says so.
func TestSubmittingAfterACutAllRotationRefusesTheCutWitnessesReceipt(t *testing.T) {
	s, kc, raw, _ := broadcastFrom(t, func(string, map[string]interface{}) ([]string, int, error) {
		return []string{}, 0, nil
	})
	if _, err := s.SubmitToWitness(context.Background(), "http://w.test/witness/event", "ERoot", raw, "0Bsig"); err == nil {
		t.Fatal("the receipt of a witness the rotation cut was accepted")
	}
	if len(kc.kept) != 0 {
		t.Fatal("it was kept")
	}
}
