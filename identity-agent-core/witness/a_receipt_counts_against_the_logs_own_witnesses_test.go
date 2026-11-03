package witness

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// witnessedRotation builds a log whose inception designates w[0] and w[1]
// (both must receipt) and whose rotation cuts w[1] and adds w[2] (both of the
// resulting pair must receipt).
func witnessedRotation(t *testing.T) (log [][]byte, icpSAID, rotSAID string, w []testWitness) {
	t.Helper()
	w = []testWitness{newTestWitness(t), newTestWitness(t), newTestWitness(t)}
	a, _ := keri.GenerateSigner(true)
	b, _ := keri.GenerateSigner(true)
	c, _ := keri.GenerateSigner(true)
	pubA, _ := a.PublicKey()
	pubB, _ := b.PublicKey()
	pubC, _ := c.PublicKey()
	nextB, _ := keri.NextDigest(pubB)
	nextC, _ := keri.NextDigest(pubC)
	toad := 2
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pubA}, NextDigests: []string{nextB},
		Witnesses: []string{w[0].aid, w[1].aid}, Toad: &toad, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	icpEv, _ := keri.ParseEvent(icp)
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: icpEv.Identifier, Keys: []string{pubB}, PriorSAID: icpEv.SAID, SN: 1,
		NextDigests: []string{nextC}, PriorWitnesses: []string{w[0].aid, w[1].aid},
		Cuts: []string{w[1].aid}, Adds: []string{w[2].aid}, Toad: &toad,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotEv, _ := keri.ParseEvent(rot)
	return [][]byte{icp, rot}, icpEv.SAID, rotEv.SAID, w
}

// The witnesses and the threshold for an event are the key log's at that
// event's own position: a witness cut by a rotation is not designated for the
// rotation, though it was for the inception.
func TestWhoWitnessesAnEventIsReadFromTheLogAtThatEvent(t *testing.T) {
	log, icpSAID, rotSAID, w := witnessedRotation(t)

	des, thr, err := designationAt(log, icpSAID)
	if err != nil || thr != 2 || len(des) != 2 || des[0] != w[0].aid || des[1] != w[1].aid {
		t.Fatalf("inception: %v %d %v", des, thr, err)
	}
	des, thr, err = designationAt(log, rotSAID)
	if err != nil || thr != 2 || len(des) != 2 || des[0] != w[0].aid || des[1] != w[2].aid {
		t.Fatalf("rotation: designated %v threshold %d err %v, want [w0 w2] and 2", des, thr, err)
	}
	if _, _, err := designationAt(log, "ENotInThisLog00000000000000000000000000000"); err == nil {
		t.Fatal("an event not in the log was given a designated set")
	}
	if _, _, err := designationAt(nil, rotSAID); err == nil {
		t.Fatal("an empty log was given a designated set")
	}
}

// A rotation cuts w[1]. This agent still has w[1] enrolled, and w[1] answers,
// but BroadcastEvent addresses and counts only the witnesses the log names for
// the rotation: with w[2] unreachable the rotation does not finalise on w[1]'s
// receipt, and w[1] is never asked.
func TestACutWitnessCannotFinaliseARotation(t *testing.T) {
	log, _, rotSAID, w := witnessedRotation(t)
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	for i := 0; i < 2; i++ { // w[2] is not enrolled, so there is no address for it
		aid := fmt.Sprintf("EContactw%d", i)
		mc.contacts[aid] = store.ContactRecord{AID: aid, OobiURL: fmt.Sprintf("http://w%d.test", i), IsWitness: true}
		_ = s.Store.SaveContactMeta(ContactMeta{ContactAID: aid, WitnessKey: w[i].aid})
	}
	var mu sync.Mutex
	asked := map[string]bool{}
	s.PostEvent = func(_ context.Context, url string, _ []byte) (map[string]interface{}, error) {
		var i int
		fmt.Sscanf(strings.TrimPrefix(url, "http://w"), "%d", &i)
		mu.Lock()
		asked[w[i].aid] = true
		mu.Unlock()
		return map[string]interface{}{"witness_aid": w[i].aid, "cesr_signature": w[i].sign(rotSAID)}, nil
	}
	if err := s.BroadcastEvent(t.Context(), "ESigner", log[1], "0Bsig", log); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f, _ := s.Store.GetFinalization(rotSAID); f != nil && f.ReceiptCount >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // a wrongly addressed w[1] would have answered by now
	f, _ := s.Store.GetFinalization(rotSAID)
	if f == nil || f.Threshold != 2 || f.ReceiptCount != 1 || f.State == FinalizeFinalized {
		t.Fatalf("finalization %+v: want threshold 2 (the log's), 1 receipt, not finalised", f)
	}
	mu.Lock()
	defer mu.Unlock()
	if asked[w[1].aid] {
		t.Fatal("a witness the rotation cut was asked to witness it")
	}
	if held, _ := kc.GetWitnessReceipts(rotSAID); len(held) != 1 || held[0].WitnessAID != w[0].aid {
		t.Fatalf("receipts kept %+v, want only w[0]'s", held)
	}
}

// Many receipts arriving together are all counted: a slower goroutine never
// writes back a lower count than a faster one already wrote. Run with -race.
func TestConcurrentReceiptsAreAllCounted(t *testing.T) {
	base, mc := testService(t)
	kc := &keepingContacts{memContacts: mc}
	s := NewService(base.Store, kc, nil, BackendDesktop)
	const n = 24
	const said = "EHconcurrent"
	pendingEvent(t, s, said, n)
	var ws []testWitness
	var des []string
	for i := 0; i < n; i++ {
		w := newTestWitness(t)
		ws = append(ws, w)
		des = append(des, w.aid)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, w := range ws {
		wg.Add(1)
		go func(w testWitness) {
			defer wg.Done()
			<-start
			s.onReceipt(said, w.aid, w.sign(said), des)
		}(w)
	}
	close(start)
	wg.Wait()
	f, _ := s.Store.GetFinalization(said)
	if f.ReceiptCount != n || f.State != FinalizeFinalized {
		t.Fatalf("count=%d state=%s: want %d and finalized", f.ReceiptCount, f.State, n)
	}
}
