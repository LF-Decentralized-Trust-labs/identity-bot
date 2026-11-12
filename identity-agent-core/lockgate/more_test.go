package lockgate

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestParallelWrongSecretsAreEachCounted(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	if err := r.s.ChangeSecret("", "correct horse"); err != nil {
		t.Fatal(err)
	}
	_ = r.s.Lock()
	var wg sync.WaitGroup
	var wrong int32
	results := make([]ProviderResult, 12)
	for i := range results {
		results[i] = r.result(80)
	}
	for i := range results {
		wg.Add(1)
		go func(p ProviderResult) {
			defer wg.Done()
			if err := r.s.Unlock(p, "nope"); errors.Is(err, ErrWrongSecret) {
				atomic.AddInt32(&wrong, 1)
			}
		}(results[i])
	}
	wg.Wait()
	if a := r.s.P.readAttempts(); a.Wrong != int(wrong) {
		t.Fatalf("%d wrong secrets were tried and %d were counted", wrong, a.Wrong)
	}
}

func TestAnUnreadableGateRecordIsNotTakenForNoGate(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	// stat on gate/gate.json fails with ENOTDIR, which is not "does not exist".
	if err := os.Rename(filepath.Join(r.dir, "gate"), filepath.Join(r.dir, "gate.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "gate"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !r.s.P.Gated() {
		t.Fatal("a stat error that is not 'does not exist' made the profile look ungated")
	}
}

func TestOutOfRangeStretchingParametersAreRefusedNotRun(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	_ = r.s.ChangeSecret("", "correct horse")
	rec, _ := r.s.P.readRecord()
	rec.Secret.MemKB = 1 << 30
	_ = r.s.P.writeRecord(rec)
	_ = r.s.Lock()
	if err := r.s.Unlock(r.result(80), "correct horse"); err == nil {
		t.Fatal("ran Argon2 with a memory size read from disk")
	}
}
