package server

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Replicates Grant's read-modify-write EXACTLY (same load/save calls, same
// per-call struct) and records what each goroutine observed, to show whether
// the read-modify-write windows actually overlap.
func TestProbeOverlapWindows(t *testing.T) {
	t.Logf("GOMAXPROCS=%d NumCPU=%d", runtime.GOMAXPROCS(0), runtime.NumCPU())
	dir := t.TempDir()
	now := time.Now().UTC()
	seed := &controllerGrants{dataDir: dir}
	for i := 0; i < 200; i++ {
		if _, err := seed.Grant(ControllerGrant{
			ControllerAID: fmt.Sprintf("ESeed%03d", i), PublicKey: "DKeyDKeyDKeyDKeyDKeyDKeyDKeyDKey",
			Label: "existing", Grade: GradeEnrolled,
		}, now); err != nil {
			t.Fatal(err)
		}
	}

	const n = 24
	var inFlight, maxInFlight int64
	sizes := make([]int, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			c := &controllerGrants{dataDir: dir}
			c.mu.Lock() // exactly as Grant does — a fresh, uncontended mutex
			cur := atomic.AddInt64(&inFlight, 1)
			for {
				m := atomic.LoadInt64(&maxInFlight)
				if cur <= m || atomic.CompareAndSwapInt64(&maxInFlight, m, cur) {
					break
				}
			}
			all := c.load()
			sizes[i] = len(all)
			all[fmt.Sprintf("ENew%02d", i)] = ControllerGrant{
				ControllerAID: fmt.Sprintf("ENew%02d", i), PublicKey: "D", Label: "l",
				Grade: GradeEnrolled, GrantedAt: now,
			}
			if err := c.save(all); err != nil {
				t.Errorf("save: %v", err)
			}
			atomic.AddInt64(&inFlight, -1)
			c.mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	final := len((&controllerGrants{dataDir: dir}).load())
	t.Logf("max concurrent read-modify-write windows: %d", maxInFlight)
	t.Logf("pre-load sizes seen by each goroutine: %v", sizes)
	t.Logf("expected %d grants, file holds %d", 200+n, final)
	if final != 200+n {
		t.Fatalf("LOST UPDATE: %d grants silently vanished", 200+n-final)
	}
}
