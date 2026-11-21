package store

import (
	"fmt"
	"sync"
	"testing"
)

// Indices are allocated while other allocations and other writes run at the
// same time: every allocation succeeds, and no index is handed out twice.
//
// An allocation reads the counter and then writes it. Begun as a read, a
// transaction that sees another connection commit before its write is
// refused at once (SQLITE_BUSY, extended code 517), and a mint that asked
// for the index fails.
func TestIndicesAreAllocatedWhileOtherWritesRun(t *testing.T) {
	_, s := openStore(t)
	const allocations, writes = 16, 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make(chan int, allocations)
	failed := make(chan error, allocations+writes)
	for i := 0; i < allocations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			idx, err := s.AllocateNextRelationshipIndex("contacts")
			if err != nil {
				failed <- fmt.Errorf("an allocation: %w", err)
				return
			}
			got <- idx
		}()
	}
	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if err := s.RememberMachineOwnerIdentity(fmt.Sprintf("EUnrelated%d", i), i+1, ""); err != nil {
				failed <- fmt.Errorf("an unrelated write: %w", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(got)
	close(failed)
	for err := range failed {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for idx := range got {
		if seen[idx] {
			t.Fatalf("index %d was allocated twice", idx)
		}
		seen[idx] = true
	}
	if len(seen) != allocations {
		t.Fatalf("%d distinct indices were allocated, want %d", len(seen), allocations)
	}
}
