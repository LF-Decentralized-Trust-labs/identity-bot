package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Pushes arriving at once, inside one second, each keep their own archive
// under their own name, whole, and leave nothing else in the directory.
func TestConcurrentPushesEachKeepTheirArchive(t *testing.T) {
	svc, _ := serviceWithOffer(t, Offer{
		Accepting: true, AcceptingNewIdentities: true, ReserveBytes: 1024,
	})
	aid := "E" + strings.Repeat("A", 43)
	const n = 12
	paths := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths[i], errs[i] = svc.ReceiveArchive(aid, []byte(fmt.Sprintf("archive %d", i)))
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if seen[paths[i]] {
			t.Fatalf("two pushes were filed as %s", paths[i])
		}
		seen[paths[i]] = true
		if b, _ := os.ReadFile(paths[i]); string(b) != fmt.Sprintf("archive %d", i) {
			t.Fatalf("%s holds %q", paths[i], b)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(paths[0]))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("the directory holds %d entries, want the %d archives", len(entries), n)
	}
}
