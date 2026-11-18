package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// A core started on port 0 takes the port the system gives it and says which:
// it answers there, and its .port file names it, so whoever started it can
// reach it without guessing a free port first.
func TestACoreAskedForAnyPortSaysWhichItTook(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{DataDir: dir, Port: 0, EntityType: "individual"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()
	if s.Port == 0 {
		t.Fatal("the core did not record the port the system gave it")
	}
	written, err := os.ReadFile(filepath.Join(dir, ".port"))
	if err != nil {
		t.Fatalf("no .port file: %v", err)
	}
	if string(written) != fmt.Sprint(s.Port) {
		t.Fatalf(".port says %q, the core is on %d", written, s.Port)
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/health", s.Port))
	if err != nil {
		t.Fatalf("the core does not answer on the port it named: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health on the port it named: %d", resp.StatusCode)
	}
}
