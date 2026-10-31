package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Sealing an owner puts the whole record in place or nothing: no temporary
// beside it, and a second seal leaves the first exactly as it was. A stop
// part way through a write is covered in atomicfile, where it can be made to
// happen.
func TestASealedOwnerIsWrittenWhole(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	oa := OwnerAuthority{AID: "ESIGNERPAIRWISE", PublicKey: "DLQN2ahzZXKRE5jrwfdWAD3LKCJ9b1A4jlwFWGoCjiux"}
	if err := s.SealOwnerAuthority(oa); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.DataDir, ownerAuthorityFile)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var back OwnerAuthority
	if err := json.Unmarshal(first, &back); err != nil || back.AID != oa.AID {
		t.Fatalf("the record reads back as %+v (%v)", back, err)
	}
	oa.AID = "ESOMEBODYELSE"
	if err := s.SealOwnerAuthority(oa); err == nil {
		t.Fatal("a second seal replaced the first")
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, first) {
		t.Fatal("a refused seal changed the record")
	}
	if left, _ := filepath.Glob(path + ".tmp*"); len(left) > 0 {
		t.Fatalf("left beside the record: %v", left)
	}
}
