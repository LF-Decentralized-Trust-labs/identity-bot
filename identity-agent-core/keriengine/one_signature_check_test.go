package keriengine

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A signature over a key log is checked by keri-go's VerifyUnderKey, which
// chooses the algorithm by the key's code, and by nothing in the core: a second
// dispatch drifted once (a stage-two identity broke on restart because the
// other verify sites stayed Ed25519-only), and would again.
func TestTheCoreChecksNoKeySignatureButThroughKeriGo(t *testing.T) {
	// iacrypto/hybrid_signature.go checks the composite signature of a
	// hybrid identity from raw keys, in every build; it is not a key log's.
	allowed := filepath.Join("..", "iacrypto", "hybrid_signature.go")
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
			p == allowed || strings.HasSuffix(p, "one_signature_check_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, banned := range []string{"signatureVerifies(", "VerifyMLDSA65("} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s calls %s: check a signature with keri.VerifyUnderKey", p, banned)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
