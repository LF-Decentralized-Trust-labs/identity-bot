package testkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"go/parser"
	"go/token"
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

// Every signature is raw 64 bytes, low-s, and verifies; run enough that a
// signer which only sometimes emitted high-s would be caught.
func TestEverySignatureIsRawAndLowS(t *testing.T) {
	k, err := New()
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	msg := []byte("a message")
	sum := sha256.Sum256(msg)
	for i := 0; i < 200; i++ {
		sig, err := k.Sign(msg)
		if err != nil || len(sig) != 64 {
			t.Fatalf("sig %d: len=%d err=%v", i, len(sig), err)
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if s.Cmp(half) > 0 {
			t.Fatal("a high-s signature came out")
		}
		if !ecdsa.Verify(&k.Priv.PublicKey, sum[:], r, s) {
			t.Fatal("signature does not verify")
		}
	}
}

func TestEncodingsAndFixedKey(t *testing.T) {
	k := FromD(big.NewInt(7))
	if c, u := k.Compressed(), k.Uncompressed(); len(c) != 33 || len(u) != 65 {
		t.Fatalf("lengths %d, %d", len(c), len(u))
	}
}

// Test-only means test-only: no file that is not a _test.go may import it.
func TestOnlyTestsImportThisPackage(t *testing.T) {
	root, _ := filepath.Abs("../..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, im := range f.Imports {
			if strings.HasSuffix(im.Path.Value, `internal/testkeys"`) && !strings.HasPrefix(p, filepath.Join(root, "internal", "testkeys")) {
				t.Errorf("%s imports testkeys but is not a test file", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
