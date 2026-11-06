package iacrypto_test

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
	"identity-agent-core/iacrypto"
)

func fileStore(t *testing.T, dir string) *keri.FileKeyStore {
	t.Helper()
	s, err := keri.NewFileKeyStore(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A partial identity must not be stored. The store refuses to overwrite, so a
// half-written identity cannot be completed on a second attempt.
func TestAPartialIdentityIsNotStored(t *testing.T) {
	dir := t.TempDir()
	_, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	secrets.NextMLDSA65Seed = nil // as if the caller had dropped one

	if err := iacrypto.StoreHybridSecrets(fileStore(t, dir), "bob", secrets); err == nil {
		t.Fatal("a hybrid identity missing a secret was stored")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%d files were written despite the refusal; a partial identity is on "+
			"disk and cannot be completed", len(entries))
	}
}

// Losing the pre-rotation secrets must be reported for what it is.
func TestLosingTheNextKeysIsReportedAsUnrecoverable(t *testing.T) {
	dir := t.TempDir()
	_, secrets, err := iacrypto.GenerateHybridKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	store := fileStore(t, dir)
	if err := iacrypto.StoreHybridSecrets(store, "carol", secrets); err != nil {
		t.Fatal(err)
	}
	// Remove only the pre-rotation material, as a partial backup would.
	for _, e := range mustReadDir(t, dir) {
		if strings.Contains(decodeName(e), "/next/") {
			if err := os.Remove(dir + "/" + e); err != nil {
				t.Fatal(err)
			}
		}
	}
	_, err = iacrypto.LoadHybridSecrets(fileStore(t, dir), "carol")
	if err == nil {
		t.Fatal("an identity missing its pre-rotation secrets loaded cleanly")
	}
	if !strings.Contains(err.Error(), "never rotate") {
		t.Errorf("the failure does not say the identity can never rotate: %v", err)
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// decodeName reverses the store's filename encoding so a test can find the
// pre-rotation files without guessing.
func decodeName(fileName string) string {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(fileName, ".key"))
	if err != nil {
		return ""
	}
	return string(raw)
}
