package backup

import (
	"strings"
	"testing"
)

// Rewriting a path's bad byte would leave a locator that no longer finds its
// file, so an external pointer that is not valid UTF-8 is refused, and a
// valid one is kept exactly.
func TestAnExternalPointerWithABadByteIsRefusedNotRewritten(t *testing.T) {
	seed := make([]byte, 64)
	c := &Collector{DataDir: t.TempDir()}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	c.addRawSection(bundle, "identity_state", []byte(`{"aid":"EMyIdentity"}`))
	good := ExternalDataPointer{Domain: "photos", Locator: "/home/me/café/a.jpg", KeyRef: "k"}
	bad := ExternalDataPointer{Domain: "photos", Locator: "/home/me/caf\xe9/a.jpg", KeyRef: "k"}

	req := ExportRequest{BIP39Seed: seed, Bundle: bundle, ExternalPointers: []ExternalDataPointer{good}}
	res, err := c.CreateArchive(CollectOptions{}, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Manifest.ExternalPointers[0].Locator; got != good.Locator {
		t.Fatalf("a valid path was changed: %q", got)
	}

	req.ExternalPointers = []ExternalDataPointer{good, bad}
	if _, err := c.CreateArchive(CollectOptions{}, req); err == nil || !strings.Contains(err.Error(), "not valid UTF-8") {
		t.Fatalf("a path with a bad byte was not refused: %v", err)
	}
}

// An archive written by a Go release that spelled a bad byte as the escape
// � is built here by hand, not by the encoder, so the test means the same
// on every release: it reads back as the replacement character, and verifies
// exactly as the archive written with the character itself.
func TestAnArchiveWrittenWithTheEscapedSpellingVerifiesLikeTheRawOne(t *testing.T) {
	seed := theOwnersSeed(t)
	arch := anArchive(t)
	arch.Manifest.ExternalPointers = []ExternalDataPointer{{Domain: "photos", Locator: "/p/caf�/x", KeyRef: "k"}}
	if err := SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "�") {
		t.Fatalf("expected the character itself in %s", raw)
	}
	old := []byte(strings.ReplaceAll(string(raw), "�", `�`))
	for name, file := range map[string][]byte{"raw": raw, "escaped": old} {
		back, err := DecodeArchive(file)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := CheckWhoWroteIt(back, seed, nil); err != nil {
			t.Fatalf("%s spelling was refused: %v", name, err)
		}
		if got := back.Manifest.ExternalPointers[0].Locator; got != "/p/caf�/x" {
			t.Fatalf("%s: locator = %q", name, got)
		}
	}
}
