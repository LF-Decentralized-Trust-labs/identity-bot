package backup

import (
	"strings"
	"testing"
)

// A locator is a file path, and a path may hold a byte that is not UTF-8. An
// encoder writes such a byte as the escape \ufffd, which reads back as the
// replacement character and encodes raw, so a manifest carrying one would not
// equal its own re-encoding and would fail its canonical check. The manifest
// is made valid on the way in (internal/validutf8), so it does not.
func TestAManifestWithAPathHoldingABadByteVerifiesAfterAFileRoundTrip(t *testing.T) {
	seed := theOwnersSeed(t)
	arch := anArchive(t)
	bad := "/home/me/photos/caf\xe9/\xff.jpg"
	arch.Manifest.ExternalPointers = []ExternalDataPointer{{Domain: "photos", Locator: bad, KeyRef: "k\xc3"}}

	// The way in: what finishArchive does to every manifest.
	arch.Manifest = validUTF8Manifest(arch.Manifest)
	if err := SignWithSeed(arch, seed); err != nil {
		t.Fatal(err)
	}
	file, err := EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(file), `\ufffd`) {
		t.Fatalf("the manifest was written with an escaped bad byte: %s", file)
	}
	back, err := DecodeArchive(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckWhoWroteIt(back, seed, nil); err != nil {
		t.Fatalf("an archive whose path holds a bad byte was refused: %v", err)
	}
	want := "/home/me/photos/caf\uFFFD/\uFFFD.jpg"
	if got := back.Manifest.ExternalPointers[0].Locator; got != want {
		t.Fatalf("locator = %q, want %q", got, want)
	}
}
