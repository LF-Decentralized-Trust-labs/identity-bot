package boundedread

import (
	"strings"
	"testing"
)

// What the core accepts to store it can fetch back: the most archive a fetch
// takes is what the largest accepted upload decodes to.
func TestWhatCanBeStoredCanBeFetchedBack(t *testing.T) {
	if Archive < ArchiveUploadBase64/4*3 {
		t.Fatalf("an archive of %d bytes can be stored (as %d bytes of base64) but is refused on fetch at %d", ArchiveUploadBase64/4*3, ArchiveUploadBase64, Archive)
	}
}

// Decode refuses a body over its limit and one with anything after the value.
func TestDecodeRefusesOverTheLimitAndTrailingJunk(t *testing.T) {
	var v map[string]string
	if err := Decode(stringsReader(`{"a":"b"}`), 100, &v); err != nil || v["a"] != "b" {
		t.Fatalf("%v %v", v, err)
	}
	if err := Decode(stringsReader(`{"a":"bbbbbbbbbb"}`), 8, &v); err == nil {
		t.Fatal("a body over the limit was decoded")
	}
	if err := Decode(stringsReader(`{"a":"b"} x`), 100, &v); err == nil {
		t.Fatal("trailing junk was accepted")
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
