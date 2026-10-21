package relayproto

import "testing"

// The signed bytes are pinned, so an implementation in another language can
// check it produces the same: sorted keys, no whitespace, no HTML escaping,
// and no signature.
func TestAControlRequestIsSignedOverPinnedBytes(t *testing.T) {
	got, err := CanonicalBody(map[string]interface{}{
		"op": "bind", "relay": "relay.example", "signed_by": "EAID", "t": "2026-10-21T00:00:00Z",
		"nonce": "n0nce-n0nce-n0nce", "allocation": "a<b>&c", "signature": "not signed over",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"allocation":"a<b>&c","nonce":"n0nce-n0nce-n0nce","op":"bind","relay":"relay.example","signed_by":"EAID","t":"2026-10-21T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// Anything but a string of printable ASCII is refused, not signed in some
// spelling another implementation would not reproduce.
func TestOnlyPrintableASCIIIsSigned(t *testing.T) {
	for _, body := range []map[string]interface{}{
		{"name": "café"},
		{"n": 1},
		{"x": "line\nbreak"},
	} {
		if _, err := CanonicalBody(body); err == nil {
			t.Errorf("%v was signed", body)
		}
	}
}
