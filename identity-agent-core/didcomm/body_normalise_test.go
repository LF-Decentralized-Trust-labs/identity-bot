package didcomm

import (
	"encoding/json"
	"testing"
)

// A body is not always handed to us compact. Python's json.dumps spaces every
// separator, pretty-printers indent, and any body carrying a URL or a snippet of
// markup contains characters Go's encoder escapes. All of those are altered on
// the way out, so a hash taken before marshalling is a hash of bytes that never
// arrive.
//
// This is the test the original round-trip test was too tidy to be: it used a
// hand-written compact body, which is the one shape that happens to survive.
func TestBodyShapesThatTravelUnchanged(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"compact", `{"text":"hi"}`},
		{"spaced separators, as json.dumps writes them", `{"said": "EAbc", "role": "engineer"}`},
		{"indented, as a pretty-printer writes them", "{\n  \"said\": \"EAbc\",\n  \"role\": \"engineer\"\n}"},
		{"embedded JSON string with escaped quotes", `{"acdc_json":"{\"v\":\"ACDC10JSON\",\"d\":\"EAbc\"}"}`},
		{"angle brackets and ampersand, which Go escapes", `{"note":"a<b & c>d"}`},
		{"a URL with a query string", `{"oobi":"http://h/x?a=1&b=2"}`},
		{"unicode", `{"name":"Zoë Ω 日本"}`},
		{"empty object", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alice, _ := GenerateKeySet("EAlice")
			bob, _ := GenerateKeySet("EBob")
			aliceDID, _ := alice.DID()
			bobDID, _ := bob.DID()
			jwm := &JWM{
				ID: "msg-1", Type: TypeNotification,
				From: "did:keri:EAlice", To: []string{"did:keri:EBob"},
				Body: json.RawMessage(tc.body),
			}
			env, err := PackAuthcrypt(alice, bobDID, jwm)
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			got, err := UnpackAuthcrypt(bob, aliceDID, env)
			if err != nil {
				t.Fatalf("unpack: %v", err)
			}
			// The body must survive as the same JSON value, whatever the encoder
			// did to its byte form.
			var want, have any
			if err := json.Unmarshal([]byte(tc.body), &want); err != nil {
				t.Fatalf("test body is not valid JSON: %v", err)
			}
			if err := json.Unmarshal(got.Body, &have); err != nil {
				t.Fatalf("received body is not valid JSON: %v", err)
			}
			if !jsonEqual(want, have) {
				t.Fatalf("body changed in flight:\n sent %s\n got  %s", tc.body, got.Body)
			}
		})
	}
}

// The signed (plaintext) mode signs over the recomputed body hash, so the same
// defect showed up there as signature_invalid rather than body_hash_mismatch.
func TestSignedModeAcceptsASpacedBody(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	aliceDID, _ := alice.DID()
	jwm := &JWM{
		ID: "msg-2", Type: TypeNotification, From: "did:keri:EAlice",
		Body: json.RawMessage(`{"said": "EAbc", "role": "engineer"}`),
	}
	env, err := PackSigned(alice, jwm)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if _, err := UnpackSigned(aliceDID, env); err != nil {
		t.Fatalf("unpack: %v", err)
	}
}

// A body that is not JSON at all must be refused at pack time, where the caller
// can still be told, rather than becoming an unexplained rejection at the far end.
func TestPackRefusesABodyThatIsNotJSON(t *testing.T) {
	alice, _ := GenerateKeySet("EAlice")
	bob, _ := GenerateKeySet("EBob")
	bobDID, _ := bob.DID()
	jwm := &JWM{
		ID: "msg-3", Type: TypeNotification, From: "did:keri:EAlice",
		To: []string{"did:keri:EBob"}, Body: json.RawMessage(`{not json`),
	}
	if _, err := PackAuthcrypt(alice, bobDID, jwm); err == nil {
		t.Fatal("packed a body that is not valid JSON")
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
