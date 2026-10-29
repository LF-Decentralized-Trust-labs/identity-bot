package agentmessage

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/agentbody"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/fixedkeys"
	"identity-agent-core/internal/vectorseeds"
)

// personProof is a paired app's signature on request, the way the app signs
// a request to speak in a conversation.
func personProof(t *testing.T, request []byte) ControllerProof {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, []byte("a person's paired app"))
	signer := ed25519Signer{ed25519.NewKeyFromSeed(seed)}
	controller, verkey, err := agentbody.Identity(signer)
	if err != nil {
		t.Fatal(err)
	}
	signed := strings.Join([]string{"IA-CONTROLLER-REQ-V2", controller, "EORGANISATION", "POST",
		"/api/conversations", "2026-10-20T11:59:00Z", "", "", "0", iacrypto.Blake3QB64Must(request)}, "\n")
	sig, err := agentbody.Sign(signer, []byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	return ControllerProof{Controller: controller, PublicKey: verkey, SignedString: signed, Signature: sig}
}

// personRecord is the Identity Agent's record of a person saying words.
func personRecord(proof ControllerProof, words string) Record {
	return Record{MessageID: "m_person", Conversation: "c_person", Seq: 1, IATime: "2026-10-20T11:59:01Z",
		Kind: KindAsk, From: Person("EPERSON"), To: "EAGENT_A", BodyHash: HashBody([]byte(words)),
		ControllerProof: &proof, Person: &PersonRef{AID: "EPERSON", Standing: "signer"}, OpenedBy: Person("EPERSON")}
}

// throughCountersigning is a record countersigned and opened again, as every
// reader of a conversation gets it.
func throughCountersigning(t *testing.T, r Record) Record {
	t.Helper()
	ks, err := fixedkeys.KeySet("EORGANISATION", vectorseeds.Seeds{
		Ed25519: strings.Repeat("40", 32), MLDSA65: strings.Repeat("41", 32),
		X25519: strings.Repeat("42", 32), MLKEM768: strings.Repeat("43", 64)})
	if err != nil {
		t.Fatal(err)
	}
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Countersign(ks, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(did, env)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A person's words still check after the Identity Agent countersigns them,
// whatever characters they hold and however the app laid out its JSON: the
// request is carried as the bytes the app signed, which no encoder rewrites.
func TestAPersonsWordsStillCheckAfterCountersigning(t *testing.T) {
	for _, c := range []struct{ name, words, request string }{
		{"characters a JSON encoder escapes", "Is 2 < 3 && 5 > 4?",
			`{"to":"EAGENT_A","body":"Is 2 < 3 && 5 > 4?","nonce":"n-00000001"}`},
		{"JSON laid out with spaces and a line break", "Hello",
			"{\"to\": \"EAGENT_A\",\n  \"body\": \"Hello\", \"nonce\": \"n-00000002\"}"},
		{"a line separator", "one\u2028two",
			`{"to":"EAGENT_A","body":"one` + "\u2028" + `two","nonce":"n-00000003"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			proof := personProof(t, []byte(c.request))
			proof.RequestBytes = []byte(c.request)
			got := throughCountersigning(t, personRecord(proof, c.words))
			if err := got.CheckSenderProof(); err != nil {
				t.Fatalf("the countersigned record no longer checks: %v", err)
			}
			if string(got.ControllerProof.RequestBytes) != c.request {
				t.Fatalf("the request came back as %q", got.ControllerProof.RequestBytes)
			}
		})
	}
}

// A record written before the request was carried as bytes nests it as JSON,
// which countersigning compacted and HTML-escaped. It still checks: the
// escaping is undone, and the result is held to the digest the app signed.
func TestARecordWrittenWithTheRequestNestedStillChecks(t *testing.T) {
	request := `{"to":"EAGENT_A","body":"Is 2 < 3 && 5 > 4?","nonce":"n-00000004"}`
	proof := personProof(t, []byte(request))
	proof.Request = json.RawMessage(request)
	got := throughCountersigning(t, personRecord(proof, "Is 2 < 3 && 5 > 4?"))
	if !strings.Contains(string(got.ControllerProof.Request), `\u003c`) {
		t.Fatalf("countersigning was expected to escape the nested request, and kept %s", got.ControllerProof.Request)
	}
	if err := got.CheckSenderProof(); err != nil {
		t.Fatalf("an older record no longer checks: %v", err)
	}

	// The words hold the six characters \u003c as text beside a real <: only
	// the escape countersigning made is undone, never the text after an
	// escaped backslash.
	words := `\` + "u003c is text, < is not"
	request = `{"to":"EAGENT_A","body":"\\u003c is text, < is not","nonce":"n-00000007"}`
	proof = personProof(t, []byte(request))
	proof.Request = json.RawMessage(request)
	if err := throughCountersigning(t, personRecord(proof, words)).CheckSenderProof(); err != nil {
		t.Fatalf("an older record holding an escaped backslash no longer checks: %v", err)
	}

	// Everything compact JSON from an app can hold at once: the characters
	// countersigning escaped, the line and paragraph separators it escaped
	// too, a quote and a backslash the app escaped itself, and an escape the
	// app wrote for a control character, which countersigning leaves alone.
	words = "a < b && c > d" + "\u2028" + "next" + "\u2029" + `"quoted" \ end` + "\u0001"
	request = `{"to":"EAGENT_A","body":"a < b && c > d` + "\u2028" + "next" + "\u2029" + `\"quoted\" \\ end\u0001","nonce":"n-00000008"}`
	proof = personProof(t, []byte(request))
	proof.Request = json.RawMessage(request)
	got = throughCountersigning(t, personRecord(proof, words))
	if !strings.Contains(string(got.ControllerProof.Request), `\u2028`) {
		t.Fatalf("countersigning was expected to escape the line separator, and kept %s", got.ControllerProof.Request)
	}
	if err := got.CheckSenderProof(); err != nil {
		t.Fatalf("an older record holding every escape at once no longer checks: %v", err)
	}
}

// An escape the app wrote itself, in either case, is kept by countersigning
// and so read as it stands; only the lowercase escapes countersigning adds are
// undone, so an app's own \u003C beside a real < still checks.
func TestAnAppsOwnEscapesAreReadAsTheyStand(t *testing.T) {
	for _, request := range []string{
		`{"to":"EAGENT_A","body":"\u003C is less-than","nonce":"n-00000010"}`,
		`{"to":"EAGENT_A","body":"\u003C and < are both less-than","nonce":"n-00000011"}`,
	} {
		var msg PersonMessage
		if err := json.Unmarshal([]byte(request), &msg); err != nil {
			t.Fatal(err)
		}
		proof := personProof(t, []byte(request))
		proof.Request = json.RawMessage(request)
		if err := throughCountersigning(t, personRecord(proof, msg.Body)).CheckSenderProof(); err != nil {
			t.Fatalf("%s: an app's own escape no longer checks: %v", request, err)
		}
	}
}

// An older record whose signed bytes countersigning lost cannot be recovered,
// and is refused rather than read some other way: one whose app sent JSON with
// spaces, which were removed, and one holding both a < and the app's own
// lowercase escape for it, which became the same six characters.
func TestAnOlderRecordWhoseSignedBytesWereLostStaysRefused(t *testing.T) {
	for _, request := range []string{
		"{\"to\": \"EAGENT_A\", \"body\": \"a < b\", \"nonce\": \"n-00000009\"}",
		`{"to":"EAGENT_A","body":"\u003c and <","nonce":"n-00000012"}`,
	} {
		var msg PersonMessage
		if err := json.Unmarshal([]byte(request), &msg); err != nil {
			t.Fatal(err)
		}
		proof := personProof(t, []byte(request))
		proof.Request = json.RawMessage(request)
		if err := throughCountersigning(t, personRecord(proof, msg.Body)).CheckSenderProof(); err == nil {
			t.Fatalf("%s: a record whose signed bytes were lost was accepted", request)
		}
	}
}

// Undoing the escaping recovers only what was signed. Words that differ from
// the signed ones, and a proof that carries the request both ways, are refused.
func TestOnlyTheSignedRequestIsEverAccepted(t *testing.T) {
	signedReq := `{"to":"EAGENT_A","body":"a < b","nonce":"n-00000005"}`

	other := personProof(t, []byte(signedReq))
	other.Request = json.RawMessage(`{"to":"EAGENT_A","body":"a > b","nonce":"n-00000005"}`)
	if err := personRecord(other, "a > b").CheckSenderProof(); err == nil {
		t.Fatal("words other than the signed ones were accepted")
	}

	both := personProof(t, []byte(signedReq))
	both.RequestBytes, both.Request = []byte(signedReq), json.RawMessage(signedReq)
	if err := personRecord(both, "a < b").CheckSenderProof(); err == nil {
		t.Fatal("a proof carrying the request twice was accepted")
	}

	bytesOff := personProof(t, []byte(signedReq))
	bytesOff.RequestBytes = []byte(`{"to":"EAGENT_A","body":"a < c","nonce":"n-00000005"}`)
	if err := personRecord(bytesOff, "a < c").CheckSenderProof(); err == nil {
		t.Fatal("request bytes other than the signed ones were accepted")
	}
}

// Undoing the escaping turns back exactly the escapes Go's encoder writes, and
// leaves the same characters alone where an escaped backslash precedes them.
func TestUndoingTheEscapingTouchesOnlyRealEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`a \u003c b \u003e c \u0026 d`: "a < b > c & d",
		`line \u2028 para \u2029`:      "line \u2028 para \u2029",
		`text \\u003c stays`:           `text \\u003c stays`,
		`slash then escape \\\u003c`:   `slash then escape \\<`,
		`other escapes \n \" \u0041`:   `other escapes \n \" \u0041`,
		`ends in a backslash \`:        `ends in a backslash \`,
	} {
		if got := string(unescapeHTML([]byte(in))); got != want {
			t.Errorf("%s undone is %s, not %s", in, got, want)
		}
	}
}
