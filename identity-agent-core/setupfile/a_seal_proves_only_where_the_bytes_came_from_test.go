package setupfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"identity-agent-core/statements"
)

// sealed is the file with a seal by the key of the published seed named.
func sealed(t testing.TB, f object, by, signedBy string) []byte {
	t.Helper()
	r := read(t, text(t, f), Options{})
	seal, err := NewSeal(identifierOf(by), 0, r.Contents, signer(signedBy))
	if err != nil {
		t.Fatal(err)
	}
	out := object{}
	for k, v := range f {
		out[k] = v
	}
	out["seal"] = seal
	return text(t, out)
}

func stateOf(t testing.TB, data []byte, resolve Resolver) SealState {
	t.Helper()
	return read(t, data, Options{}).CheckSeal(resolve).State()
}

func TestASealedFileIsSealedByTheKeyItsSealersKeyLogNamesAndNoOther(t *testing.T) {
	data := sealed(t, twoWebsites(), "exporter", "exporter")
	r := read(t, data, Options{})
	if r.Seal == nil || r.Seal.By != identifierOf("exporter") {
		t.Fatalf("the seal was not read: %+v", r.Seal)
	}
	held := r.CheckSeal(keysOf())
	if held.State() != Sealed || held.By() != identifierOf("exporter") {
		t.Fatalf("a sealed file is %s by %q", held.State(), held.By())
	}
	// The key is the one the sealer's own key log names: the caller is asked
	// for it by the sealer's identifier and the event, and has no way to say
	// "check it against this key instead".
	asked := ""
	r.CheckSeal(func(by string, sn uint64) (KeyAt, error) {
		asked = by
		return KeyAt{}, errors.New("not held")
	})
	if asked != identifierOf("exporter") {
		t.Fatalf("the key was asked for of %q", asked)
	}
	// A seal that names one Identity Agent and was signed by another's key
	// proves nothing, and names nobody.
	forged := read(t, sealed(t, twoWebsites(), "exporter", "other"), Options{}).CheckSeal(keysOf())
	if forged.State() != Broken || forged.By() != "" {
		t.Fatalf("a seal signed by somebody else is %s by %q", forged.State(), forged.By())
	}
	// With no way to find the key, or none found, it is not checked: never
	// reported as sealed, and it names nobody.
	for _, resolve := range []Resolver{nil, func(string, uint64) (KeyAt, error) { return KeyAt{}, errors.New("several keys") }} {
		if got := r.CheckSeal(resolve); got.State() != Unchecked || got.By() != "" {
			t.Fatalf("a seal nobody could check is %s by %q", got.State(), got.By())
		}
	}
	if got := stateOf(t, text(t, twoWebsites()), keysOf()); got != Unsealed {
		t.Fatalf("a file with no seal is %s", got)
	}
	// What is signed is the statement signature envelope, so a seal is never a
	// second signature format, and the key event it names is inside it.
	input, err := SealInput(r.Seal.By, r.Contents, 0)
	want, _ := statements.Envelope(r.Seal.By, "set-up-seal/1\ncontents="+r.Contents+"\nkel-sn=0")
	if err != nil || !bytes.Equal(input, want) || !strings.HasPrefix(string(input), statements.EnvelopeHeader+"\nasker: "+r.Seal.By+"\n\n") {
		t.Fatalf("the seal's input is %q, %v", input, err)
	}
	if _, err := statements.Check(SealStatement(r.Contents, 0)); err != nil {
		t.Fatalf("the seal's statement is not one a statement signature takes: %v", err)
	}
}

func TestASealByAKeyTheSealerHasLeftIsNotCalledSealed(t *testing.T) {
	data := sealed(t, twoWebsites(), "exporter", "exporter")
	got := read(t, data, Options{}).CheckSeal(keysOf("exporter"))
	if got.State() != SealedByAnEarlierKey || got.By() != identifierOf("exporter") {
		t.Fatalf("a seal by a key rotated away from is %s by %q", got.State(), got.By())
	}
	// The event a seal names is signed: moved to another event, it is not the
	// seal that was made.
	var f object
	_ = json.Unmarshal(data, &f)
	f["seal"].(object)["kel_sn"] = 1
	moved := read(t, text(t, f), Options{}).CheckSeal(func(by string, sn uint64) (KeyAt, error) {
		return KeyAt{Key: keyOf("exporter"), InForce: true}, nil
	})
	if moved.State() != Broken {
		t.Fatalf("a seal moved to another key event is %s", moved.State())
	}
}

func TestASealedFileChangedByOneByteIsReportedAsChanged(t *testing.T) {
	data := sealed(t, twoWebsites(), "exporter", "exporter")
	for name, change := range map[string][2]string{
		"one letter of a name":    {"Staff portal", "Staff portaI"},
		"one letter of an origin": {"notes.example", "notez.example"},
		"who is admitted":         {`"mode": "invite"`, `"mode": "open"`},
		"one digit of the time":   {"2026-11-20T09:00:00Z", "2026-11-20T09:00:01Z"},
	} {
		changed := bytes.Replace(data, []byte(change[0]), []byte(change[1]), 1)
		if bytes.Equal(changed, data) {
			t.Fatalf("%s: nothing was changed", name)
		}
		got := read(t, changed, Options{}).CheckSeal(keysOf())
		// It carries a seal made for other contents, and names nobody: the
		// sealer sealed something, and never this.
		if got.State() != Changed || got.By() != "" {
			t.Fatalf("a sealed file with %s changed is %s by %q", name, got.State(), got.By())
		}
	}
	// An item taken out, as a person does before importing, is a change too.
	var f object
	_ = json.Unmarshal(data, &f)
	f["items"] = f["items"].([]any)[:1]
	if got := stateOf(t, text(t, f), keysOf()); got != Changed {
		t.Fatalf("a sealed file with an item removed is %s", got)
	}
	// The seal is over what the file says, not how it is laid out: written
	// again with other spacing and its members in another order, it holds.
	_ = json.Unmarshal(data, &f)
	compact, _ := json.Marshal(f)
	if got := stateOf(t, compact, keysOf()); got != Sealed {
		t.Fatalf("the same file laid out another way is %s", got)
	}
}

// The signature is checked before the contents are compared: a seal
// anybody wrote, naming a victim, over a file of their own, is broken.
func TestASealForgedInSomebodysNameIsBrokenAndNeverTheirFileChanged(t *testing.T) {
	var f object
	_ = json.Unmarshal(sealed(t, twoWebsites(), "exporter", "other"), &f)
	f["seal"].(object)["contents"] = aDigest("some other contents")
	if got := read(t, text(t, f), Options{}).CheckSeal(keysOf()); got.State() != Broken || got.By() != "" {
		t.Fatalf("a forged seal over other contents is %s by %q", got.State(), got.By())
	}
	// A changed file whose seal was made to name the new contents.
	data := bytes.Replace(sealed(t, twoWebsites(), "exporter", "exporter"), []byte("Staff portal"), []byte("Staff portaI"), 1)
	changed := read(t, data, Options{})
	_ = json.Unmarshal(data, &f)
	f["seal"].(object)["contents"] = changed.Contents
	if got := stateOf(t, text(t, f), keysOf()); got != Broken {
		t.Fatalf("a seal moved to other contents is %s", got)
	}
}

func TestASealThatIsNotWrittenAsOneRefusesTheFile(t *testing.T) {
	var good object
	_ = json.Unmarshal(sealed(t, twoWebsites(), "exporter", "exporter"), &good)
	for name, change := range map[string]func(seal object){
		"a member it does not know":    func(s object) { s["key"] = "D" },
		"no signature":                 func(s object) { delete(s, "signature") },
		"no key event":                 func(s object) { delete(s, "kel_sn") },
		"a key event that is null":     func(s object) { s["kel_sn"] = nil },
		"a key event that is text":     func(s object) { s["kel_sn"] = "0" },
		"a sealer that is null":        func(s object) { s["by"] = nil },
		"a signature in another form":  func(s object) { s["signature"] = "0B" + s["signature"].(string)[2:] },
		"a signature at another index": func(s object) { s["signature"] = "AB" + s["signature"].(string)[2:] },
		"a sequence number below zero": func(s object) { s["kel_sn"] = -1 },
		"no Identity Agent named":      func(s object) { s["by"] = "the exporter" },
		"a digest that is not one":     func(s object) { s["contents"] = "E" },
	} {
		var f object
		raw, _ := json.Marshal(good)
		_ = json.Unmarshal(raw, &f)
		change(f["seal"].(object))
		if got := refusal(t, text(t, f)); got != BadSeal {
			t.Fatalf("a seal with %s was refused as %s", name, got)
		}
	}
	for _, notOne := range []string{`null`, `[]`, `"sealed"`, `{"kel_sn": 0.0, "by": "x", "contents": "x", "signature": "x"}`} {
		bad := strings.Replace(string(text(t, twoWebsites())), `"format"`, `"seal": `+notOne+`, "format"`, 1)
		if got := refusal(t, []byte(bad)); got != BadSeal {
			t.Fatalf("the seal %s was refused as %s", notOne, got)
		}
	}
}
