package conversationbundle

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// contracts/conversation-bundle/genuine-bundle.json is a genuine export of a
// seven-message conversation between a person and two AI agents, written by
// an Identity Agent that holds AI agents. It is published so a verifier, this
// one or one written in another language, is tested against a real export:
// it must verify, and changing anything it proves must not.

const vectorFile = "../contracts/conversation-bundle/genuine-bundle.json"

func theVector(t *testing.T) ([]byte, *Bundle) {
	t.Helper()
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Read(raw)
	if err != nil {
		t.Fatalf("the published vector does not read as a bundle: %v", err)
	}
	return raw, b
}

func faultsOf(r Report) string {
	var s []string
	for _, f := range r.Faults {
		s = append(s, f.Where+": "+f.Why)
	}
	return strings.Join(s, "\n")
}

func copyOf(t *testing.T, b *Bundle) *Bundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var out Bundle
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func TestThePublishedBundleVerifies(t *testing.T) {
	_, b := theVector(t)
	r := VerifyAgainst(b, b.Root)
	if !r.Verified {
		t.Fatalf("the published genuine bundle does not verify:\n%s", faultsOf(r))
	}
	if len(r.Messages) != 7 {
		t.Fatalf("the report covers %d messages, not the 7 exchanged", len(r.Messages))
	}
	for _, m := range r.Messages {
		if !m.Holds || !m.Anchored {
			t.Fatalf("message %d: holds %v, anchored %v", m.Seq, m.Holds, m.Anchored)
		}
	}
	if m := r.Messages[0]; m.Sender != "controller" {
		t.Fatalf("the opening is not shown as the person's, from their app: %+v", m)
	}
	if m := r.Messages[2]; m.Sender != "body" {
		t.Fatalf("the AI agent's ask is not shown as its body's: %+v", m)
	}
	if len(r.Trusts) == 0 || len(r.CannotRuleOut) == 0 {
		t.Fatal("the report does not say what it trusts and what it cannot rule out")
	}
	if r := VerifyAgainst(b, "EAnotherOrganisationAltogether"); r.Verified {
		t.Fatal("checked against another organisation, the bundle verified")
	}
}

// Changing one byte of anything the bundle proves is caught, wherever it is.
func TestAOneByteEditOfThePublishedBundleFails(t *testing.T) {
	_, b := theVector(t)
	flip := func(s string, at int) string {
		bs := []byte(s)
		bs[at%len(bs)] ^= 0x01
		return string(bs)
	}
	flipWith := func(enc *base64.Encoding) func(string, int) string {
		return func(s string, at int) string {
			raw, err := enc.DecodeString(s)
			if err != nil {
				t.Fatal(err)
			}
			raw[at%len(raw)] ^= 0x01
			return enc.EncodeToString(raw)
		}
	}
	flipB64, flipURL := flipWith(base64.StdEncoding), flipWith(base64.RawURLEncoding)
	for _, c := range []struct {
		name   string
		change func(b *Bundle)
	}{
		{"a word of the person's message", func(b *Bundle) { b.Entries[0].Body = flipB64(b.Entries[0].Body, 3) }},
		{"a word of a reply", func(b *Bundle) { b.Entries[4].Body = flipB64(b.Entries[4].Body, 0) }},
		{"the countersigned entry", func(b *Bundle) { b.Entries[2].Envelope.Plain = flipURL(b.Entries[2].Envelope.Plain, 200) }},
		{"the countersignature", func(b *Bundle) { b.Entries[3].Envelope.EdSig = flipURL(b.Entries[3].Envelope.EdSig, 5) }},
		{"a log row", func(b *Bundle) {
			i := len(b.Log.Rows) / 2
			b.Log.Rows[i].Record = strings.Replace(b.Log.Rows[i].Record, `"ok"`, `"ko"`, 1)
		}},
		{"a body credential", func(b *Bundle) { b.Credentials[0].Raw = flipB64(b.Credentials[0].Raw, 60) }},
		{"a credential's log", func(b *Bundle) { b.Credentials[1].Log[0] = flipB64(b.Credentials[1].Log[0], 40) }},
		{"the root's key log", func(b *Bundle) {
			for i := range b.KeyLogs {
				if b.KeyLogs[i].AID == b.Root {
					b.KeyLogs[i].Events[1].Raw = flipB64(b.KeyLogs[i].Events[1].Raw, 30)
				}
			}
		}},
		{"an anchor statement", func(b *Bundle) {
			b.Anchors[len(b.Anchors)-1].Statement = flip(b.Anchors[len(b.Anchors)-1].Statement, 20)
		}},
		{"a messaging key", func(b *Bundle) { b.Countersigners[0].Ed = flipURL(b.Countersigners[0].Ed, 2) }},
		{"the newest entries removed", func(b *Bundle) { b.Entries = b.Entries[:len(b.Entries)-2] }},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := copyOf(t, b)
			c.change(changed)
			if r := Verify(changed); r.Verified {
				t.Fatalf("%s was changed and the bundle still verifies", c.name)
			}
		})
	}
}

// Changing any one byte of the published file, at positions spread through
// the whole of it, either leaves it unreadable as a bundle, changes nothing it
// says, or fails verification. Nothing the bundle carries goes unchecked.
func TestChangingAnyByteOfThePublishedFileFails(t *testing.T) {
	raw, original := theVector(t)
	positions := 600
	if testing.Short() {
		positions = 60
	}
	step := len(raw) / positions
	if step == 0 {
		step = 1
	}
	checked := 0
	for at := 0; at < len(raw); at += step {
		changed := append([]byte(nil), raw...)
		changed[at] ^= 0x01
		b, err := Read(changed)
		if err != nil || reflect.DeepEqual(b, original) {
			continue
		}
		checked++
		if r := Verify(b); r.Verified {
			lo, hi := max(at-60, 0), min(at+60, len(raw))
			t.Fatalf("byte %d was changed and the bundle still verifies; around it:\n%s", at, raw[lo:hi])
		}
	}
	if checked < positions/3 {
		t.Fatalf("only %d of the changed files were readable bundles, too few to show anything", checked)
	}
}
