package drivers

import (
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
)

// A log whose events carry several signatures (a threshold of several keys) goes
// from records to signed messages and back without losing one, and what comes
// back verifies. Fails when a record's cesr_signatures are not all attached: a
// two-of-three identity is then read as signed once and refused.
func TestARecordWithSeveralSignaturesKeepsEveryOneThroughSignedMessages(t *testing.T) {
	c, err := witnessproto.ReadKelLogContract()
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := SignedMessagesFromRecords(c.Served.KEL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keri.ValidateSignedKEL(msgs); err != nil {
		t.Fatalf("the records, read as signed messages, do not verify: %v", err)
	}
	// With the first signature only, the same log is under its threshold.
	one := make([]map[string]interface{}, len(c.Served.KEL))
	for i, r := range c.Served.KEL {
		one[i] = map[string]interface{}{"raw_bytes_b64": r["raw_bytes_b64"], "cesr_signature": r["cesr_signature"]}
	}
	if m, err := SignedMessagesFromRecords(one); err == nil {
		if _, err := keri.ValidateSignedKEL(m); err == nil {
			t.Fatal("control: one signature of a two-of-three log verified")
		}
	}
	back, ok := RecordsFromSignedMessages(msgs)
	if !ok || len(back) != len(msgs) {
		t.Fatalf("the messages did not come back as records: %v", ok)
	}
	for i, r := range back {
		if got, want := strings.Join(RecordSignatures(r), ","), strings.Join(RecordSignatures(c.Served.KEL[i]), ","); got != want {
			t.Fatalf("record %d: signatures %q, want %q", i, got, want)
		}
		if r["raw_bytes_b64"] != c.Served.KEL[i]["raw_bytes_b64"] {
			t.Fatalf("record %d: the bytes changed", i)
		}
	}
	// A message that is not an event with one counted group of signatures is not handed on.
	if _, ok := RecordsFromSignedMessages([][]byte{[]byte(`{"t":"icp"}`)}); ok {
		t.Fatal("a message with no signatures was handed on as a record")
	}
}

// A log whose signatures are written under the wider codes, "2A" (a key at a
// different place in its two lists) and "2B" (an index of 64 or more), which are
// 92 characters and not 88, goes to records and back whole.
//
// Fails when each signature is assumed to be 88 characters: the message is then
// refused and an adopted later log holding one cannot be handed on.
func TestSignaturesUnderThe2AAnd2BCodesAreReadByTheirOwnWidth(t *testing.T) {
	raw := []byte(`{"v":"KERI10JSON000000_","t":"icp","d":"E","i":"E","s":"0"}`)
	sig := make([]byte, 64)
	enc := func(at keri.SignaturePlace) string {
		s, err := keri.EncodeIndexedSignature(sig, at)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a := enc(keri.SignaturePlace{Index: 0, Ondex: 0})
	twoA := enc(keri.SignaturePlace{Index: 0, Ondex: 1})
	twoB := enc(keri.SignaturePlace{Index: 70, CurrentOnly: true})
	if len(a) != 88 || len(twoA) != 92 || len(twoB) != 92 || twoA[:2] != "2A" || twoB[:2] != "2B" {
		t.Fatalf("control: widths %d %d %d, codes %q %q", len(a), len(twoA), len(twoB), twoA[:2], twoB[:2])
	}
	for name, sigs := range map[string][]string{
		"2A alone": {twoA}, "2B alone": {twoB}, "mixed": {a, twoA, twoB, a},
	} {
		m, err := SignedMessage(raw, sigs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		recs, ok := RecordsFromSignedMessages([][]byte{m})
		if !ok || len(recs) != 1 {
			t.Fatalf("%s: not handed on as a record", name)
		}
		if got := RecordSignatures(recs[0]); strings.Join(got, ",") != strings.Join(sigs, ",") {
			t.Fatalf("%s: signatures %v, want %v", name, got, sigs)
		}
	}
	// A code that is not known is not guessed at, and trailing material is refused.
	m, _ := SignedMessage(raw, []string{twoA})
	if _, ok := RecordsFromSignedMessages([][]byte{append(m, 'A')}); ok {
		t.Fatal("trailing characters after the signatures were accepted")
	}
}
