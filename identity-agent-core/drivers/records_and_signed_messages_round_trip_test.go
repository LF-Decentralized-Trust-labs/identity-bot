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
