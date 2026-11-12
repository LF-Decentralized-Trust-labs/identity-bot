package drivers_test

import (
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/drivers/signedlog"
)

// A presented log's records carry the bytes keri.ValidateSignedKEL judges, and
// the messages made from them are accepted by it: nothing weaker stands in.
func TestSignedMessagesFromRecordsAreWhatTheOneValidatorJudges(t *testing.T) {
	l := signedlog.Incept(t, signedlog.NewKeys(t, 2)).Rotate().Interact("a")
	msgs, err := drivers.SignedMessagesFromRecords(l.Records())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keri.ValidateSignedKEL(msgs); err != nil {
		t.Fatalf("the validator refused a genuine log: %v", err)
	}
}

// Parsed fields alone prove nothing, and an event with no signature is named.
func TestARecordWithoutItsSignedBytesIsNamedNotPassedOff(t *testing.T) {
	l := signedlog.Incept(t, signedlog.NewKeys(t, 2)).Rotate()
	recs := l.Records()
	delete(recs[1], "raw_bytes_b64")
	if _, err := drivers.SignedMessagesFromRecords(recs); err == nil {
		t.Fatal("a record with only parsed fields was carried as signed")
	}
	recs = l.Records()
	recs[0]["cesr_signature"] = ""
	if _, err := drivers.SignedMessagesFromRecords(recs); err == nil {
		t.Fatal("an unsigned event was carried as signed")
	}
}
