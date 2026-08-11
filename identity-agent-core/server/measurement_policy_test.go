package server

import (
	"encoding/hex"
	"strings"
	"testing"
)

// A measurement policy is the owner's answer to "is this software I accept",
// and the box being checked cannot supply it. These cover the parsing and the
// one default that matters: no policy is a refusal, never an acceptance.

func aMeasurement(b byte) string {
	raw := make([]byte, 48)
	for i := range raw {
		raw[i] = b
	}
	return hex.EncodeToString(raw)
}

func TestAMeasurementPolicyIsRead(t *testing.T) {
	got, err := parseMeasurements([]string{aMeasurement(0x11), aMeasurement(0x22)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d measurements, expected 2", len(got))
	}
	for _, m := range got {
		if len(m) != 48 {
			t.Errorf("a launch measurement is 48 bytes, got %d", len(m))
		}
	}
}

// A truncated paste is the common mistake, and it must fail where it happens.
// Left to reach the comparison it fails as a mismatch, which reads as "that box
// is running something else" and sends somebody to look at the box.
func TestATruncatedMeasurementIsRefusedWhereItIsWritten(t *testing.T) {
	half := aMeasurement(0x33)[:60]
	_, err := parseMeasurements([]string{half})
	if err == nil {
		t.Fatal("a 30-byte value was accepted as a 48-byte measurement")
	}
	if !strings.Contains(err.Error(), "48") {
		t.Errorf("the error should say what the length must be: %v", err)
	}
}

func TestSomethingThatIsNotHexIsRefused(t *testing.T) {
	if _, err := parseMeasurements([]string{"not-a-measurement"}); err == nil {
		t.Fatal("a non-hex value was accepted")
	}
}

func TestBlankEntriesAreIgnoredRatherThanRefused(t *testing.T) {
	got, err := parseMeasurements([]string{"", "  ", aMeasurement(0x44)})
	if err != nil {
		t.Fatalf("blank entries should be skipped, not fail: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d measurements, expected 1", len(got))
	}
}

// The default that everything else rests on.
//
// An empty policy could plausibly mean "accept anything", and that single
// reading would make the rest of the adoption gate decorative: the report is
// parsed, bound to the offered keys and checked for debug mode, and then
// measured against nothing at all.
func TestNoPolicyRefusesRatherThanAcceptsAnything(t *testing.T) {
	s := &CoreServer{}
	if s.acceptableMeasurement(make([]byte, 48)) {
		t.Fatal("an agent with no measurement policy accepted a measurement, which would " +
			"let any sealed box be adopted regardless of what it launched")
	}
}

func TestOnlyTheListedMeasurementsAreAccepted(t *testing.T) {
	listed, _ := hex.DecodeString(aMeasurement(0x55))
	other, _ := hex.DecodeString(aMeasurement(0x66))
	s := &CoreServer{AcceptedMeasurements: [][]byte{listed}}

	if !s.acceptableMeasurement(listed) {
		t.Error("the listed measurement was refused")
	}
	if s.acceptableMeasurement(other) {
		t.Error("an unlisted measurement was accepted")
	}
	// A prefix of a listed measurement is not that measurement.
	if s.acceptableMeasurement(listed[:24]) {
		t.Error("a truncated measurement matched a listed one")
	}
}
