package secureenclave

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Binding is the property that makes a report mean anything. Two different
// AIDs must never produce the same REPORT_DATA, or a report could be lifted
// from one instance and presented by another.
func TestBindingIsUniquePerValue(t *testing.T) {
	a := BindReportData("EPAIRWISE_A")
	b := BindReportData("EPAIRWISE_B")
	if bytes.Equal(a, b) {
		t.Fatal("two AIDs produced the same binding — a report could be replayed between instances")
	}
	if len(a) != ReportDataSize {
		t.Errorf("binding is %d bytes, the hardware field is %d", len(a), ReportDataSize)
	}
}

// A verifier recomputes the binding rather than trusting it, so it has to be
// deterministic.
func TestBindingIsDeterministic(t *testing.T) {
	if !bytes.Equal(BindReportData("EAID"), BindReportData("EAID")) {
		t.Fatal("the same AID produced two bindings — a verifier could never check one")
	}
}

// The domain separator stops a value bound for this purpose being reused as a
// signature over something else.
func TestBindingIsDomainSeparated(t *testing.T) {
	if bytes.Equal(BindReportData("EAID"), BindReportData("IA-SNP-BIND-V1\nEAID")) {
		t.Error("the binding is not domain separated from its own input")
	}
}

// "I am not in a sealed VM" and "I am, and here is the proof" must never be
// confusable — an empty report read as a valid one would defeat the entire
// exercise.
func TestUnavailableIsAnErrorNotAnEmptyReport(t *testing.T) {
	if SNPAvailable() {
		t.Skip("running on an SNP guest; this asserts the non-SNP path")
	}
	report, err := GetSNPReport("EAID")
	if err == nil {
		t.Fatal("a report was returned outside a sealed VM")
	}
	if report != nil {
		t.Error("an unavailable report must be nil, not an empty struct a caller might use")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "snp") {
		t.Errorf("the error should say what is missing: %v", err)
	}
}

// The guest computes this binding and sp-blackbox's verifier recomputes it.
// Two implementations of one construction in two repositories, so the value is
// pinned on both sides: if either changes without the other, this fails here
// rather than every instance silently failing attestation in production.
func TestBindingGoldenVector(t *testing.T) {
	got := hex.EncodeToString(BindReportData("EPAIRWISE_GOLDEN")[:32])
	const want = "d33fdad0f3127ef871d25baa13772085ec95a3fe28bfd5ba5ac3ae33bf75eab6"
	if got != want {
		t.Errorf("the binding construction changed.\n got: %s\nwant: %s\n"+
			"If this was deliberate, sp-blackbox's bindReportData must change identically "+
			"and in the same release.", got, want)
	}
}
