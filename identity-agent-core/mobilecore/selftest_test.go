package mobilecore

import (
	"encoding/json"
	"testing"
)

func TestKeriSelfTestRuns(t *testing.T) {
	out, err := RunKeriSelfTest()
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Total             int `json:"total"`
		Passed            int `json:"passed"`
		Failed            int `json:"failed"`
		AssertedElsewhere int `json:"asserted_elsewhere"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	t.Logf("total=%d passed=%d asserted-elsewhere=%d failed=%d",
		r.Total, r.Passed, r.AssertedElsewhere, r.Failed)
	if r.Failed != 0 {
		t.Errorf("%d conformance cases fail through the mobile entry point", r.Failed)
	}
	if r.Total == 0 {
		t.Error("no cases ran; the embedded vectors did not reach the binding")
	}
	// Every case must be accounted for. A run that silently dropped cases would
	// report a smaller suite as fully passing.
	if got := r.Passed + r.Failed + r.AssertedElsewhere; got != r.Total {
		t.Errorf("%d cases accounted for out of %d — the rest vanished", got, r.Total)
	}
}
