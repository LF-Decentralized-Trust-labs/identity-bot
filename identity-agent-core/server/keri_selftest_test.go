package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	keri "github.com/grapeid/keri-go"
)

func TestKeriSelfTestEndpoint(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret}
	w := httptest.NewRecorder()
	s.handleKeriSelfTest(w, httptest.NewRequest(http.MethodGet, "/api/keri/selftest", nil))

	// A build with keri-go's post-quantum test codes fails the suite on
	// purpose, so it can never pass as a production build.
	if keri.PostQuantumTestCodes() {
		if w.Code == http.StatusOK {
			t.Error("a build with the post-quantum test codes passes the conformance suite")
		}
		return
	}
	if w.Code != http.StatusOK {
		t.Errorf("status %d — the suite reports failures", w.Code)
	}
	var body struct {
		OK                bool `json:"ok"`
		Total             int  `json:"total"`
		Passed            int  `json:"passed"`
		Failed            int  `json:"failed"`
		AssertedElsewhere int  `json:"asserted_elsewhere"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	t.Logf("ok=%v total=%d passed=%d asserted=%d failed=%d",
		body.OK, body.Total, body.Passed, body.AssertedElsewhere, body.Failed)
	if !body.OK || body.Failed != 0 {
		t.Errorf("the conformance suite fails through the endpoint")
	}
	if got := body.Passed + body.Failed + body.AssertedElsewhere; got != body.Total {
		t.Errorf("%d cases accounted for out of %d", got, body.Total)
	}
}
