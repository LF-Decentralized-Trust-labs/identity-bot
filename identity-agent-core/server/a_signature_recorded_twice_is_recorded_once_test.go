package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The app records the signature it makes over each event of its identity's
// log, and an older caller may still record the one it is handed back as
// well. Recording the same signature twice must be harmless: the second is
// checked against the event again and stored again, never refused, and the
// event stays signed by it.
func TestASignatureRecordedTwiceIsRecordedOnce(t *testing.T) {
	s, _ := grantWorld(t)
	s.localOwnerSecret = testOwnerSecret
	s.router = s.buildRouter("")
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		t.Fatalf("no identity: %v", err)
	}
	events, err := s.DataStore.GetEvents(id.AID)
	if err != nil || len(events) == 0 || events[0].CesrSignature == "" {
		t.Fatalf("the founding event is not signed to begin with: %v", err)
	}
	sig := events[0].CesrSignature
	body := `{"aid":"` + id.AID + `","sequence_number":0,"cesr_signature":"` + sig + `"}`
	for _, time := range []string{"first", "second"} {
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, local("POST", "/api/events/signature", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("recording the signature a %s time was answered %d %s", time, rec.Code, rec.Body.String())
		}
	}
	after, _ := s.DataStore.GetEvents(id.AID)
	if len(after) != len(events) || after[0].CesrSignature != sig {
		t.Fatalf("recording a signature twice changed the log: %d events, founding signed %q", len(after), after[0].CesrSignature)
	}
}
