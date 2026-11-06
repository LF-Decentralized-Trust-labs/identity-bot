package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// A copy of a key log is answered with the key state it establishes, and a
// copy whose rotation was not authorised by the committed key is refused.
func TestAKeyLogIsAnsweredWithTheKeyStateItEstablishes(t *testing.T) {
	s := appHeldCore(t)
	k := appSeeds(4)
	_, out := call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{
		"t": "icp", "k": []string{verkeyOf(k[0])}, "kt": "1", "n": []string{digestOfSeed(t, k[1])}, "nt": "1"})
	icp := preparedBytes(t, out)
	icpSig := appSign(t, k[0], icp, true)
	call(t, s, s.handleCommitEvent, "/api/events/commit", map[string]any{
		"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{icpSig}})
	own, _ := s.DataStore.GetIdentity()
	_, out = call(t, s, s.handlePrepareEvent, "/api/events/prepare", map[string]any{"aid": own.AID, "t": "rot",
		"k": []string{verkeyOf(k[1])}, "kt": "1", "n": []string{digestOfSeed(t, k[2])}, "nt": "1",
		"after": map[string]string{"s": "0", "d": own.AID}})
	rot := preparedBytes(t, out)

	ask := func(rotSig string) (int, KeyState) {
		body, _ := json.Marshal(map[string]any{"aid": own.AID, "events": []map[string]any{
			{"raw_b64": base64.StdEncoding.EncodeToString(icp), "sigs": []string{icpSig}},
			{"raw_b64": base64.StdEncoding.EncodeToString(rot), "sigs": []string{rotSig}},
		}})
		rec := httptest.NewRecorder()
		s.handleKeyState(rec, remote(http.MethodPost, "/public/key-state", string(body)))
		var st KeyState
		_ = json.Unmarshal(rec.Body.Bytes(), &st)
		return rec.Code, st
	}
	if code, _ := ask(appSign(t, k[3], rot, true)); code != http.StatusUnprocessableEntity {
		t.Fatalf("a rotation signed by a key nobody committed to was answered %d", code)
	}
	code, st := ask(appSign(t, k[1], rot, true))
	if code != http.StatusOK {
		t.Fatalf("a sound log was answered %d", code)
	}
	ev, _ := keri.ParseEvent(rot)
	if st.LastEstablishment["s"] != "1" || st.LastEstablishment["d"] != ev.SAID ||
		len(st.K) != 1 || st.K[0] != verkeyOf(k[1]) || strings.TrimSpace(string(st.Kt)) != `"1"` {
		t.Fatalf("the key state is not the rotation's: %+v", st)
	}
	if _, ok := publicRoutes["POST /public/key-state"]; !ok {
		t.Fatal("the route is not declared public")
	}
}
