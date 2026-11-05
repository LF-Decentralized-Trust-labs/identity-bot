package server

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"identity-agent-core/store"
)

// A server can serve the genuine bytes of a log beside parsed fields it has
// edited. What this agent keeps, and every reader of it, goes by the bytes.
func TestAServedLogWithEditedFieldsIsReadAsItsBytesSay(t *testing.T) {
	s := witnessWithSeed(t, 1)
	icp := map[string]interface{}{
		"v": "KERI10JSON", "t": "icp", "s": "0", "i": "EServed", "d": "EServed",
		"k": []interface{}{"DGenuineKey"}, "b": []interface{}{"BGenuineWitness"},
	}
	raw, _ := json.Marshal(icp)
	served := []map[string]interface{}{{
		"raw_bytes_b64": base64.StdEncoding.EncodeToString(raw), "cesr_signature": "x",
		"t": "ixn", "k": []interface{}{"DEdited"}, "b": []interface{}{},
		"event_json": `{"t":"icp","k":["DEdited"],"b":[]}`,
	}}
	if err := s.DataStore.SaveContactKEL(store.ContactKELRecord{AID: "EServed", KEL: served, KelVerified: true}); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.DataStore.GetContactKEL("EServed")
	if !rec.KelVerified {
		t.Fatal("a log with its bytes stays verified")
	}
	if ws := witnessKeysIn(rec.KEL); len(ws) != 1 || ws[0] != "BGenuineWitness" {
		t.Fatalf("witnesses read from edited fields: %v", ws)
	}
	ev, err := eventFromKELEntry(rec.KEL[0])
	if err != nil || ev["t"] != "icp" || ev["k"].([]interface{})[0] != "DGenuineKey" {
		t.Fatalf("event read from edited text: %v %v", ev, err)
	}
	if rec.KEL[0]["t"] != "icp" || rec.KEL[0]["k"].([]interface{})[0] != "DGenuineKey" {
		t.Fatalf("top-level fields read from edits: %v", rec.KEL[0])
	}
}
