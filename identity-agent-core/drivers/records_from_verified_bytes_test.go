package drivers

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// servedRecords is what a server publishes for a genuine log: the bytes and
// signature, plus parsed fields beside them.
func servedRecords(t *testing.T) (string, []map[string]interface{}) {
	aid, raws, sigs := signedLog(t)
	var recs []map[string]interface{}
	for i, raw := range raws {
		var ev map[string]interface{}
		if err := json.Unmarshal(raw, &ev); err != nil {
			t.Fatal(err)
		}
		rec := map[string]interface{}{
			"event_json": string(raw), "raw_bytes_b64": base64.StdEncoding.EncodeToString(raw),
			"cesr_signature": sigs[i], "event_type": ev["t"],
		}
		recs = append(recs, rec)
	}
	return aid, recs
}

func TestEditedParsedFieldsOfAVerifiedLogChangeNothingKept(t *testing.T) {
	aid, recs := servedRecords(t)
	in, ok := ValidateKELInputFromRecords(aid, recs)
	if !ok {
		t.Fatal("genuine records should build an input")
	}
	if got, err := ValidateKELFromBytes(in); err != nil || !got.KelVerified {
		t.Fatalf("genuine log must verify: %v %+v", err, got)
	}
	genuine, ok := RecordsFromVerifiedBytes(recs)
	if !ok {
		t.Fatal("genuine records must rebuild")
	}

	// The same genuine bytes, with every unchecked field edited.
	for _, r := range recs {
		r["t"] = "ixn"
		r["k"] = []interface{}{"DATTACKERKEY"}
		r["b"] = []interface{}{}
		r["event_type"] = "ixn"
		r["public_key"] = "DATTACKERKEY"
		r["event_json"] = `{"t":"icp","k":["DATTACKERKEY"],"b":[]}`
	}
	// The edits do not touch the verdict, which is the whole problem.
	in2, _ := ValidateKELInputFromRecords(aid, recs)
	if got, _ := ValidateKELFromBytes(in2); !got.KelVerified {
		t.Fatal("test premise: edited fields leave the verdict unchanged")
	}
	edited, ok := RecordsFromVerifiedBytes(recs)
	if !ok {
		t.Fatal("edited records still carry their bytes")
	}
	a, _ := json.Marshal(genuine)
	b, _ := json.Marshal(edited)
	if string(a) != string(b) {
		t.Fatalf("edited parsed fields reached what is kept:\n%s\n%s", a, b)
	}
	if edited[0]["t"] != "icp" || edited[1]["t"] != "rot" || edited[0]["event_type"] != "icp" {
		t.Fatalf("type not derived from bytes: %v %v", edited[0]["t"], edited[1]["t"])
	}
	if _, has := edited[0]["public_key"]; has {
		t.Fatal("an unverified field survived")
	}
	if edited[1]["sequence_number"] != int64(1) {
		t.Fatalf("sequence number not derived: %v", edited[1]["sequence_number"])
	}
}

func TestAVerifiedLogWithoutItsBytesIsNotKeptAsVerified(t *testing.T) {
	_, recs := servedRecords(t)
	delete(recs[1], "raw_bytes_b64")
	kel, verified, problems := SealedKEL(recs, true, nil)
	if verified || len(problems) == 0 || len(kel) != 2 {
		t.Fatalf("verified=%v problems=%v", verified, problems)
	}
	if _, v, _ := SealedKEL(recs, false, nil); v {
		t.Fatal("an unverified log must stay unverified")
	}
}
