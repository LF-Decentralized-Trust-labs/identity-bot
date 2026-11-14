package drivers

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// vector is witnessproto's keripy vectors (interop/make_witness_receipt_vectors.py).
type vector struct {
	Controller string   `json:"controller"`
	EventSAID  string   `json:"event_said"`
	EventB64   string   `json:"event_b64"`
	Witnesses  []string `json:"witnesses"`
	Receipts   []struct {
		Witness    string `json:"witness"`
		SeedB64    string `json:"seed_b64"`
		Index      int    `json:"index"`
		ReceiptB64 string `json:"receipt_b64"`
		Attachment string `json:"attachment"`
	} `json:"receipts"`
	// Later events of the same log: a rotation that changed the witness list,
	// and an event whose sequence number is written in hex.
	Later []struct {
		SN        int      `json:"sn"`
		EventSAID string   `json:"event_said"`
		EventB64  string   `json:"event_b64"`
		Witnesses []string `json:"witnesses"`
		Receipts  []struct {
			Witness    string `json:"witness"`
			SeedB64    string `json:"seed_b64"`
			Index      int    `json:"index"`
			ReceiptB64 string `json:"receipt_b64"`
			Attachment string `json:"attachment"`
		} `json:"receipts"`
	} `json:"later"`
}

func loadVector(t *testing.T) (vector, []byte) {
	t.Helper()
	b, err := os.ReadFile("../witnessproto/testdata/keripy_witness_receipts.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(v.EventB64)
	return v, raw
}

// The list in force at an event is the inception's, amended by each rotation,
// and is read at the event's own place in the log.
func TestTheListInForceAtAnEventIsCarriedThroughRotations(t *testing.T) {
	v, icp := loadVector(t)
	rot, _ := base64.StdEncoding.DecodeString(v.Later[0].EventB64)
	in := ValidateKELInput{RawEvents: [][]byte{icp, rot}}
	at0, ok := WitnessingOf(in, v.EventSAID)
	if !ok || len(at0.Designated) != 2 || at0.Designated[0] != v.Witnesses[0] || at0.Designated[1] != v.Witnesses[1] {
		t.Fatalf("at the inception: %v %v", at0.Designated, ok)
	}
	at1, ok := WitnessingOf(in, v.Later[0].EventSAID)
	if !ok || len(at1.Designated) != 1 || at1.Designated[0] != v.Later[0].Witnesses[0] {
		t.Fatalf("after the rotation: %v %v", at1.Designated, ok)
	}
	if _, ok := WitnessingOf(in, "ENotInTheLog"); ok {
		t.Fatal("an event that is not in the log has a list")
	}
}
