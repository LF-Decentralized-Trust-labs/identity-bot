package witnessproto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
)

// keripyNotice is what keripy 1.3.6 produced: see
// interop/make_key_state_notice_vectors.py.
type keripyNotice struct {
	Stamp          string          `json:"stamp"`
	Controller     string          `json:"controller"`
	EventsB64      []string        `json:"events_b64"`
	KeyStateRecord json.RawMessage `json:"key_state_record"`
	Witness        string          `json:"witness"`
	WitnessSeedB64 string          `json:"witness_seed_b64"`
	KsnB64         string          `json:"ksn_b64"`
	KsnSignature   string          `json:"ksn_signature"`
	LocURL         string          `json:"loc_url"`
	LocB64         string          `json:"loc_b64"`
	LocSignature   string          `json:"loc_signature"`
}

func loadKeripyNotice(t *testing.T) (keripyNotice, time.Time) {
	t.Helper()
	b, err := os.ReadFile("testdata/keripy_key_state_notice.json")
	if err != nil {
		t.Fatal(err)
	}
	var v keripyNotice
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, v.Stamp)
	if err != nil {
		t.Fatal(err)
	}
	return v, at
}

func (v keripyNotice) signer(t *testing.T) Signer {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(v.WitnessSeedB64)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return func(text string) (string, string, error) {
		sig, err := keri.MatterQB64("0B", ed25519.Sign(priv, []byte(text)))
		return v.Witness, sig, err
	}
}

// The notice keripy's witness gives is believed, and states keripy's place and
// event for the identifier.
func TestAKeyStateNoticeKeripyMakesIsBelieved(t *testing.T) {
	v, at := loadKeripyNotice(t)
	var rec KeyStateRecord
	if err := json.Unmarshal(v.KeyStateRecord, &rec); err != nil {
		t.Fatal(err)
	}
	st, err := VerifyKeyStateNotice(SignedReply{RpyB64: v.KsnB64, WitnessAID: v.Witness, Signature: v.KsnSignature},
		v.Witness, v.Controller, at)
	if err != nil {
		t.Fatalf("keripy's notice was refused: %v", err)
	}
	if st.SN != 2 || st.SAID != rec.D || !st.At.Equal(at) {
		t.Fatalf("keripy's notice read as %+v, want place 2 and event %s", st, rec.D)
	}
}

// Our record of the same events is keripy's record, and the notice we make of
// it is keripy's notice, byte for byte and signature for signature.
func TestOurKeyStateNoticeIsTheOneKeripyMakes(t *testing.T) {
	v, at := loadKeripyNotice(t)
	var kel []LoggedEvent
	for i, e := range v.EventsB64 {
		kel = append(kel, LoggedEvent{SequenceNum: i, RawBytesB64: e, StoredAt: v.Stamp})
	}
	rec, err := KeyStateRecordOf(v.Controller, kel)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var theirs bytes.Buffer
	if err := json.Compact(&theirs, v.KeyStateRecord); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ours, theirs.Bytes()) {
		t.Fatalf("our key state record\n%s\nis not keripy's\n%s", ours, theirs.Bytes())
	}
	ans, err := SignedKeyStateNotice(v.Witness, rec, at, v.signer(t))
	if err != nil {
		t.Fatal(err)
	}
	if ans.RpyB64 != v.KsnB64 {
		got, _ := base64.StdEncoding.DecodeString(ans.RpyB64)
		want, _ := base64.StdEncoding.DecodeString(v.KsnB64)
		t.Fatalf("our notice\n%s\nis not keripy's\n%s", got, want)
	}
	if ans.Signature != v.KsnSignature {
		t.Fatalf("our signature %s is not keripy's %s", ans.Signature, v.KsnSignature)
	}
}

// keripy's /loc/scheme is believed, and ours is keripy's byte for byte.
func TestAWitnessLocationIsTheOneKeripyMakes(t *testing.T) {
	v, at := loadKeripyNotice(t)
	loc, err := VerifyWitnessLocation(SignedReply{RpyB64: v.LocB64, WitnessAID: v.Witness, Signature: v.LocSignature}, v.Witness)
	if err != nil {
		t.Fatalf("keripy's location was refused: %v", err)
	}
	if loc.URL != "https://witness.example:5631" {
		t.Fatalf("keripy's location read as %q", loc.URL)
	}
	ans, err := SignedWitnessLocation(v.Witness, v.LocURL, at, v.signer(t))
	if err != nil {
		t.Fatal(err)
	}
	if ans.RpyB64 != v.LocB64 || ans.Signature != v.LocSignature {
		got, _ := base64.StdEncoding.DecodeString(ans.RpyB64)
		want, _ := base64.StdEncoding.DecodeString(v.LocB64)
		t.Fatalf("our location\n%s\nis not keripy's\n%s", got, want)
	}
}
