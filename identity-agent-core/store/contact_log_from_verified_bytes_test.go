package store

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	keri "github.com/grapeid/keri-go"
)

func genuineInception(t *testing.T) (aid, rawB64, sig string, ev map[string]interface{}) {
	t.Helper()
	s, _ := keri.GenerateSigner(true)
	n, _ := keri.GenerateSigner(true)
	pub, _ := s.PublicKey()
	npub, _ := n.PublicKey()
	dig, _ := keri.NextDigest(npub)
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{dig}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(raw)
	sg, _ := s.Sign(raw)
	q, _ := keri.MatterQB64(keri.CodeEd25519Sig, sg)
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	return parsed.Identifier, base64.StdEncoding.EncodeToString(raw), q, ev
}

func tampered(rawB64, sig string) []map[string]interface{} {
	return []map[string]interface{}{{
		"t": "ixn", "k": []interface{}{"DEDITED"}, "event_json": `{"t":"ixn","k":["DEDITED"]}`,
		"raw_bytes_b64": rawB64, "cesr_signature": sig,
	}}
}

func TestAContactLogKeptAsVerifiedSaysOnlyWhatItsBytesSay(t *testing.T) {
	aid, rawB64, sig, ev := genuineInception(t)
	sq, err := NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]interface {
		SaveContactKEL(ContactKELRecord) error
		GetContactKEL(string) (*ContactKELRecord, error)
	}{"sqlite": sq, "file": fs} {
		if err := st.SaveContactKEL(ContactKELRecord{AID: aid, KEL: tampered(rawB64, sig), KelVerified: true}); err != nil {
			t.Fatal(err)
		}
		got, _ := st.GetContactKEL(aid)
		if !got.KelVerified || got.KEL[0]["t"] != "icp" || got.KEL[0]["event_type"] != "icp" {
			t.Fatalf("%s: t=%v verified=%v", name, got.KEL[0]["t"], got.KelVerified)
		}
		k, _ := got.KEL[0]["k"].([]interface{})
		want, _ := ev["k"].([]interface{})
		if len(k) != 1 || k[0] != want[0] {
			t.Fatalf("%s: k=%v, bytes say %v", name, k, want)
		}
		if got.KEL[0]["event_json"] == `{"t":"ixn","k":["DEDITED"]}` {
			t.Fatalf("%s: event_json kept as served", name)
		}
	}
}

func TestARecordStoredBeforeThisIsCorrectedWhenRead(t *testing.T) {
	aid, rawB64, sig, _ := genuineInception(t)
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := map[string]ContactKELRecord{aid: {AID: aid, KEL: tampered(rawB64, sig), KelVerified: true}}
	b, _ := json.Marshal(old)
	if err := os.WriteFile(filepath.Join(dir, "contact_kels.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fs.GetContactKEL(aid)
	if err != nil || got == nil || got.KEL[0]["t"] != "icp" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestAVerifiedContactLogWithNoBytesIsNotKeptVerified(t *testing.T) {
	aid, _, _, _ := genuineInception(t)
	sq, _ := NewSQLiteStore(t.TempDir())
	_ = sq.SaveContactKEL(ContactKELRecord{AID: aid, KelVerified: true,
		KEL: []map[string]interface{}{{"t": "icp", "k": []interface{}{"DX"}}}})
	got, _ := sq.GetContactKEL(aid)
	if got.KelVerified || len(got.ValidationErrors) == 0 {
		t.Fatalf("%+v", got)
	}
}
