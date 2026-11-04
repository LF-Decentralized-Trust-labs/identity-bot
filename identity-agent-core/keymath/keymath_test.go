package keymath

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// keymath reaches no network and no storage, whatever it imports: it is
// handed a seed, and nothing it is built from may be able to send or keep one.
// drivers is allowed for the one reading of signatures every verifier shares;
// what it depends on is checked here with the rest.
func TestKeymathReachesNoNetworkOrStorage(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		switch {
		case dep == "net" || strings.HasPrefix(dep, "net/") || dep == "database/sql" || dep == "os/exec",
			strings.Contains(dep, "sqlite"),
			strings.HasPrefix(dep, "identity-agent-core/") && dep != "identity-agent-core/iacrypto" &&
				dep != "identity-agent-core/messagingkeys" && dep != "identity-agent-core/keymath" &&
				dep != "identity-agent-core/presentation" && dep != "identity-agent-core/drivers":
			t.Errorf("keymath depends on %s", dep)
		}
	}
}

// An error says what is wrong with the request and never repeats any of it.
func TestAnErrorRepeatsNothingItWasSent(t *testing.T) {
	secret := strings.Repeat("ab", 31) + "zz" // not hex at the end: refused
	for _, op := range []string{"pq_next", "sign_mldsa65", "messaging_keyset", "nonsense"} {
		_, err := Do(op, []byte(`{"seed_hex":"`+secret+`","msg_b64":"`+secret+`"}`))
		if err == nil {
			t.Fatalf("%s accepted a malformed seed", op)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "abab") {
			t.Fatalf("%s repeated its input in an error: %v", op, err)
		}
	}
}

// The same child seed gives the same keys every time, and a signature that
// verifies under the key it commits to.
func TestAChildSeedGivesTheSameKeysEveryTime(t *testing.T) {
	seed := hex.EncodeToString([]byte(strings.Repeat("\x07", 32)))
	a, err := Do("pq_next", []byte(`{"seed_hex":"`+seed+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Do("pq_next", []byte(`{"seed_hex":"`+seed+`"}`))
	if string(a) != string(b) {
		t.Fatal("the same seed gave two post-quantum keys")
	}
	var pq PostQuantumNext
	_ = json.Unmarshal(a, &pq)
	if d, _ := keri.NextDigest(pq.Verkey); d != pq.Digest || !strings.HasPrefix(pq.Verkey, "2AAE") {
		t.Fatalf("the commitment is not the next-key digest of the key under 2AAE: %+v", pq)
	}
	sig, err := Do("sign_mldsa65", []byte(`{"seed_hex":"`+seed+`","msg_b64":"`+base64.StdEncoding.EncodeToString([]byte("m"))+`"}`))
	if err != nil || !strings.Contains(string(sig), "sig_b64") {
		t.Fatalf("signing: %s %v", sig, err)
	}
	m1, err := Do("messaging_keyset", []byte(`{"seed_hex":"`+seed+`"}`))
	m2, _ := Do("messaging_keyset", []byte(`{"seed_hex":"`+seed+`"}`))
	if err != nil || string(m1) != string(m2) || !strings.Contains(string(m1), "IA-HYBRID-1") {
		t.Fatalf("messaging keyset: %s %v", m1, err)
	}
}

// An event is read as the engine reads it, and one whose digest does not
// match its bytes is refused.
func TestAnEventIsReadAsTheEngineReadsIt(t *testing.T) {
	s, _ := keri.GenerateSigner(true)
	n, _ := keri.GenerateSigner(true)
	p, _ := s.PublicKey()
	np, _ := n.PublicKey()
	d, _ := keri.NextDigest(np)
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{p}, NextDigests: []string{d}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Do("parse_event", []byte(`{"raw_b64":"`+base64.StdEncoding.EncodeToString(raw)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev Event
	_ = json.Unmarshal(out, &ev)
	parsed, _ := keri.ParseEvent(raw)
	if ev.T != "icp" || ev.D != parsed.SAID || ev.I != parsed.Identifier || len(ev.Fields) != len(parsed.Fields) {
		t.Fatalf("the event was read differently: %+v", ev)
	}
	tampered := []byte(strings.Replace(string(raw), p, np, 1))
	if _, err := Do("parse_event", []byte(`{"raw_b64":"`+base64.StdEncoding.EncodeToString(tampered)+`"}`)); err == nil {
		t.Fatal("an event whose bytes no longer match its digest was read")
	}
}

// An Ed25519 signature is written at the places it counts, and read back there.
func TestAnEd25519SignatureIsIndexedWhereItIsAsked(t *testing.T) {
	sig := bytes.Repeat([]byte{5}, 64)
	req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(sig), "index": 0, "ondex": 0})
	out, err := Do("index_ed25519_sig", req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sig string `json:"sig_qb64"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	read, err := keri.ParseIndexedSignature(got.Sig)
	if err != nil || read.At.Index != 0 || read.At.Ondex != 0 || !bytes.Equal(read.Raw, sig) {
		t.Fatalf("read back %+v: %v", read, err)
	}
	if _, err := Do("index_ed25519_sig", []byte(`{"sig_b64":"AAAA","index":0,"ondex":0}`)); err == nil {
		t.Fatal("a signature of the wrong size was indexed")
	}
}

// The two places are written as asked, not swapped: an index that differs from
// its prior-next place reads back with each where it was put.
func TestAnEd25519SignatureKeepsItsIndexAndPriorNextApart(t *testing.T) {
	sig := bytes.Repeat([]byte{5}, 64)
	for _, at := range [][2]int{{2, 0}, {0, 3}, {1, 2}, {5, 1}} {
		req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(sig), "index": at[0], "ondex": at[1]})
		out, err := Do("index_ed25519_sig", req)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Sig string `json:"sig_qb64"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		read, err := keri.ParseIndexedSignature(got.Sig)
		if err != nil || read.At.Index != at[0] || read.At.Ondex != at[1] || !bytes.Equal(read.Raw, sig) {
			t.Fatalf("index %d, prior-next %d was read back as %+v: %v", at[0], at[1], read.At, err)
		}
	}
}

// A current-only Ed25519 signature carries no prior-next place, and reads back
// as one.
func TestACurrentOnlyEd25519SignatureOpensNothing(t *testing.T) {
	sig := bytes.Repeat([]byte{5}, 64)
	req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(sig), "index": 1, "ondex": 7, "current_only": true})
	out, err := Do("index_ed25519_sig", req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sig string `json:"sig_qb64"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	read, err := keri.ParseIndexedSignature(got.Sig)
	if err != nil || read.At.Index != 1 || !read.At.CurrentOnly || !bytes.Equal(read.Raw, sig) {
		t.Fatalf("read back %+v: %v", read.At, err)
	}
}

// A signature that is not on a key event is written unindexed (0B), the form
// the core's verifiers read against a bare public key: the same text the
// engine's own CesrEncode writes.
func TestASignatureOffAKeyEventIsWrittenUnindexed(t *testing.T) {
	sig := bytes.Repeat([]byte{5}, 64)
	out, err := Do("ed25519_sig", []byte(`{"sig_b64":"`+base64.StdEncoding.EncodeToString(sig)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sig string `json:"sig_qb64"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	want, _ := keri.MatterQB64(keri.CodeEd25519Sig, sig)
	if got.Sig != want || !strings.HasPrefix(got.Sig, "0B") {
		t.Fatalf("got %q, want %q", got.Sig, want)
	}
	if _, err := Do("ed25519_sig", []byte(`{"sig_b64":"AAAA"}`)); err == nil {
		t.Fatal("a signature of the wrong size was written")
	}
}
