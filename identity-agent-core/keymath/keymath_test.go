package keymath

import (
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
				dep != "identity-agent-core/messagingkeys" && dep != "identity-agent-core/keymath":
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
