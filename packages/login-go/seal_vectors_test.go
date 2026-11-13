package login

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The same file the TypeScript sealing is held to.
const sealVectorsPath = "../login-web/test-vectors/seal.json"

type sealVectors struct {
	RID       string `json:"rid"`
	Inception string `json:"relay_inception"`
	RelayLog  string `json:"relay_log"`
	RelaySN   int    `json:"relay_sn"`
	SeedHex   string `json:"relay_seed_hex"`
	SealKey   struct {
		PrivateHex string `json:"private_hex"`
		PublicB64  string `json:"public_b64u"`
		Statement  string `json:"statement"`
	} `json:"seal_key"`
	Requests []struct {
		Name          string `json:"name"`
		EphDHex       string `json:"eph_d_hex"`
		Content       string `json:"content"`
		Outer         string `json:"outer"`
		AnswerNHex    string `json:"answer_n_hex"`
		AnswerContent string `json:"answer_content"`
		AnswerOuter   string `json:"answer_outer"`
	} `json:"requests"`
	Refusals []struct {
		Name  string `json:"name"`
		RID   string `json:"rid"`
		Outer string `json:"outer"`
	} `json:"refusals"`
	AnswerRefusals []struct {
		Name        string `json:"name"`
		Request     string `json:"request"`
		AnswerOuter string `json:"answer_outer"`
	} `json:"answer_refusals"`
	Sizes []struct {
		ContentLen int `json:"content_len"`
		CtLen      int `json:"ct_len"`
	} `json:"sizes"`
}

func loadSealVectors(t *testing.T) sealVectors {
	t.Helper()
	raw, err := os.ReadFile(sealVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v sealVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSealKeyIsMadeFromTheIdentifiersSeedAndVouchedFor(t *testing.T) {
	v := loadSealVectors(t)
	seed, _ := hex.DecodeString(v.SeedHex)
	k, err := SealKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := b64.EncodeToString(k.Public()); got != v.SealKey.PublicB64 {
		t.Fatalf("sealing key from the seed: got %s want %s", got, v.SealKey.PublicB64)
	}
	if hex.EncodeToString(k.priv.Bytes()) != v.SealKey.PrivateHex {
		t.Fatal("the private half differs")
	}
	// Ed25519 signs deterministically, so the statement is the same bytes.
	signer := ed25519.NewKeyFromSeed(seed)
	kel, err := b64.DecodeString(v.RelayLog)
	if err != nil {
		t.Fatal(err)
	}
	st, err := SealKeyStatement(kel, v.RelaySN, k, v.RID, func(b []byte) ([]byte, error) { return ed25519.Sign(signer, b), nil })
	if err != nil {
		t.Fatal(err)
	}
	if st != v.SealKey.Statement {
		t.Fatalf("statement: got %s want %s", st, v.SealKey.Statement)
	}
	if _, err := SealKeyFromSeed(seed[:31]); err == nil {
		t.Fatal("a short seed made a key")
	}
}

func TestSealedCallsMatchTheSharedCases(t *testing.T) {
	v := loadSealVectors(t)
	seed, _ := hex.DecodeString(v.SeedHex)
	k, _ := SealKeyFromSeed(seed)
	for _, c := range v.Requests {
		d, _ := hex.DecodeString(c.EphDHex)
		eph, err := ecdh.P256().NewPrivateKey(d)
		if err != nil {
			t.Fatal(err)
		}
		outer, reply, err := sealRequestWith(eph, v.RID, k.Public(), []byte(c.Content))
		if err != nil || string(outer) != c.Outer {
			t.Fatalf("%s: the call sealed: %v\n got %s\nwant %s", c.Name, err, outer, c.Outer)
		}
		content, r2, err := k.OpenRequest(v.RID, []byte(c.Outer))
		if err != nil || string(content) != c.Content {
			t.Fatalf("%s: the call opened: %v", c.Name, err)
		}
		n, _ := hex.DecodeString(c.AnswerNHex)
		if a, err := r2.sealWithN(n, []byte(c.AnswerContent)); err != nil || string(a) != c.AnswerOuter {
			t.Fatalf("%s: the answer sealed: %v", c.Name, err)
		}
		if a, err := reply.Open([]byte(c.AnswerOuter)); err != nil || string(a) != c.AnswerContent {
			t.Fatalf("%s: the answer opened: %v", c.Name, err)
		}
	}
	for _, c := range v.Refusals {
		if _, _, err := k.OpenRequest(c.RID, []byte(c.Outer)); err != ErrSealed {
			t.Errorf("%s: opened, or refused another way: %v", c.Name, err)
		}
	}
	for _, c := range v.AnswerRefusals {
		for _, q := range v.Requests {
			if q.Name != c.Request {
				continue
			}
			d, _ := hex.DecodeString(q.EphDHex)
			eph, _ := ecdh.P256().NewPrivateKey(d)
			_, reply, _ := sealRequestWith(eph, v.RID, k.Public(), []byte(q.Content))
			if _, err := reply.Open([]byte(c.AnswerOuter)); err != ErrSealed {
				t.Errorf("an answer, %s: opened, or refused another way: %v", c.Name, err)
			}
		}
	}
	for _, s := range v.Sizes {
		outer, _, err := SealRequest(v.RID, k.Public(), make([]byte, s.ContentLen))
		if err != nil {
			t.Fatal(err)
		}
		var o outerRequest
		_ = json.Unmarshal(outer, &o)
		ct, _ := b64.DecodeString(o.Ct)
		if len(ct) != s.CtLen {
			t.Errorf("%d bytes seal to %d, want %d", s.ContentLen, len(ct), s.CtLen)
		}
	}
	if _, _, err := SealRequest(v.RID, k.Public(), make([]byte, SealMax+1)); err != ErrSealed {
		t.Error("more than a message may carry was sealed")
	}
	if _, _, err := SealRequest(v.RID, make([]byte, 65), []byte("x")); err != ErrSealed {
		t.Error("a point off the curve was sealed to")
	}
	// A different seed's key opens none of these.
	other, _ := SealKeyFromSeed(sha256Sum("another seed"))
	if _, _, err := other.OpenRequest(v.RID, []byte(v.Requests[0].Outer)); err != ErrSealed {
		t.Error("another back end's key opened the call")
	}
}

func sha256Sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
