package statements

import (
	"crypto/ed25519"
	"encoding/hex"

	"encoding/json"
	"identity-agent-core/iacrypto"
	"os"
	"strings"
	"testing"
)

type vectors struct {
	DecisionApprovals []struct {
		Decision struct {
			ID          int    `json:"id"`
			Title       string `json:"title"`
			DecidedBy   string `json:"decided_by"`
			Impact      string `json:"impact"`
			UndoMinutes int    `json:"undo_minutes"`
		} `json:"decision"`
		Statement string `json:"statement"`
		TitleHash string `json:"title_hash"`
		Envelope  struct {
			Asker string `json:"asker"`
			Bytes string `json:"bytes"`
		} `json:"envelope_for_asker"`
	} `json:"decision_approvals"`
	GenericOK []struct {
		Name, Statement, Header string
	} `json:"generic_ok"`
	Refused []struct {
		Name      string `json:"name"`
		Statement string `json:"statement"`
		Title     string `json:"title"`
		Because   string `json:"refused_because"`
	} `json:"refused"`
	TitleOK []struct{ Statement, Title string } `json:"title_ok"`
	Sig     struct {
		Seed, Asker, Statement string
		SeedHex                string `json:"seed_hex"`
		PublicKeyHex           string `json:"public_key_hex"`
		SignatureHex           string `json:"signature_hex"`
		SignatureQB64          string `json:"signature_qb64"`
	} `json:"signature_vector"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEveryPublishedDecisionApprovalReadsAndSignsTheBytesPublished(t *testing.T) {
	for _, c := range load(t).DecisionApprovals {
		d, err := ReadDecisionApproval(c.Statement)
		if err != nil {
			t.Fatalf("%q: %v", c.Statement, err)
		}
		if d.TitleHash != c.TitleHash {
			t.Fatalf("title hash %s, vector says %s", d.TitleHash, c.TitleHash)
		}
		if err := CheckTitle(d, c.Decision.Title); err != nil {
			t.Fatalf("the vector's own title is refused: %v", err)
		}
		env, err := Envelope(c.Envelope.Asker, c.Statement)
		if err != nil || string(env) != c.Envelope.Bytes {
			t.Fatalf("envelope is\n%q\nvector says\n%q (%v)", env, c.Envelope.Bytes, err)
		}
	}
}

func TestAStatementThatMeetsTheGenericRulesIsShownWithItsHeader(t *testing.T) {
	for _, c := range load(t).GenericOK {
		s, err := Show(c.Statement, "")
		if err != nil || s.Header != c.Header || s.Verbatim != c.Statement {
			t.Fatalf("%s: %+v %v", c.Name, s, err)
		}
	}
}

func TestEveryPublishedRefusalIsRefusedBeforeAnythingIsShown(t *testing.T) {
	for _, c := range load(t).Refused {
		_, err := Show(c.Statement, c.Title)
		if err == nil {
			t.Fatalf("%s: shown, want refusal %q", c.Name, c.Because)
		}
		if !strings.Contains(err.Error(), c.Because) {
			t.Fatalf("%s: refused as %q, want it to say %q", c.Name, err, c.Because)
		}
	}
}

func TestADecisionApprovalIsShownFromTheCheckedStatementAndTitleOnly(t *testing.T) {
	c := load(t).TitleOK[0]
	s, err := Show(c.Statement, c.Title)
	if err != nil || s.Form != DecisionApprovalForm {
		t.Fatal(s, err)
	}
	var shown strings.Builder
	for _, r := range s.Rows {
		shown.WriteString(r.Label + "|" + r.Value + "\n")
	}
	if !strings.Contains(shown.String(), `"Use the existing queue for retries"`) || !strings.Contains(shown.String(), "agent-a") {
		t.Fatalf("rows: %s", shown.String())
	}
	// without a sentence the fingerprint is shown rather than a sentence nobody checked
	s, err = Show(c.Statement, "")
	if err != nil || !strings.Contains(s.Rows[0].Value, "fingerprint") {
		t.Fatal(s, err)
	}
}

func TestTheEnvelopeNamesTheAskerSoASignatureForOneVerifierIsNotAnothers(t *testing.T) {
	st := "my-note/1\nI agree."
	a, _ := Envelope("EAAAA", st)
	b, _ := Envelope("EBBBB", st)
	if string(a) == string(b) {
		t.Fatal("two askers, one envelope")
	}
	if _, err := Envelope("not an identifier\nasker: EBBBB", st); err == nil {
		t.Fatal("an asker that is not an identifier was taken")
	}
	if !strings.HasPrefix(string(a), "statement-signature/1\nasker: EAAAA\n\nmy-note/1") || strings.HasPrefix(string(a), "{") {
		t.Fatalf("%q", a)
	}
}

// The signature the Identity Agent makes is the bytes in the vector, so a verifier in any language that
// rebuilds the envelope checks the same signature (the console's Python does, from the same file).
func TestTheSignatureOfTheEnvelopeIsTheVectorsByteForByte(t *testing.T) {
	v := load(t).Sig
	seed, _ := hex.DecodeString(v.SeedHex)
	env, err := Envelope(v.Asker, v.Statement)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != v.PublicKeyHex {
		t.Fatal("the vector's key is not its seed's")
	}
	raw := ed25519.Sign(key, env)
	if hex.EncodeToString(raw) != v.SignatureHex {
		t.Fatalf("signature %x, vector says %s", raw, v.SignatureHex)
	}
	q, err := iacrypto.MatterIndexedSigQB64("A", 0, raw, 88)
	if err != nil || q != v.SignatureQB64 {
		t.Fatalf("spelling %q (%v), vector says %q", q, err, v.SignatureQB64)
	}
}
