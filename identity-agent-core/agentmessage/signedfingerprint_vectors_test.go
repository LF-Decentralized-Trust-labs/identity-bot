package agentmessage

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"identity-agent-core/agentbody"
	"identity-agent-core/internal/contractcheck"
)

// fingerprintVectors are the salted fingerprint and the statement a person
// signs (ADR-067), worked through from fixed inputs: the file another
// implementation tests itself against.
//
//go:embed signed-fingerprint-vectors.json
var fingerprintVectors []byte

type fingerprintVectorSet struct {
	About   string `json:"about"`
	SeedHex string `json:"seed_hex"`
	Signer  string `json:"signer"`
	Verkey  string `json:"verkey"`

	Fingerprints []struct {
		Name        string `json:"name"`
		SaltHex     string `json:"salt_hex"`
		WordsHex    string `json:"words_hex"`
		Fingerprint string `json:"fingerprint"`
	} `json:"fingerprints"`
	// RefusedFingerprints are salts a signer may not use.
	RefusedFingerprints []struct {
		Name    string `json:"name"`
		SaltHex string `json:"salt_hex"`
	} `json:"refused_fingerprints"`
	// VersionZero is the unsalted hash of words: it verifies in a record made
	// before salted fingerprints, and is refused for a new write.
	VersionZero struct {
		WordsHex    string `json:"words_hex"`
		Fingerprint string `json:"fingerprint"`
	} `json:"version_zero"`
	Statements []struct {
		Name      string          `json:"name"`
		Statement PersonStatement `json:"statement"`
		SaltHex   string          `json:"salt_hex"`
		WordsHex  string          `json:"words_hex"`
		Signed    string          `json:"signed"`
		Signature string          `json:"signature"`
	} `json:"statements"`
	RefusedStatements []struct {
		Name      string          `json:"name"`
		Statement PersonStatement `json:"statement"`
	} `json:"refused_statements"`
}

func TestThePublishedFingerprintVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		writeFingerprintVectors(t)
	}
	var set fingerprintVectorSet
	if err := json.Unmarshal(fingerprintVectors, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Fingerprints) == 0 || len(set.Statements) == 0 || len(set.RefusedStatements) == 0 || len(set.RefusedFingerprints) == 0 {
		t.Fatal("the vector file is missing a section")
	}
	want := set
	if err := fillFingerprintVectors(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set, want) {
		got, _ := json.MarshalIndent(set, "", "  ")
		re, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("the published fingerprint vectors are not what this package produces:\n file:\n%s\n recomputed:\n%s", got, re)
	}
	for _, s := range set.Statements {
		salt, words := unhex(t, s.SaltHex), unhex(t, s.WordsHex)
		if err := VerifyPersonWords(s.Statement, set.Verkey, s.Signature, salt, words); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		if len(words) > 0 {
			words[0] ^= 1
		} else {
			words = []byte("x")
		}
		if VerifyPersonWords(s.Statement, set.Verkey, s.Signature, salt, words) == nil {
			t.Fatalf("%s: other words passed", s.Name)
		}
	}
	for _, r := range set.RefusedStatements {
		if r.Statement.Check() == nil {
			t.Fatalf("%s was accepted; it must be refused", r.Name)
		}
	}
	for _, r := range set.RefusedFingerprints {
		if _, err := Fingerprint(unhex(t, r.SaltHex), nil); err == nil {
			t.Fatalf("%s: the salt was accepted", r.Name)
		}
	}
	w := unhex(t, set.VersionZero.WordsHex)
	if err := CheckFingerprint(FingerprintV0, nil, w, set.VersionZero.Fingerprint, true); err != nil {
		t.Fatal(err)
	}
	if CheckFingerprint(FingerprintV0, nil, w, set.VersionZero.Fingerprint, false) == nil {
		t.Fatal("version 0 was accepted for a new write")
	}
}

// An implementation written from the prose, in another language, agrees with
// the vector file.
func TestAnIndependentImplementationAgreesWithTheFingerprintVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_signed_fingerprint_vectors.py",
		"signed-fingerprint-vectors.json", "blake3")
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fillFingerprintVectors(set *fingerprintVectorSet) error {
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil {
		return err
	}
	signer := ed25519Signer{ed25519.NewKeyFromSeed(seed)}
	if set.Signer, set.Verkey, err = agentbody.Identity(signer); err != nil {
		return err
	}
	for i := range set.Fingerprints {
		f := &set.Fingerprints[i]
		words, _ := hex.DecodeString(f.WordsHex)
		salt, _ := hex.DecodeString(f.SaltHex)
		if f.Fingerprint, err = Fingerprint(salt, words); err != nil {
			return err
		}
	}
	w, _ := hex.DecodeString(set.VersionZero.WordsHex)
	set.VersionZero.Fingerprint = HashBody(w)
	for i := range set.Statements {
		s := &set.Statements[i]
		words, _ := hex.DecodeString(s.WordsHex)
		salt, _ := hex.DecodeString(s.SaltHex)
		s.Statement.Signer = set.Signer
		s.Statement.FingerprintVersion = FingerprintV1
		if s.Statement.Fingerprint, err = Fingerprint(salt, words); err != nil {
			return err
		}
		s.Signed = string(s.Statement.Bytes())
		if s.Signature, err = SignPerson(signer, s.Statement); err != nil {
			return err
		}
	}
	return nil
}

func writeFingerprintVectors(t *testing.T) {
	t.Helper()
	var set fingerprintVectorSet
	set.About = "The salted fingerprint and the statement a person signs (ADR-067); the rules are in " +
		"contracts/agent-message/signed-fingerprint.md. The person's device key is Ed25519, from seed_hex. " +
		"Salts and words are hex. contracts/check_signed_fingerprint_vectors.py recomputes every value."
	set.SeedHex = "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
	salt := func(b byte, n int) string { return hex.EncodeToString(runOf(b, n)) }
	text := func(s string) string { return hex.EncodeToString([]byte(s)) }
	type fp = struct {
		Name        string `json:"name"`
		SaltHex     string `json:"salt_hex"`
		WordsHex    string `json:"words_hex"`
		Fingerprint string `json:"fingerprint"`
	}
	set.Fingerprints = []fp{
		{Name: "a short message", SaltHex: salt(0x11, 16), WordsHex: text("yes")},
		{Name: "the same words under another salt", SaltHex: salt(0x12, 16), WordsHex: text("yes")},
		{Name: "no words", SaltHex: salt(0x13, 16), WordsHex: ""},
		{Name: "words that are not text", SaltHex: salt(0x14, 32), WordsHex: "00ff10c3a9e282ac"},
		{Name: "a byte moved from the salt to the words, salt side", SaltHex: salt(0x15, 17), WordsHex: text("yes")},
		{Name: "a byte moved from the salt to the words, words side", SaltHex: salt(0x15, 16), WordsHex: "15" + text("yes")},
		{Name: "the longest salt", SaltHex: salt(0x16, MaxSalt), WordsHex: text("hello")},
	}
	set.RefusedFingerprints = []struct {
		Name    string `json:"name"`
		SaltHex string `json:"salt_hex"`
	}{
		{"no salt", ""},
		{"a salt of 15 bytes", salt(0x21, 15)},
		{"a salt over 1024 bytes", salt(0x22, MaxSalt+1)},
	}
	set.VersionZero.WordsHex = text("an old message")
	base := PersonStatement{Conversation: "c_vector", MessageID: "m_1", Kind: PersonKindMessage,
		From: "EPERSON", To: "EAGENT", Nonce: "nonce-0123456789abcdef", Time: "2026-11-06T10:00:00Z"}
	with := func(f func(*PersonStatement)) PersonStatement { s := base; f(&s); return s }
	type st = struct {
		Name      string          `json:"name"`
		Statement PersonStatement `json:"statement"`
		SaltHex   string          `json:"salt_hex"`
		WordsHex  string          `json:"words_hex"`
		Signed    string          `json:"signed"`
		Signature string          `json:"signature"`
	}
	set.Statements = []st{
		{Name: "a message", Statement: base, SaltHex: salt(0x31, 16), WordsHex: text("hello")},
		{Name: "an ask answering a message", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.InReplyTo = PersonKindAsk, "m_2", "m_1" }), SaltHex: salt(0x32, 16), WordsHex: text("what is next?")},
		{Name: "a split", Statement: with(func(s *PersonStatement) {
			s.Kind, s.MessageID, s.To, s.RangeFirst, s.RangeLast = PersonKindSplit, "m_3", "EOWNER", "m_1", "m_2"
		}), SaltHex: salt(0x33, 16), WordsHex: text("a summary")},
		{Name: "a hand-off", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindHandOff, "m_4", "ENEWOWNER" }), SaltHex: salt(0x34, 16), WordsHex: text("over to you")},
		{Name: "a close, with no words and no recipient", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindClose, "m_5", "" }), SaltHex: salt(0x35, 16), WordsHex: ""},
		{Name: "a reopen", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindReopen, "m_6", "" }), SaltHex: salt(0x36, 16), WordsHex: ""},
	}
	type rs = struct {
		Name      string          `json:"name"`
		Statement PersonStatement `json:"statement"`
	}
	bad := func(name string, f func(*PersonStatement)) rs {
		s := base
		s.Signer, s.FingerprintVersion, s.Fingerprint = "DSIGNER", FingerprintV1, "EFINGERPRINT"
		f(&s)
		return rs{name, s}
	}
	set.RefusedStatements = []rs{
		bad("an unsalted fingerprint (version 0)", func(s *PersonStatement) { s.FingerprintVersion = 0 }),
		bad("an unknown fingerprint version", func(s *PersonStatement) { s.FingerprintVersion = 2 }),
		bad("no message id", func(s *PersonStatement) { s.MessageID = "" }),
		bad("a line break in a field", func(s *PersonStatement) { s.To = "EA\nEB" }),
		bad("a message to nobody", func(s *PersonStatement) { s.To = "" }),
		bad("a close naming a recipient", func(s *PersonStatement) { s.Kind = PersonKindClose }),
		bad("a split with no range", func(s *PersonStatement) { s.Kind = PersonKindSplit }),
		bad("a message naming a range", func(s *PersonStatement) { s.RangeFirst, s.RangeLast = "m_1", "m_2" }),
		bad("a kind that does not exist", func(s *PersonStatement) { s.Kind = "shout" }),
		bad("a short nonce", func(s *PersonStatement) { s.Nonce = "short" }),
		bad("a time that is not RFC 3339", func(s *PersonStatement) { s.Time = "yesterday" }),
	}
	if err := fillFingerprintVectors(&set); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("signed-fingerprint-vectors.json", append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
