package agentmessage

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
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

type fingerprintVector struct {
	Name        string `json:"name"`
	SaltHex     string `json:"salt_hex"`
	WordsHex    string `json:"words_hex"`
	Fingerprint string `json:"fingerprint"`
}

type refusedSalt struct {
	Name    string `json:"name"`
	SaltHex string `json:"salt_hex"`
}

type statementVector struct {
	Name      string          `json:"name"`
	Statement PersonStatement `json:"statement"`
	SaltHex   string          `json:"salt_hex"`
	WordsHex  string          `json:"words_hex"`
	Signed    string          `json:"signed"`
	Signature string          `json:"signature"`
}

type refusedStatement struct {
	Name      string          `json:"name"`
	Statement PersonStatement `json:"statement"`
}

// refusedRaw is a statement given as JSON text, for what a typed struct
// cannot hold: a field of the wrong JSON type or one the statement lacks.
type refusedRaw struct {
	Name string `json:"name"`
	JSON string `json:"json"`
}

type fingerprintVectorSet struct {
	About   string `json:"about"`
	SeedHex string `json:"seed_hex"`
	Signer  string `json:"signer"`
	Verkey  string `json:"verkey"`

	Fingerprints []fingerprintVector `json:"fingerprints"`
	// RefusedFingerprints are salts a signer may not use.
	RefusedFingerprints []refusedSalt `json:"refused_fingerprints"`
	// VersionZero is the unsalted hash of words: it verifies in a record made
	// before salted fingerprints, and is refused for a new write.
	VersionZero struct {
		WordsHex    string `json:"words_hex"`
		Fingerprint string `json:"fingerprint"`
	} `json:"version_zero"`
	Statements        []statementVector  `json:"statements"`
	RefusedStatements []refusedStatement `json:"refused_statements"`
	RefusedRaw        []refusedRaw       `json:"refused_raw_statements"`
}

func TestThePublishedFingerprintVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		writeFingerprintVectors(t)
	}
	var set fingerprintVectorSet
	if err := json.Unmarshal(fingerprintVectors, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Fingerprints) == 0 || len(set.Statements) == 0 || len(set.RefusedStatements) == 0 ||
		len(set.RefusedFingerprints) == 0 || len(set.RefusedRaw) == 0 {
		t.Fatal("the vector file is missing a section")
	}
	// Recomputed into a new value built only from the file's inputs, so no
	// slice is shared with set and a changed published value cannot match
	// itself.
	want, err := computeFingerprintVectors(set)
	if err != nil {
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
	for _, r := range set.RefusedRaw {
		if parseRawStatement(r.JSON) == nil {
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

// parseRawStatement is nil only for a statement that decodes as the contract
// says (known fields, the right JSON types) and passes Check.
func parseRawStatement(raw string) error {
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	var s PersonStatement
	if err := d.Decode(&s); err != nil {
		return err
	}
	return s.Check()
}

// The tests above must be able to fail: a changed published byte is caught.
func TestAChangedPublishedFingerprintVectorIsCaught(t *testing.T) {
	var set fingerprintVectorSet
	if err := json.Unmarshal(fingerprintVectors, &set); err != nil {
		t.Fatal(err)
	}
	flip := func(s string) string {
		b := []byte(s)
		if b[len(b)-2] == 'A' {
			b[len(b)-2] = 'B'
		} else {
			b[len(b)-2] = 'A'
		}
		return string(b)
	}
	for name, change := range map[string]func(*fingerprintVectorSet){
		"a fingerprint":            func(x *fingerprintVectorSet) { x.Fingerprints[0].Fingerprint = flip(x.Fingerprints[0].Fingerprint) },
		"the unsalted fingerprint": func(x *fingerprintVectorSet) { x.VersionZero.Fingerprint = flip(x.VersionZero.Fingerprint) },
		"a statement's time":       func(x *fingerprintVectorSet) { x.Statements[0].Statement.Time = "2026-11-06T10:00:01Z" },
		"a statement's fingerprint": func(x *fingerprintVectorSet) {
			x.Statements[0].Statement.Fingerprint = flip(x.Statements[0].Statement.Fingerprint)
		},
		"a signature":       func(x *fingerprintVectorSet) { x.Statements[0].Signature = flip(x.Statements[0].Signature) },
		"the signed string": func(x *fingerprintVectorSet) { x.Statements[0].Signed += "x" },
	} {
		var x fingerprintVectorSet
		if err := json.Unmarshal(fingerprintVectors, &x); err != nil {
			t.Fatal(err)
		}
		change(&x)
		want, err := computeFingerprintVectors(x)
		if err != nil {
			t.Fatal(err)
		}
		if reflect.DeepEqual(x, want) {
			t.Errorf("a changed %s still matched the recomputed vectors", name)
		}
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

// computeFingerprintVectors rebuilds every derived value in a set from its
// inputs, into a new value that shares no slice with in.
func computeFingerprintVectors(in fingerprintVectorSet) (fingerprintVectorSet, error) {
	out := fingerprintVectorSet{About: in.About, SeedHex: in.SeedHex}
	seed, err := hex.DecodeString(in.SeedHex)
	if err != nil {
		return out, err
	}
	signer := ed25519Signer{ed25519.NewKeyFromSeed(seed)}
	if out.Signer, out.Verkey, err = agentbody.Identity(signer); err != nil {
		return out, err
	}
	for _, f := range in.Fingerprints {
		words, err := hex.DecodeString(f.WordsHex)
		if err != nil {
			return out, err
		}
		salt, err := hex.DecodeString(f.SaltHex)
		if err != nil {
			return out, err
		}
		f.Fingerprint, err = Fingerprint(salt, words)
		if err != nil {
			return out, err
		}
		out.Fingerprints = append(out.Fingerprints, f)
	}
	out.RefusedFingerprints = append([]refusedSalt(nil), in.RefusedFingerprints...)
	out.VersionZero.WordsHex = in.VersionZero.WordsHex
	w, err := hex.DecodeString(in.VersionZero.WordsHex)
	if err != nil {
		return out, err
	}
	out.VersionZero.Fingerprint = HashBody(w)
	for _, s := range in.Statements {
		words, err := hex.DecodeString(s.WordsHex)
		if err != nil {
			return out, err
		}
		salt, err := hex.DecodeString(s.SaltHex)
		if err != nil {
			return out, err
		}
		s.Statement.Signer = out.Signer
		s.Statement.FingerprintVersion = FingerprintV1
		if s.Statement.Fingerprint, err = Fingerprint(salt, words); err != nil {
			return out, err
		}
		s.Signed = string(s.Statement.Bytes())
		if s.Signature, err = SignPerson(signer, s.Statement); err != nil {
			return out, err
		}
		out.Statements = append(out.Statements, s)
	}
	out.RefusedStatements = append([]refusedStatement(nil), in.RefusedStatements...)
	out.RefusedRaw = append([]refusedRaw(nil), in.RefusedRaw...)
	return out, nil
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
	type fp = fingerprintVector
	set.Fingerprints = []fp{
		{Name: "a short message", SaltHex: salt(0x11, 16), WordsHex: text("yes")},
		{Name: "the same words under another salt", SaltHex: salt(0x12, 16), WordsHex: text("yes")},
		{Name: "no words", SaltHex: salt(0x13, 16), WordsHex: ""},
		{Name: "words that are not text", SaltHex: salt(0x14, 32), WordsHex: "00ff10c3a9e282ac"},
		{Name: "a byte moved from the salt to the words, salt side", SaltHex: salt(0x15, 17), WordsHex: text("yes")},
		{Name: "a byte moved from the salt to the words, words side", SaltHex: salt(0x15, 16), WordsHex: "15" + text("yes")},
		{Name: "the longest salt", SaltHex: salt(0x16, MaxSalt), WordsHex: text("hello")},
	}
	set.RefusedFingerprints = []refusedSalt{
		{"no salt", ""},
		{"a salt of 15 bytes", salt(0x21, 15)},
		{"a salt over 1024 bytes", salt(0x22, MaxSalt+1)},
	}
	set.VersionZero.WordsHex = text("an old message")
	base := PersonStatement{Agent: "EIDENTITYAGENT", Conversation: "c_vector", MessageID: "m_1", Kind: PersonKindMessage,
		From: "EPERSON", To: "EAGENT", Nonce: "nonce-0123456789abcdef", Time: "2026-11-06T10:00:00Z"}
	with := func(f func(*PersonStatement)) PersonStatement { s := base; f(&s); return s }
	type st = statementVector
	set.Statements = []st{
		{Name: "a message", Statement: base, SaltHex: salt(0x31, 16), WordsHex: text("hello")},
		{Name: "an ask answering a message", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.InReplyTo = PersonKindAsk, "m_2", "m_1" }), SaltHex: salt(0x32, 16), WordsHex: text("what is next?")},
		{Name: "a split", Statement: with(func(s *PersonStatement) {
			s.Kind, s.MessageID, s.To, s.RangeFirst, s.RangeLast = PersonKindSplit, "m_3", "EOWNER", "m_1", "m_2"
		}), SaltHex: salt(0x33, 16), WordsHex: text("a summary")},
		{Name: "a hand-off", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindHandOff, "m_4", "ENEWOWNER" }), SaltHex: salt(0x34, 16), WordsHex: text("over to you")},
		{Name: "a close, with no words and no recipient", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindClose, "m_5", "" }), SaltHex: salt(0x35, 16), WordsHex: ""},
		{Name: "a nonce of 8 two-byte characters, which is 16 bytes", Statement: with(func(s *PersonStatement) { s.MessageID, s.Nonce = "m_7", strings.Repeat("é", 8) }), SaltHex: salt(0x37, 16), WordsHex: text("bytes, not characters")},
		{Name: "a time with an offset and a fraction", Statement: with(func(s *PersonStatement) { s.MessageID, s.Time = "m_8", "2026-11-06T11:00:00.25+01:00" }), SaltHex: salt(0x38, 16), WordsHex: text("hello")},
		{Name: "a raise of the turn limit, whose words are the new limit", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindLimit, "m_9", "" }), SaltHex: salt(0x39, 16), WordsHex: text("80")},
		{Name: "a reopen", Statement: with(func(s *PersonStatement) { s.Kind, s.MessageID, s.To = PersonKindReopen, "m_6", "" }), SaltHex: salt(0x36, 16), WordsHex: ""},
	}
	type rs = refusedStatement
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
		bad("a limit naming a recipient", func(s *PersonStatement) { s.Kind = PersonKindLimit }),
		bad("a split with no range", func(s *PersonStatement) { s.Kind = PersonKindSplit }),
		bad("a message naming a range", func(s *PersonStatement) { s.RangeFirst, s.RangeLast = "m_1", "m_2" }),
		bad("a kind that does not exist", func(s *PersonStatement) { s.Kind = "shout" }),
		bad("no identity agent", func(s *PersonStatement) { s.Agent = "" }),
		bad("a short nonce", func(s *PersonStatement) { s.Nonce = "short" }),
		bad("a nonce of 15 bytes", func(s *PersonStatement) { s.Nonce = "nonce-123456789" }),
		bad("a nonce of 7 two-byte characters, 14 bytes", func(s *PersonStatement) { s.Nonce = strings.Repeat("é", 7) }),
		bad("a time that is not RFC 3339", func(s *PersonStatement) { s.Time = "yesterday" }),
		bad("a date with no time", func(s *PersonStatement) { s.Time = "2026-11-06" }),
		bad("a time in the basic form", func(s *PersonStatement) { s.Time = "20261106T100000Z" }),
		bad("a space where the T goes", func(s *PersonStatement) { s.Time = "2026-11-06 10:00:00Z" }),
		bad("a time with no zone", func(s *PersonStatement) { s.Time = "2026-11-06T10:00:00" }),
		bad("a lower-case t and z", func(s *PersonStatement) { s.Time = "2026-11-06t10:00:00z" }),
		bad("hour 24", func(s *PersonStatement) { s.Time = "2026-11-06T24:00:00Z" }),
		bad("a day that does not exist", func(s *PersonStatement) { s.Time = "2026-02-30T10:00:00Z" }),
		bad("a leap second", func(s *PersonStatement) { s.Time = "2026-12-31T23:59:60Z" }),
		bad("a time with spaces around it", func(s *PersonStatement) { s.Time = " 2026-11-06T10:00:00Z" }),
	}
	rawStatement := func(version string) string {
		return `{"agent":"EIDENTITYAGENT","conversation":"c_vector","message_id":"m_1","kind":"message",` +
			`"from":"EPERSON","signer":"DSIGNER","to":"EAGENT","nonce":"nonce-0123456789abcdef",` +
			`"time":"2026-11-06T10:00:00Z","fingerprint_version":` + version + `,"fingerprint":"EFINGERPRINT"}`
	}
	set.RefusedRaw = []refusedRaw{
		{"the fingerprint version as JSON true", rawStatement("true")},
		{"the fingerprint version as a string", rawStatement(`"1"`)},
		{"the fingerprint version as 1.0", rawStatement("1.0")},
		{"the fingerprint version as 1.5", rawStatement("1.5")},
		{"the fingerprint version missing", strings.Replace(rawStatement("1"), `"fingerprint_version":1,`, "", 1)},
		{"a field the statement does not have", strings.Replace(rawStatement("1"), `"kind":"message",`, `"kind":"message","words":"hello",`, 1)},
		{"the nonce as a number", strings.Replace(rawStatement("1"), `"nonce":"nonce-0123456789abcdef"`, `"nonce":1234567890123456`, 1)},
		// Go's decoder reads these four without complaint (a key in any case,
		// a null, a key twice), each in a statement that is otherwise good, so
		// the Go reader here refuses them itself.
		{"an optional field spelt in capitals", strings.Replace(rawStatement("1"), `"kind":"message",`, `"kind":"message","IN_REPLY_TO":"e1",`, 1)},
		{"an optional field spelt with a capital", strings.Replace(rawStatement("1"), `"kind":"message",`, `"kind":"message","In_reply_to":"e1",`, 1)},
		{"an optional field as null", strings.Replace(rawStatement("1"), `"kind":"message",`, `"kind":"message","in_reply_to":null,`, 1)},
		{"a field twice", strings.Replace(rawStatement("1"), `"kind":"message",`, `"kind":"message","kind":"message",`, 1)},
	}
	out, err := computeFingerprintVectors(set)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(out, "", "  ")
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
