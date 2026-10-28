package agentbody

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
)

// Every published vector is what this package produces from its inputs: the
// encoded enrolment, the strings a body signs and its signatures over them,
// the six words, the grades. A change to any of them breaks this test before
// it breaks another implementation.
func TestThePublishedBodyVectorsHold(t *testing.T) {
	if os.Getenv("IA_WRITE_CONTRACTS") == "1" {
		writeBodyVectors(t)
	}
	set, err := BodyVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Enrolments) == 0 || len(set.RefusedEnrolments) == 0 || len(set.EnrolProofs) == 0 ||
		len(set.SignedRequests) == 0 || len(set.Words) == 0 || len(set.Grades) == 0 {
		t.Fatal("the vector file is missing a section")
	}
	// Recomputed into a second copy read from the file, so nothing the
	// recomputation writes can reach the values it is compared with.
	want, err := BodyVectors()
	if err != nil {
		t.Fatal(err)
	}
	if err := fillBodyVectors(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set, want) {
		got, _ := json.MarshalIndent(set, "", "  ")
		recomputed, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("the published body vectors are not what this package produces:\n file:\n%s\n recomputed:\n%s", got, recomputed)
	}

	// What is derived is also accepted by the checks the Identity Agent runs.
	for _, e := range set.Enrolments {
		parsed, err := ParseEnrolment(e.Encoded)
		if err != nil || !reflect.DeepEqual(parsed, e.Fields) {
			t.Fatalf("%s does not read back: %v %+v", e.Name, err, parsed)
		}
	}
	for _, r := range set.RefusedEnrolments {
		if _, err := ParseEnrolment(r.Encoded); err == nil {
			t.Fatalf("%s was read; it must be refused", r.Name)
		}
	}
	for _, p := range set.EnrolProofs {
		if err := Verify(set.Host, set.Verkey, p.Signature, []byte(p.Signed)); err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
	}
	for _, r := range set.SignedRequests {
		if err := Verify(set.Host, set.Verkey, r.Headers[HeaderSignature], []byte(r.Signed)); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
	}
	if err := Verify(set.P256.Host, set.P256.Verkey, set.P256.Signature, []byte(set.P256.Signed)); err != nil {
		t.Fatalf("the P-256 signature: %v", err)
	}
	if Verify(set.P256.Host, set.P256.Verkey, set.P256.RefusedSignature, []byte(set.P256.Signed)) == nil {
		t.Fatal("the high-s P-256 signature was accepted")
	}
}

// The enrolment string's payload and the body's keys are the objects the
// schema in contracts/agent-body describes.
func TestTheBodySchemaDescribesTheseTypes(t *testing.T) {
	s, err := contractcheck.Read("../contracts/agent-body/agent-body.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var faults []string
	faults = append(faults, s.Matches("enrolment", Enrolment{})...)
	faults = append(faults, s.Matches("keys", Keys{})...)
	for _, f := range faults {
		t.Error(f)
	}
}

// fillBodyVectors computes every derived value in set from its inputs.
func fillBodyVectors(set *BodyVectorSet) error {
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil {
		return err
	}
	signer := ed25519Signer{ed25519.NewKeyFromSeed(seed)}
	if set.Host, set.Verkey, err = Identity(signer); err != nil {
		return err
	}
	set.Keys.Host, set.Keys.Verkey = set.Host, set.Verkey
	set.KeysDigest = set.Keys.KeysDigest()

	for i := range set.Enrolments {
		e := &set.Enrolments[i]
		if e.Encoded, err = e.Fields.Encode(); err != nil {
			return err
		}
	}
	for i := range set.EnrolProofs {
		p := &set.EnrolProofs[i]
		p.Signed = string(EnrolProof(set.Enrolments[0].Fields, p.Nonce, set.Keys, p.ClaimedGrade, p.Platform, p.Placement))
		if p.Signature, err = Sign(signer, []byte(p.Signed)); err != nil {
			return err
		}
	}
	for i := range set.SignedRequests {
		r := &set.SignedRequests[i]
		h := r.Headers
		h[HeaderHost] = set.Host
		r.Signed = string(SignedRequest{
			For: h[HeaderFor], Host: h[HeaderHost], Method: r.Method, Target: r.Target,
			Timestamp: h[HeaderTimestamp], Nonce: h[HeaderNonce], Body: []byte(r.Body),
			WorkItem: h[HeaderWorkItem], Reason: h[HeaderReason], Session: h[HeaderSession],
		}.Bytes())
		if h[HeaderSignature], err = Sign(signer, []byte(r.Signed)); err != nil {
			return err
		}
	}
	for i := range set.Words {
		set.Words[i].Words = Words(set.Words[i].Host)
	}
	for i := range set.Grades {
		g := &set.Grades[i]
		g.Grade, g.Clamped = Grade(g.Claimed)
	}
	p := &set.P256
	if p.Signature != "" {
		high, err := highS(p.Signature)
		if err != nil {
			return err
		}
		p.RefusedSignature = high
	}
	return nil
}

// highS is the same P-256 signature with s replaced by n-s.
func highS(qb64 string) (string, error) {
	// A 64-byte value under a two-character code: two lead bytes were
	// prepended before encoding, and the code replaced their two characters.
	padded, err := base64.RawURLEncoding.DecodeString("AA" + qb64[2:])
	if err != nil || len(padded) != 66 {
		return "", fmt.Errorf("not a P-256 machine signature: %q", qb64)
	}
	raw := padded[2:]
	s := new(big.Int).SetBytes(raw[32:])
	out := append([]byte{}, raw...)
	new(big.Int).Sub(elliptic.P256().Params().N, s).FillBytes(out[32:])
	return iacrypto.MatterFixedQB64(iacrypto.CodeP256Sig, out)
}

// writeBodyVectors writes body-vectors.json from the inputs below. Run it with
// IA_WRITE_CONTRACTS=1 when a format changes on purpose, and review the diff:
// every changed line is a change another implementation has to make.
func writeBodyVectors(t *testing.T) {
	t.Helper()
	var set BodyVectorSet
	set.About = "AI agent body enrolment and signed requests, worked through. Every string a body signs is " +
		"the lines shown joined with a newline (0x0a), no trailing newline. Signatures are the machine " +
		"key's, CESR-encoded; the Ed25519 ones are reproducible from seed_hex. Digests are Blake3-256, CESR " +
		"code E. The enrolment string is iabody1. followed by the base64url (no padding) of the JSON fields."
	set.SeedHex = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0"
	set.Keys = Keys{
		X25519:   "x25519-public-key-base64url",
		MLKEM768: "mlkem768-public-key-base64url",
		Ed25519:  "ed25519-public-key-base64url",
		MLDSA65:  "mldsa65-public-key-base64url",
	}
	exp := time.Date(2026, 10, 28, 12, 15, 0, 0, time.UTC)
	set.Enrolments = append(set.Enrolments, struct {
		Name    string    `json:"name"`
		Fields  Enrolment `json:"fields"`
		Encoded string    `json:"encoded"`
	}{Name: "an enrolment", Fields: Enrolment{Version: 1, URL: "https://ia.example", IdentityAgent: "EIdentityAgent0000000000000000000000000000000",
		KeyStateSN: 3, KeyStateSAID: "EKeyState00000000000000000000000000000000000", Agent: "EAIAgent000000000000000000000000000000000000",
		AgentName: "Research assistant", Secret: "one-time-secret-0001", Expires: exp}})
	for _, r := range []struct{ name, encoded string }{
		{"another prefix", "iabody2.eyJ2IjoxfQ"},
		{"not base64url", "iabody1.***"},
		{"not JSON", "iabody1.bm90IGpzb24"},
		{"version 2", "iabody1." + b64json(map[string]any{"v": 2, "url": "u", "ia": "E", "d": "E", "agent": "E", "secret": "s"})},
		{"no secret", "iabody1." + b64json(map[string]any{"v": 1, "url": "u", "ia": "E", "d": "E", "agent": "E"})},
	} {
		set.RefusedEnrolments = append(set.RefusedEnrolments, struct {
			Name    string `json:"name"`
			Encoded string `json:"encoded"`
		}{r.name, r.encoded})
	}
	for _, p := range [][4]string{
		{"a software key", GradeSoftware, "linux/amd64", "vm"},
		{"a key the machine says is in hardware", GradeHardwareAsserted, "macos/arm64", "computer"},
	} {
		set.EnrolProofs = append(set.EnrolProofs, struct {
			Name         string `json:"name"`
			Nonce        string `json:"nonce"`
			ClaimedGrade string `json:"claimed_grade"`
			Platform     string `json:"platform"`
			Placement    string `json:"placement"`
			Signed       string `json:"signed"`
			Signature    string `json:"signature"`
		}{Name: p[0], Nonce: "enrol-nonce-0001", ClaimedGrade: p[1], Platform: p[2], Placement: p[3]})
	}
	type req = struct {
		Name    string            `json:"name"`
		Headers map[string]string `json:"headers"`
		Method  string            `json:"method"`
		Target  string            `json:"target"`
		Body    string            `json:"body"`
		Signed  string            `json:"signed"`
	}
	set.SignedRequests = []req{
		{Name: "a GET with no body", Method: "GET", Target: "/api/agent-host/inbox?wait=30",
			Headers: map[string]string{HeaderFor: "EIdentityAgent0000000000000000000000000000000",
				HeaderTimestamp: "2026-10-28T12:00:00Z", HeaderNonce: "request-nonce-0001"}},
		{Name: "a POST with a stated purpose and a session", Method: "post", Target: "/api/agent-host/messages",
			Body: `{"conversation":"c_1","text":"done"}`,
			Headers: map[string]string{HeaderFor: "EIdentityAgent0000000000000000000000000000000",
				HeaderTimestamp: "2026-10-28T12:00:01Z", HeaderNonce: "request-nonce-0002",
				HeaderWorkItem: "issue-42", HeaderReason: "report the result", HeaderSession: "run-7"}},
	}
	host, _, _ := Identity(ed25519Signer{ed25519.NewKeyFromSeed(must(hex.DecodeString(set.SeedHex)))})
	for _, h := range []string{host, "1AAIAtzkysVOrUt0qUoLK39vKrGYuBbLRQ8wF1pjUz__rAab"} {
		set.Words = append(set.Words, struct {
			Host  string   `json:"host"`
			Words []string `json:"words"`
		}{Host: h})
	}
	for _, c := range []string{GradeSoftware, GradeHardwareAsserted, GradeHardwareAttested, GradeAttestedRuntime, "", "root"} {
		set.Grades = append(set.Grades, struct {
			Claimed string `json:"claimed"`
			Grade   string `json:"grade"`
			Clamped bool   `json:"clamped"`
		}{Claimed: c})
	}
	// A fixed P-256 key; its signature is made once, here, and published.
	d := new(big.Int).SetBytes(must(hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")))
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	p := p256Signer{priv}
	set.P256.Host, set.P256.Verkey, _ = Identity(p)
	set.P256.Signed = string(SignedRequest{For: "EIdentityAgent0000000000000000000000000000000", Host: set.P256.Host,
		Method: "GET", Target: "/api/agent-host/binding", Timestamp: "2026-10-28T12:00:02Z", Nonce: "request-nonce-0003"}.Bytes())
	sum := sha256.Sum256([]byte(set.P256.Signed))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	pub, _ := p.PublicKey()
	if set.P256.Signature, err = iacrypto.MachineSignatureQB64(pub, raw); err != nil {
		t.Fatal(err)
	}

	if err := fillBodyVectors(&set); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(set); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("body-vectors.json", out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// The embedded copy is the one read; refresh it for the rest of this run.
	bodyVectors = out.Bytes()
}

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
