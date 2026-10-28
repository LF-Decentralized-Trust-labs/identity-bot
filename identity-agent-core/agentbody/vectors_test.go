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

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
	"identity-agent-core/internal/fixedkeys"
)

// Every published vector is what this package produces from its inputs: the
// body's keys, the encoded enrolment, the enrolment request and the string K
// signs for it, the signed requests, the six words, the grades. A change to
// any of them breaks this test before it breaks another implementation.
func TestThePublishedBodyVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		writeBodyVectors(t)
	}
	set, err := BodyVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Enrolments) == 0 || len(set.RefusedEnrolments) == 0 || len(set.EnrolRequests) == 0 ||
		len(set.SignedRequests) == 0 || len(set.RefusedNonces) == 0 || len(set.Words) == 0 || len(set.Grades) == 0 {
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
	if err := set.Keys.CheckSealingKeys(); err != nil {
		t.Fatalf("the body's sealing keys: %v", err)
	}
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
	for _, r := range set.EnrolRequests {
		if err := CheckNonce(r.Request.Nonce); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if err := Verify(set.Host, set.Verkey, r.Request.Signature, []byte(r.Signed)); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
	}
	for _, r := range set.SignedRequests {
		if err := CheckNonce(r.Headers[HeaderNonce]); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		if err := Verify(set.Host, set.Verkey, r.Headers[HeaderSignature], []byte(r.Signed)); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
	}
	for _, n := range set.RefusedNonces {
		if CheckNonce(n) == nil {
			t.Fatalf("the nonce %q was accepted; it must be refused", n)
		}
	}
	checkTheSealedEnrolment(t, set)
	if err := Verify(set.P256.Host, set.P256.Verkey, set.P256.Signature, []byte(set.P256.Signed)); err != nil {
		t.Fatalf("the P-256 signature: %v", err)
	}
	if Verify(set.P256.Host, set.P256.Verkey, set.P256.RefusedSignature, []byte(set.P256.Signed)) == nil {
		t.Fatal("the high-s P-256 signature was accepted")
	}
}

// The sealed enrolment opens, with the Identity Agent's keys, to the first
// enrol request, sealed from the keys it names.
func checkTheSealedEnrolment(t *testing.T, set BodyVectorSet) {
	t.Helper()
	sealed := set.SealedEnrolment
	if sealed.Sender != set.Keys {
		t.Fatal("the enrolment is sealed from keys other than the body's")
	}
	ia, err := fixedkeys.KeySet(set.IdentityAgentKeys.AID, set.IdentityAgentSeeds)
	if err != nil {
		t.Fatal(err)
	}
	jwm, err := didcomm.UnpackAuthcrypt(ia, sealed.Sender.DID(), sealed.Envelope)
	if err != nil {
		t.Fatalf("the sealed enrolment does not open: %v", err)
	}
	first := set.EnrolRequests[0].Request
	if jwm.Type != didcomm.TypeBodyEnrolment || jwm.ID != first.Nonce ||
		jwm.From != "did:keri:"+set.Host || !reflect.DeepEqual(jwm.To, []string{"did:keri:" + set.IdentityAgentKeys.AID}) {
		t.Fatalf("the sealed enrolment is not the first request's message: %+v", jwm)
	}
	var inner EnrolRequest
	if err := json.Unmarshal(jwm.Body, &inner); err != nil || inner != first {
		t.Fatalf("the sealed enrolment carries another request: %v %+v", err, inner)
	}
}

// The objects the body's side of enrolment sends are the ones the schema in
// contracts/agent-body describes, and every object it defines is one of them.
func TestTheBodySchemaDescribesTheseTypes(t *testing.T) {
	s, err := contractcheck.Read("../contracts/agent-body/agent-body.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]any{
		"enrolment":        Enrolment{},
		"keys":             Keys{},
		"enrol_request":    EnrolRequest{},
		"sealed_enrolment": SealedEnrolment{},
		// The signed request's headers are HTTP headers, not JSON a Go type
		// writes; the vectors and the independent check hold them instead.
		"signed_request": nil,
	}
	var faults []string
	for def, v := range held {
		if v != nil {
			faults = append(faults, s.Matches(def, v)...)
		}
	}
	faults = append(faults, s.Unheld(held)...)
	for _, f := range faults {
		t.Error(f)
	}
}

// An implementation written from the schema's prose, in another language,
// agrees with the vector file.
func TestAnIndependentImplementationAgreesWithTheBodyVectors(t *testing.T) {
	contractcheck.Independently(t, "../contracts", "body-vectors.json")
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
	sealing, err := fixedkeys.KeySet(set.Host, set.SealingSeeds)
	if err != nil {
		return err
	}
	if set.Keys, err = KeysFrom(set.Host, set.Verkey, sealing); err != nil {
		return err
	}
	set.KeysDigest = set.Keys.KeysDigest()
	if len(set.Enrolments) == 0 {
		return fmt.Errorf("no enrolment")
	}
	first := set.Enrolments[0].Fields
	ia, err := fixedkeys.KeySet(first.IdentityAgent, set.IdentityAgentSeeds)
	if err != nil {
		return err
	}
	did, err := ia.DID()
	if err != nil {
		return err
	}
	set.IdentityAgentKeys = *did

	for i := range set.Enrolments {
		e := &set.Enrolments[i]
		if e.Encoded, err = e.Fields.Encode(); err != nil {
			return err
		}
	}
	for i := range set.EnrolRequests {
		r := &set.EnrolRequests[i]
		r.Signed = string(EnrolProof(first, r.Nonce, set.Keys, r.ClaimedGrade, r.Platform, r.Placement))
		sig, err := Sign(signer, []byte(r.Signed))
		if err != nil {
			return err
		}
		r.Request = EnrolRequest{Secret: first.Secret, Agent: first.Agent, Keys: set.Keys, Nonce: r.Nonce,
			ClaimedGrade: r.ClaimedGrade, Platform: r.Platform, Placement: r.Placement, Signature: sig}
	}
	set.SealedEnrolment.Sender = set.Keys
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
	if p := &set.P256; p.Signature != "" {
		if p.RefusedSignature, err = highS(p.Signature); err != nil {
			return err
		}
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
// every changed line is a change another implementation has to make. The
// sealed enrolment and the P-256 signature draw fresh randomness, so those
// two change on every run.
func writeBodyVectors(t *testing.T) {
	t.Helper()
	var set BodyVectorSet
	set.About = "AI agent body enrolment and signed requests, worked through; the rules are in " +
		"contracts/agent-body/agent-body.schema.json. Every string a body signs is the lines shown joined with " +
		"a newline (0x0a), no trailing newline. Signatures by K are CESR: the Ed25519 ones reproduce exactly " +
		"from seed_hex. Keys made from seeds follow contracts/README.md."
	set.SeedHex = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0"
	set.SealingSeeds = seeds(0x10)
	set.IdentityAgentSeeds = seeds(0x20)
	const ia = "EIdentityAgent0000000000000000000000000000000"
	exp := time.Date(2026, 10, 28, 12, 15, 0, 0, time.UTC)
	set.Enrolments = append(set.Enrolments, struct {
		Name    string    `json:"name"`
		Fields  Enrolment `json:"fields"`
		Encoded string    `json:"encoded"`
	}{Name: "an enrolment", Fields: Enrolment{Version: 1, URL: "https://ia.example", IdentityAgent: ia,
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
	for _, p := range [][5]string{
		{"a software key", "enrol-nonce-0001", GradeSoftware, "linux/amd64", "vm"},
		{"a key the machine says is in hardware", "enrol-nonce-0002", GradeHardwareAsserted, "macos/arm64", "computer"},
	} {
		set.EnrolRequests = append(set.EnrolRequests, struct {
			Name         string       `json:"name"`
			Nonce        string       `json:"nonce"`
			ClaimedGrade string       `json:"claimed_grade"`
			Platform     string       `json:"platform"`
			Placement    string       `json:"placement"`
			Signed       string       `json:"signed"`
			Request      EnrolRequest `json:"request"`
		}{Name: p[0], Nonce: p[1], ClaimedGrade: p[2], Platform: p[3], Placement: p[4]})
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
			Headers: map[string]string{HeaderFor: ia, HeaderTimestamp: "2026-10-28T12:00:00Z", HeaderNonce: "request-nonce-0001"}},
		{Name: "a POST with a stated purpose and a session", Method: "post", Target: "/api/agent-host/messages",
			Body: `{"conversation":"c_1","text":"done"}`,
			Headers: map[string]string{HeaderFor: ia, HeaderTimestamp: "2026-10-28T12:00:01Z", HeaderNonce: "request-nonce-0002",
				HeaderWorkItem: "issue-42", HeaderReason: "report the result", HeaderSession: "run-7"}},
	}
	set.RefusedNonces = []string{"", "fifteen-chars-0"}
	if err := fillBodyVectors(&set); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{set.Host, "1AAIAtzkysVOrUt0qUoLK39vKrGYuBbLRQ8wF1pjUz__rAab"} {
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

	// The first request, sealed as agent-host seals it.
	sealing, err := fixedkeys.KeySet(set.Host, set.SealingSeeds)
	if err != nil {
		t.Fatal(err)
	}
	first := set.EnrolRequests[0].Request
	inner, _ := json.Marshal(first)
	set.SealedEnrolment.Envelope, err = didcomm.PackAuthcrypt(sealing, &set.IdentityAgentKeys, &didcomm.JWM{
		ID: first.Nonce, Type: didcomm.TypeBodyEnrolment, From: "did:keri:" + set.Host,
		To: []string{"did:keri:" + ia}, CreatedTime: "2026-10-28T12:00:00Z", Body: inner,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A fixed P-256 key; its signature is made once, here, and published.
	d := new(big.Int).SetBytes(must(hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")))
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	p := p256Signer{priv}
	set.P256.Host, set.P256.Verkey, _ = Identity(p)
	set.P256.Signed = string(SignedRequest{For: ia, Host: set.P256.Host, Method: "GET", Target: "/api/agent-host/binding",
		Timestamp: "2026-10-28T12:00:02Z", Nonce: "request-nonce-0003"}.Bytes())
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

// seeds are a keyset's seeds: each key's seed is its own run of bytes,
// counting up from start.
func seeds(start byte) fixedkeys.Seeds {
	run := func(from byte, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = from + byte(i)
		}
		return hex.EncodeToString(b)
	}
	return fixedkeys.Seeds{Ed25519: run(start, 32), MLDSA65: run(start+1, 32), X25519: run(start+2, 32), MLKEM768: run(start+3, 64)}
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
