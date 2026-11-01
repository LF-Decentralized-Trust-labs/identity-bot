package agentbody

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestAnEnrolmentStringRoundTrips(t *testing.T) {
	e := Enrolment{URL: "https://ia.example", IdentityAgent: "EIA", KeyStateSN: 3, KeyStateSAID: "EKS",
		Agent: "EAGENT", AgentName: "Research assistant", Secret: "s3cret", Expires: time.Now().Add(EnrolmentWindow).UTC().Truncate(time.Second)}
	s, err := e.Encode()
	if err != nil || !strings.HasPrefix(s, EnrolmentPrefix) {
		t.Fatalf("encode: %v %q", err, s)
	}
	got, err := ParseEnrolment(" " + s + "\n")
	if err != nil || got.Secret != e.Secret || got.KeyStateSAID != "EKS" || got.Version != 1 || !got.Expires.Equal(e.Expires) {
		t.Fatalf("parse: %v %+v", err, got)
	}
	if _, err := ParseEnrolment("iabody1.bm90IGpzb24"); err == nil {
		t.Fatal("a damaged string was read")
	}
}

// A body cannot award itself a grade it has not been shown to have.
func TestAClaimAboveWhatIsCheckedIsClamped(t *testing.T) {
	for claim, want := range map[string][2]interface{}{
		GradeSoftware:         {GradeSoftware, false},
		GradeHardwareAsserted: {GradeHardwareAsserted, false},
		GradeHardwareAttested: {GradeHardwareAsserted, true},
		GradeAttestedRuntime:  {GradeHardwareAsserted, true},
		"root":                {GradeSoftware, true},
	} {
		g, c := Grade(claim)
		if g != want[0] || c != want[1] {
			t.Fatalf("%s gave %s, clamped=%v", claim, g, c)
		}
	}
}

type ed25519Signer struct{ priv ed25519.PrivateKey }

func (s ed25519Signer) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s ed25519Signer) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

type p256Signer struct{ priv *ecdsa.PrivateKey }

func (s p256Signer) PublicKey() ([]byte, error) {
	return elliptic.MarshalCompressed(elliptic.P256(), s.priv.X, s.priv.Y), nil
}
func (s p256Signer) Sign(d []byte) ([]byte, error) {
	sum := sha256.Sum256(d)
	r, ss, err := ecdsa.Sign(rand.Reader, s.priv, sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	ss.FillBytes(out[32:])
	return out, nil
}

// Both kinds of machine key sign and verify: P-256, which is what secure
// hardware holds, and Ed25519, the software key where a machine has none.
func TestABodySignsWithEitherKindOfKey(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	pPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, s := range map[string]Signer{"ed25519": ed25519Signer{edPriv}, "p256": p256Signer{pPriv}} {
		host, verkey, err := Identity(s)
		if err != nil {
			t.Fatalf("%s identity: %v", name, err)
		}
		msg := SignedRequest{Host: host, Method: "post", Target: "/api/mcp?x=1", Timestamp: "2026-10-20T00:00:00Z",
			Nonce: "n1", Body: []byte("{}")}.Bytes()
		sig, err := Sign(s, msg)
		if err != nil {
			t.Fatalf("%s sign: %v", name, err)
		}
		if err := Verify(host, verkey, sig, msg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if Verify(host, verkey, sig, append(msg, '!')) == nil {
			t.Fatalf("%s: a signature verified over another message", name)
		}
	}
	// An identifier from one machine with the key of another is refused.
	h1, _, _ := Identity(ed25519Signer{edPriv})
	_, v2, _ := Identity(p256Signer{pPriv})
	sig, _ := Sign(p256Signer{pPriv}, []byte("x"))
	if Verify(h1, v2, sig, []byte("x")) == nil {
		t.Fatal("an identifier and a key from two machines were accepted together")
	}
}
