package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
)

// A controller signs an offer the owner's device can trust — and only that.
//
// The offer is the one part of the controller ceremony that used to carry no
// signature: a bare key and a claim anybody who photographed the screen could
// replay. These check that a signed offer round-trips, and that each way of
// tampering with it is refused with its own reason — because the offer is the
// SOLE authentication before an owner is asked to approve a machine.

// aSignedOffer builds a controller offer signed by a fresh P-256 key, the way
// the enclave signs one on real hardware (which a test cannot reach).
func aSignedOffer(t *testing.T, agent, timestamp string) (ControllerOffer, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	verkey, err := iacrypto.MachineVerkeyForKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := iacrypto.MachineAIDForKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(canonicalControllerOffer(verkey, agent, timestamp)))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sig, err := iacrypto.MachineSignatureQB64(pub, raw)
	if err != nil {
		t.Fatal(err)
	}
	return ControllerOffer{
		AID:         aid,
		PublicKey:   verkey,
		ProtectedBy: "test enclave",
		AgentOrigin: agent,
		Timestamp:   timestamp,
		Signature:   sig,
	}, priv
}

func TestAFreshSignedOfferIsAccepted(t *testing.T) {
	now := time.Now().UTC()
	offer, _ := aSignedOffer(t, "https://agent.example/x", now.Format(time.RFC3339))
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err != nil {
		t.Fatalf("a fresh, correctly signed offer must be accepted: %v", err)
	}
}

func TestAStaleOfferIsRefused(t *testing.T) {
	now := time.Now().UTC()
	// Signed ten minutes ago — past the window, so replaying a photographed
	// offer later is refused even though the signature is perfectly valid.
	old := now.Add(-10 * time.Minute)
	offer, _ := aSignedOffer(t, "https://agent.example/x", old.Format(time.RFC3339))
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err == nil {
		t.Fatal("an offer older than the window must be refused")
	}
}

func TestAnOfferRepointedToAnotherAgentIsRefused(t *testing.T) {
	now := time.Now().UTC()
	// Signed for one agent, then the agent_origin swapped to another. The
	// signature covers the agent, so the swap breaks it — a captured offer
	// cannot be aimed at a different agent.
	offer, _ := aSignedOffer(t, "https://agent.example/mine", now.Format(time.RFC3339))
	offer.AgentOrigin = "https://agent.attacker/theirs"
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err == nil {
		t.Fatal("an offer whose agent was changed after signing must be refused")
	}
}

func TestAnOfferWithAMovedTimestampIsRefused(t *testing.T) {
	now := time.Now().UTC()
	// Signed stale, then the timestamp edited to look fresh. The signature
	// covers the timestamp, so moving it breaks it — a stale offer cannot be
	// made to look current.
	old := now.Add(-10 * time.Minute)
	offer, _ := aSignedOffer(t, "https://agent.example/x", old.Format(time.RFC3339))
	offer.Timestamp = now.Format(time.RFC3339)
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err == nil {
		t.Fatal("an offer whose timestamp was moved after signing must be refused")
	}
}

func TestAnOfferNamingADifferentKeyThanItsAidIsRefused(t *testing.T) {
	now := time.Now().UTC()
	offer, _ := aSignedOffer(t, "https://agent.example/x", now.Format(time.RFC3339))
	// A second real key's identifier, spliced in where the first's belongs, so
	// the offer names one machine and would grant another.
	other, _ := aSignedOffer(t, "https://agent.example/x", now.Format(time.RFC3339))
	offer.AID = other.AID
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err == nil {
		t.Fatal("an offer whose identifier and key are different keys must be refused")
	}
}

// An identity's own discovery record is the same shape as an offer — an
// identifier and a public key — and is served to anyone who knows the
// identifier. Its identifier is a transferable identity (an inception SAID),
// not a machine's key, so it must be refused before it is ever read as a
// computer asking to act. This is the check that used to live on the scanning
// device and now lives here.
func TestAnOfferNamingATransferableIdentityIsRefused(t *testing.T) {
	now := time.Now().UTC()
	offer, _ := aSignedOffer(t, "https://agent.example/x", now.Format(time.RFC3339))
	// The real shape of what an agent serves at its own OOBI address: a
	// self-addressing (E) identifier, which is an identity and not a machine.
	offer.AID = "EBkHULb-btNlTxGi8Jhao_Y2fBI6Y9yvguWRf29gVPta"
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err == nil {
		t.Fatal("an offer whose identifier is an identity, not a machine, must be refused")
	}
}

func TestAnUnsignedOfferIsRefused(t *testing.T) {
	now := time.Now().UTC()
	offer, _ := aSignedOffer(t, "https://agent.example/x", now.Format(time.RFC3339))
	offer.Signature = ""
	if err := (&CoreServer{}).checkControllerOffer(offer, now); err == nil {
		t.Fatal("an offer with no signature must be refused — there is no unsigned path")
	}
}

// A signature over a different message does not verify — the core anti-forgery
// property, asserted directly so a change to the canonical string cannot pass.
func TestASignatureOverOtherBytesDoesNotVerify(t *testing.T) {
	now := time.Now().UTC()
	good, priv := aSignedOffer(t, "https://agent.example/x", now.Format(time.RFC3339))
	// Re-sign a DIFFERENT canonical string, keep everything else.
	sum := sha256.Sum256([]byte("not the canonical offer"))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, sum[:])
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	pub := elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y)
	bad, _ := iacrypto.MachineSignatureQB64(pub, raw)
	good.Signature = bad
	if err := (&CoreServer{}).checkControllerOffer(good, now); err == nil {
		t.Fatal("a signature made over other bytes must not verify")
	}
}

