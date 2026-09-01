package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/login"
)

// Mints an identity to own a machine with, and returns it.
func mintedToOwnAMachine(t *testing.T, s *CoreServer) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleMintMachineOwner(rec,
		httptest.NewRequest(http.MethodPost, "/api/machines/owner-identity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("minting failed: %d %s", rec.Code, rec.Body.String())
	}
	var minted struct {
		AID string `json:"aid"`
	}
	json.NewDecoder(rec.Body).Decode(&minted)
	if minted.AID == "" {
		t.Fatal("no identity minted, so there is nothing to sign a machine's requests as")
	}
	return minted.AID
}

func askToSignAs(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/machines/owner/sign", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	s.handleSignAsAMachineOwner(rec, req)
	return rec
}

// The signature is made with the key the MACHINE will check against.
//
// A machine is adopted by a pairwise identity, not by the root, and it verifies
// against the key that identity's own log puts in force. A signature from
// anything else verifies here and is refused there, which is a failure with no
// visible cause — so this checks the produced signature against the identity's
// public key rather than merely that something came back.
func TestSigningForAMachineUsesTheIdentityThatAdoptedIt(t *testing.T) {
	s := adoptingOwner(t)
	owner := mintedToOwnAMachine(t, s)

	rec := askToSignAs(t, s, `{"owner_aid":"`+owner+`","method":"get","path":"/api/identity"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("signing refused: %d %s", rec.Code, rec.Body.String())
	}
	var out signAsMachineOwnerResponse
	json.NewDecoder(rec.Body).Decode(&out)
	if out.Signature == "" || out.Timestamp == "" {
		t.Fatalf("nothing to send: %+v", out)
	}
	if out.OwnerAID != owner {
		t.Fatalf("signed as %s, asked for %s", out.OwnerAID, owner)
	}

	// The method is upper-cased in the canonical string, so a caller that sent
	// "get" must still produce the signature the machine checks for "GET".
	signed := canonicalRequestString("GET", "/api/identity", out.Timestamp, nil)

	idx, known, err := s.DataStore.MachineOwnerIndex(owner)
	if err != nil || !known {
		t.Fatalf("the index for %s was not written down (%v)", owner, err)
	}
	pub, err := s.pairwisePublicKey(idx)
	if err != nil {
		t.Fatal(err)
	}
	verkey, err := login.DecodeVerkey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := login.VerifyString(signed, out.Signature, verkey)
	if err != nil || !ok {
		t.Fatalf("the machine would refuse this signature: %v (ok=%v)", err, ok)
	}

	// And it is NOT the root key, which is the whole point of the pairwise
	// identity — a machine that could recognise the root would let anybody who
	// saw one signature link every machine to the same person.
	if identity, _ := s.DataStore.GetIdentity(); identity != nil && pub == identity.PublicKey {
		t.Fatal("the machine was signed to with the root key, so every machine this " +
			"owner adopts is publicly the same person")
	}
}

// Naming an identity is not the same as holding its key.
//
// A pairwise owner identity travels: it is given to the provisioning host, sent
// to the machine, and reported back by it. So it is not a secret, and a device
// that signed as any identity it was handed would sign as somebody else's owner
// for anybody who asked.
func TestThisDeviceRefusesToSignAsAnIdentityItNeverMinted(t *testing.T) {
	s := adoptingOwner(t)
	// Well-formed and real — minted on a DIFFERENT device — so what is being
	// tested is the record of having minted it, not the shape of the string.
	somebodyElse := mintedToOwnAMachine(t, adoptingOwner(t))

	rec := askToSignAs(t, s, `{"owner_aid":"`+somebodyElse+`","method":"GET","path":"/api/identity"}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("this device signed as an identity it never minted: %s", rec.Body.String())
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected a refusal naming the reason, got %d %s", rec.Code, rec.Body.String())
	}
}

// A path that does not start with / would be signed here and resolved
// differently by whatever sends it, so the machine would check a different
// string than the one that arrives and every request would fail silently.
func TestSigningRefusesAPathTheMachineWouldNotSee(t *testing.T) {
	s := adoptingOwner(t)
	owner := mintedToOwnAMachine(t, s)

	rec := askToSignAs(t, s, `{"owner_aid":"`+owner+`","method":"GET","path":"api/identity"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a relative path was signed: %d %s", rec.Code, rec.Body.String())
	}
}

// A machine acting for somebody must never obtain the OWNER's signature.
//
// The controller gate raises high-risk actions rather than closing them, which
// is right for actions. This is not an action: it is the key that satisfies
// every owner route on every machine this device owns. A controller holding one
// of these is the owner, and the gate is decorative.
func TestAControllerCannotAskThisDeviceToSignAsTheOwner(t *testing.T) {
	req, ok := controllerNeedsLevel["POST /api/machines/owner/sign"]
	if !ok {
		t.Fatal("the route that signs as a machine's owner is not named in the " +
			"controller rules, so a controller reaches it by default")
	}
	if !req.Closed {
		t.Fatalf("a controller may reach the owner's signing route at level %q — "+
			"no authentication level makes this safe", req.Level)
	}
	if strings.TrimSpace(req.Why) == "" {
		t.Fatal("a refusal with no reason leaves somebody unable to act on it")
	}
}
