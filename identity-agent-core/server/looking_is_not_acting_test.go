package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Asking who is calling must not use up their request.
//
// Caller resolution can run before the handler on the same request —
// authorize() resolves for a scoped route, and three handlers resolve for
// themselves. When resolution spent the signature, the handler's own
// verification then failed with "this signed request has already been used",
// so a machine was refused because the agent had looked at who it was.
//
// WHAT THIS DID NOT BREAK, because the first version of this comment said it
// did. POST /api/notify is a public route, and authorize serves those without
// resolving a caller at all — so notify never met the resolver and was never
// affected. The failure that looked like proof of it was two tests signing
// identical bytes in the same second and spending each other's signature.
//
// What the split does buy is real: before it, every machine-signed request to
// a scoped route wrote to the process-wide replay map from middleware, so
// asking who was calling consumed the one use that request had.
func TestLookingAtAMachineDoesNotUseUpItsRequest(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	key := enrolledMachine(t, s, aid)

	req := signedNotify(t, key, aid, notifyBody(t))
	if cc := s.resolveCaller(req); cc.CallerAID != aid {
		t.Fatalf("the machine was not recognised: %q", cc.CallerAID)
	}
	if _, err := s.verifyAssetSignature(req); err != nil {
		t.Fatalf("the handler could no longer verify its own request: %v", err)
	}
}

// And replay protection is still where it matters: acting twice on one
// signature is refused, even though looking twice is not.
func TestOneSignatureStillBuysOneAction(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	key := enrolledMachine(t, s, aid)

	// A body unique to this test. The signature is deterministic — same key,
	// same path, timestamp to the second — so a shared body would collide with
	// whatever else in this package signed one in the same second, and the
	// first use here would already have been spent by somebody else.
	body := []byte(`{"to_aid":"EPERSON","kind":"maintenance","severity":"warning","title":"one signature, one action"}`)
	req := signedNotify(t, key, aid, body)
	if _, err := s.verifyAssetSignature(req); err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	if _, err := s.verifyAssetSignature(signedNotify(t, key, aid, body)); err == nil {
		t.Fatal("the same signature was accepted twice, so a captured request can be replayed")
	}
}

// The bound holds: a caller naming an enrolled machine and signing garbage
// cannot make this agent buffer whatever it likes before being refused.
//
// The identifier is not a secret — a delegated inception names its delegator in
// an event anybody can read — and the signature is not checked until after the
// body has been read, so the read is what needs the limit rather than the
// signature.
func TestAnUnprovenRequestCannotMakeUsBufferWhateverItSends(t *testing.T) {
	s := notifyTestServer(t)
	const aid = "EMACHINE-ONE"
	enrolledMachine(t, s, aid)

	huge := bytes.NewReader(make([]byte, maxSignedBodyBytes+(8<<20)))
	req := httptest.NewRequest(http.MethodPost, "/api/notify", huge)
	req.RemoteAddr = "203.0.113.9:51000"
	req.Header.Set(headerAssetAID, aid)
	req.Header.Set(headerAssetTimestamp, time.Now().UTC().Format(time.RFC3339))
	req.Header.Set(headerAssetSig, "not-a-signature")

	if _, err := s.identifyAssetFromSignature(req); err == nil {
		t.Fatal("garbage was accepted as a signature")
	}
	if n := huge.Len(); n == 0 {
		t.Fatalf("the whole body was read before the signature was checked; "+
			"%d bytes should have been left unread", huge.Len())
	}
}
