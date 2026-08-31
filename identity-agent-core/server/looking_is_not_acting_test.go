package server

import "testing"

// Asking who is calling must not use up their request.
//
// Caller resolution can run before the handler on the same request. When it
// spent the signature, the handler's own verification then failed with "this
// signed request has already been used" — so a machine was refused because the
// agent had looked at who it was. Notify, the one route an enrolled machine
// could reach, returned 403 for every well-formed call.
//
// It was invisible to the existing tests because they call the handler
// directly; only a request through the real router meets the resolver first.
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
