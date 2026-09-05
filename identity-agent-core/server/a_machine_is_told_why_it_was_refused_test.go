package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
)

// A machine learns what happened to its own authorisation, and nobody else does.
//
// Both halves are the test. Saying more to a machine that proved it is that
// machine is the point; saying more to anyone who types an identifier would turn
// the refusal into a way to discover which machines an identity has trusted,
// which is a map of somebody's devices.
//
// The second half is the one that rots quietly: it stays green if the proof is
// removed and everybody is told everything, because the messages are still
// correct sentences. So the unproven case asserts the vague wording explicitly
// rather than merely asserting a 403.

// aMachineNobodyGranted returns an identifier and its seed, with no grant made.
//
// Derived rather than invented, because a machine's identifier IS its key and
// the two halves must agree for a signature to verify against the identifier.
func aMachineNobodyGranted(t *testing.T, salt byte) (string, []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i) ^ salt
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return iacrypto.NonTransferableAIDQB64(pub), seed
}

const theVagueRefusal = "not authorised to act for this identity, or its authorisation has ended"

func theRefusalGivenTo(t *testing.T, s *CoreServer, req *http.Request) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.buildRouter("").ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// A machine whose authorisation was taken away is told so, and told what to do.
func TestAMachineWhoseAuthorisationEndedIsToldWhatHappened(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	// Revoking DELETES the grant — the record was the whole authorisation — so
	// what follows is the agent answering about a machine it no longer has any
	// record of, which is the hard case rather than the easy one.
	if err := s.controllers().Revoke(aid); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	code, body := theRefusalGivenTo(t, s,
		asThatMachine(t, aid, "GET", "/api/identity", "", seed, "", time.Time{}))

	if code != http.StatusForbidden {
		t.Fatalf("a revoked machine must still be refused, got %d", code)
	}
	if strings.Contains(body, theVagueRefusal) {
		t.Errorf("a machine that proved it holds its own key was given the "+
			"undifferentiated refusal, which is what this exists to replace: %s", body)
	}
	if !strings.Contains(body, "Authorise this machine again") {
		t.Errorf("the refusal must say what would fix it, got: %s", body)
	}
}

// Someone who cannot prove they are that machine learns nothing about it.
//
// THE ONE THAT MUST NOT REGRESS. Without it, deleting the proof would leave
// every other assertion here passing.
func TestAnUnprovenCallerLearnsNothingAboutAMachine(t *testing.T) {
	s := newAuthTestServer(t)
	aid, _ := anAuthorisedMachine(t, s, GradeEnrolled)
	if err := s.controllers().Revoke(aid); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	// The real identifier of a real machine, signed with a key that is not its
	// own — exactly what somebody probing for other people's devices can do.
	_, someoneElsesSeed := aMachineNobodyGranted(t, 0x5A)

	code, body := theRefusalGivenTo(t, s,
		asThatMachine(t, aid, "GET", "/api/identity", "", someoneElsesSeed, "", time.Time{}))

	if code != http.StatusForbidden {
		t.Fatalf("an unsigned claim must be refused, got %d", code)
	}
	if !strings.Contains(body, theVagueRefusal) {
		t.Errorf("a caller that did not prove it holds this machine's key must get the "+
			"undifferentiated refusal, not a description of that machine's history: %s", body)
	}
	for _, leak := range []string{"Authorise this machine again", "restored from a backup", "expired"} {
		if strings.Contains(body, leak) {
			t.Errorf("the refusal told an unproven caller %q about a machine it cannot "+
				"prove it is: %s", leak, body)
		}
	}
}

// A machine nobody ever authorised is told that plainly, including the case
// nobody thinks of: the identity came back from a backup, which never carries
// which machines may act.
func TestAMachineNobodyAuthorisedIsToldPlainly(t *testing.T) {
	s := newAuthTestServer(t)
	ownerSeedForTest(t, s)
	aid, seed := aMachineNobodyGranted(t, 0x11)

	code, body := theRefusalGivenTo(t, s,
		asThatMachine(t, aid, "GET", "/api/identity", "", seed, "", time.Time{}))

	if code != http.StatusForbidden {
		t.Fatalf("a machine with no grant must be refused, got %d", code)
	}
	if !strings.Contains(body, "is not authorised by this identity") {
		t.Errorf("expected a plain statement that this machine is not authorised, got: %s", body)
	}
	if !strings.Contains(body, "restored from a backup") {
		t.Errorf("a restore leaves an identity with no controllers, and that is the case "+
			"a person is least likely to guess; the refusal should name it: %s", body)
	}
}

// Nothing here widens what is admitted.
//
// The refusal path gained the ability to verify a signature against an
// identifier rather than against a grant. If that ever became the admitting
// check, any machine could name itself and be let in — so this asserts the
// authorised machine still works and, above it, that the unauthorised one is
// still refused with a 403 rather than served.
func TestTellingAMachineMoreDoesNotAdmitIt(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)

	// Asserted on the refusal itself rather than on the status code. "not 403"
	// is also satisfied by an unrelated fault in whatever handler runs next, so
	// a status check here would keep passing if admission broke in a new way.
	//
	// It cannot assert 200 either: newAuthTestServer builds a CoreServer with no
	// DataStore, so a handler that reads one faults once the machine is let
	// through. That is a limit of the harness rather than of the code, and it is
	// exactly why this asserts what the middleware decided instead of what the
	// handler managed to return.
	_, body := theRefusalGivenTo(t, s,
		asThatMachine(t, aid, "GET", "/api/identity", "", seed, "", time.Time{}))
	if strings.Contains(body, "not_authorized") {
		t.Fatalf("an authorised machine was refused: %s", body)
	}

	// A machine that signs perfectly well for itself and holds no grant is
	// refused, however plainly it is told why.
	stranger, strangerSeed := aMachineNobodyGranted(t, 0x22)
	code, _ := theRefusalGivenTo(t, s,
		asThatMachine(t, stranger, "GET", "/api/identity", "", strangerSeed, "", time.Time{}))
	if code != http.StatusForbidden {
		t.Fatalf("a machine holding no grant must be refused however well it signs, got %d", code)
	}
}

// The body survives a refusal, so whatever runs next sees the request that was
// sent rather than an empty one.
//
// The refusal path now reads the body to check a signature. The admitting path
// already had this bug once and carries a comment about it; reading the body in
// a second place is a second chance to reintroduce it.
func TestARefusalDoesNotEatTheRequestBody(t *testing.T) {
	s := newAuthTestServer(t)
	ownerSeedForTest(t, s)
	aid, seed := aMachineNobodyGranted(t, 0x33)

	const body = `{"this":"must still be readable"}`
	req := asThatMachine(t, aid, "POST", "/api/verify", body, seed, "", time.Time{})

	if _, _, err := s.theControllerBehind(req); err == nil {
		t.Fatal("a machine with no grant must be refused")
	}
	got := make([]byte, len(body))
	n, _ := req.Body.Read(got)
	if string(got[:n]) != body {
		t.Errorf("the body was consumed by the refusal: %q of %d bytes readable", got[:n], len(body))
	}
}

// A machine somebody borrowed is told its time ran out, not that it is unknown.
//
// THE BRANCH NOTHING REACHED. The revoked case above exercises the other one —
// revoking deletes the grant, so it lands on "no record of it at all" — and this
// branch could be replaced with the undifferentiated sentence without a single
// test noticing. The two refusals need different actions from the owner: renew
// an authorisation that lapsed, versus make one that never existed or was taken
// away.
func TestAMachineWhoseBorrowedTimeRanOutIsToldThat(t *testing.T) {
	s := newAuthTestServer(t)
	ownerSeedForTest(t, s)
	aid, seed := aMachineNobodyGranted(t, 0x44)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	// Granted two days ago, expired yesterday. Made in the past rather than
	// waiting for it to lapse, so the test asserts a state rather than a delay.
	if _, err := s.controllers().Grant(ControllerGrant{
		ControllerAID: aid,
		PublicKey:     iacrypto.VerkeyQB64(pub),
		Label: "a machine somebody borrowed",
		// SCOPED, not enrolled. An enrolled grant has its expiry forced to zero --
		// a machine somebody keeps lasts until they say otherwise -- so only a
		// borrowed one can lapse, and writing this with the wrong grade produces a
		// grant that never expires and a test that proves nothing.
		Grade:     GradeScoped,
		ExpiresAt:     time.Now().UTC().Add(-24 * time.Hour),
	}, time.Now().UTC().Add(-48*time.Hour)); err != nil {
		t.Fatalf("granting: %v", err)
	}

	code, body := theRefusalGivenTo(t, s,
		asThatMachine(t, aid, "GET", "/api/identity", "", seed, "", time.Time{}))

	if code != http.StatusForbidden {
		t.Fatalf("an expired machine must be refused, got %d", code)
	}
	if strings.Contains(body, theVagueRefusal) {
		t.Errorf("a machine that proved it holds its own key got the undifferentiated "+
			"refusal: %s", body)
	}
	if !strings.Contains(body, "expired") {
		t.Errorf("an authorisation that lapsed should say so, since renewing it is a "+
			"different action from making a new one: %s", body)
	}
	// It must NOT be told the identity was restored from a backup — that is the
	// other branch's story, and sending an owner to look for a restore that never
	// happened is worse than saying nothing.
	if strings.Contains(body, "restored from a backup") {
		t.Errorf("an expired grant was described as a missing one: %s", body)
	}
}
