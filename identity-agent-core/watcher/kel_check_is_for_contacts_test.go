package watcher

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/login"
)

// checkedAt is the address a cross-check must be signed for in these tests.
const checkedAt = "https://us.example"

// heldLog is the one log this agent serves, and heldDigest its digest at 1.
var heldLog = []map[string]interface{}{
	{"t": "icp", "i": "EHeld", "s": "0"}, {"t": "rot", "i": "EHeld", "s": "1"},
}

var heldDigest = func() string {
	d, err := witnessproto.KelDigestAtSeq(heldLog, 1)
	if err != nil {
		panic(err)
	}
	return d
}()

func servesHeld(aid string) ([]map[string]interface{}, bool) {
	return heldLog, aid == "EHeld"
}

var contactSeed = func() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i) + 40
	}
	return seed
}()

// checkingService is a watcher with one accepted contact, EContact, whose
// signatures it verifies, and a clock fixed at the returned time.
func checkingService(t *testing.T) (*Service, time.Time) {
	t.Helper()
	s := storedService(t)
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	key := ed25519.NewKeyFromSeed(contactSeed).Public().(ed25519.PublicKey)
	s.VerifyRequester = func(requester, statement, sig string) bool {
		if requester != "EContact" {
			return false
		}
		ok, err := login.VerifyString(statement, sig, key)
		return err == nil && ok
	}
	return s, now
}

// signedCheck is a request from EContact to checkedAt, signed at the given time.
func signedCheck(aid string, seq int, digest string, at int64) KelCheckRequest {
	return signedCheckTo(aid, seq, digest, at, checkedAt, contactSeed)
}

func signedCheckTo(aid string, seq int, digest string, at int64, to string, seed []byte) KelCheckRequest {
	sig, err := login.SignString(KelCheckRequestStatement(aid, seq, digest, to, at), seed)
	if err != nil {
		panic(err)
	}
	return KelCheckRequest{AID: aid, Seq: seq, Digest: digest, Requester: "EContact", At: at, Signature: sig}
}

func answer(t *testing.T, s *Service, req KelCheckRequest) (string, bool) {
	t.Helper()
	resp, fromContact, err := s.KelCheck(req, checkedAt, servesHeld)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(resp)
	return string(b), fromContact
}

// Failed before: the signature was never read, so anybody holding a log (any
// key log is fetchable) could ask whether this agent had met that identity.
func TestKelCheckAnswersOnlyAContactWhoSigned(t *testing.T) {
	s, now := checkingService(t)
	at := now.Unix()
	other := make([]byte, ed25519.SeedSize)
	unsigned := KelCheckRequest{AID: "EHeld", Seq: 1, Digest: heldDigest}
	noSig := signedCheck("EHeld", 1, heldDigest, at)
	noSig.Signature = ""
	noAt := signedCheck("EHeld", 1, heldDigest, at)
	noAt.At = 0
	noWho := signedCheck("EHeld", 1, heldDigest, at)
	noWho.Requester = ""
	stranger := signedCheck("EHeld", 1, heldDigest, at)
	stranger.Requester = "EStranger"
	changedAsk := signedCheck("EHeld", 1, heldDigest, at)
	changedAsk.Seq = 2

	for name, req := range map[string]KelCheckRequest{
		"unsigned":                    unsigned,
		"no signature":                noSig,
		"no time":                     noAt,
		"no requester":                noWho,
		"not a contact":               stranger,
		"signed by another key":       signedCheckTo("EHeld", 1, heldDigest, at, checkedAt, other),
		"signed for another address":  signedCheckTo("EHeld", 1, heldDigest, at, "https://them.example", contactSeed),
		"changed after it was signed": changedAsk,
	} {
		got, fromContact := answer(t, s, req)
		if got != `{"match":false}` || fromContact {
			t.Errorf("%s: answered %s (from a contact: %v), expected no match from a stranger", name, got, fromContact)
		}
	}

	// The same request, properly signed by the contact, is answered.
	if got, fromContact := answer(t, s, signedCheck("EHeld", 1, heldDigest, at)); got != `{"match":true}` || !fromContact {
		t.Fatalf("a contact's signed request was answered %s (from a contact: %v)", got, fromContact)
	}
}

// Match or no-match only: never the digest, never when it was first seen.
func TestKelCheckAnswersMatchOrNoMatchAndNothingElse(t *testing.T) {
	s, now := checkingService(t)
	at := now.Unix()
	for i, req := range []KelCheckRequest{
		signedCheck("EHeld", 1, "Eguess", at),  // served, wrong digest
		signedCheck("ENever", 1, "Eguess", at), // not served
	} {
		if got, _ := answer(t, s, req); got != `{"match":false}` {
			t.Fatalf("probe %d answered %s, expected only a no-match", i, got)
		}
	}
}

// Failed before: a request was good for ever.
func TestAnOldOrFutureRequestIsNotAnswered(t *testing.T) {
	s, now := checkingService(t)
	for _, c := range []struct {
		offset int64
		want   string
	}{
		{-61, `{"match":false}`}, {61, `{"match":false}`},
		{-60, `{"match":true}`}, {60, `{"match":true}`},
	} {
		got, _ := answer(t, s, signedCheck("EHeld", 1, heldDigest, now.Unix()+c.offset))
		if got != c.want {
			t.Errorf("a request %d s from now was answered %s, want %s", c.offset, got, c.want)
		}
	}
}

// Failed before: a captured request could be sent again as often as wanted.
func TestARequestIsAnsweredOnceInTheWindow(t *testing.T) {
	s, now := checkingService(t)
	req := signedCheck("EHeld", 1, heldDigest, now.Unix())
	if got, _ := answer(t, s, req); got != `{"match":true}` {
		t.Fatalf("first answer %s", got)
	}
	if got, fromContact := answer(t, s, req); got != `{"match":false}` || fromContact {
		t.Fatalf("a replayed request was answered %s (from a contact: %v)", got, fromContact)
	}
	// A different question at the same moment is not a replay.
	if got, _ := answer(t, s, signedCheck("EHeld", 1, heldDigest, now.Unix()+1)); got != `{"match":true}` {
		t.Fatalf("a new request was treated as a replay: %s", got)
	}
}

func TestTheReplayCacheForgetsAndIsBounded(t *testing.T) {
	var c replayCache
	t0 := time.Unix(1_800_000_000, 0)
	if !c.first("a", t0) || c.first("a", t0.Add(time.Second)) {
		t.Fatal("the same key twice inside the window was not refused")
	}
	if !c.first("a", t0.Add(2*kelCheckWindow+time.Second)) {
		t.Fatal("a key was still remembered after the window had passed")
	}
	var full replayCache
	for i := 0; i < maxRemembered; i++ {
		if !full.first(string(rune(i+1)), t0) {
			t.Fatalf("entry %d refused before the cache was full", i)
		}
	}
	if full.first("one more", t0) {
		t.Fatal("the cache grew past its bound")
	}
}

// A watcher with no way to check a requester answers nobody.
func TestKelCheckWithNoWayToCheckARequesterAnswersNoMatch(t *testing.T) {
	s, now := checkingService(t)
	s.VerifyRequester = nil
	if got, _ := answer(t, s, signedCheck("EHeld", 1, heldDigest, now.Unix())); got != `{"match":false}` {
		t.Fatalf("answered %s", got)
	}
}

// Failed before: a contact was answered about any identity this agent had met
// at the contact's own address, so two agents agreed only if each had met the
// identity at the other's address. Now only an identity whose log we serve.
func TestAContactIsAnsweredOnlyAboutAnIdentityWeServe(t *testing.T) {
	s, now := checkingService(t)
	// The store holds a record for an identity we do not serve: not enough.
	if err := s.RecordFirstSeen("EElsewhere", 1, heldDigest, SourceOOBI, "http://contact.example/public/oobi/EElsewhere"); err != nil {
		t.Fatal(err)
	}
	at := now.Unix()
	for i, aid := range []string{"EElsewhere", "ENever"} {
		got, fromContact := answer(t, s, signedCheck(aid, 1, heldDigest, at+int64(i)))
		if got != `{"match":false}` || !fromContact {
			t.Errorf("%s: answered %s (from a contact: %v), expected no match", aid, got, fromContact)
		}
	}
	if got, _ := answer(t, s, signedCheck("EHeld", 1, heldDigest, at+10)); got != `{"match":true}` {
		t.Fatalf("an identity we serve was answered %s", got)
	}
	if resp, _, err := s.KelCheck(signedCheck("EHeld", 1, heldDigest, at+11), checkedAt, nil); err != nil || resp.Match {
		t.Fatalf("with no log served: %+v %v", resp, err)
	}
}
