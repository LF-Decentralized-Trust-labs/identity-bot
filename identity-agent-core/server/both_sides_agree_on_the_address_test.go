package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/endpoint"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
	"identity-agent-core/watcher"
)

// The asking side signs for the address it dials, the contact's OOBI base. The
// answering side checks the address its own endpoint service reports. Nothing
// but a test over both ends shows those are the same string. This runs the real
// asker (VerifyKel, down to its cross-check of the contact) against the real
// router of the answering agent.
//
// Failed before: a request was checked against the caller-supplied Host, so a
// mismatch between the two sides' idea of the address was invisible, and the
// two-agent test signed by hand.
func TestAskerAndAnswererAgreeOnTheAddressEndToEnd(t *testing.T) {
	// The answering agent, Bob, through its full router. EBob is the identity it
	// serves, and Alice met EBob's log at Bob's address: the ordinary setup, with
	// no introduction in the other direction.
	bob := watcherAgent(t, "EOther", 0, "Eother")
	if err := bob.WatcherService.Store.SetConfig("default_l2_url", "http://127.0.0.1:1/public/kel-digest"); err != nil {
		t.Fatal(err)
	}
	bob.registerPairwiseKEL("EBob", ebobLog)
	bob.EndpointService = endpoint.New(nil, 0)
	srv := httptest.NewServer(bob.buildRouter())
	defer srv.Close()
	bob.EndpointService.SetOverrideURL(srv.URL)

	aliceSeed := make([]byte, 32)
	for i := range aliceSeed {
		aliceSeed[i] = byte(i) + 5
	}
	if err := bob.DataStore.SaveContact(store.ContactRecord{
		AID: "EAliceToBob", Status: "accepted", OobiURL: "http://test/public/oobi/EAliceToBob",
		PublicKey: iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(aliceSeed).Public().(ed25519.PublicKey)),
	}); err != nil {
		t.Fatal(err)
	}
	bob.WatcherService.VerifyRequester = bob.verifyContactRequest

	// A hosted watcher that holds another digest for EBob, and is trusted.
	hostedKeySeed := make([]byte, 32)
	for i := range hostedKeySeed {
		hostedKeySeed[i] = byte(i) + 77
	}
	hostedAID := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(hostedKeySeed).Public().(ed25519.PublicKey))
	hosted := watcherAgent(t, "EOther", 0, "Eother").WatcherService
	hosted.SignDigest = func(st string) (string, string, error) {
		sig, err := login.SignString(st, hostedKeySeed)
		return hostedAID, sig, err
	}
	if err := hosted.Store.SetConfig("public_watcher_service", "true"); err != nil {
		t.Fatal(err)
	}
	hostedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq, _ := strconv.Atoi(r.URL.Query().Get("seq"))
		resp, err := hosted.GetPublicDigest(r.URL.Query().Get("aid"), seq)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer hostedSrv.Close()

	// Alice: has met EBob before, at Bob's address, and asks Bob.
	ds, err := store.NewSQLiteStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ds.Close() })
	alice := watcher.NewService(watcher.NewSQLiteStore(ds.DB()))
	alice.L2 = &watcher.L2Client{HTTPClient: http.DefaultClient, TrustedSigners: func() []string { return []string{hostedAID} }}
	if err := alice.Store.SetConfig("default_l2_url", hostedSrv.URL); err != nil {
		t.Fatal(err)
	}
	alice.L3.AllowLocal = func(string) bool { return true }
	alice.SignRequest = func(_, st string) (string, string, error) {
		sig, err := login.SignString(st, aliceSeed)
		return "EAliceToBob", sig, err
	}
	// The contact's address is its OOBI base, as peerWatchers derives it.
	bobBase := peerBaseURL(srv.URL + "/public/oobi/EBobContact")
	if err := alice.SetPeerWatchEnabled(true); err != nil {
		t.Fatal(err)
	}
	alice.PeerWatchers = func() []watcher.PeerWatcher { return []watcher.PeerWatcher{{AID: "EBobContact", URL: bobBase}} }

	kel := ebobLog
	in := watcher.VerifyKelInput{AID: "EBob", KEL: kel, SourceType: watcher.SourceOOBI, SourceURL: bobBase + "/public/oobi/EBob"}
	ctx := context.Background()
	if res, err := alice.VerifyKel(ctx, in); err != nil || !res.OK {
		t.Fatalf("first contact: %+v %v", res, err)
	}
	// Only now does the hosted watcher hold something else for EBob.
	if err := hosted.RecordFirstSeen("EBob", 0, "Edifferent", watcher.SourceOOBI, "http://hosted/oobi"); err != nil {
		t.Fatal(err)
	}
	// A contact's answer is context: the escalation stands either way, and the
	// answer is recorded. Where Bob believes he is reached is not where Alice
	// signed for, so he says no match.
	var lastL3 string
	alice.OnEvent = func(typ string, p map[string]interface{}) {
		if typ != "kel_verification" {
			return
		}
		lastL3 = ""
		srcs, _ := p["sources"].([]watcher.SourceOutcome)
		for _, o := range srcs {
			if o.Type == "L3" {
				lastL3 = o.Outcome
			}
		}
	}
	l3 := func(*watcher.VerifyKelResult) string { return lastL3 }
	bob.EndpointService.SetOverrideURL("https://not-where-alice-dialled.example")
	res, err := alice.VerifyKel(ctx, in)
	if err != nil || res.OverallOutcome != "escalated" || l3(res) != "no_match" {
		t.Fatalf("with the sides disagreeing on the address: %+v %v", res, err)
	}
	// Agreeing, Bob answers match, which is recorded and does not quiet the escalation.
	bob.EndpointService.SetOverrideURL(srv.URL)
	res, err = alice.VerifyKel(ctx, in)
	if err != nil || !res.OK || res.OverallOutcome != "escalated" || l3(res) != "match" {
		t.Fatalf("the contact's match at the address she dialled: %+v %v", res, err)
	}
}

// ebobLog is the log of EBob that the agents here serve, and ebobDigest its digest at 0.
var ebobLog = []map[string]interface{}{{"v": "KERI10JSON000256_", "t": "icp", "i": "EBob", "s": "0"}}

var ebobDigest = func() string {
	d, err := witnessproto.KelDigestAtSeq(ebobLog, 0)
	if err != nil {
		panic(err)
	}
	return d
}()

// contactAndAgent is a watcher agent holding EBob's log, reached at address, with
// EContact as a contact in the given status whose requests are signed by seed.
func contactAndAgent(t *testing.T, status string, seed []byte) *CoreServer {
	t.Helper()
	s := watcherAgent(t, "EBob", 0, "Ebob")
	s.registerPairwiseKEL("EBob", ebobLog)
	if err := s.DataStore.SaveContact(store.ContactRecord{
		AID: "EContact", Status: status, OobiURL: "http://test/public/oobi/EContact",
		PublicKey: iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)),
	}); err != nil {
		t.Fatal(err)
	}
	s.WatcherService.VerifyRequester = s.verifyContactRequest
	return s
}

func signedBody(t *testing.T, seed []byte, to string, at int64) string {
	t.Helper()
	sig, err := login.SignString(watcher.KelCheckRequestStatement("EBob", 0, ebobDigest, to, at), seed)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(watcher.KelCheckRequest{AID: "EBob", Seq: 0, Digest: ebobDigest, Requester: "EContact", At: at, Signature: sig})
	return string(b)
}

// Failed before: the address a request had to name was taken from the request's
// own Host and forwarding headers when the agent had no address of its own, so
// the caller chose it.
func TestTheAddressARequestMustNameIsNeverTakenFromTheRequest(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 9
	s := contactAndAgent(t, "accepted", seed)
	router := s.buildRouter()
	post := func(body string) string {
		req := remote("POST", "/public/kel-check", body)
		req.Header.Set("X-Forwarded-Host", "chosen-by-caller.example")
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	at := time.Now().Unix()
	// Signed for the host the caller named: not answered, with no address of our own.
	if got := post(signedBody(t, seed, "https://chosen-by-caller.example", at)); !strings.Contains(got, `"match":false`) {
		t.Fatalf("a request signed for the address the caller chose was answered: %s", got)
	}
	if got := post(signedBody(t, seed, "http://example.com", at+1)); !strings.Contains(got, `"match":false`) {
		t.Fatalf("a request signed for the Host header was answered: %s", got)
	}
	// With an address of our own, the same request naming it is answered.
	s.EndpointService = endpoint.New(nil, 0)
	s.EndpointService.SetOverrideURL("https://us.example")
	if got := post(signedBody(t, seed, "https://us.example", at+2)); !strings.Contains(got, `"match":true`) {
		t.Fatalf("a request for our own address was not answered: %s", got)
	}
	if got := post(signedBody(t, seed, "https://chosen-by-caller.example", at+3)); !strings.Contains(got, `"match":false`) {
		t.Fatalf("the caller's chosen address was accepted beside our own: %s", got)
	}
}

// Failed before: a contact that was pending or declined, with a key on file, was
// answered as an accepted one.
func TestOnlyAnAcceptedContactIsAnswered(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 11
	for status, want := range map[string]bool{"accepted": true, "pending": false, "declined": false, "": false} {
		s := contactAndAgent(t, status, seed)
		stmt := "anything"
		sig, _ := login.SignString(stmt, seed)
		if got := s.verifyContactRequest("EContact", stmt, sig); got != want {
			t.Errorf("status %q: verified = %v, want %v", status, got, want)
		}
		if got := s.contactAddress("EContact") != ""; got != want {
			t.Errorf("status %q: has an address = %v, want %v", status, got, want)
		}
	}
	s := contactAndAgent(t, "accepted", seed)
	sig, _ := login.SignString("anything", seed)
	if s.verifyContactRequest("ENobody", "anything", sig) {
		t.Error("a requester who is not a contact was verified")
	}
	if s.verifyContactRequest("EContact", "something else", sig) {
		t.Error("a signature over other text was verified")
	}
}

// Failed before: every request, from anybody, ran the contact scan and the
// signature check before any limit applied, so a caller could make this agent do
// that work as often as it liked.
func TestACallerIsLimitedBeforeAnySignatureIsChecked(t *testing.T) {
	s := watcherAgent(t, "EBob", 0, "Ebob")
	checked := 0
	s.WatcherService.VerifyRequester = func(string, string, string) bool { checked++; return false }
	s.EndpointService = endpoint.New(nil, 0)
	s.EndpointService.SetOverrideURL("https://us.example")
	router := s.buildRouter()
	body := fmt.Sprintf(`{"aid":"EBob","seq":0,"digest":"Ebob","requester":"EWho","at":%d,"signature":"x"}`, time.Now().Unix())
	for i := 0; i < 200; i++ {
		req := remote("POST", "/public/kel-check", body)
		req.RemoteAddr = "203.0.113.9:1"
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	if checked == 0 || checked > 60 {
		t.Fatalf("200 requests from one caller had %d signatures checked, expected 1 to 60", checked)
	}
}

// Failed before: a contact was answered about an identity only if we had first
// met its log at the contact's address, which the normal case never is. Now
// only an identity whose log we serve, whatever else the watcher holds.
func TestAContactAskingAboutAnIdentityWeDoNotServeGetsNoMatch(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 13
	s := contactAndAgent(t, "accepted", seed)
	s.EndpointService = endpoint.New(nil, 0)
	s.EndpointService.SetOverrideURL("https://us.example")
	if err := s.WatcherService.RecordFirstSeen("EUnserved", 0, ebobDigest, watcher.SourceOOBI, "http://test/public/oobi/EUnserved"); err != nil {
		t.Fatal(err)
	}
	router := s.buildRouter()
	ask := func(aid string, at int64) string {
		sig, _ := login.SignString(watcher.KelCheckRequestStatement(aid, 0, ebobDigest, "https://us.example", at), seed)
		b, _ := json.Marshal(watcher.KelCheckRequest{AID: aid, Seq: 0, Digest: ebobDigest, Requester: "EContact", At: at, Signature: sig})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, remote("POST", "/public/kel-check", string(b)))
		return rec.Body.String()
	}
	at := time.Now().Unix()
	if got := ask("EBob", at); !strings.Contains(got, `"match":true`) {
		t.Fatalf("an identity we serve was not answered: %s", got)
	}
	if got := ask("EUnserved", at+1); !strings.Contains(got, `"match":false`) {
		t.Fatalf("an identity we hold but do not serve was answered: %s", got)
	}
}

// Failed before: the stand-in key was decoded nowhere, so a contact's request
// took one more decode than a stranger's. It is kept in the form a contact's
// key is, and a signature by it must verify, so removing it is caught.
func TestAStrangerIsCheckedAgainstAStandInKeyDecodedLikeAContactsKey(t *testing.T) {
	key, err := login.DecodeVerkey(standInKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("the stand-in key does not decode as a contact's does: %v", err)
	}
	sig, _ := login.SignString("anything", make([]byte, ed25519.SeedSize))
	if ok, err := login.VerifyString("anything", sig, key); err != nil || !ok {
		t.Fatalf("the stand-in key is not one a signature is checked against: %v", err)
	}
	s := contactAndAgent(t, "accepted", make([]byte, 32))
	if s.verifyContactRequest("EStranger", "anything", sig) {
		t.Fatal("a stranger signing with the stand-in's own key was accepted")
	}
}

// Failed before (removing the stand-in survived): a request from somebody who is
// not a contact must decode a key and verify a signature exactly as one from a
// contact does, or the time taken says which identifiers are contacts.
func TestARequestFromAStrangerTakesTheSameStepsAsOneFromAContact(t *testing.T) {
	var decodes, verifies int
	oldD, oldV := decodeVerkey, verifyString
	decodeVerkey = func(k string) ([]byte, error) { decodes++; return oldD(k) }
	verifyString = func(m, sig string, k []byte) (bool, error) { verifies++; return oldV(m, sig, k) }
	t.Cleanup(func() { decodeVerkey, verifyString = oldD, oldV })

	seed := make([]byte, 32)
	seed[0] = 6
	s := contactAndAgent(t, "accepted", seed)
	sig, _ := login.SignString("anything", seed)
	for _, who := range []string{"EContact", "EStranger", ""} {
		decodes, verifies = 0, 0
		_ = s.verifyContactRequest(who, "anything", sig)
		if decodes != 1 || verifies != 1 {
			t.Fatalf("requester %q: %d decodes and %d verifications, want 1 and 1", who, decodes, verifies)
		}
	}
}
