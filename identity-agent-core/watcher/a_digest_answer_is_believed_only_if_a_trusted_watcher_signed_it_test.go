package watcher

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/store"
)

type testWatcherKey struct {
	seed []byte
	aid  string
}

func newTestWatcherKey(b byte) testWatcherKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i) + b
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return testWatcherKey{seed: seed, aid: iacrypto.NonTransferableAIDQB64(pub)}
}

func (k testWatcherKey) sign(stmt string) (string, string, error) {
	sig, err := login.SignString(stmt, k.seed)
	return k.aid, sig, err
}

// servedBy runs a watcher's own serving code (GetPublicDigest) behind HTTP, the
// way /public/kel-digest does, optionally altering the answer on the way out.
func servedBy(t *testing.T, signer *testWatcherKey, alter func(*DigestResponse)) (url string, serving *Service) {
	t.Helper()
	serving, _ = migratedWatcher(t)
	// The watchers these tests stand up are public watcher services; without
	// that they answer as for an identity never seen.
	if err := serving.Store.SetConfig(configPublicWatcher, "true"); err != nil {
		t.Fatal(err)
	}
	if signer != nil {
		serving.SignDigest = signer.sign
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq, _ := strconv.Atoi(r.URL.Query().Get("seq"))
		resp, err := serving.GetPublicDigest(r.URL.Query().Get("aid"), seq)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if alter != nil {
			alter(resp)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, serving
}

func clientTrusting(keys ...testWatcherKey) *L2Client {
	c := &L2Client{HTTPClient: http.DefaultClient}
	c.TrustedSigners = func() []string {
		var out []string
		for _, k := range keys {
			out = append(out, k.aid)
		}
		return out
	}
	return c
}

func seen(t *testing.T, ws *Service, aid string, seq int, digest string) {
	t.Helper()
	now := time.Now().UTC()
	if err := ws.Store.RecordFirstSeen(FirstSeenRecord{
		AID: aid, SequenceNum: seq, KelDigest: digest, FirstSeenAt: now, LastConfirmedAt: now,
		SeenCount: 1, SourceType: SourceOOBI,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAnAnswerSignedByATrustedWatcherIsAccepted(t *testing.T) {
	k := newTestWatcherKey(1)
	url, serving := servedBy(t, &k, nil)
	seen(t, serving, "EAlice", 0, "abcd")
	got, _, err := clientTrusting(k).QueryDigest(context.Background(), url, "EAlice", 0)
	if err != nil || got.Digest == nil || *got.Digest != "abcd" {
		t.Fatalf("got %+v, %v", got, err)
	}
	// An identity the watcher has not seen is also a signed answer.
	if got, _, err = clientTrusting(k).QueryDigest(context.Background(), url, "EBob", 0); err != nil || got.Digest != nil {
		t.Fatalf("an unseen identity: %+v, %v", got, err)
	}
}

func TestAnAnswerNoTrustedWatcherSignedIsUnavailable(t *testing.T) {
	trusted, other := newTestWatcherKey(1), newTestWatcherKey(9)
	cases := map[string]struct {
		signer *testWatcherKey
		alter  func(*DigestResponse)
		client *L2Client
	}{
		"unsigned":              {nil, nil, clientTrusting(trusted)},
		"a watcher not trusted": {&other, nil, clientTrusting(trusted)},
		"nobody trusted":        {&trusted, nil, &L2Client{HTTPClient: http.DefaultClient}},
		"a changed digest": {&trusted, func(r *DigestResponse) {
			d := "ffff"
			r.Digest = &d
		}, clientTrusting(trusted)},
		"a changed time": {&trusted, func(r *DigestResponse) {
			d := "2020-01-01T00:00:00Z"
			r.FirstSeenAt = &d
		}, clientTrusting(trusted)},
		"another identity's answer": {&trusted, func(r *DigestResponse) { r.AID = "EMallory" }, clientTrusting(trusted)},
		"another position's answer": {&trusted, func(r *DigestResponse) { r.SequenceNumber = 7 }, clientTrusting(trusted)},
		"a signature of nothing":    {&trusted, func(r *DigestResponse) { r.Signature = "0B" + strings.Repeat("A", 86) }, clientTrusting(trusted)},
		"a signer that is no key":   {&trusted, func(r *DigestResponse) { r.SignedBy = "EAlice" }, clientTrusting(trusted)},
	}
	for name, c := range cases {
		url, serving := servedBy(t, c.signer, c.alter)
		seen(t, serving, "EAlice", 0, "abcd")
		got, _, err := c.client.QueryDigest(context.Background(), url, "EAlice", 0)
		if err == nil || got != nil {
			t.Errorf("%s: accepted %+v", name, got)
		}
	}
}

// The attack the signature closes: whoever answers on the address can make an
// honest identity look duplicitous on first contact. Control first, so the
// refusal below is known to come from the signature and nothing else.
func TestASpoofedAnswerCannotBlockAnIdentity(t *testing.T) {
	trusted, attacker := newTestWatcherKey(1), newTestWatcherKey(9)
	honest, rival := twoHistories(t)
	run := func(signer *testWatcherKey) *VerifyKelResult {
		// The serving watcher itself holds the rival history, so what a trusted
		// signer signs is the conflicting answer.
		url := aWatcherHolding(t, signer, rival).URL
		ws, _ := migratedWatcher(t)
		ws.L2 = clientTrusting(trusted)
		if err := setStanding(ws, url); err != nil {
			t.Fatal(err)
		}
		res, err := ws.VerifyKel(context.Background(), presenting(t, honest, SourceOOBI))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := run(&trusted); !res.Blocked {
		t.Fatal("control: a trusted watcher's proven conflicting history should block on first contact")
	}
	for name, signer := range map[string]*testWatcherKey{"unsigned": nil, "attacker": &attacker} {
		if res := run(signer); res.Blocked || !res.OK {
			t.Errorf("%s: an unproven watcher pushed the identity to %q (%s)", name, res.OverallOutcome, res.Reason)
		}
	}
}

// What the client checks is what witnessproto defines, so a second
// implementation of the serving side can be tested against the same text.
func TestTheServingSideSignsTheSharedStatement(t *testing.T) {
	k := newTestWatcherKey(1)
	_, serving := servedBy(t, &k, nil)
	seen(t, serving, "EAlice", 0, "abcd")
	r, _ := serving.GetPublicDigest("EAlice", 0)
	stmt, _ := witnessproto.DigestStatement(r.AID, r.SequenceNumber, r.Digest, r.FirstSeenAt, r.ObservedSince)
	if r.SignedBy != k.aid {
		t.Fatalf("signed_by %q", r.SignedBy)
	}
	_, want, _ := k.sign(stmt)
	if r.Signature != want {
		t.Fatal("the signature is not over the shared statement")
	}
}

// The seeded address, and only that, is corrected on an agent that ran
// migration 12.
func TestTheSeededDeadWatcherAddressIsCorrectedAndAChosenOneIsNot(t *testing.T) {
	for _, tc := range []struct {
		name, stored, want string
	}{
		{"the seeded dead default", "https://watcher.grapeid.org/public/kel-digest", DefaultL2DigestURL},
		{"its trailing-slash spelling", "https://watcher.grapeid.org/public/kel-digest/", DefaultL2DigestURL},
		{"an address the owner chose", "https://my-watcher.example/public/kel-digest", "https://my-watcher.example/public/kel-digest"},
	} {
		ws, db := migratedWatcher(t)
		if _, err := db.Exec(`DELETE FROM watcher_config WHERE key='default_l2_url'`); err != nil {
			t.Fatal(err)
		}
		// An agent as migration 12 left it, before migration 53.
		if _, err := db.Exec(`INSERT INTO watcher_config (key, value) VALUES ('default_l2_url', ?)`, tc.stored); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DELETE FROM identity_schema_migrations WHERE version >= 53`); err != nil {
			t.Fatal(err)
		}
		if err := store.ApplyIdentityMigrations(db); err != nil {
			t.Fatal(err)
		}
		if got := ws.DefaultL2URL(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAFreshAgentReachesTheShippedWatcherAddress(t *testing.T) {
	ws, db := migratedWatcher(t)
	if _, err := db.Exec(`DELETE FROM watcher_config WHERE key='default_l2_url'`); err != nil {
		t.Fatal(err)
	}
	if got := ws.DefaultL2URL(); got != DefaultL2DigestURL || !strings.Contains(got, "watcher1.") {
		t.Fatalf("%q", got)
	}
}

// The binding of an answer to the question asked is a check of its own: the
// signature is genuine here, so only the identifier and sequence comparison
// stands between a replayed answer and a block. Each case is a genuinely
// signed answer from a trusted watcher, for something other than what was asked.
func TestAGenuineAnswerForAnotherQuestionIsNotAnAnswerToThisOne(t *testing.T) {
	trusted := newTestWatcherKey(1)
	aid := "EHonest000000000000000000000000000000000000"
	other := "EOther0000000000000000000000000000000000000"
	// asked is what the client asks (aid at seq 2); the watcher answers with
	// the signed answer for (answerAID, answerSeq), where it holds a digest that
	// conflicts with the identity's own key log.
	cases := []struct {
		name      string
		answerAID string
		answerSeq int
	}{
		{"the same sequence of another identity", other, 2},
		{"another sequence of the same identity", aid, 1},
	}
	for _, tc := range cases {
		serving, _ := migratedWatcher(t)
		serving.SignDigest = trusted.sign
		if err := serving.Store.SetConfig(configPublicWatcher, "true"); err != nil {
			t.Fatal(err)
		}
		seen(t, serving, tc.answerAID, tc.answerSeq, "ffff")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp, err := serving.GetPublicDigest(tc.answerAID, tc.answerSeq) // whatever was asked
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		// The answer is genuine: asked for what it is about, it is believed.
		if got, _, err := clientTrusting(trusted).QueryDigest(context.Background(), srv.URL, tc.answerAID, tc.answerSeq); err != nil || got.Digest == nil {
			t.Fatalf("%s: control: %+v, %v", tc.name, got, err)
		}
		// Asked about another question, it is refused, not read as an answer.
		if got, _, err := clientTrusting(trusted).QueryDigest(context.Background(), srv.URL, aid, 2); err == nil || got != nil {
			t.Errorf("%s: a replayed answer was accepted: %+v", tc.name, got)
		}
		// And it cannot make the identity look duplicitous.
		ws, _ := migratedWatcher(t)
		ws.L2 = clientTrusting(trusted)
		if err := setStanding(ws, srv.URL); err != nil {
			t.Fatal(err)
		}
		res, err := ws.VerifyKel(context.Background(), VerifyKelInput{AID: aid, KEL: keyLog(aid, 3), SourceType: SourceOOBI})
		if err != nil {
			t.Fatal(err)
		}
		if res.Blocked || !res.OK {
			t.Errorf("%s: a replayed answer pushed the identity to %q (%s)", tc.name, res.OverallOutcome, res.Reason)
		}
	}
}

func TestTheTrustedWatchersAreTheShippedOnesPlusWhatTheOwnerAdded(t *testing.T) {
	a, b, shipped := newTestWatcherKey(1), newTestWatcherKey(2), newTestWatcherKey(3)
	old := DefaultL2SignerAIDs
	t.Cleanup(func() { DefaultL2SignerAIDs = old })

	ws, _ := migratedWatcher(t)
	if len(old) == 0 {
		if got := ws.TrustedL2Signers(); len(got) != 0 {
			t.Fatalf("nothing shipped and nothing added, yet %v is trusted", got)
		}
	}
	DefaultL2SignerAIDs = []string{shipped.aid}
	if got := ws.TrustedL2Signers(); len(got) != 1 || got[0] != shipped.aid {
		t.Fatalf("shipped only: %v", got)
	}
	list, _ := json.Marshal([]string{a.aid, b.aid})
	if err := ws.Store.SetConfig("l2_signer_aids", string(list)); err != nil {
		t.Fatal(err)
	}
	got := ws.TrustedL2Signers()
	if len(got) != 3 || got[0] != shipped.aid || got[1] != a.aid || got[2] != b.aid {
		t.Fatalf("shipped plus added: %v", got)
	}
	// A stored row never replaces the shipped list, and rubbish is ignored.
	if err := ws.Store.SetConfig("l2_signer_aids", "not json"); err != nil {
		t.Fatal(err)
	}
	if got := ws.TrustedL2Signers(); len(got) != 1 || got[0] != shipped.aid {
		t.Fatalf("a malformed row: %v", got)
	}

	// The client the service builds reads that same list: an owner-added
	// watcher's answer is believed, one nobody listed is not.
	if err := ws.Store.SetConfig("l2_signer_aids", string(list)); err != nil {
		t.Fatal(err)
	}
	ws.L2.HTTPClient = http.DefaultClient // the test server is on loopback
	url, serving := servedBy(t, &a, nil)
	seen(t, serving, "EAlice", 0, "abcd")
	if got, _, err := ws.L2.QueryDigest(context.Background(), url, "EAlice", 0); err != nil || got.Digest == nil {
		t.Fatalf("an owner-added watcher: %+v, %v", got, err)
	}
	if err := ws.Store.SetConfig("l2_signer_aids", "[]"); err != nil {
		t.Fatal(err)
	}
	if got, _, err := ws.L2.QueryDigest(context.Background(), url, "EAlice", 0); err == nil {
		t.Fatalf("a watcher nobody listed was believed: %+v", got)
	}
}

// The shared vectors carry a key and signature, so a second implementation can
// check its signing; this implementation's verifier must accept every one.
func TestTheSharedVectorSignaturesVerifyThroughTheClientsOwnCheck(t *testing.T) {
	raw, err := os.ReadFile("../witnessproto/kel-digest-statement-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name      string  `json:"name"`
		AID       string  `json:"aid"`
		Seq       int     `json:"seq"`
		Digest    *string `json:"digest"`
		FirstSeen *string `json:"first_seen_at"`
		Observed  *string `json:"observed_since"`
		SignedBy  string  `json:"signed_by"`
		Signature string  `json:"signature"`
	}
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 2 {
		t.Fatal("the vectors have lost cases")
	}
	for _, v := range vs {
		c := &L2Client{TrustedSigners: func() []string { return []string{v.SignedBy} }}
		r := &DigestResponse{AID: v.AID, SequenceNumber: v.Seq, Digest: v.Digest, FirstSeenAt: v.FirstSeen, ObservedSince: v.Observed, SignedBy: v.SignedBy, Signature: v.Signature}
		if err := c.verifyAnswer(r, v.AID, v.Seq); err != nil {
			t.Errorf("%s: %v", v.Name, err)
		}
		d := "ffff"
		r.Digest = &d
		if err := c.verifyAnswer(r, v.AID, v.Seq); err == nil {
			t.Errorf("%s: a changed digest still verified", v.Name)
		}
	}
}
