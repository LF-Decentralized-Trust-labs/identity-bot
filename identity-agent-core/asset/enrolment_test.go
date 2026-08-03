package asset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"identity-agent-core/drivers"
)

// A stand-in KERI engine that records what it was asked to delegate over.
//
// The single most important property of this flow is that the identity is
// minted over the key the MACHINE generated, and not one derived from the
// owner's seed. That is invisible in the response and only observable in the
// request, so the fake captures it.
type fakeKeri struct {
	server       *httptest.Server
	gotPublicKey string
	gotNextKey   string
	gotDelegator string
	gotName      string
	// Atomic because the race test drives this concurrently on purpose; a
	// plain int here would report a data race in the fake and mask the thing
	// under test.
	anchorsIssued atomic.Int64
}

func newFakeKeri(t *testing.T) *fakeKeri {
	t.Helper()
	f := &fakeKeri{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PublicKey     string `json:"public_key"`
			NextPublicKey string `json:"next_public_key"`
			Name          string `json:"name"`
			DelegatorName string `json:"delegator_name"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.gotPublicKey = body.PublicKey
		f.gotNextKey = body.NextPublicKey
		f.gotName = body.Name
		f.gotDelegator = body.DelegatorName

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"aid":           "EDELEGATED-AID",
			"delegator_aid": body.DelegatorName,
			"said":          "ESAID",
			"dip_event":     map[string]interface{}{"t": "dip"},
			"delegator_ixn": map[string]interface{}{"t": "ixn"},
		})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func newEnrolHandler(t *testing.T, keri *fakeKeri) *Handler {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	driver := drivers.NewKeriDriver()
	driver.BaseURL = keri.server.URL

	return &Handler{
		Store:      store,
		KeriDriver: driver,
		RootAID:    func() string { return "EORG-ROOT" },
		PersistDelegationAnchor: func(rootAID string, ixn map[string]interface{}) error {
			keri.anchorsIssued.Add(1)
			return nil
		},
	}
}

func issueToken(t *testing.T, h *Handler, name, kind, origin string) Enrolment {
	t.Helper()
	e, err := h.Store.CreateEnrolment(Enrolment{
		DisplayName: name, AssetType: kind, Origin: origin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// testMachine is a machine that holds its own key, which is the whole premise
// of this flow: the private half is generated where the machine is and never
// reaches the agent. Placeholder key strings cannot express that, because a
// machine that cannot sign cannot prove it holds anything.
type testMachine struct {
	pub  string
	next string
	priv ed25519.PrivateKey
}

func newTestMachine(t *testing.T) *testMachine {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a machine key: %v", err)
	}
	nextPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating the next key: %v", err)
	}
	return &testMachine{
		pub:  base64.RawURLEncoding.EncodeToString(pub),
		next: base64.RawURLEncoding.EncodeToString(nextPub),
		priv: priv,
	}
}

// sign produces the proof of possession for a token, exactly as a real machine
// would. It goes through the exported payload builder rather than spelling the
// canonical string a second time — two independent spellings would drift, and
// would present as an unexplainable signature mismatch.
func (m *testMachine) sign(token string) string {
	return base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(m.priv, []byte(EnrolProofPayload(token, m.pub, m.next))))
}

func enrol(t *testing.T, h *Handler, token string, m *testMachine) *httptest.ResponseRecorder {
	t.Helper()
	return enrolRaw(t, h, map[string]string{
		"token": token, "public_key": m.pub, "next_public_key": m.next,
		"signature": m.sign(token),
	})
}

func enrolRaw(t *testing.T, h *Handler, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(fields)
	r := httptest.NewRequest(http.MethodPost, "/api/enrol", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleEnrol(w, r)
	return w
}

// The property that makes this different from every other asset: the identity
// is delegated over the key the machine generated. Deriving one from the
// owner's seed would put a copy of the machine's private key on the owner's
// device, and a key that exists in two places proves less than one that does
// not.
func TestTheIdentityIsMintedOverTheMachinesOwnKey(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	token := issueToken(t, h, "a device this agent owns", "host", "https://device.example")

	m := newTestMachine(t)
	w := enrol(t, h, token.Token, m)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrolment failed: %d %s", w.Code, w.Body.String())
	}

	if keri.gotPublicKey != m.pub || keri.gotNextKey != m.next {
		t.Errorf("the delegation was issued over %q/%q, not the machine's key",
			keri.gotPublicKey, keri.gotNextKey)
	}
	if keri.gotDelegator != "EORG-ROOT" {
		t.Errorf("delegated from %q rather than the owner's root", keri.gotDelegator)
	}
}

func TestTheEnrolledAssetIsDelegatedAndRecorded(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	token := issueToken(t, h, "a device this agent owns", "host", "https://device.example")

	m := newTestMachine(t)
	w := enrol(t, h, token.Token, m)
	var out struct {
		Asset Asset `json:"asset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}

	if out.Asset.DelegationModel != "delegated" {
		t.Errorf("model is %q — a machine's authority must end with its owner", out.Asset.DelegationModel)
	}
	if out.Asset.DelegatorAID != "EORG-ROOT" {
		t.Errorf("delegator is %q", out.Asset.DelegatorAID)
	}
	if out.Asset.PairwiseAID != "EDELEGATED-AID" {
		t.Errorf("aid is %q", out.Asset.PairwiseAID)
	}
	// The field records where a key sits in the owner's derivation tree. This
	// key is not in it at all, so a number here would be a lie.
	if out.Asset.SigningIndex != 0 {
		t.Errorf("a signing index was recorded (%d) for a key the owner never derived", out.Asset.SigningIndex)
	}
	if _, found := h.Store.GetAsset(out.Asset.ID); !found {
		t.Error("the asset was returned but not stored")
	}
}

// The delegation is only real once the owner's own KEL records it. Without the
// anchor there is an asset claiming an identity nobody can verify.
func TestAnUnanchorableDelegationIsNotIssued(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	h.PersistDelegationAnchor = func(string, map[string]interface{}) error {
		return errAnchorFailed
	}
	token := issueToken(t, h, "a device this agent owns", "host", "")

	m := newTestMachine(t)
	w := enrol(t, h, token.Token, m)
	if w.Code == http.StatusCreated {
		t.Fatal("an asset was created whose delegation was never anchored")
	}
	if len(h.Store.ListAssets()) != 0 {
		t.Error("an unverifiable asset was stored anyway")
	}
}

// Without a token, anything that could reach the port could enrol itself as the
// owner's machine and start speaking with the owner's delegated authority.
func TestEnrollingWithoutAValidTokenIsRefused(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)

	if w := enrol(t, h, "", newTestMachine(t)); w.Code != http.StatusBadRequest {
		t.Errorf("no token: %d", w.Code)
	}
	if w := enrol(t, h, "not-a-real-token", newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("invented token: %d", w.Code)
	}
	if len(h.Store.ListAssets()) != 0 {
		t.Error("something enrolled without a token")
	}
}

// There is exactly one machine a token was issued for. A second use is either a
// mistake or somebody else, and neither should succeed.
func TestATokenWorksOnce(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	token := issueToken(t, h, "a device this agent owns", "host", "")

	if w := enrol(t, h, token.Token, newTestMachine(t)); w.Code != http.StatusCreated {
		t.Fatalf("first use failed: %d %s", w.Code, w.Body.String())
	}
	w := enrol(t, h, token.Token, newTestMachine(t))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a token was used twice: %d", w.Code)
	}
	if n := len(h.Store.ListAssets()); n != 1 {
		t.Errorf("%d assets exist after one token", n)
	}
}

// A token that never expires is a permanent way to become the owner's machine,
// sitting in whatever scrollback it was pasted into.
func TestAnExpiredTokenIsRefused(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)

	e, err := h.Store.CreateEnrolment(Enrolment{
		DisplayName: "late", AssetType: "host",
		ExpiresAt: time.Now().UTC().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := enrol(t, h, e.Token, newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("an expired token was accepted: %d", w.Code)
	}
}

func TestARevokedTokenIsRefused(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	token := issueToken(t, h, "a device this agent owns", "host", "")

	if err := h.Store.RevokeEnrolment(token.Token); err != nil {
		t.Fatal(err)
	}
	if w := enrol(t, h, token.Token, newTestMachine(t)); w.Code != http.StatusForbidden {
		t.Errorf("a revoked token was accepted: %d", w.Code)
	}
}

// A token is issued for a named thing at a known address. If the machine could
// supply either, an operator's record of what they authorised would be whatever
// the machine decided to call itself.
func TestAMachineCannotNameItselfOrClaimAnAddress(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)
	token := issueToken(t, h, "a device this agent owns", "host", "https://device.example")

	m := newTestMachine(t)
	w := enrolRaw(t, h, map[string]string{
		"token": token.Token, "public_key": m.pub, "next_public_key": m.next,
		"signature": m.sign(token.Token),
		// All three supplied by the machine, and all three must be ignored.
		"display_name": "something else", "origin": "https://elsewhere.example",
		"asset_type": "domain",
	})

	var out struct {
		Asset Asset `json:"asset"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)

	if out.Asset.DisplayName != "a device this agent owns" {
		t.Errorf("the machine renamed itself to %q", out.Asset.DisplayName)
	}
	if out.Asset.Origin != "https://device.example" {
		t.Errorf("the machine claimed the address %q", out.Asset.Origin)
	}
	if out.Asset.AssetType != "host" {
		t.Errorf("the machine changed its own type to %q", out.Asset.AssetType)
	}
}

// An enrolment token has to say what it is for, or an operator reviewing the
// list cannot tell what they authorised.
func TestATokenMustSayWhatItIsFor(t *testing.T) {
	keri := newFakeKeri(t)
	h := newEnrolHandler(t, keri)

	if _, err := h.Store.CreateEnrolment(Enrolment{AssetType: "host"}); err == nil {
		t.Error("a nameless token was issued")
	}
	if _, err := h.Store.CreateEnrolment(Enrolment{DisplayName: "thing"}); err == nil {
		t.Error("a token with no asset type was issued")
	}
}

var errAnchorFailed = &anchorError{}

type anchorError struct{}

func (*anchorError) Error() string { return "the anchor could not be written" }
