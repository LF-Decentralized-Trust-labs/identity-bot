package keriengine

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/drivers"

	keri "github.com/grapeid/keri-go"
)

// servedIdentity stands up an agent publishing its own introduction, the way a
// real one does: event records carrying the canonical bytes and the signature.
func servedIdentity(t *testing.T, claimAID string) (*httptest.Server, string) {
	t.Helper()
	e := New()

	// The signer is kept rather than discarded, because the introduction has to
	// be signed to be worth anything and only whoever holds the key can do it.
	signer, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	nextSigner, err := keri.GenerateSigner(true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	next, err := nextSigner.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	icp, err := e.CreateInceptionNamed(pub, next, "served")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel("served")
	if err != nil {
		t.Fatal(err)
	}
	aid := icp.AID
	if claimAID != "" {
		aid = claimAID // claim to be somebody else
	}

	records := make([]map[string]interface{}, 0, len(kel.KEL))
	sigs := make([]string, 0, len(kel.KEL))
	for i, ev := range kel.KEL {
		raw, err := base64.StdEncoding.DecodeString(kel.RawEventsB64[i])
		if err != nil {
			t.Fatal(err)
		}
		// Signed over the bytes the event was published as, which is the only
		// thing a verifier can reproduce.
		rawSig, err := signer.Sign(raw)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sig)
		records = append(records, map[string]interface{}{
			"sequence_number": i,
			"event_json":      ev,
			"raw_bytes_b64":   kel.RawEventsB64[i],
			"cesr_signature":  sig,
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": aid, "public_key": icp.PublicKey, "kel": records,
			"raw_events_b64": kel.RawEventsB64, "cesr_signatures": sigs,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, icp.AID
}

// An introduction served without signatures is the case this agent used to
// treat as proven. It reads fine and establishes nothing, and the difference
// has to reach the caller.
func TestAnUnsignedIntroductionDoesNotEstablishAKey(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	icp, err := e.CreateInceptionNamed(pub, next, "served")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel("served")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": icp.AID, "public_key": icp.PublicKey,
			"raw_events_b64": kel.RawEventsB64,
		})
	}))
	t.Cleanup(srv.Close)

	got, err := New().ResolveOobi(srv.URL + "/public/oobi/" + icp.AID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("an introduction nobody signed reported as verified; anyone can serve a log " +
			"they wrote themselves, so this is the whole check")
	}
	if !strings.Contains(strings.Join(got.ValidationErrors, " "), "no signature") {
		t.Errorf("the caller was not told why it is unverified: %v", got.ValidationErrors)
	}
}

func TestAnIntroductionIsFetchedAndVerified(t *testing.T) {
	srv, aid := servedIdentity(t, "")
	got, err := New().ResolveOobi(srv.URL + "/public/oobi/" + aid)
	if err != nil {
		t.Fatal(err)
	}
	if got.CID != aid {
		t.Fatalf("resolved %s, expected %s", got.CID, aid)
	}
	if !got.KelVerified {
		t.Fatalf("a genuine introduction did not verify: %v", got.ValidationErrors)
	}
	if got.CurrentPublicKey == "" {
		t.Error("the key now in force was not reported")
	}
}

// The check that matters. Whoever serves the URL controls every byte, so an
// introduction claiming an identifier its key log does not derive must be
// refused — otherwise anyone can serve a well-formed log under any name.
func TestAnIntroductionClaimingSomebodyElsesIdentifierIsRefused(t *testing.T) {
	srv, _ := servedIdentity(t, "EImpersonatingSomebodyElse0123456789ABCDEFG")
	got, err := New().ResolveOobi(srv.URL + "/public/oobi/x")
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("an introduction verified under an identifier its log does not derive — " +
			"impersonation would succeed")
	}
}

// Served without canonical bytes, the log can be read and not verified. That
// must be reported as unverified rather than as verified.
func TestAnIntroductionWithoutCanonicalBytesIsNotClaimedVerified(t *testing.T) {
	e := New()
	pub, next, _ := keys(t)
	icp, err := e.CreateInceptionNamed(pub, next, "served")
	if err != nil {
		t.Fatal(err)
	}
	kel, err := e.GetKel("served")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"aid": icp.AID, "public_key": icp.PublicKey, "kel": kel.KEL,
		})
	}))
	defer srv.Close()

	got, err := New().ResolveOobi(srv.URL + "/public/oobi/" + icp.AID)
	if err != nil {
		t.Fatal(err)
	}
	if got.KelVerified {
		t.Fatal("an unverifiable introduction was reported as verified")
	}
	if !strings.Contains(strings.Join(got.ValidationErrors, " "), "not verified") {
		t.Errorf("the caller was not told why: %v", got.ValidationErrors)
	}
}

// An address that is not an HTTP URL is refused before anything is fetched.
func TestOnlyFetchableAddressesAreResolved(t *testing.T) {
	for _, bad := range []string{"", "not a url", "file:///etc/passwd", "ftp://x.example/oobi"} {
		if _, err := New().ResolveOobi(bad); err == nil {
			t.Errorf("%q was accepted as an OOBI", bad)
		}
	}
}

// The engine satisfies the interface with all three now implemented.
func TestTheEngineStillSatisfiesTheInterface(t *testing.T) {
	var _ drivers.KeriEngine = New()
	_ = base64.StdEncoding
	_ = keri.DefaultVersion
}
