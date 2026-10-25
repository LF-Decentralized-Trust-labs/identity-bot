package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"
)

func encode(t *testing.T, l signedLog) string {
	t.Helper()
	s, err := EncodeKeyLog(l.raws, l.sigs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// aRotatedIdentity is an identity rotated once, from k0 to k1. witnesses
// names its witnesses, or none.
func aRotatedIdentity(t *testing.T, witnesses []string) (full, inceptionOnly signedLog) {
	t.Helper()
	k0, k1, k2 := newSigner(t), newSigner(t), newSigner(t)
	inceptionOnly = anInception(t, k0, k1, witnesses)
	icpEv, _ := keri.ParseEvent(inceptionOnly.raws[0])
	rot, err := keri.BuildRotation(keri.RotationInput{
		Prefix: inceptionOnly.aid, Keys: []string{k1.pub}, PriorSAID: icpEv.SAID, SN: 1,
		NextDigests: []string{k2.digest(t)}, PriorWitnesses: witnesses,
	})
	if err != nil {
		t.Fatal(err)
	}
	full = signedLog{aid: inceptionOnly.aid,
		raws: append(append([][]byte{}, inceptionOnly.raws...), rot),
		sigs: append(append([]string{}, inceptionOnly.sigs...), k1.sign(t, rot))}
	return full, inceptionOnly
}

// An identity with no witnesses has nobody who could show a rotation is the
// newest, so a shortened log retiring nothing is indistinguishable from the
// real one. Such an identity is never rotated, and a log that shows a
// rotation is refused rather than believed.
func TestARotationNothingCanProveTheNewestIsRefused(t *testing.T) {
	full, _ := aRotatedIdentity(t, nil)
	if _, err := KeyFromKeyLog(full.aid, encode(t, full)); err == nil ||
		!strings.Contains(err.Error(), "names no witnesses") {
		t.Fatalf("a rotation from an identity with no witnesses was taken as its current key: %v", err)
	}
}

// An identity that names witnesses may rotate; its log is taken as it stands.
func TestAWitnessedIdentityMayRotate(t *testing.T) {
	w, err := keri.GenerateSigner(false)
	if err != nil {
		t.Fatal(err)
	}
	wpub, _ := w.PublicKey()
	full, _ := aRotatedIdentity(t, []string{wpub})
	if _, err := KeyFromKeyLog(full.aid, encode(t, full)); err != nil {
		t.Fatalf("a witnessed identity's rotation was refused: %v", err)
	}
}

func TestAnEmptyIdentifierIsRefused(t *testing.T) {
	_, _, keyLog := aRealIdentity(t)
	if _, err := KeyFromKeyLog("", keyLog); err == nil {
		t.Fatal("a key log was taken as proving the key of no identifier at all")
	}
}

// A sign-in carries an inception and a little after it; a longer log is not
// checked on anybody's behalf.
func TestAKeyLogLongerThanASignInCarriesIsRefused(t *testing.T) {
	k0, k1 := newSigner(t), newSigner(t)
	l := anInception(t, k0, k1, nil)
	icpEv, _ := keri.ParseEvent(l.raws[0])
	prior := icpEv.SAID
	for sn := 1; sn <= MaxKeyLogEvents; sn++ {
		ixn, err := keri.BuildInteraction(keri.InteractionInput{Prefix: l.aid, PriorSAID: prior, SN: sn})
		if err != nil {
			t.Fatal(err)
		}
		ev, _ := keri.ParseEvent(ixn)
		prior = ev.SAID
		l.raws = append(l.raws, ixn)
		l.sigs = append(l.sigs, k0.sign(t, ixn))
	}
	if _, err := KeyFromKeyLog(l.aid, encode(t, l)); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("a %d-event log was checked: %v", len(l.raws), err)
	}
	if _, err := KeyFromKeyLog(l.aid, strings.Repeat("A", MaxKeyLogBytes+1)); err == nil {
		t.Fatal("a key log over the byte bound was read")
	}
}

// A carried key log has no delegator's log with it, so a delegated inception
// in it claims an approval nobody can see.
func TestACarriedDelegatedInceptionIsRefused(t *testing.T) {
	site, _ := aDelegatedSite(t, true)
	if _, err := KeyFromKeyLog(site.aid, encode(t, site)); err == nil {
		t.Fatal("a delegated inception carried without its delegator's approval was accepted")
	}
}

// A page serving its own genuine log, under its own identifier, at the
// address where another identity's introduction should be, establishes
// nothing about that other identity: the identifier it serves must be the one
// asked for.
func TestAnIntroductionForSomebodyElseAtTheirAddressEstablishesNothing(t *testing.T) {
	k0, k1 := newSigner(t), newSigner(t)
	own := anInception(t, k0, k1, nil)
	srv := own.serve(t)
	const victim = "EVictimWhoseAddressThisIs"
	if _, err := KeyFromOOBI(&http.Client{Timeout: 5 * time.Second}, srv.URL+"/oobi/"+victim, victim); err == nil {
		t.Fatal("another identity's genuine log was taken as the victim's key")
	}
}

// A registry that cannot be reached does not stop a sign-in: the site reads
// the key from the assertion's key log. And the registration goes to the
// site's current address, not one the relationship was made at.
func TestARegistrationGoesToTheSitesCurrentAddress(t *testing.T) {
	var got map[string]string
	current := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer current.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()

	h, rel := aRelationshipFor(t, goneURL+"/oobi/ESite")
	bundle := &ChallengeBundle{SiteAID: "ESite", SiteOOBI: current.URL + "/oobi/ESite"}
	if err := h.registerPairwiseOnDevRelay(rel, bundle); err != nil {
		t.Fatalf("registering at the site's current address failed: %v", err)
	}
	if got["aid"] != rel.PairwiseAID {
		t.Fatalf("the current address received %v, not the registration", got)
	}
}

// The whole preparation of a sign-in goes ahead when the site's key registry
// refuses the registration: publishing is a courtesy, and the site takes the
// key from the assertion. Before, a registry that was down, full or moved
// stopped every sign-in at that site.
func TestASignInIsPreparedWhenTheRegistryRefuses(t *testing.T) {
	siteAID, siteSeed, siteLog := aRealIdentity(t)
	kl, err := DecodeKeyLog(siteLog)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	const token = "a-session"
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/oobi/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"aid": siteAID, "raw_events_b64": kl.RawEventsB64, "cesr_signatures": kl.CesrSignatures,
			})
		case r.URL.Path == "/i/"+token:
			b := ChallengeBundle{V: "ASK1", T: 1, SiteAID: siteAID, SiteOOBI: srv.URL + "/oobi/" + siteAID,
				Audience: "https://site.example", Nonce: "n", Dt: time.Now().UTC().Format(time.RFC3339),
				Expiry:               time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
				RequestedDisclosures: []string{}, RequestedCredentials: []RequestedCredential{},
				CallbackURL: srv.URL + "/callback", SessionToken: token}
			if err := SignChallengeForAsset(&b, siteSeed); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(b)
		default: // the registry: full
			http.Error(w, "full", http.StatusInsufficientStorage)
		}
	}))
	defer srv.Close()

	h, _ := aRelationshipFor(t, srv.URL+"/oobi/"+siteAID)
	_, rel, preview, err := h.prepareLogin(StartLoginRequest{SessionToken: token, RPSessionURL: srv.URL})
	if err != nil {
		t.Fatalf("a registry refusing the registration stopped the sign-in: %v", err)
	}
	if preview == nil || rel == nil || preview.PairwiseAID != rel.PairwiseAID {
		t.Fatalf("the sign-in was not prepared: %+v", preview)
	}
}
