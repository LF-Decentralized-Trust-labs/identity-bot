package login

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// aSiteServing serves a site's key log and, at /i/{token}, a challenge signed
// by the site with the given expiry.
func aSiteServing(t *testing.T, token, expiry string) (*httptest.Server, string) {
	t.Helper()
	siteAID, siteSeed, siteLog := aRealIdentity(t)
	kl, err := DecodeKeyLog(siteLog)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/oobi/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"aid": siteAID, "raw_events_b64": kl.RawEventsB64, "cesr_signatures": kl.CesrSignatures,
			})
		case r.URL.Path == "/i/"+token:
			b := ChallengeBundle{V: "ASK1", T: 1, SiteAID: siteAID, SiteOOBI: srv.URL + "/oobi/" + siteAID,
				Audience: "https://site.example", Nonce: "n", Dt: time.Now().UTC().Format(time.RFC3339),
				Expiry:               expiry,
				RequestedDisclosures: []string{}, RequestedCredentials: []RequestedCredential{},
				CallbackURL: srv.URL + "/callback", SessionToken: token}
			if err := SignChallengeForAsset(&b, siteSeed); err != nil {
				t.Error(err)
			}
			_ = json.NewEncoder(w).Encode(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, siteAID
}

// The expiry that counts is the one in the challenge whose signature was
// verified, so a login the site signed with a passed expiry is refused however
// the request reached this device.
func TestALoginTheSiteSignedAsExpiredIsRefused(t *testing.T) {
	const token = "a-session"
	srv, siteAID := aSiteServing(t, token, time.Now().Add(-5*time.Minute).UTC().Format(time.RFC3339))
	h, _ := aRelationshipFor(t, srv.URL+"/oobi/"+siteAID)
	_, _, _, err := h.prepareLogin(StartLoginRequest{SessionToken: token, RPSessionURL: srv.URL})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("a login signed with a passed expiry was prepared: %v", err)
	}
}

// A login prepared while live, and approved after it expired, is refused
// before anything is signed for the site.
func TestALoginApprovedAfterItExpiredIsRefused(t *testing.T) {
	const token = "a-session"
	srv, siteAID := aSiteServing(t, token, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	h, _ := aRelationshipFor(t, srv.URL+"/oobi/"+siteAID)
	bundle, rel, _, err := h.prepareLogin(StartLoginRequest{SessionToken: token, RPSessionURL: srv.URL})
	if err != nil {
		t.Fatalf("a live login was refused: %v", err)
	}
	bundle.Expiry = time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	if _, err := h.completeLogin(&pendingLogin{Bundle: bundle, Relationship: rel}); !errors.Is(err, ErrExpired) {
		t.Fatalf("a login that expired before approval was completed: %v", err)
	}
}

func TestCheckExpiry(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		expiry string
		want   error
	}{
		"live":            {now.Add(time.Minute).UTC().Format(time.RFC3339), nil},
		"inside the skew": {now.Add(-30 * time.Second).UTC().Format(time.RFC3339), nil},
		"expired":         {now.Add(-2 * time.Minute).UTC().Format(time.RFC3339), ErrExpired},
		"missing":         {"", ErrExpiryUnreadable},
		"not a time":      {"tomorrow", ErrExpiryUnreadable},
	} {
		if err := CheckExpiry(c.expiry, now); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}
