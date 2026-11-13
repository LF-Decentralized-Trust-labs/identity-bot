package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/login"
)

// Starting a sign-in as an asset for a key a browser holds (ADR-066), and
// reading how it went, for an add-on that fronts the asset (an app that serves
// pages). It is the core's own challenge and the core's own result, the ones
// POST /api/login/challenge and GET /api/login/challenge/{token}/status serve
// to a caller of the core's API; this is the same two steps for a caller that
// is code in this process rather than a request. The person's Identity Agent
// fetches the challenge at /i/{token} and answers at /api/login/callback, as
// for any other sign-in: nothing about that is the add-on's.

// BrowserKeySignIn is a sign-in started for a browser's key.
type BrowserKeySignIn struct {
	// CanonicalBody is the exact text Sig covers (login.CanonicalChallengeBody),
	// so a party outside this process can check the signature and read the
	// challenge from the same bytes.
	CanonicalBody string
	// Sig is the asset's signature over CanonicalBody.
	Sig string
	// Pointer is what the person's Identity Agent opens to fetch the challenge.
	Pointer string
	// Session names the sign-in here. Collector is the secret that releases its
	// result: whoever started the sign-in keeps both and shows neither to the
	// browser.
	Session, Collector string
}

// SignInRefused is why a sign-in could not be started, with the status the
// core's own route would have answered.
type SignInRefused struct {
	Code   int
	Reason string
}

func (e *SignInRefused) Error() string { return e.Reason }

// BrowserKeySignInResult is how a started sign-in stands.
type BrowserKeySignInResult struct {
	// State is "pending", "declined" or "verified".
	State string
	// Pairwise is the person's identifier at the asset and BrowserKey the
	// thumbprint the verified assertion repeated; both only when verified.
	Pairwise, BrowserKey string
	Disclosures          map[string]string
	// SiteAID is the asset the challenge was signed as, and FrontEnd the kind of
	// front end it named, both from the challenge itself: so whoever asks can
	// check the sign-in was started for it, and for the kind it expects.
	SiteAID, FrontEnd string
}

// startBrowserKeySignIn is the core's signed challenge for the asset, naming
// browserKey, with a collector secret minted for it. It is a browser's: the
// kind is never the caller's to name (see startFrontEndKeySignIn).
func (s *CoreServer) startBrowserKeySignIn(assetID, audience, browserKey, publicURL string) (BrowserKeySignIn, error) {
	if browserKey == "" {
		return BrowserKeySignIn{}, &SignInRefused{http.StatusBadRequest, "a sign-in for a browser's key names the key"}
	}
	token, qr, code, msg := s.createSignedAssetChallenge(assetID, audience, "", nil, browserKey, asset.FrontEndBrowser, publicURL, false)
	if code != 0 {
		return BrowserKeySignIn{}, &SignInRefused{code, msg}
	}
	return s.finishStartingKeySignIn(token, qr)
}

// startFrontEndKeySignIn starts a sign-in for the key of an installed app (or a
// browser) on behalf of the add-on whose back end signed r. The installed_app
// kind is the core's to establish, not the caller's to name (ADR-072 section 4):
//
//   - the caller is an app's back end (signed as the app, or found to be the
//     app by the add-on that authenticated it), and r is not one a web page
//     made (a browser Origin or Fetch-Metadata header), however it reached the
//     add-on's route;
//   - the asset is the calling app's own, never another's;
//   - the key must be proved by a hardware attestation that the core verifies
//     itself, held to the program the OWNER named for the asset
//     (verifyInstalledAppKey). The app's say-so is not read as proof.
func (s *CoreServer) startFrontEndKeySignIn(r *http.Request, callerAsset, assetID, audience, key, frontEnd, publicURL string, proof *InstalledAppKeyProof) (BrowserKeySignIn, error) {
	if key == "" {
		return BrowserKeySignIn{}, &SignInRefused{http.StatusBadRequest, "a sign-in for a front end's key names the key"}
	}
	if frontEnd != asset.FrontEndBrowser && frontEnd != asset.FrontEndInstalledApp {
		return BrowserKeySignIn{}, &SignInRefused{http.StatusBadRequest, "a sign-in names its front end, 'browser' or 'installed_app'"}
	}
	if err := s.theAppAsking(r, callerAsset, assetID); err != nil {
		return BrowserKeySignIn{}, err
	}
	var fact *installedAppFact
	if frontEnd == asset.FrontEndInstalledApp {
		if aPageAsked(r) {
			return BrowserKeySignIn{}, &SignInRefused{http.StatusForbidden, "a request that came from a web page cannot start an installed-app sign-in"}
		}
		f, err := s.verifyInstalledAppKey(assetID, key, proof, time.Now())
		if err != nil {
			return BrowserKeySignIn{}, &SignInRefused{http.StatusForbidden, err.Error()}
		}
		fact = &f
	}
	token, qr, code, msg := s.createSignedAssetChallenge(assetID, audience, "", nil, key, frontEnd, publicURL, fact != nil)
	if code != 0 {
		return BrowserKeySignIn{}, &SignInRefused{code, msg}
	}
	if fact != nil {
		s.holdInstalledAppFact(token, *fact)
	}
	return s.finishStartingKeySignIn(token, qr)
}

// aPageAsked is whether a web page's browser made this request, to whatever
// route: a browser sends Origin on any cross-origin or non-GET request, and
// Sec-Fetch-Mode or Sec-Fetch-Site on all of them, and a page cannot remove
// them. An installed app or a server sends none of these.
func aPageAsked(r *http.Request) bool {
	h := r.Header
	return h.Get("Origin") != "" || h.Get("Sec-Fetch-Mode") != "" || h.Get("Sec-Fetch-Site") != "" || h.Get("Sec-Fetch-Dest") != ""
}

func (s *CoreServer) finishStartingKeySignIn(token, qr string) (BrowserKeySignIn, error) {
	secret, err := s.mintCollectorSecret(token)
	if err != nil {
		return BrowserKeySignIn{}, &SignInRefused{http.StatusInternalServerError, "could not start a login"}
	}
	s.challengeMu.Lock()
	b, ok := s.challenges[token]
	s.challengeMu.Unlock()
	if !ok {
		return BrowserKeySignIn{}, &SignInRefused{http.StatusInternalServerError, "the challenge is not held"}
	}
	return BrowserKeySignIn{CanonicalBody: login.CanonicalChallengeBody(b), Sig: b.Sig, Pointer: qr, Session: token, Collector: secret}, nil
}

// browserKeySignInResult is how the sign-in stands, given its collector
// secret and the asset asking (siteAID). A wrong secret and an unknown sign-in
// are the same error, and so is a sign-in that was not for a browser's key or
// not for the asking asset.
func (s *CoreServer) browserKeySignInResult(siteAID, session, collector string) (BrowserKeySignInResult, error) {
	errUnknown := errors.New("no such sign-in")
	if bound, held := s.collectorHeld(session, collector); !bound || !held {
		return BrowserKeySignInResult{}, errUnknown
	}
	s.challengeMu.Lock()
	b, ok := s.challenges[session]
	s.challengeMu.Unlock()
	if !ok || b.BrowserKey == "" || b.SiteAID != siteAID {
		// Another asset's sign-in is, to this one, no sign-in. This is decided
		// before anything is read, because reading a finished sign-in releases
		// it: an asker that is not the asset it was for must not use it up.
		return BrowserKeySignInResult{}, errUnknown
	}
	st, _, _, cerr := s.collectSignIn(session, collector, time.Now())
	if cerr != nil {
		return BrowserKeySignInResult{}, errors.New("could not read this sign-in")
	}
	switch st["status"] {
	case "complete":
		if st["released"] == true {
			return BrowserKeySignInResult{}, errors.New("this sign-in's result was collected already, or not collected in time")
		}
		// The callback stores a login.AssertionVerifyResult's fields: a string
		// pairwise identifier and a map[string]string of disclosures. Anything
		// else is not read as "verified with nothing disclosed", which would
		// quietly drop what the person chose to show: it is an error.
		out := BrowserKeySignInResult{State: "verified", BrowserKey: fmt.Sprint(st["browser_key"]), SiteAID: b.SiteAID, FrontEnd: b.FrontEnd}
		pairwise, ok := st["pairwise_aid"].(string)
		if !ok || pairwise == "" {
			return BrowserKeySignInResult{}, errors.New("the verified sign-in carries no identifier for the person")
		}
		out.Pairwise = pairwise
		if d, present := st["disclosures"]; present && d != nil {
			m, ok := d.(map[string]string)
			if !ok {
				return BrowserKeySignInResult{}, fmt.Errorf("the verified sign-in's disclosures are a %T, not the map the callback stores", d)
			}
			out.Disclosures = m
		}
		return out, nil
	case "denied":
		return BrowserKeySignInResult{State: "declined", SiteAID: b.SiteAID, FrontEnd: b.FrontEnd}, nil
	}
	return BrowserKeySignInResult{State: "pending", SiteAID: b.SiteAID, FrontEnd: b.FrontEnd}, nil
}

// assetStillAdmits says whether the asset's enrolment policy lets this person
// (by the identifier they signed in with) in now: the same MEMBERSHIP gate the
// callback applied when they signed in, asked again, so someone removed from
// the roster since is no longer admitted. It does not re-check the policy's
// required credential (RequiredCredSchema): that needs what the person
// presented, which is not kept after the sign-in. An error means the asset could not be
// read, which is not an answer either way.
func (s *CoreServer) assetStillAdmits(assetID, pairwiseAID string) (bool, error) {
	if s.assetHandler == nil {
		return false, errors.New("the assets are not open")
	}
	a, found, err := s.assetHandler.Store.GetAsset(assetID)
	if err != nil {
		return false, err
	}
	if !found || pairwiseAID == "" {
		return false, nil
	}
	ok, _ := s.admitsMember(a, pairwiseAID)
	return ok, nil
}
