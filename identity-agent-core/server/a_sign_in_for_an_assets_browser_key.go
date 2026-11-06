package server

import (
	"errors"
	"fmt"
	"net/http"

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
}

// startBrowserKeySignIn is the core's signed challenge for the asset, naming
// browserKey, with a collector secret minted for it.
func (s *CoreServer) startBrowserKeySignIn(assetID, audience, browserKey, publicURL string) (BrowserKeySignIn, error) {
	if browserKey == "" {
		return BrowserKeySignIn{}, &SignInRefused{http.StatusBadRequest, "a sign-in for a browser's key names the key"}
	}
	token, qr, code, msg := s.createSignedAssetChallenge(assetID, audience, nil, browserKey, publicURL)
	if code != 0 {
		return BrowserKeySignIn{}, &SignInRefused{code, msg}
	}
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
// secret. A wrong secret and an unknown sign-in are the same error, and so is
// a sign-in that was not for a browser's key.
func (s *CoreServer) browserKeySignInResult(session, collector string) (BrowserKeySignInResult, error) {
	errUnknown := errors.New("no such sign-in")
	if bound, held := s.collectorHeld(session, collector); !bound || !held {
		return BrowserKeySignInResult{}, errUnknown
	}
	s.challengeMu.Lock()
	b, ok := s.challenges[session]
	s.challengeMu.Unlock()
	if !ok || b.BrowserKey == "" {
		return BrowserKeySignInResult{}, errUnknown
	}
	st := s.challengeStatusOf(session)
	switch st["status"] {
	case "complete":
		out := BrowserKeySignInResult{State: "verified", BrowserKey: fmt.Sprint(st["browser_key"])}
		out.Pairwise, _ = st["pairwise_aid"].(string)
		out.Disclosures, _ = st["disclosures"].(map[string]string)
		return out, nil
	case "denied":
		return BrowserKeySignInResult{State: "declined"}, nil
	}
	return BrowserKeySignInResult{State: "pending"}, nil
}
