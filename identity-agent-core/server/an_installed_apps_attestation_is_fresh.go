package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"identity-agent-core/secureenclave"
)

// An installed app's attestation is made fresh by the core, once, and the key
// proves it holds the key at every sign-in (ADR-072 Amendment 3).
//
// A hardware attestation says "this key is in hardware". Nothing in it says
// "and it is asking now", so one that leaked (it holds only public facts) could
// be shown again to name the victim's key. So the core hands the app's back end
// an ASK first, for one attestation:
//
//   - a random challenge, which the app's hardware attests the key with (Android
//     attestation challenge, App Attest clientDataHash, TPM qualifying data);
//   - for a TPM, a second random value the core keeps and never gives out, the
//     key of the credential that ties the AK to the EK (see tpm_key_certify.go);
//   - one use: the ask is spent when the proof is read, whether or not it holds,
//     and it expires in installedAppAskLife.
//
// Then the key itself signs a statement that names the asset, the ask's
// challenge and the key (InstalledAppSignInStatement), so only whoever holds the
// key can start the sign-in, each time.

const (
	installedAppAskLife = 5 * time.Minute
	// An asset can have this many asks open. An app's back end asks once for
	// each sign-in it starts; more than this are an app that is not finishing them.
	installedAppAsksPerAsset = 20
)

type installedAppAsk struct {
	asset         string
	challenge     []byte
	credentialKey []byte // never leaves the core
	until         time.Time
}

// InstalledAppKeyAsk is what an app's back end gets before it asks its
// installed front end for a hardware attestation: the challenge to attest the
// key with, and the name of the ask, which the proof must carry back.
type InstalledAppKeyAsk struct {
	ID        string `json:"ask"`
	Challenge []byte `json:"challenge"`
	// Expires is when the ask stops being usable.
	Expires time.Time `json:"expires"`
}

// InstalledAppSignInStatement is what an installed app's key signs to start a
// sign-in: the asset, the ask's challenge and the key's own thumbprint. For
// Android and a TPM it is the ECDSA (ASN.1) signature of its SHA-256; for an
// Apple App Attest key it is an assertion whose clientDataHash is that SHA-256.
func InstalledAppSignInStatement(assetID string, challenge []byte, keyThumbprint string) []byte {
	return []byte("identity-agent installed-app sign-in v1\n" + assetID + "\n" +
		base64.RawURLEncoding.EncodeToString(challenge) + "\n" + keyThumbprint)
}

// theAppAsking settles which app is asking, and refuses everything but the
// app's back end asking for its own asset: the check startFrontEndKeySignIn and
// beginInstalledAppKey share. It returns a *SignInRefused.
func (s *CoreServer) theAppAsking(r *http.Request, callerAsset, assetID string) error {
	// The app asking is the one the core's own check of the request says (it
	// signed as the app), or, for a route an add-on authenticates itself (an
	// app's machine, sealed to this Identity Agent), the app that add-on found
	// the caller to be: callerAsset, which an add-on takes from its own verified
	// binding and never from the request body.
	askingApp := callerAsset
	if app, ok := TheAppThatAsked(r); ok {
		if callerAsset != "" && callerAsset != app.Asset {
			return &SignInRefused{http.StatusForbidden, "the app that signed this request is not the one the add-on found asking"}
		}
		askingApp = app.Asset
	}
	if askingApp == "" {
		return &SignInRefused{http.StatusForbidden, "only an app's back end starts a sign-in for its front end"}
	}
	if askingApp != assetID {
		return &SignInRefused{http.StatusForbidden, "an app starts sign-ins for its own asset only"}
	}
	return nil
}

// beginInstalledAppKey issues the ask for one attestation of an installed
// app's key, for the calling app's own asset. A request a web page made gets none.
func (s *CoreServer) beginInstalledAppKey(r *http.Request, callerAsset, assetID string) (InstalledAppKeyAsk, error) {
	if err := s.theAppAsking(r, callerAsset, assetID); err != nil {
		return InstalledAppKeyAsk{}, err
	}
	if aPageAsked(r) {
		return InstalledAppKeyAsk{}, &SignInRefused{http.StatusForbidden, "a request that came from a web page cannot ask for an installed-app attestation"}
	}
	random := func(n int) []byte {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return b
	}
	idRaw, challenge, credKey := random(18), random(32), random(secureenclave.TPMCredentialKeyLen)
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	now := time.Now()
	s.installedAppAskMu.Lock()
	defer s.installedAppAskMu.Unlock()
	if s.installedAppAsks == nil {
		s.installedAppAsks = map[string]installedAppAsk{}
	}
	open := 0
	for k, a := range s.installedAppAsks {
		if now.After(a.until) {
			delete(s.installedAppAsks, k)
		} else if a.asset == assetID {
			open++
		}
	}
	if open >= installedAppAsksPerAsset {
		return InstalledAppKeyAsk{}, &SignInRefused{http.StatusTooManyRequests, "this app has too many attestations open: finish or let them expire"}
	}
	until := now.Add(installedAppAskLife)
	s.installedAppAsks[id] = installedAppAsk{asset: assetID, challenge: challenge, credentialKey: credKey, until: until}
	return InstalledAppKeyAsk{ID: id, Challenge: challenge, Expires: until}, nil
}

var errAskNotHeld = errors.New("the attestation was not asked for by this core for this app, or was used already, or has expired")

// takeInstalledAppAsk spends the ask: it is gone whether or not what follows holds.
func (s *CoreServer) takeInstalledAppAsk(id, assetID string, now time.Time) (installedAppAsk, error) {
	s.installedAppAskMu.Lock()
	defer s.installedAppAskMu.Unlock()
	a, ok := s.installedAppAsks[id]
	delete(s.installedAppAsks, id)
	if !ok || a.asset != assetID || now.After(a.until) {
		return installedAppAsk{}, errAskNotHeld
	}
	return a, nil
}

// verifyKeyPossession is whether the key signed the sign-in statement for this
// ask: so the sign-in is started by whoever holds the key, now.
func verifyKeyPossession(platform string, pub *ecdsa.PublicKey, signature []byte, assetID string, ask installedAppAsk, thumbprint, appleAppID string) error {
	if len(signature) == 0 {
		return errors.New("the installed app's key did not sign this sign-in")
	}
	digest := sha256.Sum256(InstalledAppSignInStatement(assetID, ask.challenge, thumbprint))
	if platform == "apple" {
		if _, err := verifyAppleInstalledAssertion(signature, digest[:], pub, appleAppID); err != nil {
			return errors.New("the installed app's key did not sign this sign-in: " + err.Error())
		}
		return nil
	}
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return errors.New("the installed app's key did not sign this sign-in")
	}
	return nil
}
