package server

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// An installed app's key is proved, not claimed (ADR-072 section 4, Amendment 3).
//
// An installed front end holds a key in its device's secure hardware, and the
// person's approval of a sign-in for that key is an app-key grant that lasts
// until it is ended. A grant that never lapses must rest on more than the
// caller's word, so before the core starts such a sign-in it verifies a
// hardware attestation of the key itself, and holds it to the program the
// asset's OWNER named (asset.InstalledAppIdentity):
//
//   - Android: Android Key Attestation to a pinned Google root, for a P-256
//     key the hardware generated and limits to signing, whose attested
//     package and signing certificates are the owner's.
//   - iOS and macOS: Apple App Attest, to Apple's pinned root, for the
//     owner's "<team id>.<bundle id>".
//   - Windows: a TPM key certify, to pinned TPM manufacturer roots. A TPM
//     proves the key is in the computer's TPM and not which program holds it,
//     so it is accepted only where the owner has said they accept that
//     (InstalledAppIdentity.TPMKeys).
//
// The attested public key must be the key the sign-in names.

// InstalledAppKeyProof is the evidence an add-on's back end carries from its
// installed front end: the platform that vouches, and that platform's own
// evidence (Android: the certificate chain, each DER preceded by its length as
// 4 bytes big-endian; Apple: the CBOR attestation object; TPM: the JSON
// document secureenclave.VerifyTPMKeyCertify reads).
type InstalledAppKeyProof struct {
	Platform string `json:"platform"` // "android", "apple" or "tpm"
	Evidence []byte `json:"evidence"`
}

// InstalledAppKeyChallenge is the challenge the installed app asks its
// hardware to attest its key with, for the asset: so an attestation made for
// one app's asset is not another's.
func InstalledAppKeyChallenge(assetID string) []byte {
	sum := sha256.Sum256([]byte("grape installed-app key v1\n" + assetID))
	return sum[:]
}

// The verifiers, as variables only so a test can stand in for the hardware
// vendors' signatures; the verifiers themselves are tested in secureenclave.
var (
	verifyAndroidInstalledKey = secureenclave.VerifyInstalledAppKeyAttestation
	verifyAppleInstalledKey   = secureenclave.VerifyAppleAppAttest
	verifyTPMInstalledKey     = secureenclave.VerifyTPMKeyCertify
)

// installedAppFact is what the core established about an installed app's key,
// kept with the grant it leads to.
type installedAppFact struct {
	Platform string    `json:"platform"`
	Level    string    `json:"level"`
	Proved   time.Time `json:"proved"`
}

func (s *CoreServer) holdInstalledAppFact(token string, f installedAppFact) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	if s.installedAppFacts == nil {
		s.installedAppFacts = map[string]installedAppFact{}
	}
	for t := range s.installedAppFacts {
		if _, open := s.challenges[t]; !open {
			delete(s.installedAppFacts, t) // its sign-in is gone: nothing will take this
		}
	}
	s.installedAppFacts[token] = f
}

func (s *CoreServer) takeInstalledAppFact(token string) (installedAppFact, bool) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	f, ok := s.installedAppFacts[token]
	delete(s.installedAppFacts, token)
	return f, ok
}

var errNoProof = errors.New("an installed-app sign-in needs a hardware attestation of the installed app's key, and this request has none")

// verifyInstalledAppKey is whether the proof shows that key (a P-256 thumbprint,
// RFC 7638) is held in hardware by the program the owner named for the asset.
func (s *CoreServer) verifyInstalledAppKey(assetID, key string, proof *InstalledAppKeyProof, now time.Time) (installedAppFact, error) {
	if proof == nil || len(proof.Evidence) == 0 {
		return installedAppFact{}, errNoProof
	}
	if s.assetHandler == nil {
		return installedAppFact{}, errors.New("the assets are not open")
	}
	a, found, err := s.assetHandler.Store.GetAsset(assetID)
	if err != nil || !found {
		return installedAppFact{}, errors.New("no such asset")
	}
	if a.InstalledApp.IsEmpty() {
		return installedAppFact{}, errors.New("the owner of this app has not said which installed program is its own, so no installed-app key can be accepted")
	}
	challenge := InstalledAppKeyChallenge(a.ID)
	var facts *secureenclave.InstalledAppKeyFacts
	switch proof.Platform {
	case "android":
		if a.InstalledApp.AndroidPackage == "" {
			return installedAppFact{}, errors.New("the owner has not named an Android program for this app")
		}
		facts, err = verifyAndroidInstalledKey(proof.Evidence, challenge, now)
		if err == nil {
			err = holdsToAndroidProgram(facts, a.InstalledApp)
		}
	case "apple":
		if a.InstalledApp.AppleAppID == "" {
			return installedAppFact{}, errors.New("the owner has not named an Apple program for this app")
		}
		facts, err = verifyAppleInstalledKey(proof.Evidence, challenge, a.InstalledApp.AppleAppID, now)
	case "tpm":
		if !a.InstalledApp.TPMKeys {
			return installedAppFact{}, errors.New("the owner has not accepted a TPM key for this app: a TPM proves the key is in the computer, not which program holds it")
		}
		facts, err = verifyTPMInstalledKey(proof.Evidence, challenge, now)
	default:
		return installedAppFact{}, fmt.Errorf("a key is proved on 'android', 'apple' or 'tpm', not '%s'", proof.Platform)
	}
	if err != nil {
		return installedAppFact{}, fmt.Errorf("the installed app's key is not proved: %w", err)
	}
	if facts == nil || facts.Platform != proof.Platform {
		return installedAppFact{}, errors.New("the installed app's key is not proved by the platform it names")
	}
	tp, err := thumbprintOfECKey(facts.Public)
	if err != nil || tp != key {
		return installedAppFact{}, errors.New("the attested key is not the key this sign-in names")
	}
	return installedAppFact{Platform: facts.Platform, Level: facts.Level, Proved: now.UTC()}, nil
}

// holdsToAndroidProgram: the attestation states the package and the signing
// certificates of the app that asked for the key, and they must be the
// owner's. An attestation that states none proves no program.
func holdsToAndroidProgram(f *secureenclave.InstalledAppKeyFacts, id asset.InstalledAppIdentity) error {
	if !f.AppIDPresent || len(f.AppPackages) != 1 || f.AppPackages[0] != id.AndroidPackage {
		return errors.New("the key was not made by the program the owner named for this app")
	}
	if len(f.AppSigners) == 0 {
		return errors.New("the key's attestation names no signing certificate")
	}
	owners := map[string]bool{}
	for _, d := range id.AndroidSigners {
		owners[d] = true
	}
	for _, d := range f.AppSigners {
		if !owners[hex.EncodeToString(d)] {
			return errors.New("the key was made by a program signed by a certificate the owner did not name")
		}
	}
	return nil
}

func thumbprintOfECKey(k *ecdsa.PublicKey) (string, error) {
	if k == nil || k.X == nil || k.Y == nil {
		return "", errors.New("no key")
	}
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	return login.ThumbprintP256(enc(k.X.FillBytes(make([]byte, 32))), enc(k.Y.FillBytes(make([]byte, 32))))
}
