package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
//   - Windows: a TPM key certify, to pinned TPM manufacturer roots. Only a
//     physical TPM chip counts (a discrete chip, a firmware TPM in the CPU, or
//     Pluton): a virtual or cloud TPM, whose key the hypervisor's operator can
//     read, is refused unless the owner separately opted in to it
//     (InstalledAppIdentity.VirtualTPMKeys), and then the proof records that its
//     class is virtual. A TPM proves the key is in the computer's chip and not
//     which program holds it, so it is accepted only where the owner has said
//     they accept that (InstalledAppIdentity.TPMKeys).
//
// The attested public key must be the key the sign-in names.
//
// A key held in software (platform "software") is accepted too, unless the
// asset's owner requires a hardware key (asset.Asset.RequireHardwareKey, ADR-072
// Amendment 17): the key still signs the sign-in for a fresh ask, so it is held
// by whoever starts the sign-in, but nothing proves where it is kept, so the grant
// it leads to is kept at the software grade and lapses as a browser's does.

// InstalledAppKeyProof is the evidence an add-on's back end carries from its
// installed front end: the platform that vouches, and that platform's own
// evidence (Android: the certificate chain, each DER preceded by its length as
// 4 bytes big-endian; Apple: the CBOR attestation object; TPM: the JSON
// document secureenclave.VerifyTPMKeyCertify reads).
type InstalledAppKeyProof struct {
	Platform string `json:"platform"` // "android", "apple", "tpm" or "software"
	// Evidence is the platform's own evidence; for "software" it is the key's
	// uncompressed P-256 point (65 bytes, 0x04 first), which nothing vouches for.
	Evidence []byte `json:"evidence"`
	// Ask names the ask (beginInstalledAppKey) the evidence was made for, and
	// KeySignature is the key's own signature over InstalledAppSignInStatement
	// for that ask: ECDSA (ASN.1) for Android and a TPM, an App Attest assertion
	// for Apple.
	Ask          string `json:"ask"`
	KeySignature []byte `json:"key_signature"`
}

// The verifiers, as variables only so a test can stand in for the hardware
// vendors' signatures; the verifiers themselves are tested in secureenclave.
var (
	verifyAndroidInstalledKey     = secureenclave.VerifyInstalledAppKeyAttestation
	verifyAppleInstalledKey       = secureenclave.VerifyAppleAppAttest
	verifyTPMInstalledKey         = secureenclave.VerifyTPMKeyCertifyClasses
	verifyAppleInstalledAssertion = secureenclave.VerifyAppleAssertion
)

// installedAppFact is what the core established about an installed app's key,
// kept with the grant it leads to.
type installedAppFact struct {
	Platform string    `json:"platform"`
	Level    string    `json:"level"`
	Proved   time.Time `json:"proved"`
	// For a TPM key: who certified the endorsement key of the chip that signed, and its
	// class ("physical", or "virtual" where the owner opted in to virtual TPMs), so an owner
	// or auditor can see which chip it was and whether a hypervisor's operator could read it.
	EKIssuer string `json:"ek_issuer,omitempty"`
	EKClass  string `json:"ek_class,omitempty"`
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

// errTPMKeysNotAllowed is shown to the person as it stands: it says what to do, and it is the
// same words wherever the refusal is passed on.
var errTPMKeysNotAllowed = errors.New("This app's owner has not allowed sign-in from a Windows computer's security chip. Ask them to allow it, or sign in from a phone.")

// errVirtualTPM is what a person is told when the computer's TPM is a virtual or cloud one.
var errVirtualTPM = errors.New("This computer's security chip is a virtual one (a virtual machine's), which this app does not accept. Sign in from a physical computer or a phone, or ask the app's owner whether they will allow virtual computers.")

// inWordsForPerson gives the plain sentence for the refusals of a TPM key a person can act on.
func inWordsForPerson(err error) error {
	if errors.Is(err, secureenclave.ErrVirtualTPM) {
		return errVirtualTPM
	}
	return err
}

var errNoProof = errors.New("an installed-app sign-in needs a hardware attestation of the installed app's key, and this request has none")

// The two grades an installed app's key is kept at (ADR-072 Amendment 17), as the
// sign-in's result and the owner's list of grants say them.
const (
	// KeyGradeHardware: the core verified the device's secure hardware's own
	// attestation of the key (Android, Apple, or a TPM the owner accepts).
	KeyGradeHardware = "hardware"
	// KeyGradeSoftware: the key signed the sign-in, and nothing proves where it is
	// kept. Accepted only where the owner does not require a hardware key.
	KeyGradeSoftware = "software"
)

// PlatformSoftware is the "platform" of a key held in software.
const PlatformSoftware = "software"

// errHardwareKeyRequired is what the person is told when the owner requires a
// hardware key and this device's key is not one the hardware proves.
var errHardwareKeyRequired = errors.New("This app's owner requires a sign-in key kept in a device's secure hardware, and this device's key is not one. Sign in from a phone or a computer whose security hardware the app accepts, or ask the app's owner.")

// Grade is the grade the key was kept at: software for a key nothing vouched for,
// hardware for one a platform's attestation proved.
func (f installedAppFact) Grade() string {
	if f.Platform == PlatformSoftware {
		return KeyGradeSoftware
	}
	return KeyGradeHardware
}

// accepts are the platforms the core will take an installed app's key on for this
// asset, as its owner set it: what the ask tells the front end, so it uses the key
// the Identity Agent will accept. It informs and decides nothing: the proof is
// still checked against the owner's setting when it arrives.
func accepts(a asset.Asset) []string {
	out := []string{}
	if a.InstalledApp.AndroidPackage != "" {
		out = append(out, "android")
	}
	if a.InstalledApp.AppleAppID != "" {
		out = append(out, "apple")
	}
	if a.InstalledApp.TPMKeys {
		out = append(out, "tpm")
	}
	if !a.RequireHardwareKey {
		out = append(out, PlatformSoftware)
	}
	return out
}

// verifySoftwareKey is whether a key held in software signed the sign-in for this
// ask. The ask is spent before anything is checked, as for a hardware key. The
// owner's requirement of a hardware key is asked first, and refuses before the ask
// is touched: there is no fallback the caller can choose.
func (s *CoreServer) verifySoftwareKey(a asset.Asset, key string, proof *InstalledAppKeyProof, now time.Time) (installedAppFact, error) {
	if a.RequireHardwareKey {
		return installedAppFact{}, errHardwareKeyRequired
	}
	ask, err := s.takeInstalledAppAsk(proof.Ask, a.ID, now)
	if err != nil {
		return installedAppFact{}, err
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), proof.Evidence)
	if x == nil {
		return installedAppFact{}, errors.New("a key held in software is given as its uncompressed P-256 point")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	tp, err := thumbprintOfECKey(pub)
	if err != nil || tp != key {
		return installedAppFact{}, errors.New("the key given is not the key this sign-in names")
	}
	if err := verifyKeyPossession(PlatformSoftware, pub, proof.KeySignature, a.ID, ask, key, ""); err != nil {
		return installedAppFact{}, err
	}
	return installedAppFact{Platform: PlatformSoftware, Level: KeyGradeSoftware, Proved: now.UTC()}, nil
}

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
	if proof.Platform == PlatformSoftware {
		return s.verifySoftwareKey(a, key, proof, now)
	}
	if a.InstalledApp.IsEmpty() {
		return installedAppFact{}, errors.New("the owner of this app has not said which installed program is its own, so no installed-app key can be accepted")
	}
	// The ask is spent here, before anything is checked: a proof made for it
	// gets one try. Its challenge is the core's own, for this one attestation.
	ask, err := s.takeInstalledAppAsk(proof.Ask, a.ID, now)
	if err != nil {
		return installedAppFact{}, err
	}
	challenge := ask.challenge
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
			return installedAppFact{}, errTPMKeysNotAllowed
		}
		facts, err = verifyTPMInstalledKey(proof.Evidence, challenge, ask.credentialKey, now, a.InstalledApp.AcceptsVirtualTPM())
	default:
		return installedAppFact{}, fmt.Errorf("a key is proved on 'android', 'apple' or 'tpm', or given as 'software', not '%s'", proof.Platform)
	}
	if err != nil {
		if errors.Is(err, secureenclave.ErrVirtualTPM) {
			return installedAppFact{}, errVirtualTPM
		}
		return installedAppFact{}, fmt.Errorf("the installed app's key is not proved: %w", err)
	}
	if facts == nil || facts.Platform != proof.Platform {
		return installedAppFact{}, errors.New("the installed app's key is not proved by the platform it names")
	}
	// Whatever the verifier did, a virtual TPM's proof is never kept for an owner who did not
	// opt in to one: this is the owner's rule, held here as well as in the verifier.
	if facts.EKIssuer != nil && facts.EKIssuer.Class != secureenclave.TPMClassPhysical &&
		!(facts.EKIssuer.Class == secureenclave.TPMClassVirtual && a.InstalledApp.AcceptsVirtualTPM()) {
		return installedAppFact{}, errVirtualTPM
	}
	tp, err := thumbprintOfECKey(facts.Public)
	if err != nil || tp != key {
		return installedAppFact{}, errors.New("the attested key is not the key this sign-in names")
	}
	// The key itself signs this sign-in for this ask: a leaked attestation holds
	// only public facts, and cannot.
	if err := verifyKeyPossession(facts.Platform, facts.Public, proof.KeySignature, a.ID, ask, key, a.InstalledApp.AppleAppID); err != nil {
		return installedAppFact{}, err
	}
	f := installedAppFact{Platform: facts.Platform, Level: facts.Level, Proved: now.UTC()}
	if facts.EKIssuer != nil {
		f.EKIssuer, f.EKClass = facts.EKIssuer.Subject, facts.EKIssuer.Class
	}
	return f, nil
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
