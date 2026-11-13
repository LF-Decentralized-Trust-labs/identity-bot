package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// An installed app's signing key is accepted only as a P-256 key the hardware
// generated and limits to signing, asked for with the challenge the core chose.
func TestAnInstalledAppsKeyIsAttestedOnlyWhenTheHardwareGeneratedAndLimitsItToSigning(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey := softwareRSA(t)
	now := time.Now()
	const ch = "the core's challenge"
	for name, c := range map[string]struct {
		mod  func(*chainSpec)
		fail bool
	}{
		"a strongbox signing key":  {mod: func(*chainSpec) {}},
		"a software level":         {mod: func(s *chainSpec) { s.level = attestSoftware }, fail: true},
		"an imported key":          {mod: func(s *chainSpec) { s.imported = true }, fail: true},
		"a key that also decrypts": {mod: func(s *chainSpec) { s.purposes = []int{kmPurposeSign, kmPurposeDecrypt} }, fail: true},
		"a decrypt-only key":       {mod: func(s *chainSpec) { s.purposes = []int{kmPurposeDecrypt} }, fail: true},
		"another challenge":        {mod: func(s *chainSpec) { s.challenge = "not mine" }, fail: true},
		"a P-384 key":              {mod: func(s *chainSpec) { s.leafKey = &other.PublicKey }, fail: true},
		"an RSA key":               {mod: func(s *chainSpec) { s.leafKey = &rsaKey.PublicKey }, fail: true},
		"an unlocked bootloader":   {mod: func(s *chainSpec) { s.bootUnlocked = true }, fail: true},
		"a self-signed boot":       {mod: func(s *chainSpec) { s.bootState = 1 }, fail: true},
		"an unverified boot":       {mod: func(s *chainSpec) { s.bootState = 2 }, fail: true},
		"a failed boot":            {mod: func(s *chainSpec) { s.bootState = 3 }, fail: true},
		"no root of trust at all":  {mod: func(s *chainSpec) { s.rootOfTrust = false }, fail: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := chainSpec{level: attestStrongBox, challenge: ch, purposes: []int{kmPurposeSign}, noAuth: true,
				created: now.Add(-time.Hour), leafKey: &ec.PublicKey, noOAEP: true, rootOfTrust: true}
			c.mod(&s)
			aProductionCoreOffline(t)
			chain, root := builtChain(t, s)
			f, err := verifyInstalledAppKeyAttestation(chain, []byte(ch), now, [][sha256.Size]byte{root})
			if c.fail {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !f.Public.Equal(&ec.PublicKey) {
				t.Fatal("not the attested key")
			}
		})
	}
}

// aProductionCoreOffline is a production core with no network and the committed
// copy of Google's list kept in its data directory, an hour old: what a phone
// that fetched the list earlier holds. No test reaches Google's server.
func aProductionCoreOffline(t *testing.T, extra ...string) {
	t.Helper()
	googleIsUnreachable(t)
	aCopyKeptFor(t, time.Hour, statusListJSON(extra...))
	prev := isDevBuild
	isDevBuild = func() bool { return false }
	t.Cleanup(func() { isDevBuild = prev })
}

func anInstalledAppsStrongBoxChain(t *testing.T) (chain []byte, root [sha256.Size]byte, now time.Time) {
	t.Helper()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now = time.Now()
	chain, root = builtChain(t, chainSpec{level: attestStrongBox, challenge: "the core's challenge", purposes: []int{kmPurposeSign},
		noAuth: true, created: now.Add(-time.Hour), leafKey: &ec.PublicKey, noOAEP: true, rootOfTrust: true})
	return chain, root, now
}

// A certificate Google has listed refuses the installed app's key, whichever
// certificate in the chain it is.
func TestAnInstalledAppsKeyWithARevokedCertificateIsRefused(t *testing.T) {
	for _, serial := range []string{serialRoot, serialIntermediate, serialLeaf} {
		t.Run("serial "+serial, func(t *testing.T) {
			aProductionCoreOffline(t, serial, "REVOKED")
			chain, root, now := anInstalledAppsStrongBoxChain(t)
			_, err := verifyInstalledAppKeyAttestation(chain, []byte("the core's challenge"), now, [][sha256.Size]byte{root})
			if !errors.Is(err, ErrAttestationRevoked) {
				t.Fatalf("not refused as revoked: %v", err)
			}
		})
	}
}

// With no list to be had, a production build does not trust the key.
func TestAnInstalledAppsKeyIsRefusedInProductionWhenNoListIsAvailable(t *testing.T) {
	googleIsUnreachable(t) // nothing kept either
	prev := isDevBuild
	isDevBuild = func() bool { return false }
	t.Cleanup(func() { isDevBuild = prev })
	chain, root, now := anInstalledAppsStrongBoxChain(t)
	_, err := verifyInstalledAppKeyAttestation(chain, []byte("the core's challenge"), now, [][sha256.Size]byte{root})
	if !errors.Is(err, ErrNoStatusList) {
		t.Fatalf("not refused for want of the list: %v", err)
	}
}

// A kept copy older than seven days is no list at all.
func TestAnInstalledAppsKeyIsRefusedInProductionWhenTheKeptListIsStale(t *testing.T) {
	googleIsUnreachable(t)
	aCopyKeptFor(t, 8*24*time.Hour, statusListJSON())
	prev := isDevBuild
	isDevBuild = func() bool { return false }
	t.Cleanup(func() { isDevBuild = prev })
	chain, root, now := anInstalledAppsStrongBoxChain(t)
	_, err := verifyInstalledAppKeyAttestation(chain, []byte("the core's challenge"), now, [][sha256.Size]byte{root})
	if !errors.Is(err, ErrNoStatusList) {
		t.Fatalf("not refused for want of a young enough list: %v", err)
	}
}

// A seed-wrapping check never accepts an EC key.
func TestTheSeedKeyPolicyRefusesAnECKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := seedWrapKeyPolicy(&AndroidKeyFacts{ECPublicKey: &ec.PublicKey, Generated: true}); err == nil {
		t.Fatal("an EC key passed the seed key policy")
	}
}
