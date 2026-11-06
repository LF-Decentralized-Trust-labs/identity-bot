package secureenclave

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func realChain(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "android_attestation", name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	var ders [][]byte
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		ders = append(ders, b.Bytes)
	}
	return JoinAttestationChain(ders...)
}

// The real chains Google publishes, from real phones: the level the core reads
// is the level the phone's hardware stated, and agrees with Google's own decoding.
func TestRealPhonesAttestationsAreReadAsTheHardwareStatedThem(t *testing.T) {
	for _, c := range []struct{ name, level string }{
		{"blueline_sdk28_SB_RSA_NONE", "strongbox"},
		{"akita_sdk34_SB_RSA_NONE", "strongbox"},
		{"blueline_sdk28_TEE_RSA_NONE", "tee"},
		{"akita_sdk34_TEE_RSA_NONE", "tee"},
		{"akita_sdk34_TEE_RSA_NONE_USERAUTH", "tee"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := VerifyAndroidKeyAttestation(realChain(t, c.name), []byte("challenge"), time.Now())
			if err != nil {
				t.Fatalf("a real phone's chain was refused: %v", err)
			}
			if f.LevelName() != c.level {
				t.Fatalf("level %s, the phone's hardware said %s", f.LevelName(), c.level)
			}
			if !f.Generated || f.PublicKey.N.BitLen() != 2048 {
				t.Fatalf("generated=%v bits=%d", f.Generated, f.PublicKey.N.BitLen())
			}
			// Compare against Google's decoding of the same leaf.
			raw, _ := os.ReadFile(filepath.Join("testdata", "android_attestation", c.name+".json"))
			var g struct {
				AttestationChallenge string
				SoftwareEnforced     struct{ CreationDateTime string }
				HardwareEnforced     struct {
					NoAuthRequired bool
					Purposes       []string
					RootOfTrust    struct {
						DeviceLocked      bool
						VerifiedBootState string
					}
				}
			}
			if err := json.Unmarshal(raw, &g); err != nil {
				t.Fatal(err)
			}
			if want, _ := base64.StdEncoding.DecodeString(g.AttestationChallenge); !bytes.Equal(want, f.Challenge) {
				t.Errorf("challenge %q, Google decodes %q", f.Challenge, want)
			}
			if g.HardwareEnforced.NoAuthRequired != f.NoAuthRequired {
				t.Errorf("noAuthRequired %v, Google decodes %v", f.NoAuthRequired, g.HardwareEnforced.NoAuthRequired)
			}
			if f.DeviceLocked != g.HardwareEnforced.RootOfTrust.DeviceLocked ||
				!strings.EqualFold(f.BootState, g.HardwareEnforced.RootOfTrust.VerifiedBootState) {
				t.Errorf("root of trust %q/%v, Google decodes %+v", f.BootState, f.DeviceLocked, g.HardwareEnforced.RootOfTrust)
			}
			if len(f.Purposes) != 1 || f.Purposes[0] != 2 || g.HardwareEnforced.Purposes[0] != "2" {
				t.Errorf("purposes %v vs %v", f.Purposes, g.HardwareEnforced.Purposes)
			}
			if f.Created.UnixMilli() <= 0 {
				t.Error("creation time not read")
			}
		})
	}
}

// Those keys sign; the seed key must decrypt. The policy refuses them, so a real
// StrongBox key made for something else cannot stand in for the seed key.
func TestARealStrongBoxKeyThatSignsIsNotTheSeedKey(t *testing.T) {
	f, err := VerifyAndroidKeyAttestation(realChain(t, "akita_sdk34_SB_RSA_NONE"), []byte("challenge"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := seedWrapKeyPolicy(f); err == nil || !errors.Is(err, ErrNotAttested) {
		t.Fatalf("policy accepted a signing key: %v", err)
	}
}

func TestARealChainIsRefusedWhenAnythingAboutItIsOff(t *testing.T) {
	good := realChain(t, "akita_sdk34_SB_RSA_NONE")
	chain, _ := splitChain(good)
	now := time.Now()

	t.Run("wrong challenge", func(t *testing.T) {
		if _, err := VerifyAndroidKeyAttestation(good, []byte("another"), now); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("a flipped byte in the leaf", func(t *testing.T) {
		bad := bytes.Clone(good)
		bad[4+len(chain[0].Raw)-5] ^= 1 // inside the leaf's signature
		if _, err := VerifyAndroidKeyAttestation(bad, []byte("challenge"), now); err == nil {
			t.Fatal("accepted a tampered chain")
		}
	})
	t.Run("a leaf alone", func(t *testing.T) {
		if _, err := VerifyAndroidKeyAttestation(JoinAttestationChain(chain[0].Raw), []byte("challenge"), now); err == nil {
			t.Fatal("accepted a lone certificate")
		}
	})
	t.Run("the root cut off", func(t *testing.T) {
		var ders [][]byte
		for _, c := range chain[:len(chain)-1] {
			ders = append(ders, c.Raw)
		}
		if _, err := VerifyAndroidKeyAttestation(JoinAttestationChain(ders...), []byte("challenge"), now); err == nil {
			t.Fatal("accepted a chain with no root")
		}
	})
	t.Run("a different chain's leaf spliced on", func(t *testing.T) {
		other, _ := splitChain(realChain(t, "akita_sdk34_TEE_RSA_NONE"))
		var ders [][]byte
		ders = append(ders, other[0].Raw)
		for _, c := range chain[1:] {
			ders = append(ders, c.Raw)
		}
		if _, err := VerifyAndroidKeyAttestation(JoinAttestationChain(ders...), []byte("challenge"), now); err == nil {
			t.Fatal("accepted a leaf its intermediate did not sign")
		}
	})
	t.Run("no pinned roots", func(t *testing.T) {
		if _, err := verifyAndroidKeyAttestation(good, []byte("challenge"), now, nil); err == nil {
			t.Fatal("accepted with no pinned roots")
		}
	})
	// The intermediates in this chain expired in 2024. The key was made in 2024,
	// and they are checked as of then, so today's date does not refuse it.
	t.Run("checked when the key was made, not today", func(t *testing.T) {
		if _, err := VerifyAndroidKeyAttestation(good, []byte("challenge"), now.AddDate(5, 0, 0)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("truncated and garbage input", func(t *testing.T) {
		for _, b := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 9, 1}, good[:len(good)-5], bytes.Repeat([]byte{0xff}, 40)} {
			if _, err := VerifyAndroidKeyAttestation(b, []byte("challenge"), now); err == nil {
				t.Fatalf("accepted %d bytes", len(b))
			}
		}
	})
}

func softwareRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func goodSpec(k *rsa.PrivateKey) chainSpec {
	return chainSpec{level: attestStrongBox, challenge: SeedWrapAttestationChallenge, purposes: []int{kmPurposeDecrypt},
		noAuth: true, created: time.Now().Add(-time.Hour), leafKey: &k.PublicKey}
}

func TestABuiltChainIsAcceptedOnlyWhereTheHardwareHoldsAGoodKey(t *testing.T) {
	k := softwareRSA(t)
	now := time.Now()
	for name, c := range map[string]struct {
		mod  func(*chainSpec)
		fail bool
		pol  bool // refused by the seed key policy rather than the chain check
	}{
		"strongbox decrypt key":                  {mod: func(*chainSpec) {}},
		"tee decrypt key":                        {mod: func(s *chainSpec) { s.level = attestTrustedEnvironment }},
		"software level":                         {mod: func(s *chainSpec) { s.level = attestSoftware }, fail: true},
		"attested in software, held in hardware": {mod: func(s *chainSpec) { s.attestSoft = true }, fail: true},
		"wrong challenge":                        {mod: func(s *chainSpec) { s.challenge = "something else" }, fail: true},
		"imported key":                           {mod: func(s *chainSpec) { s.imported = true }, pol: true},
		"signing key":                            {mod: func(s *chainSpec) { s.purposes = []int{2} }, pol: true},
		"decrypts and also signs":                {mod: func(s *chainSpec) { s.purposes = []int{kmPurposeDecrypt, 2} }, pol: true},
		"oaep and also no padding":               {mod: func(s *chainSpec) { s.extraPadding = 1 }, pol: true},
		"oaep and also pkcs1":                    {mod: func(s *chainSpec) { s.extraPadding = 4 }, pol: true},
		"needs a person":                         {mod: func(s *chainSpec) { s.noAuth = false }, pol: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := goodSpec(k)
			c.mod(&s)
			chain, root := builtChain(t, s)
			f, err := verifyAndroidKeyAttestation(chain, []byte(SeedWrapAttestationChallenge), now, [][sha256.Size]byte{root})
			if c.fail {
				if err == nil || !errors.Is(err, ErrNotAttested) {
					t.Fatalf("accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			perr := seedWrapKeyPolicy(f)
			if c.pol != (perr != nil) {
				t.Fatalf("policy said %v", perr)
			}
		})
	}
}

// A chain that is perfectly formed and ends at a root nobody pinned is a chain
// an app made for itself.
func TestAChainToARootNobodyPinnedIsRefused(t *testing.T) {
	k := softwareRSA(t)
	chain, _ := builtChain(t, goodSpec(k))
	if _, err := VerifyAndroidKeyAttestation(chain, []byte(SeedWrapAttestationChallenge), time.Now()); err == nil ||
		!strings.Contains(err.Error(), "Google attestation root") {
		t.Fatalf("an app-made chain was accepted: %v", err)
	}
}

// The two pinned keys are the ones Google publishes: guards a typo in the pin.
func TestThePinnedRootsAreTheOnesGooglePublishes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "android_attestation", "google_roots_2026-11-06.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pems []string
	if err := json.Unmarshal(raw, &pems); err != nil {
		t.Fatal(err)
	}
	if len(pems) != len(googleAttestationRoots) {
		t.Fatalf("Google lists %d roots, %d are pinned", len(pems), len(googleAttestationRoots))
	}
	for i, p := range pems {
		blk, _ := pem.Decode([]byte(p))
		if blk == nil {
			t.Fatal("root does not decode")
		}
		cs, err := splitChain(JoinAttestationChain(blk.Bytes))
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(cs[0].RawSubjectPublicKeyInfo) != googleAttestationRoots[i] {
			t.Errorf("root %d is not the pinned key", i)
		}
	}
}
