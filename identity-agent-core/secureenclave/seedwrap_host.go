package secureenclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// A seed wrapper that the app supplies, for the platform where the hardware
// cannot be reached from Go.
//
// Android's Keystore is a Java API. Go has no path to it, which is why the app
// reports what the Keystore can do (capability_android.go) and why the key that
// protects the seed has to live in the app's process as well. The core still
// decides what the answer means, and it does not take the app's word for where
// the key is:
//
//   - the app hands over the key's ATTESTATION CHAIN, and the core checks it
//     back to Google's root (android_key_attestation.go). The hardware that
//     holds the key signed a statement of where it lives; "StrongBox" or "TEE"
//     is read out of that, never declared by the app. The scheme recorded in
//     the envelope comes from it too;
//   - the core does the WRAPPING ITSELF, to the public key the attestation
//     proves belongs to that hardware, and the app only decrypts inside the
//     hardware. An app that attested a real StrongBox key and wrapped under a
//     software key of its own would otherwise pass every check above; here the
//     seed is encrypted to the attested key, and storeSeedAs's round-trip check
//     then proves the hardware holds the private half;
//   - the wrapper counts as hardware protection ONLY while the key protection
//     the app declared is proven usable;
//   - whatever it returns is checked by storeSeedAs like any other wrapper: the
//     seed is not in the output, and the output opens back to the seed.
//
// WHY RSA AND NOT AES. Android attests only asymmetric keys, so an AES key
// cannot say where it lives. The seed is wrapped as a hybrid: a random data key
// seals it with AES-256-GCM, and the data key is sealed with RSA-OAEP under the
// attested key. The blob is
//
//	0x01 | u16 length of the sealed data key | sealed data key | 12-byte nonce | GCM output
//
// with the label seedWrapAAD as additional data.
//
// WHY OAEP WITH SHA-256 AND A SHA-1 MASK (seedwrap_oaep.go). The Android
// Keystore masks with SHA-1 before API 34 whatever the Java spec says, and
// StrongBox is guaranteed only SHA-256 as a digest, so this is the one pairing
// that works in StrongBox and on every phone this app installs on.
//
// Same shape as DeclareHardwareKeyProtection: the app registers before the
// server starts, and an app that registers nothing has no wrapper, said plainly.

// SeedWrapAttestationChallenge is what the app must put in the key's attestation
// request. It names the purpose, so a chain made for something else is refused.
//
// It is a FIXED string, so it does not prove the attestation is fresh: a chain
// recorded earlier for the same key passes just as well. That is fine here,
// because freshness is not what is relied on. Proof that the hardware holds the
// private half right now comes from storeSeedAs's round trip: the core seals to
// the attested public key, the app must decrypt that inside the hardware, and
// the seed is stored only when what comes back opens to the seed. (Why no
// boot-state check is needed: see seedWrapKeyPolicy. What the chain is held to
// besides that, Google's revocation list and the app's declared identity, is in
// attested.)
const SeedWrapAttestationChallenge = "identity-agent-seed-wrap-v1"

const seedWrapAAD = "identity-agent-seed-wrap/v1"

// SeedWrapHost is what an app implements to hold the key that protects the root
// seed in the platform's hardware. On Android: a 2048-bit RSA key in the
// Keystore, generated in StrongBox where the phone has it and in the TEE
// otherwise, never exportable, with no user-authentication requirement because
// the agent runs without a person present, generated with the attestation
// challenge SeedWrapAttestationChallenge.
type SeedWrapHost interface {
	// Available reports whether the key exists or can be made, right now.
	Available() bool
	// AttestationChain is the key's attestation certificate chain, leaf first,
	// each certificate's DER preceded by its length as 4 bytes big-endian (see
	// JoinAttestationChain). Empty when the key cannot be attested.
	AttestationChain() []byte
	// UnwrapKey decrypts a data key that was RSA-OAEP (SHA-256, SHA-1 mask) encrypted to the
	// key's public half, inside the hardware.
	UnwrapKey(wrapped []byte) ([]byte, error)
}

var (
	seedWrapHostMu sync.RWMutex
	seedWrapHost   SeedWrapHost

	// attestationRoots and attestationClock are what the check is made against.
	// Tests replace them; nothing else does.
	attestationRoots = googleAttestationRoots
	attestationClock = time.Now

	// verifiedLevel is the level the last SUCCESSFUL check found. The scheme
	// recorded with a seed comes from it, never from a second read of the app's
	// chain, which the app could change between the check and the label.
	verifiedLevel string
	// verifiedCaveat is what the last successful check let through unchecked
	// (a development build with no revocation list), "" when nothing.
	verifiedCaveat string
)

// DeclareSeedWrapHost registers the app's wrapper. Called through mobilecore
// before the server starts. Passing nil removes it.
func DeclareSeedWrapHost(h SeedWrapHost) {
	seedWrapHostMu.Lock()
	seedWrapHost = h
	verifiedLevel, verifiedCaveat = "", ""
	seedWrapHostMu.Unlock()
}

func declaredSeedWrapHost() SeedWrapHost {
	seedWrapHostMu.RLock()
	defer seedWrapHostMu.RUnlock()
	return seedWrapHost
}

// ProfileSeedWrapHost is what an app implements, besides SeedWrapHost, to hold a
// Keystore key per profile (ADR-074 section 3): the same three calls, each
// naming the Keystore alias the key is under. The app makes the key under that
// alias on first use, with the same properties and the same attestation
// challenge as the device-wide key. An app that registers none keeps one key for
// every profile, as before, and says so by registering nothing.
type ProfileSeedWrapHost interface {
	AvailableFor(alias string) bool
	AttestationChainFor(alias string) []byte
	UnwrapKeyFor(alias string, wrapped []byte) ([]byte, error)
}

// androidSeedAliasBase is the Keystore alias prefix of a profile's key.
const androidSeedAliasBase = "identity-agent-seed-wrap"

var seedWrapProfileHost ProfileSeedWrapHost

// DeclareProfileSeedWrapHost registers the app's per-profile wrapper. Called
// through mobilecore before the server starts, beside DeclareSeedWrapHost.
// Passing nil removes it.
func DeclareProfileSeedWrapHost(h ProfileSeedWrapHost) {
	seedWrapHostMu.Lock()
	seedWrapProfileHost = h
	verifiedLevel, verifiedCaveat = "", ""
	seedWrapHostMu.Unlock()
}

func declaredProfileSeedWrapHost() ProfileSeedWrapHost {
	seedWrapHostMu.RLock()
	defer seedWrapHostMu.RUnlock()
	return seedWrapProfileHost
}

// hostedSeedWrapper is the app's wrapper as the seam sees it. With an alias it
// is the app's key of that name, reached through the per-profile host.
type hostedSeedWrapper struct {
	host  SeedWrapHost
	alias string
}

// KeyNameFor and ForKey make this a per-profile wrapper (PerProfileKeys) when
// the app has registered a per-profile host. With none, KeyNameFor is empty and
// every profile uses the device-wide key.
func (w hostedSeedWrapper) KeyNameFor(profile string) string {
	if declaredProfileSeedWrapHost() == nil {
		return ""
	}
	return ProfileKeyName(androidSeedAliasBase, profile)
}

func (w hostedSeedWrapper) ForKey(name string) SeedWrapper {
	return hostedSeedWrapper{host: w.host, alias: name}
}

// The three calls the host makes, to the device-wide key or the alias's.
func (w hostedSeedWrapper) hostAvailable() bool {
	if w.alias == "" {
		return w.host.Available()
	}
	h := declaredProfileSeedWrapHost()
	return h != nil && h.AvailableFor(w.alias)
}

func (w hostedSeedWrapper) hostChain() []byte {
	if w.alias == "" {
		return w.host.AttestationChain()
	}
	if h := declaredProfileSeedWrapHost(); h != nil {
		return h.AttestationChainFor(w.alias)
	}
	return nil
}

func (w hostedSeedWrapper) hostUnwrapKey(wrapped []byte) ([]byte, error) {
	if w.alias == "" {
		return w.host.UnwrapKey(wrapped)
	}
	h := declaredProfileSeedWrapHost()
	if h == nil {
		return nil, fmt.Errorf("the app registered no per-profile seed wrapper, so key %q cannot be used", w.alias)
	}
	return h.UnwrapKeyFor(w.alias, wrapped)
}

// declaredHostSeedWrapper is the wrapper for whatever the app registered, or nil
// when it registered nothing.
func declaredHostSeedWrapper() SeedWrapper {
	h := declaredSeedWrapHost()
	if h == nil {
		return nil
	}
	return hostedSeedWrapper{host: h}
}

// attested is what the attestation proves about the key, or why it proves
// nothing: the chain to Google's root, the key's policy, the app it was made
// for (android_app_identity.go) and Google's revocation list
// (android_attestation_status.go). Checked afresh each time: the chain is a
// signature check and a parse. The revocation list is the one input that is not
// recomputed: it is held in memory and fetched at most once a day, never per call.
//
// A check that fails clears the level the last one found, so nothing goes on
// naming hardware that the latest check did not prove.
func (w hostedSeedWrapper) attested() (*AndroidKeyFacts, error) {
	f, err := w.checkAttestation()
	if err != nil {
		seedWrapHostMu.Lock()
		verifiedLevel, verifiedCaveat = "", ""
		seedWrapHostMu.Unlock()
		return nil, err
	}
	seedWrapHostMu.Lock()
	verifiedLevel = f.LevelName()
	verifiedCaveat = f.caveat()
	seedWrapHostMu.Unlock()
	return f, nil
}

func (w hostedSeedWrapper) checkAttestation() (*AndroidKeyFacts, error) {
	chain := w.hostChain()
	if len(chain) == 0 {
		return nil, notAttested("the app supplied no attestation chain")
	}
	f, err := verifyAndroidKeyAttestation(chain, []byte(SeedWrapAttestationChallenge), attestationClock(), attestationRoots)
	if err != nil {
		return nil, err
	}
	if err := seedWrapKeyPolicy(f); err != nil {
		return nil, err
	}
	if err := checkAppIdentity(f); err != nil {
		return nil, err
	}
	if err := checkRevocation(f, attestationClock()); err != nil {
		return nil, err
	}
	return f, nil
}

// caveat is what the check that licensed this wrapper let through unchecked:
// storeSeedAs records it in the envelope, so the file says it.
func (w hostedSeedWrapper) caveat() string {
	seedWrapHostMu.RLock()
	defer seedWrapHostMu.RUnlock()
	return verifiedCaveat
}

// Scheme says which hardware holds the key: the level the last successful check
// of the attestation found. Wrap and Available run that check, and storeSeedAs
// asks for the scheme only after one of them has, so the label on a stored seed
// is always one that was verified.
//
// When no check has succeeded in this process (a stored seed being opened before
// anything was stored), it reads the level out of the chain WITHOUT checking it.
// That reading only helps a stored seed find the wrapper that opens it, and
// opensScheme below accepts any level there, so a chain that can no longer be
// verified or read cannot make a stored seed unreadable.
func (w hostedSeedWrapper) Scheme() string {
	seedWrapHostMu.RLock()
	level := verifiedLevel
	seedWrapHostMu.RUnlock()
	if level == "" {
		level = "unattested"
		if chain, err := splitChain(w.hostChain()); err == nil {
			if f, err := readKeyDescription(chain[0]); err == nil {
				level = f.LevelName()
			}
		}
	}
	return hostedSchemePrefix + level + hostedSchemeSuffix
}

const (
	hostedSchemePrefix = "android-keystore-"
	hostedSchemeSuffix = "-rsa2048oaep-aes256gcm"
)

// AndroidKeystoreLevel names the Android hardware a seed-wrap scheme was
// attested to: "strongbox" or "tee". Empty for any other scheme, including one
// whose key could not be attested, so a caller never names hardware that was
// not proven.
func AndroidKeystoreLevel(scheme string) string {
	if !(hostedSeedWrapper{}).opensScheme(scheme) {
		return ""
	}
	switch level := scheme[len(hostedSchemePrefix) : len(scheme)-len(hostedSchemeSuffix)]; level {
	case "strongbox", "tee":
		return level
	}
	return ""
}

// opensScheme: this wrapper opens any seed it wrote, whichever hardware level
// its label names. The hardware itself decides whether it can decrypt.
func (w hostedSeedWrapper) opensScheme(scheme string) bool {
	return len(scheme) > len(hostedSchemePrefix)+len(hostedSchemeSuffix) &&
		scheme[:len(hostedSchemePrefix)] == hostedSchemePrefix &&
		scheme[len(scheme)-len(hostedSchemeSuffix):] == hostedSchemeSuffix
}

// Available is true only when the app says its key works, the app has proven
// the phone's key protection usable, AND the key's attestation proves it was
// generated in a TEE or StrongBox and suits the seed.
func (w hostedSeedWrapper) Available() bool {
	if !detectCapability().RootKeyPermitted() || !w.hostAvailable() {
		return false
	}
	_, err := w.attested()
	return err == nil
}

// WhyUnavailable says why the attestation was not accepted, for the report.
func (w hostedSeedWrapper) whyNotAttested() string {
	if _, err := w.attested(); err != nil {
		return err.Error()
	}
	return ""
}

func (w hostedSeedWrapper) Wrap(plain []byte) ([]byte, error) {
	if !detectCapability().RootKeyPermitted() || !w.hostAvailable() {
		return nil, fmt.Errorf("the app's seed wrapper is not usable")
	}
	f, err := w.attested()
	if err != nil {
		return nil, err
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	sealedKey, err := oaepEncryptSHA256MGF1SHA1(f.PublicKey, dek)
	if err != nil {
		return nil, fmt.Errorf("seal the data key to the attested key: %w", err)
	}
	if len(sealedKey) > 0xFFFF {
		return nil, fmt.Errorf("sealed data key too long")
	}
	gcm, err := newSeedGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := []byte{seedWrapFormat, byte(len(sealedKey) >> 8), byte(len(sealedKey))}
	out = append(out, sealedKey...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, []byte(seedWrapAAD)), nil
}

// Unwrap does not re-verify the attestation: a seed that was written under a
// checked key must stay readable if Google reissues its roots, and the
// hardware's own refusal to decrypt for a key it does not hold is the check
// that matters here.
func (w hostedSeedWrapper) Unwrap(blob []byte) ([]byte, error) {
	if w.host == nil {
		return nil, fmt.Errorf("the app's seed wrapper is not usable")
	}
	if len(blob) < 3 || blob[0] != seedWrapFormat {
		return nil, fmt.Errorf("not a seed wrapped by an app's Keystore key")
	}
	n := int(blob[1])<<8 | int(blob[2])
	if len(blob) < 3+n+12+16 {
		return nil, fmt.Errorf("the wrapped seed is cut off")
	}
	sealedKey, rest := blob[3:3+n], blob[3+n:]
	dek, err := w.hostUnwrapKey(sealedKey)
	if err != nil {
		return nil, fmt.Errorf("the hardware key would not open the data key: %w", err)
	}
	gcm, err := newSeedGCM(dek)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], []byte(seedWrapAAD))
	if err != nil {
		return nil, fmt.Errorf("the wrapped seed did not authenticate: %w", err)
	}
	return plain, nil
}

const seedWrapFormat = 1

func newSeedGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("the data key is %d bytes, not 32", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// noSeedWrapHostWhy is the reason when the app registered no seed wrapper. It is
// declared here, untagged, so every host can test the wording.
const noSeedWrapHostWhy = "this app has not supplied its StrongBox/TEE Keystore key for the seed yet " +
	"(no seed wrapper is registered)"

// A wrapped blob must not carry the seed it is supposed to hide. The
// sealedVolumeWrapper is the one exception and is identity on purpose.
//
// The exemption is a TYPE check, not a match on the scheme name: a wrapper from
// anywhere else (an app's host wrapper, a test double) that merely names itself
// "sealed-volume" is still checked for leaking the seed.
func wrapLeaksTheSeed(w SeedWrapper, blob, seed []byte) bool {
	if _, sealed := w.(sealedVolumeWrapper); sealed {
		return false
	}
	return bytes.Contains(blob, seed)
}
