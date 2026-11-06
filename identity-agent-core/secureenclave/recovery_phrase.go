package secureenclave

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/internal/atomicfile"
)

// THE RECOVERY PHRASE IS THE ROOT SEED IN ANOTHER SPELLING.
//
// The seed is PBKDF2 of the phrase, so the phrase reproduces the seed and the
// seed cannot reproduce the phrase. An app that keeps the phrase in its own
// secure storage (flutter_secure_storage: DPAPI on Windows, plugin-dependent
// elsewhere) keeps the root seed in software, and the rule that production does
// not run without hardware protection of the root seed (owner, 2026-11-05) would
// be met on the seed and missed on its twin.
//
// So the phrase is held HERE, under the same wrapper as the seed, by the same
// rules: a production build refuses to write it where it cannot be wrapped, and
// a development build may hold it unwrapped and says so.
//
// Why held at all, rather than shown once and kept in memory until the owner
// confirms they wrote it down: closing the app in that window would lose the
// only copy, the identity would exist, and nobody could ever recover it. Holding
// it wrapped keeps recovery possible across a restart, and costs nothing the
// seed does not already cost.
//
// The wrapper cannot take a phrase directly: the TPM wrapper is RSA-OAEP and
// carries at most a few hundred bytes, a 24-word phrase is close to that.
// So a fresh random key encrypts the phrase (AES-256-GCM) and the wrapper
// protects that key. Opening the phrase needs the hardware exactly as opening
// the seed does.

// phraseMu serialises store, load and forget: one file, several requests.
var phraseMu sync.Mutex

// ErrNoRecoveryPhrase is LoadRecoveryPhrase's answer when none is held. Any
// other failure means one is held and could not be read.
var ErrNoRecoveryPhrase = errors.New("no recovery phrase is held here")

// ErrADifferentPhraseIsHeld is the answer to holding a phrase where a different
// one is already held, by a caller that did not say it is replacing it. The
// root seed is refused the same way (handleSetRootSeed): the phrase held may be
// the only copy of an identity, and a re-onboarding, or a second app process
// that read "none" a moment before another one finished a phrase move, would
// otherwise overwrite it without a word. Only finishing a move, and a
// deliberate reset, replace a held phrase (ReplaceRecoveryPhrase).
var ErrADifferentPhraseIsHeld = errors.New("a different recovery phrase is already held here")

const holderRecoveryPhrase = "recovery-phrase"

// holderPhraseMovingTo is the second phrase held while an identity moves to a
// new phrase (ADR-061 section 10): between the move's two rotations both
// phrases are needed, and losing either loses the identity. It is held under
// the same wrapper, by the same rules, as the phrase in force, in a file of
// its own; the holder name is bound into its encryption, so neither file can be
// copied over the other and still open.
const holderPhraseMovingTo = "recovery-phrase-moving-to"

// the longest phrase accepted: 24 words of at most 8 letters and 23 spaces,
// with room to spare. Anything longer is not a phrase.
const maxRecoveryPhraseBytes = 512

type phraseEnvelope struct {
	V          int    `json:"v"`
	Wrap       string `json:"wrap"`
	Key        string `json:"key"`    // the data key, wrapped (or in the clear when Wrap is "none")
	Sealed     string `json:"sealed"` // nonce || AES-GCM(phrase)
	Protection string `json:"protection,omitempty"`
	Why        string `json:"why,omitempty"`
	Holder     string `json:"holder"`
}

func recoveryPhrasePath(dataDir string) string {
	return filepath.Join(dataDir, "secureenclave", "recovery_phrase.key")
}

func phraseMovingToPath(dataDir string) string {
	return filepath.Join(dataDir, "secureenclave", "recovery_phrase_moving_to.key")
}

// phraseSlot names one of the two places a phrase can be held.
type phraseSlot struct {
	holder string
	path   func(dataDir string) string
}

var (
	slotInForce  = phraseSlot{holder: holderRecoveryPhrase, path: recoveryPhrasePath}
	slotMovingTo = phraseSlot{holder: holderPhraseMovingTo, path: phraseMovingToPath}
)

// StoreRecoveryPhrase holds a person's recovery phrase. It refuses, having
// written nothing, wherever StoreIdentityRootSeed would refuse, and outside a
// development build it cannot write the phrase unwrapped.
//
// Holding the phrase already held is a no-op. A different phrase already held
// is refused with ErrADifferentPhraseIsHeld, as is any held phrase that cannot
// be opened to compare: it is not replaced unless the caller says so
// (ReplaceRecoveryPhrase).
func StoreRecoveryPhrase(dataDir string, phrase []byte) error {
	return storeRecoveryPhrase(slotInForce, dataDir, phrase, platformSeedWrapper(), !isDevBuild(), false)
}

// ReplaceRecoveryPhrase holds phrase in place of whatever is held. For
// finishing a phrase move, when the phrase moved to becomes the phrase in
// force, and for a deliberate reset; never for a migration or an onboarding.
func ReplaceRecoveryPhrase(dataDir string, phrase []byte) error {
	return storeRecoveryPhrase(slotInForce, dataDir, phrase, platformSeedWrapper(), !isDevBuild(), true)
}

// StorePhraseMovingTo holds the phrase an identity is moving to, beside the
// phrase in force, under the same wrapper and with the same refusals,
// including ErrADifferentPhraseIsHeld: a move already under way is dropped
// first (ForgetPhraseMovingTo), never overwritten.
func StorePhraseMovingTo(dataDir string, phrase []byte) error {
	return storeRecoveryPhrase(slotMovingTo, dataDir, phrase, platformSeedWrapper(), !isDevBuild(), false)
}

// ReplacePhraseMovingTo is ReplaceRecoveryPhrase for the phrase moved to.
func ReplacePhraseMovingTo(dataDir string, phrase []byte) error {
	return storeRecoveryPhrase(slotMovingTo, dataDir, phrase, platformSeedWrapper(), !isDevBuild(), true)
}

func storeRecoveryPhrase(slot phraseSlot, dataDir string, phrase []byte, w SeedWrapper, requireWrap, replacing bool) error {
	phraseMu.Lock()
	defer phraseMu.Unlock()
	if len(phrase) == 0 || len(phrase) > maxRecoveryPhraseBytes {
		return fmt.Errorf("a recovery phrase is between 1 and %d bytes", maxRecoveryPhraseBytes)
	}
	if !replacing {
		held, err := loadPhraseLocked(slot, dataDir)
		switch {
		case err == nil && bytes.Equal(held, phrase):
			return nil
		case err == nil:
			return ErrADifferentPhraseIsHeld
		case errors.Is(err, ErrNoRecoveryPhrase):
		case IsRootSeedRefusal(err):
			return err
		default:
			return fmt.Errorf("%w: the one held could not be opened to compare (%v)", ErrADifferentPhraseIsHeld, err)
		}
	}
	// The protection rule the seed is held to (key protection proven usable AND
	// a wrapper that works), not its founding rule: where an identity may be
	// founded is a question about the identity, and a phrase that exists must be
	// protected wherever it exists.
	works := wrapperWorksAt(w, dataDir)
	if requireWrap && !rootSeedMayLiveHere(detectCapability(), works, false) {
		reason := "its key protection is not proven usable"
		if detectCapability().RootKeyPermitted() {
			reason = "key hardware is usable but " + whyNotWrappedAt(dataDir)
		}
		return cannotLiveHere(detectCapability(), reason+", so the recovery phrase could only be written as a plain file")
	}

	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		return err
	}
	sealed, err := sealPhrase(slot.holder, dk, phrase)
	if err != nil {
		return err
	}
	env := phraseEnvelope{V: 1, Wrap: seedWrapNone, Key: base64.StdEncoding.EncodeToString(dk),
		Sealed: base64.StdEncoding.EncodeToString(sealed), Protection: ProtectionUnwrapped,
		Why: whyNotWrappedAt(dataDir), Holder: slot.holder}
	if works {
		blob, werr := w.Wrap(dk)
		if werr != nil {
			return fmt.Errorf("wrap recovery phrase key (%s): %w", w.Scheme(), werr)
		}
		if len(blob) == 0 || wrapLeaksTheSeed(w, blob, dk) {
			return fmt.Errorf("the %s wrapper returned the key in the clear, "+
				"so the recovery phrase is not recorded as wrapped", w.Scheme())
		}
		back, uerr := w.Unwrap(blob)
		if uerr != nil || !bytes.Equal(back, dk) {
			return fmt.Errorf("wrap verification failed (%s): %v", w.Scheme(), uerr)
		}
		protection := ProtectionHardwareWrapped
		if _, sv := w.(sealedVolumeWrapper); sv {
			protection = ProtectionSealedVolume
		}
		env.Wrap, env.Key, env.Protection, env.Why = w.Scheme(), base64.StdEncoding.EncodeToString(blob), protection, ""
	}
	if requireWrap && env.Wrap == seedWrapNone {
		return cannotLiveHere(detectCapability(), "the recovery phrase would have been written unwrapped")
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	p := slot.path(dataDir)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	if err := atomicfile.Write(p, data, 0600); err != nil {
		return err
	}
	if env.Wrap == seedWrapNone {
		log.Printf("[secureenclave] *** DEVELOPMENT BUILD *** the recovery phrase is held UNWRAPPED (%s); a production build refuses to", env.Why)
	}
	return nil
}

// LoadRecoveryPhrase returns the held phrase. A phrase held unwrapped is served
// only by a development build: a production build refuses it with the same
// refusal as an unwrapped root seed.
func LoadRecoveryPhrase(dataDir string) ([]byte, error) {
	return loadPhrase(slotInForce, dataDir)
}

// LoadPhraseMovingTo returns the phrase an identity is moving to, with the
// refusals LoadRecoveryPhrase gives. ErrNoRecoveryPhrase means no move is held.
func LoadPhraseMovingTo(dataDir string) ([]byte, error) {
	return loadPhrase(slotMovingTo, dataDir)
}

func loadPhrase(slot phraseSlot, dataDir string) ([]byte, error) {
	phraseMu.Lock()
	defer phraseMu.Unlock()
	return loadPhraseLocked(slot, dataDir)
}

func loadPhraseLocked(slot phraseSlot, dataDir string) ([]byte, error) {
	raw, err := os.ReadFile(slot.path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrNoRecoveryPhrase, err)
	}
	if err != nil {
		return nil, fmt.Errorf("recovery phrase not available in secure storage: %w", err)
	}
	var env phraseEnvelope
	if jerr := json.Unmarshal(raw, &env); jerr != nil || env.V < 1 || env.Wrap == "" {
		return nil, fmt.Errorf("recovery phrase envelope corrupt")
	}
	key, err := base64.StdEncoding.DecodeString(env.Key)
	if err != nil {
		return nil, fmt.Errorf("recovery phrase envelope corrupt: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Sealed)
	if err != nil {
		return nil, fmt.Errorf("recovery phrase envelope corrupt: %w", err)
	}
	if env.Wrap == seedWrapNone {
		if aProductionBuild() {
			return nil, existingSeedRefusal("the recovery phrase is held unwrapped: " + env.Why)
		}
	} else {
		w := platformSeedWrapper()
		if w == nil || w.Scheme() != env.Wrap {
			return nil, fmt.Errorf("the recovery phrase is wrapped with %q, which this build/platform cannot open", env.Wrap)
		}
		if key, err = w.Unwrap(key); err != nil {
			return nil, fmt.Errorf("recovery phrase unwrap failed (%s): %w", env.Wrap, err)
		}
	}
	return openPhrase(slot.holder, key, sealed)
}

// RecoveryPhraseProtection says what protects the held phrase, from its
// envelope alone: ok is false when none is held.
func RecoveryPhraseProtection(dataDir string) (protection, scheme string, ok bool) {
	return phraseProtection(slotInForce, dataDir)
}

// PhraseMovingToProtection is RecoveryPhraseProtection for the phrase moved to.
func PhraseMovingToProtection(dataDir string) (protection, scheme string, ok bool) {
	return phraseProtection(slotMovingTo, dataDir)
}

func phraseProtection(slot phraseSlot, dataDir string) (protection, scheme string, ok bool) {
	raw, err := os.ReadFile(slot.path(dataDir))
	if err != nil {
		return "", "", false
	}
	var env phraseEnvelope
	if json.Unmarshal(raw, &env) != nil || env.Wrap == "" {
		return "", "", false
	}
	return env.Protection, env.Wrap, true
}

// ForgetRecoveryPhrase removes the held phrase and confirms it is gone. Nothing
// held is not an error.
func ForgetRecoveryPhrase(dataDir string) error {
	return forgetPhrase(slotInForce, dataDir)
}

// ForgetPhraseMovingTo removes the held phrase moved to and confirms it is gone.
func ForgetPhraseMovingTo(dataDir string) error {
	return forgetPhrase(slotMovingTo, dataDir)
}

func forgetPhrase(slot phraseSlot, dataDir string) error {
	phraseMu.Lock()
	defer phraseMu.Unlock()
	p := slot.path(dataDir)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("the recovery phrase is still there after removal")
	}
	return nil
}

func sealPhrase(holder string, key, phrase []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, phrase, []byte(holder)), nil
}

func openPhrase(holder string, key, sealed []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, fmt.Errorf("recovery phrase envelope corrupt")
	}
	out, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], []byte(holder))
	if err != nil {
		return nil, fmt.Errorf("recovery phrase envelope corrupt: %w", err)
	}
	return out, nil
}
