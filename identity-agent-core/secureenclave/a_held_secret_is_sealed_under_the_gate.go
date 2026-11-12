package secureenclave

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/atomicfile"
)

// THE OTHER SECRETS A LOGGED-OUT IDENTITY KEEPS (ADR-074 section 2).
//
// The root seed is sealed under the gate key GK. The recovery phrase reproduces
// that seed and the backup credential key opens a person's cloud sign-in, so
// they get the same layer: under the hardware wrapper alone, anything that can
// ask the device to unwrap (any process of the same user, on the same machine)
// reads them while the identity is locked. With the gate layer there is no key
// to open them with until the owner passes the provider.
//
// Same rule as the seed: a gated profile that is locked writes and reads none
// of them; a profile with no gate is served exactly as before.

// keyUnderGateSuffix names a held key that carries the gate layer, so an
// envelope written without it does not open as one written with it.
const keyUnderGateSuffix = "+gate"

// HoldKeyUnderTheGate is KeyToHoldUnderTheWrapper with the gate layer: for a
// gated profile the key is sealed under GK first, and a locked profile gets
// ErrIdentityLocked and nothing is written.
func HoldKeyUnderTheGate(dataDir, what string, key []byte) ([]byte, error) {
	sealer, gated, err := theGateForThisSeed(dataDir)
	if err != nil {
		return nil, err
	}
	if !gated {
		return KeyToHoldUnderTheWrapper(dataDir, what, key)
	}
	sealed, err := sealer.Seal(key)
	if err != nil {
		return nil, fmt.Errorf("seal the %s key under the gate key: %w", what, err)
	}
	return KeyToHoldUnderTheWrapper(dataDir, what+keyUnderGateSuffix, sealed)
}

// OpenKeyHeldUnderTheGate reverses HoldKeyUnderTheGate. A locked, gated profile
// gets ErrIdentityLocked whatever is on disk. needsGate is true when the profile
// is gated and the key was held before it had the gate layer: it is served, and
// the caller holds it again with HoldKeyUnderTheGate.
func OpenKeyHeldUnderTheGate(dataDir, what string, held []byte) (key []byte, wrapped, needsGate bool, err error) {
	sealer, gated, err := theGateForThisSeed(dataDir)
	if err != nil {
		return nil, false, false, err
	}
	if !gated {
		key, wrapped, err = OpenKeyHeldUnderTheWrapper(what, held)
		return key, wrapped, false, err
	}
	if sealed, w, gerr := OpenKeyHeldUnderTheWrapper(what+keyUnderGateSuffix, held); gerr == nil {
		plain, oerr := sealer.Open(sealed)
		if oerr != nil {
			return nil, w, false, fmt.Errorf("the %s key does not open under the gate key: %w", what, oerr)
		}
		return plain, w, false, nil
	}
	key, wrapped, err = OpenKeyHeldUnderTheWrapper(what, held)
	return key, wrapped, err == nil, err
}

var (
	gateKeyFilesMu sync.Mutex
	gateKeyFiles   = map[string]string{} // path relative to the data directory -> what
)

// RegisterGateSealedKeyFile tells this package that the file at rel (relative to
// a profile's data directory) holds a key made by HoldKeyUnderTheGate for what,
// so that changing the gate key (the identity secret) re-seals it with the seed.
// A package that holds such a key calls this once, at init.
func RegisterGateSealedKeyFile(rel, what string) {
	gateKeyFilesMu.Lock()
	defer gateKeyFilesMu.Unlock()
	gateKeyFiles[rel] = what
}

// ReSealGateHeldSecrets moves everything held under the gate key besides the
// root seed (the recovery phrases and the registered key files) from one key to
// another. open must accept what either key sealed, so that doing it twice, as a
// crash and a retry do, is the same as once. Nothing held is not an error.
func ReSealGateHeldSecrets(dataDir string, open, seal func([]byte) ([]byte, error)) error {
	for _, slot := range []phraseSlot{slotInForce, slotMovingTo} {
		if err := reSealPhrase(slot, dataDir, open, seal); err != nil {
			return err
		}
	}
	gateKeyFilesMu.Lock()
	files := map[string]string{}
	for k, v := range gateKeyFiles {
		files[k] = v
	}
	gateKeyFilesMu.Unlock()
	for rel, what := range files {
		if err := reSealKeyFile(filepath.Join(dataDir, rel), what, dataDir, open, seal); err != nil {
			return err
		}
	}
	return nil
}

func reSealKeyFile(path, what, dataDir string, open, seal func([]byte) ([]byte, error)) error {
	held, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var plain []byte
	if sealed, _, gerr := OpenKeyHeldUnderTheWrapper(what+keyUnderGateSuffix, held); gerr == nil {
		if plain, err = open(sealed); err != nil {
			return fmt.Errorf("the %s key does not open under the gate key: %w", what, err)
		}
	} else if plain, _, err = OpenKeyHeldUnderTheWrapper(what, held); err != nil {
		return fmt.Errorf("the %s key cannot be opened to re-seal it: %w", what, err)
	}
	sealed, err := seal(plain)
	if err != nil {
		return err
	}
	out, err := KeyToHoldUnderTheWrapper(dataDir, what+keyUnderGateSuffix, sealed)
	if err != nil {
		return err
	}
	return atomicfile.Write(path, out, 0o600)
}

func reSealPhrase(slot phraseSlot, dataDir string, open, seal func([]byte) ([]byte, error)) error {
	phraseMu.Lock()
	defer phraseMu.Unlock()
	raw, err := os.ReadFile(slot.path(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var env phraseEnvelope
	if json.Unmarshal(raw, &env) != nil || env.V < 1 || env.Wrap == "" {
		return fmt.Errorf("recovery phrase envelope corrupt")
	}
	dk, err := phraseDataKey(env)
	if err != nil {
		return err
	}
	sealedB, err := base64.StdEncoding.DecodeString(env.Sealed)
	if err != nil {
		return fmt.Errorf("recovery phrase envelope corrupt: %w", err)
	}
	inner, err := openPhrase(slot.holder, dk, sealedB)
	if err != nil {
		return err
	}
	if env.Gate != "" {
		if inner, err = open(inner); err != nil {
			return fmt.Errorf("the recovery phrase does not open under the gate key: %w", err)
		}
	}
	gated, err := seal(inner)
	if err != nil {
		return err
	}
	re, err := sealPhrase(slot.holder, dk, gated)
	if err != nil {
		return err
	}
	env.Sealed, env.Gate = base64.StdEncoding.EncodeToString(re), gateScheme
	out, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if bytes.Equal(out, raw) {
		return nil
	}
	return atomicfile.Write(slot.path(dataDir), out, 0o600)
}
