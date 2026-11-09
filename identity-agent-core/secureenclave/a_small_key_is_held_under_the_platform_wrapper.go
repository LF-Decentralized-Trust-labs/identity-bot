package secureenclave

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
)

// A small key, held the way the root seed is: under the platform wrapper where
// this machine has one.
//
// Callers that keep their own secrets on disk (the backup credential store holds
// a cloud sign-in token this way) need a key for them that is not itself a plain
// file beside them. This is the seed's wrapper, used for that: the caller keeps
// the returned bytes wherever it keeps its files, and gives them back to
// OpenKeyHeldUnderTheWrapper to get the key again.
//
// It does not refuse where there is no wrapper, unlike the root seed. A token
// to one person's cloud drive is not an identity, and a machine that cannot
// protect a key says so in the envelope and in the log instead of being unable
// to back up at all. Where a wrapper works, it is always used.

const holderHeldKey = "held-key"

type heldKeyEnvelope struct {
	V          int    `json:"v"`
	Wrap       string `json:"wrap"`
	Key        string `json:"key"` // wrapped by the platform, or in the clear when Wrap is "none"
	Protection string `json:"protection,omitempty"`
	Why        string `json:"why,omitempty"`
	Holder     string `json:"holder"`
}

// ErrNotAHeldKey is OpenKeyHeldUnderTheWrapper's answer to bytes that are not
// an envelope written by KeyToHoldUnderTheWrapper, so a caller can tell a key
// it stored before this existed from a damaged one.
var ErrNotAHeldKey = errors.New("not a held-key envelope")

// KeyToHoldUnderTheWrapper returns the bytes to store for key. what names the
// use and is bound into the envelope, so an envelope for one use does not open
// as another's.
func KeyToHoldUnderTheWrapper(dataDir, what string, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("no key to hold")
	}
	w := platformSeedWrapper()
	env := heldKeyEnvelope{V: 1, Wrap: seedWrapNone, Key: base64.StdEncoding.EncodeToString(key),
		Protection: ProtectionUnwrapped, Why: whyNotWrappedAt(dataDir), Holder: holderHeldKey + ":" + what}
	if wrapperWorksAt(w, dataDir) {
		blob, protection, why, err := wrapAndCheck(w, what+" key", key)
		if err != nil {
			return nil, err
		}
		env.Wrap, env.Key, env.Protection, env.Why = w.Scheme(), base64.StdEncoding.EncodeToString(blob), protection, why
	} else {
		log.Printf("[secureenclave] the %s key is held UNWRAPPED: %s", what, env.Why)
	}
	return json.Marshal(env)
}

// OpenKeyHeldUnderTheWrapper returns the key KeyToHoldUnderTheWrapper made
// held. wrapped says whether the platform wrapper protects it, so a caller
// holding an unwrapped one can put it through the wrapper when one appears.
func OpenKeyHeldUnderTheWrapper(what string, held []byte) (key []byte, wrapped bool, err error) {
	var env heldKeyEnvelope
	if jerr := json.Unmarshal(held, &env); jerr != nil || env.V < 1 || env.Wrap == "" {
		return nil, false, ErrNotAHeldKey
	}
	if env.Holder != holderHeldKey+":"+what {
		return nil, false, fmt.Errorf("this key was held for something else")
	}
	k, err := base64.StdEncoding.DecodeString(env.Key)
	if err != nil {
		return nil, false, fmt.Errorf("held key envelope corrupt: %w", err)
	}
	if env.Wrap == seedWrapNone {
		return k, false, nil
	}
	w := platformSeedWrapper()
	if w == nil || !wrapperOpensScheme(w, env.Wrap) {
		return nil, true, fmt.Errorf("the %s key is wrapped with %q, which this build/platform cannot open", what, env.Wrap)
	}
	if k, err = w.Unwrap(k); err != nil {
		return nil, true, fmt.Errorf("%s key unwrap failed (%s): %w", what, env.Wrap, err)
	}
	return k, true, nil
}

// TheWrapperWorksHere reports whether a key given to KeyToHoldUnderTheWrapper
// would be wrapped on this machine.
func TheWrapperWorksHere(dataDir string) bool {
	return wrapperWorksAt(platformSeedWrapper(), dataDir)
}
