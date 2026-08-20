package backup

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// Splitting the way into an archive across several holders, so that the
// recovery words are necessary and not sufficient.
//
// The words used to open everything, offline, with no agent involved — so
// every check this software performed governed only what this software would
// do, and somebody holding the archive and the words simply did not run it. A
// stolen phrase meant immediate, total and silent disclosure, and the waiting
// period protected against impersonation alone.
//
// Now the words open a small bootstrap envelope, and the rest needs the words
// PLUS any k of a set of shares. A share is held by a designated witness, a
// paired device, or a passphrase.
//
// WHY A THRESHOLD RATHER THAN A LIST OF REQUIREMENTS. Requiring a particular
// holder makes the case this exists for unrecoverable: everything burns, every
// device is gone, the owner holds their words and their backup, and a
// required-device rule refuses. A threshold survives that as long as enough
// other shares remain, while still forcing an attacker to obtain k separate
// things.
//
// AND NEVER AN ALTERNATIVE. There is no "this way in, or that one" anywhere.
// An alternative is only as strong as its weakest branch, so offering a PIN
// alongside three witnesses means an attacker uses the PIN. This is the same
// trap the passphrase slot documents: adding a second independent way in makes
// an archive easier to open, not harder.

// HowTheWayInIsSplit describes a threshold over holders.
type HowTheWayInIsSplit struct {
	// Needed is how many shares must be gathered. Never zero, never one
	// without the owner having been told what one means.
	Needed int `json:"needed"`
	// Holders are who has a share, in a stable order.
	Holders []ShareHolder `json:"holders"`
}

// ShareHolder is somebody or something that holds one share.
type ShareHolder struct {
	// ID is how this holder is named. For a witness or a paired device this is
	// its AID — never an email address or a phone number, because a holder
	// reachable only at a handle is one an attacker can take over.
	ID string `json:"id"`
	// Kind is "witness", "device" or "passphrase", for what the screen says
	// rather than for how any of this works.
	Kind string `json:"kind"`
	// PublicKeyB64 is the X25519 key this holder's share is sealed to. The
	// agent writing the backup never holds the matching private key, which is
	// what stops the machine that made an archive from also being able to
	// open it.
	PublicKeyB64 string `json:"public_key_b64"`
	// Address is where to ask, when there is somewhere to ask. Empty for a
	// passphrase, which is not somewhere you send a request.
	Address string `json:"address,omitempty"`
	// KnownAs is what THIS holder files its holding under, and the only
	// identifier a request to it may carry.
	//
	// Never the identity's own AID. A holder is asked to protect somebody
	// without being told who they are, so each relationship gets an
	// identifier of its own — and sending the real one would hand every
	// holder, and anybody watching, the name of the identity they help
	// protect. It would also undo the reason a witness is addressed by a
	// pairwise identifier and a relay of its own in the first place.
	//
	// Empty means the holder files under the identity's own AID, which is
	// only appropriate for one of the owner's own devices.
	KnownAs string `json:"known_as,omitempty"`
}

// SealedShare is one holder's share, sealed so only that holder can read it.
type SealedShare struct {
	HolderID        string `json:"holder_id"`
	EphemeralPubB64 string `json:"ephemeral_pub_b64"`
	WrappedB64      string `json:"wrapped_b64"`
	NonceB64        string `json:"nonce_b64"`
}

// SubsetWrap is the archive key, wrapped under one particular combination of
// shares.
//
// These live inside the bootstrap envelope rather than the cleartext manifest,
// because the combinations name the holders, and who holds a share for an
// identity is not something to write on the outside of its backup.
type SubsetWrap struct {
	// HolderIDs is which shares open this wrap, sorted, so the same set always
	// produces the same key.
	HolderIDs  []string `json:"holder_ids"`
	WrappedB64 string   `json:"wrapped_b64"`
	NonceB64   string   `json:"nonce_b64"`
}

// maxCombinations bounds how many subsets an archive may carry.
//
// The way in is wrapped once per combination of holders that can open it,
// which is what lets this be built from key derivation and authenticated
// encryption that are already in use here rather than from a secret-sharing
// scheme written for the occasion. The cost is combinatorial, so it is
// bounded: three of five is ten wraps, five of nine is a hundred and
// twenty-six, and anything past this is refused when it is chosen rather than
// discovered later.
const maxCombinations = 256

// SplitTheWayIn wraps an archive key so that the words plus any Needed shares
// open it, and fewer never do.
func SplitTheWayIn(bek, seedKEK []byte, split HowTheWayInIsSplit) ([]SealedShare, []SubsetWrap, error) {
	if err := split.Validate(); err != nil {
		return nil, nil, err
	}

	// One secret per holder, sealed so that only that holder can produce it.
	secrets := map[string][]byte{}
	var sealed []SealedShare
	for _, h := range split.Holders {
		s := make([]byte, 32)
		if _, err := rand.Read(s); err != nil {
			return nil, nil, fmt.Errorf("make a share for %s: %w", h.ID, err)
		}
		secrets[h.ID] = s

		pub, err := DecodeB64(h.PublicKeyB64)
		if err != nil {
			return nil, nil, fmt.Errorf("read the key for holder %s: %w", h.ID, err)
		}
		ephPub, wrapped, nonce, err := SealBEK(pub, s)
		if err != nil {
			return nil, nil, fmt.Errorf("seal a share to %s: %w", h.ID, err)
		}
		sealed = append(sealed, SealedShare{
			HolderID:        h.ID,
			EphemeralPubB64: EncodeB64(ephPub),
			WrappedB64:      EncodeB64(wrapped),
			NonceB64:        EncodeB64(nonce),
		})
	}

	var wraps []SubsetWrap
	for _, subset := range combinations(holderIDs(split.Holders), split.Needed) {
		key, err := keyForSubset(seedKEK, subset, secrets)
		if err != nil {
			return nil, nil, err
		}
		wrapped, nonce, err := WrapBEK(key, bek)
		if err != nil {
			return nil, nil, fmt.Errorf("wrap the way in: %w", err)
		}
		wraps = append(wraps, SubsetWrap{
			HolderIDs:  subset,
			WrappedB64: EncodeB64(wrapped),
			NonceB64:   EncodeB64(nonce),
		})
	}
	return sealed, wraps, nil
}

// ReassembleTheWayIn recovers the archive key from the words and the shares
// that came back.
//
// gathered maps a holder's ID to the share it returned. Extra shares are
// welcome; fewer than Needed is a refusal that says how many are missing,
// because "the words were right and they are not enough" is the one thing
// somebody in the middle of a recovery has to be told plainly.
func ReassembleTheWayIn(seedKEK []byte, gathered map[string][]byte, wraps []SubsetWrap) ([]byte, error) {
	if len(gathered) == 0 {
		return nil, fmt.Errorf("no shares were gathered")
	}
	for _, w := range wraps {
		have := true
		for _, id := range w.HolderIDs {
			if _, ok := gathered[id]; !ok {
				have = false
				break
			}
		}
		if !have {
			continue
		}
		key, err := keyForSubset(seedKEK, w.HolderIDs, gathered)
		if err != nil {
			return nil, err
		}
		wrapped, err := DecodeB64(w.WrappedB64)
		if err != nil {
			return nil, fmt.Errorf("read a wrap: %w", err)
		}
		nonce, err := DecodeB64(w.NonceB64)
		if err != nil {
			return nil, fmt.Errorf("read a wrap: %w", err)
		}
		bek, err := UnwrapBEK(key, wrapped, nonce)
		if err != nil {
			// A share that is present but wrong. Keep going: another
			// combination may be satisfied by shares that are right.
			continue
		}
		return bek, nil
	}
	return nil, fmt.Errorf(
		"the recovery words are right, and %d share(s) is not enough to open this backup",
		len(gathered))
}

// keyForSubset derives the key one particular combination of shares produces.
//
// The subset is sorted first, so the same shares always give the same key
// however they arrived. The shares are hashed together and then combined with
// the key the words produced — CombineFactors, the same derivation the
// passphrase slot uses to make two factors necessary rather than either
// sufficient.
func keyForSubset(seedKEK []byte, ids []string, secrets map[string][]byte) ([]byte, error) {
	sorted := append([]string{}, ids...)
	sort.Strings(sorted)

	h := sha256.New()
	for _, id := range sorted {
		s, ok := secrets[id]
		if !ok {
			return nil, fmt.Errorf("no share for holder %s", id)
		}
		// The holder's name goes in with its share. This is belt and braces
		// rather than load-bearing, and worth saying so: the ids are sorted
		// and the secrets are random, so a share presented under the wrong
		// name already changes the concatenation and fails. Removing this
		// binding does not fail any test here. It stays because it makes the
		// derivation say what it means — this share, from this holder — and
		// costs a hash of a short string.
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write(s)
	}
	return CombineFactors(h.Sum(nil), seedKEK)
}

// Validate refuses a split that cannot do what somebody choosing it believes.
func (s HowTheWayInIsSplit) Validate() error {
	if len(s.Holders) == 0 {
		return fmt.Errorf("no holders were named, so there is nothing to split the way in across")
	}
	if s.Needed <= 0 {
		return fmt.Errorf("a threshold of %d would let this open with no shares at all", s.Needed)
	}
	if s.Needed > len(s.Holders) {
		// The failure that protects an identity from its owner rather than
		// from an attacker, and the worst moment to find it is a recovery.
		return fmt.Errorf(
			"this asks for %d shares from %d holders, so it could never be opened",
			s.Needed, len(s.Holders))
	}

	seen := map[string]bool{}
	for _, h := range s.Holders {
		if strings.TrimSpace(h.ID) == "" {
			return fmt.Errorf("a holder was named with no identifier")
		}
		if seen[h.ID] {
			// Otherwise one holder counts twice toward a threshold of two,
			// which is a threshold of one wearing a disguise.
			return fmt.Errorf("holder %s was named twice, and would count twice", h.ID)
		}
		seen[h.ID] = true
		if strings.Contains(h.ID, "@") {
			// A holder reachable only at a handle is one an attacker can take
			// over, and a share released through a hijacked mailbox looks
			// exactly like a share released properly.
			return fmt.Errorf(
				"holder %q looks like an email address; a holder is named by its own identifier", h.ID)
		}
		if h.PublicKeyB64 == "" {
			return fmt.Errorf("holder %s has no key to seal its share to", h.ID)
		}
	}

	if n := countCombinations(len(s.Holders), s.Needed); n > maxCombinations {
		return fmt.Errorf(
			"%d of %d holders would need %d separate wrappings, past the limit of %d",
			s.Needed, len(s.Holders), n, maxCombinations)
	}
	return nil
}

// OnlyShareIsAPassphrase reports a configuration the caller should refuse.
//
// A passphrase may stand alone as a share; a PIN may not, and neither may any
// single low-entropy secret. An attacker holding the archive can try every
// six-digit PIN offline, without asking anybody and without anything noticing,
// so as the only share it is a way in rather than a share.
func (s HowTheWayInIsSplit) OnlyShareIsAPassphrase() bool {
	return len(s.Holders) == 1 && s.Holders[0].Kind == "passphrase"
}

func holderIDs(hs []ShareHolder) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.ID)
	}
	sort.Strings(out)
	return out
}

// combinations lists every set of k ids, each sorted, in a stable order.
func combinations(ids []string, k int) [][]string {
	var out [][]string
	var pick func(start int, chosen []string)
	pick = func(start int, chosen []string) {
		if len(chosen) == k {
			out = append(out, append([]string{}, chosen...))
			return
		}
		for i := start; i < len(ids); i++ {
			pick(i+1, append(chosen, ids[i]))
		}
	}
	pick(0, nil)
	return out
}

func countCombinations(n, k int) int {
	if k > n || k < 0 {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	result := 1
	for i := 0; i < k; i++ {
		result = result * (n - i) / (i + 1)
		if result > maxCombinations*1000 {
			return result // already far past any limit; stop growing
		}
	}
	return result
}
