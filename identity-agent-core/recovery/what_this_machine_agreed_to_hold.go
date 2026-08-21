package recovery

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"identity-agent-core/backup"
)

// What this machine agreed to hold for other identities.
//
// A holding is small on purpose: an identifier, a private key, and the promise
// this machine made. No archive, no share, nothing about the person whose
// identity it protects. Agreeing to help should not mean learning anything.

// AgreeToHold is asked of a machine that is being invited to hold a share.
type AgreeToHold struct {
	// IdentityAID is what the holding is filed under. For a recovery witness
	// this is a pairwise identifier made for this relationship alone, so that
	// agreeing to help does not tell this machine who the person is, and so
	// that naming the holder in a backup reveals nothing about them.
	IdentityAID string `json:"identity_aid"`
	// HolderID is the name this machine will be known by in that archive.
	HolderID string        `json:"holder_id"`
	Policy   HoldingPolicy `json:"policy"`
}

// AgreedToHold is what the holder answers: a public key, and nothing else.
type AgreedToHold struct {
	HolderID     string `json:"holder_id"`
	PublicKeyB64 string `json:"public_key_b64"`
}

// Holdings is every share this machine has agreed to hold.
type Holdings struct{ DataDir string }

// Agree takes on a holding and returns the public key to seal a share to.
//
// The KEY IS MADE HERE, by the machine that will have to use it, and only the
// public half goes back. That ordering is load-bearing: if the owner's agent
// generated the pair and handed over the private half, then the machine that
// wrote the backup would once have held every key needed to open it, and
// "a machine can write a backup it cannot read" would stop being true.
func (h *Holdings) Agree(req AgreeToHold) (*AgreedToHold, error) {
	if strings.TrimSpace(req.IdentityAID) == "" {
		return nil, fmt.Errorf("no identity was named")
	}
	if strings.TrimSpace(req.HolderID) == "" {
		return nil, fmt.Errorf("this holding has no name for this machine")
	}
	// Agreeing again gives back the SAME key, and never a new one.
	//
	// Minting a second key silently invalidates every share already sealed to
	// the first, so every backup taken before today stops being openable by
	// this holder — and nothing would say so until a recovery. Refusing
	// outright was the first attempt at preventing that, and it broke the
	// ordinary case instead: every backup after the first asks its holders
	// again, got a refusal, and quietly dropped them, so the day-one story
	// worked exactly once.
	//
	// A Find that ERRORS is not a Find that found nothing. Treating it as one
	// meant a truncated or unreadable holding file walked straight past the
	// guard and minted a second key — the exact outcome the guard exists to
	// prevent, reached by the one path where the file is already in trouble.
	existing, err := h.Find(req.IdentityAID, req.HolderID)
	if err != nil {
		return nil, fmt.Errorf("this machine cannot read what it already holds: %w", err)
	}
	if existing != nil {
		priv, derr := backup.DecodeB64(existing.PrivateKeyB64)
		if derr != nil {
			return nil, fmt.Errorf("this machine cannot read the key it already holds: %w", derr)
		}
		pub, perr := backup.PublicFromPrivate(priv)
		if perr != nil {
			return nil, fmt.Errorf("this machine cannot read the key it already holds: %w", perr)
		}
		return &AgreedToHold{HolderID: existing.HolderID, PublicKeyB64: backup.EncodeB64(pub)}, nil
	}

	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("make a key for this holding: %w", err)
	}
	priv, pub, err := backup.DeriveSealKeypair(seed)
	if err != nil {
		return nil, fmt.Errorf("make a key for this holding: %w", err)
	}

	holding := Holding{
		IdentityAID:   req.IdentityAID,
		HolderID:      req.HolderID,
		PrivateKeyB64: backup.EncodeB64(priv),
		Policy:        req.Policy,
	}
	if err := h.save(holding); err != nil {
		return nil, err
	}
	return &AgreedToHold{HolderID: req.HolderID, PublicKeyB64: backup.EncodeB64(pub)}, nil
}

// Find returns the holding for an identity and holder name, or nil.
func (h *Holdings) Find(identityAID, holderID string) (*Holding, error) {
	raw, err := os.ReadFile(h.pathFor(identityAID, holderID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var holding Holding
	if err := json.Unmarshal(raw, &holding); err != nil {
		return nil, fmt.Errorf("a holding on this machine is unreadable: %w", err)
	}
	return &holding, nil
}

// All lists what this machine has agreed to hold, without the keys.
//
// The private halves are deliberately blanked: this answers a screen showing
// what somebody has taken on, and that screen has no use for the material that
// makes it work.
func (h *Holdings) All() ([]Holding, error) {
	entries, err := os.ReadDir(h.dir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Holding
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(h.dir(), e.Name()))
		if err != nil {
			return nil, err
		}
		var holding Holding
		if err := json.Unmarshal(raw, &holding); err != nil {
			return nil, fmt.Errorf("a holding on this machine is unreadable: %w", err)
		}
		holding.PrivateKeyB64 = ""
		out = append(out, holding)
	}
	return out, nil
}

// Forget drops a holding, which is how somebody stops being a share holder.
//
// The shares already sealed to this key become unopenable, so whoever this
// machine was helping should be told to take a fresh backup. That is the
// caller's job to say; this one only does what it was asked.
func (h *Holdings) Forget(identityAID, holderID string) error {
	err := os.Remove(h.pathFor(identityAID, holderID))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (h *Holdings) dir() string { return filepath.Join(h.DataDir, "shares_held") }

func (h *Holdings) pathFor(identityAID, holderID string) string {
	// Both names go into the filename, base64'd so that an identifier can
	// never climb out of this directory or collide with another.
	return filepath.Join(h.dir(),
		backup.EncodeB64([]byte(identityAID+"\x00"+holderID))+".json")
}

func (h *Holdings) save(holding Holding) error {
	if err := os.MkdirAll(h.dir(), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(holding, "", "  ")
	if err != nil {
		return err
	}
	// Written aside, flushed, and renamed. A holding IS a private key, and it
	// is the only copy — losing it to a power cut makes every share already
	// sealed to it unopenable, permanently and silently. The ask record beside
	// it was already written this way; this was not, which had it backwards:
	// of the two, this is the one that cannot be reconstructed.
	path := h.pathFor(holding.IdentityAID, holding.HolderID)
	tmp := path + ".writing"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
