package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
)

// The identity a sealed machine makes for itself.
//
// A machine running on hardware somebody else owns has to be able to decrypt
// what is sent to it — that is the whole point, since the requests are
// encrypted so that the operator cannot read them. So it must hold a private
// key. But the owner's seed lives on their own device and deliberately never
// reaches this hardware.
//
// Those two facts only collide if the machine has to use the OWNER's identity.
// It does not. A hosted agent is a distinct thing acting on the owner's behalf,
// so it gets its own identity, with its own keys, made here and never leaving.
// The owner's authority arrives afterwards as a signature over the event below
// — authority rather than key material, which is what lets the machine be
// trusted without being given anything it could use to impersonate the owner.
//
// The encryption keys are committed inside the event the identifier is derived
// from, so the identifier vouches for them. Substituting the keys means
// substituting the identifier, and the identifier is what the owner signed.

// boxIdentity is a freshly made identity for this machine, before anyone has
// vouched for it.
type boxIdentity struct {
	// AID is this machine's own identifier, derived from the event below.
	AID string
	// InceptionEvent is what the owner is asked to sign. It carries the keys,
	// so signing it is what ties these exact keys to this owner.
	InceptionEvent map[string]interface{}
	// Current and Next are held here and persisted by the caller. Next is the
	// keyset this identity has committed to rotating into, and it is generated
	// now because the commitment is a digest of a key that must already exist.
	Current *didcomm.KeySet
	Next    *didcomm.KeySet
}

// newBoxIdentity makes this machine an identity of its own, under delegatorAID.
//
// Nothing here is published and nothing is trusted yet. What comes back is an
// offer: these are my keys, this is who I say I act for, here is the event that
// binds the two. Whether it becomes real depends on the owner checking the
// hardware first and then signing it — in that order, because signing first
// would mean vouching for whatever keys were handed over.
func newBoxIdentity(delegatorAID string) (*boxIdentity, error) {
	if delegatorAID == "" {
		return nil, fmt.Errorf("a machine cannot make an identity without knowing who it acts for")
	}

	// The identifier is not known until the event is built, and the event
	// cannot be built without the keys — so the keys are made first and the
	// identifier is written onto them afterwards.
	current, err := didcomm.GenerateKeySet("")
	if err != nil {
		return nil, fmt.Errorf("could not generate this machine's keys: %w", err)
	}
	next, err := didcomm.GenerateKeySet("")
	if err != nil {
		return nil, fmt.Errorf("could not generate this machine's next keys: %w", err)
	}

	ed, dsa, x, kem, err := current.PublicMaterial()
	if err != nil {
		return nil, err
	}
	nextEd, nextDsa, _, _, err := next.PublicMaterial()
	if err != nil {
		return nil, err
	}

	built, err := iacrypto.BuildHybridDelegatedInception(iacrypto.HybridKeyMaterial{
		Ed25519SigningRaw:     ed,
		MLDSA65SigningRaw:     dsa,
		X25519AgreementRaw:    x,
		MLKEM768EncapRaw:      kem,
		NextEd25519SigningRaw: nextEd,
		NextMLDSA65SigningRaw: nextDsa,
	}, delegatorAID)
	if err != nil {
		return nil, fmt.Errorf("could not build this machine's inception: %w", err)
	}

	current.AID = built.AID
	next.AID = built.AID

	return &boxIdentity{
		AID:            built.AID,
		InceptionEvent: built.InceptionEvent,
		Current:        current,
		Next:           next,
	}, nil
}

// --- keeping it across restarts ---

// An identity that did not survive a restart would not be an identity. A
// counterparty holds this identifier and encrypts to these keys; if a power cut
// produced a different one, every relationship it had would be silently
// unreachable and the owner's signature over the old one would point at
// something that no longer exists.
//
// So it is written down once, at the moment it is made, and read back
// afterwards. On a sealed machine this lands on the encrypted volume, which is
// the same place the rest of the agent's private material lives — readable by
// the software the measurement covers, and by nothing else.

const boxIdentityFile = "box_identity.json"

type boxIdentityWire struct {
	AID            string                 `json:"aid"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	CurrentKeys    json.RawMessage        `json:"current_keys"`
	NextKeys       json.RawMessage        `json:"next_keys"`
}

func (s *CoreServer) boxIdentityPath() string {
	return filepath.Join(s.DataDir, boxIdentityFile)
}

func (s *CoreServer) saveBoxIdentity(b *boxIdentity) error {
	current, err := b.Current.Marshal()
	if err != nil {
		return fmt.Errorf("could not encode this machine's keys: %w", err)
	}
	next, err := b.Next.Marshal()
	if err != nil {
		return fmt.Errorf("could not encode this machine's next keys: %w", err)
	}
	raw, err := json.MarshalIndent(boxIdentityWire{
		AID:            b.AID,
		InceptionEvent: b.InceptionEvent,
		CurrentKeys:    current,
		NextKeys:       next,
	}, "", "  ")
	if err != nil {
		return err
	}
	// 0600 and atomic, like every other file holding private keys here: a
	// half-written one would be an identity that loads as corrupt, which is the
	// same as losing it.
	return writeFileAtomic(s.boxIdentityPath(), raw, 0600)
}

// loadBoxIdentity returns nil when this machine has never made one, which is
// the ordinary state of a machine that has not been provisioned.
//
// A file that exists and will not parse is a different thing entirely and is
// reported as an error rather than treated as absence — because absence leads
// to making a NEW identity, which would abandon the one counterparties already
// hold rather than fixing whatever went wrong.
func (s *CoreServer) loadBoxIdentity() (*boxIdentity, error) {
	raw, err := os.ReadFile(s.boxIdentityPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("this machine's identity could not be read: %w", err)
	}

	var w boxIdentityWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("this machine's identity file is unreadable, and making a new one "+
			"would abandon the identifier counterparties already hold: %w", err)
	}
	current, err := didcomm.UnmarshalKeySet(w.CurrentKeys)
	if err != nil {
		return nil, fmt.Errorf("this machine's keys could not be read: %w", err)
	}
	next, err := didcomm.UnmarshalKeySet(w.NextKeys)
	if err != nil {
		return nil, fmt.Errorf("this machine's next keys could not be read: %w", err)
	}
	if w.AID == "" || w.InceptionEvent == nil {
		return nil, fmt.Errorf("this machine's identity file is incomplete")
	}
	return &boxIdentity{
		AID:            w.AID,
		InceptionEvent: w.InceptionEvent,
		Current:        current,
		Next:           next,
	}, nil
}

// ensureBoxIdentity returns this machine's identity, making one only if it has
// never had one.
//
// Create-once, deliberately. A second identity is not a repair: the first is
// what the owner signed and what counterparties encrypt to, so replacing it
// silently would look like a machine that had lost its memory and behave like a
// different machine wearing the same address.
func (s *CoreServer) ensureBoxIdentity(delegatorAID string) (*boxIdentity, error) {
	existing, err := s.loadBoxIdentity()
	if err != nil {
		return nil, err
	}
	if existing != nil {
		s.boxIdentity = existing
		return existing, nil
	}
	made, err := newBoxIdentity(delegatorAID)
	if err != nil {
		return nil, err
	}
	if err := s.saveBoxIdentity(made); err != nil {
		// Returning an identity that was not written down would mean handing
		// out keys that vanish on the next restart — worse than failing here,
		// because the failure would surface later as counterparties unable to
		// reach a machine that believes it is fine.
		return nil, fmt.Errorf("this machine made an identity it could not keep: %w", err)
	}
	s.boxIdentity = made
	return made, nil
}
