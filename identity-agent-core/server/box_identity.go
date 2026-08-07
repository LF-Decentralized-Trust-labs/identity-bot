package server

import (
	"fmt"

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
