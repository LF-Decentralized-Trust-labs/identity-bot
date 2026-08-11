package keriengine

import (
	"fmt"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

// CreateHybridInception founds an identity holding classical and post-quantum
// keys together.
//
// The keys are generated here, in this process, which is the difference that
// matters. The Python driver's version fills the post-quantum fields with
// random bytes and says so in its own docstring — random bytes are not a public
// key, there is no private half, and nothing can ever sign with them. An
// identity founded that way carries a post-quantum key it can never use.
//
// synthetic selects fixed, predictable material. That is correct for
// conformance vectors and never correct for an identity: anyone can reproduce
// the private half.
func (e *Engine) CreateHybridInception(synthetic bool, name string) (*drivers.DriverHybridInceptionResponse, error) {
	var (
		material iacrypto.HybridKeyMaterial
		secrets  iacrypto.HybridSecrets
		err      error
	)
	if synthetic {
		material = iacrypto.SyntheticHybridKeyMaterial(0)
	} else {
		material, secrets, err = iacrypto.GenerateHybridKeyMaterial()
		if err != nil {
			return nil, fmt.Errorf("generating hybrid key material: %w", err)
		}
	}

	result, err := iacrypto.BuildHybridInception(material)
	if err != nil {
		return nil, fmt.Errorf("building the hybrid inception: %w", err)
	}

	// A real hybrid identity's secrets are written to the caller's store before
	// the identity is reported as created.
	//
	// Generating them and dropping them would produce exactly the failure this
	// method exists to fix: an identity founded on post-quantum keys that
	// nothing can ever sign with. It would also publish a pre-rotation
	// commitment the identity cannot satisfy, so it could never rotate either —
	// and unlike a lost signing key, that cannot be recovered from, because the
	// commitment is already in the log.
	//
	// The store belongs to the caller and lives on the controller device; the
	// engine writes through to it and keeps nothing.
	if !synthetic {
		if e.secrets == nil {
			return nil, fmt.Errorf("no secret store was configured, so the private half of this " +
				"identity would be generated and immediately lost. That identity could never " +
				"sign and could never rotate. Construct the engine with NewWithSecretStore, or " +
				"ask for synthetic material if this is a conformance vector rather than an identity")
		}
		label := name
		if label == "" {
			label = result.AID
		}
		if err := iacrypto.StoreHybridSecrets(e.secrets, label, secrets); err != nil {
			return nil, fmt.Errorf("storing the identity's private material: %w", err)
		}
	}

	raw, err := decodeB64(result.RawBytesB64)
	if err != nil {
		return nil, fmt.Errorf("the hybrid inception this engine built is not readable: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, fmt.Errorf("the hybrid inception does not parse as a KERI event: %w", err)
	}
	first, err := entry(raw)
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = result.AID
	}
	e.state.put(&identity{
		Name:            name,
		AID:             result.AID,
		PublicKey:       result.PublicKey,
		NextKeyDigest:   result.NextKeyDigest,
		Witnesses:       ev.Witnesses,
		Toad:            witnessThreshold(ev),
		SN:              0,
		LastSAID:        result.SAID,
		KEL:             []kelEntry{first},
		Registries:      map[string]*registry{},
		HistoryVerified: true,
	})

	return &drivers.DriverHybridInceptionResponse{
		AID:            result.AID,
		SAID:           result.SAID,
		InceptionEvent: result.InceptionEvent,
		RawBytesB64:    result.RawBytesB64,
		CipherSuite:    result.CipherSuite,
		PublicKey:      result.PublicKey,
		NextKeyDigest:  result.NextKeyDigest,
	}, nil
}
