package recovery

import "identity-agent-core/drivers"

// KeriDriverAdapter adapts the production KERI driver to KeriDriverPort.
type KeriDriverAdapter struct {
	Driver *drivers.KeriDriver
}

func (a *KeriDriverAdapter) CreateInception(publicKey, nextPublicKey string) (*KeriInceptionResult, error) {
	resp, err := a.Driver.CreateInception(publicKey, nextPublicKey)
	if err != nil {
		return nil, err
	}
	return &KeriInceptionResult{
		AID:            resp.AID,
		PublicKey:      resp.PublicKey,
		NextKeyDigest:  resp.NextKeyDigest,
		InceptionEvent: resp.InceptionEvent,
		InceptionSAID:  eventSAID(resp.InceptionEvent),
		SequenceNumber: 0,
	}, nil
}

func (a *KeriDriverAdapter) CreateHybridInception(synthetic bool, name string) (*KeriInceptionResult, error) {
	resp, err := a.Driver.CreateHybridInception(synthetic, name)
	if err != nil {
		return nil, err
	}
	return &KeriInceptionResult{
		AID:            resp.AID,
		PublicKey:      resp.PublicKey,
		NextKeyDigest:  resp.NextKeyDigest,
		InceptionEvent: resp.InceptionEvent,
		InceptionSAID:  eventSAID(resp.InceptionEvent),
		SequenceNumber: 0,
	}, nil
}

func (a *KeriDriverAdapter) RotateWithAnchor(name, newPublicKey, newNextPublicKey string, anchorData []interface{}) (*KeriRotationResult, error) {
	resp, err := a.Driver.RotateAidWithAnchor(name, newPublicKey, newNextPublicKey, anchorData)
	if err != nil {
		return nil, err
	}
	said := resp.Said
	if said == "" {
		said = eventSAID(resp.RotationEvent)
	}
	return &KeriRotationResult{
		AID:              resp.AID,
		NewPublicKey:     resp.NewPublicKey,
		NewNextKeyDigest: resp.NewNextKeyDigest,
		RotationEvent:    resp.RotationEvent,
		RotationSAID:     said,
		RawBytesB64:      resp.RawBytesB64,
		SequenceNumber:   resp.SequenceNumber,
	}, nil
}

func (a *KeriDriverAdapter) Interact(name string, data []interface{}) (*KeriInteractResult, error) {
	resp, err := a.Driver.Interact(name, data)
	if err != nil {
		return nil, err
	}
	return &KeriInteractResult{
		AID:            resp.AID,
		IxnEvent:       resp.IxnEvent,
		Said:           resp.Said,
		SequenceNumber: resp.SequenceNumber,
	}, nil
}