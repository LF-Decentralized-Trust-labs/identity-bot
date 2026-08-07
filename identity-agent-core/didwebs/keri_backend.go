package didwebs

import (
	"context"

	"identity-agent-core/drivers"
)

// KeriDriverBackend adapts the Python KERI driver for local KEL replay.
type KeriDriverBackend struct {
	Driver *drivers.KeriDriver
}

func (b *KeriDriverBackend) ValidateKEL(ctx context.Context, aid string, events []map[string]interface{}) (bool, string, []string, error) {
	if b == nil || b.Driver == nil {
		return false, "", []string{"KERI driver unavailable"}, nil
	}
	_ = ctx
	res, err := b.Driver.ValidateKEL(aid, events)
	if err != nil {
		return false, "", []string{err.Error()}, err
	}
	return res.KelVerified, res.CurrentPublicKey, res.ValidationErrors, nil
}
