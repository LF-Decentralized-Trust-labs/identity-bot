package didwebs

import (
	"context"

	"identity-agent-core/drivers"
)

// KeriDriverBackend adapts the Python KERI driver for local KEL replay.
type KeriDriverBackend struct {
	Driver drivers.KeriEngine
}

func (b *KeriDriverBackend) ValidateKEL(ctx context.Context, aid string, events []map[string]interface{}) (bool, string, []string, error) {
	if b == nil || b.Driver == nil {
		return false, "", []string{"KERI driver unavailable"}, nil
	}
	_ = ctx
	// Where the published document carries the canonical bytes, check those:
	// only they can show that the inception derives the identifier being
	// claimed, and that the events were signed. Without them a forged log
	// satisfies every remaining check, because whoever forged it wrote every
	// field being compared.
	var (
		res *drivers.DriverValidateKELResponse
		err error
	)
	if in, ok := drivers.ValidateKELInputFromRecords(aid, events); ok {
		res, err = b.Driver.ValidateKELBytes(in)
	} else {
		res, err = b.Driver.ValidateKEL(aid, events)
	}
	if err != nil {
		return false, "", []string{err.Error()}, err
	}
	return res.KelVerified, res.CurrentPublicKey, res.ValidationErrors, nil
}
