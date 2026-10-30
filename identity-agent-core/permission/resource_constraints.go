package permission

import (
	"encoding/json"
	"fmt"
)

// CheckResourceConstraints refuses arguments that fall outside a grant's
// per-capability resource constraints (CallerContext.ResourceConstraints).
// A constraint maps a capability id to {argKey: [allowedValues]}: for the
// capability asked for, every constrained argKey must be present in args and
// its value must equal one of the allowed values. No constraints, or none for
// this capability, means unconstrained.
//
// It is the one reading of a grant's constraints: a runtime calling a
// capability and a verifier checking a message sent under a grant both use
// it, so a grant limits the same arguments either way.
func CheckResourceConstraints(constraints map[string]interface{}, capabilityID string, args []byte) error {
	if len(constraints) == 0 {
		return nil
	}
	raw, ok := constraints[capabilityID]
	if !ok {
		return nil
	}
	capC, ok := raw.(map[string]interface{})
	if !ok || len(capC) == 0 {
		return nil
	}
	var parsed map[string]interface{}
	if len(args) > 0 {
		_ = json.Unmarshal(args, &parsed)
	}
	for argKey, allowedRaw := range capC {
		allowed, ok := allowedRaw.([]interface{})
		if !ok || len(allowed) == 0 {
			continue
		}
		val, present := parsed[argKey]
		if !present {
			return fmt.Errorf("capability %q requires constrained argument %q", capabilityID, argKey)
		}
		match := false
		for _, a := range allowed {
			if fmt.Sprint(a) == fmt.Sprint(val) {
				match = true
				break
			}
		}
		if !match {
			return fmt.Errorf("argument %q=%v is not permitted for capability %q", argKey, val, capabilityID)
		}
	}
	return nil
}
