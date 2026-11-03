package asset

import (
	"errors"
	"fmt"
	"time"
)

// ErrNoCapabilities refuses a grant that gives nothing.
var ErrNoCapabilities = errors.New("capabilities is required (the capability ceiling this asset may invoke)")

// ErrGrantLapsed refuses a grant whose end has already passed.
var ErrGrantLapsed = errors.New("valid_until is in the past, so the grant would never be in force")

// checkGrantAsked refuses a grant that should not be issued, for any kind of
// delegated asset: one that gives no capability, one already past its end, one
// whose limits the gateway would not enforce as written.
func checkGrantAsked(noun string, capabilities []string, validUntil *time.Time, constraints map[string]interface{}) error {
	caps := NormaliseCapabilities(capabilities)
	if len(caps) == 0 {
		return fmt.Errorf("%s: %w", noun, ErrNoCapabilities)
	}
	if validUntil != nil && !validUntil.After(time.Now()) {
		return ErrGrantLapsed
	}
	return CheckResourceConstraints(constraints, caps)
}

// CheckResourceConstraints refuses constraints the gateway would not enforce as
// written: any shape but per capability id, per argument, a list of allowed
// values; an empty map or list, which the gateway reads as "no limit" though it
// looks like "nothing allowed"; and a limit on a capability the grant does not
// give, which could never apply. Accepting any of these would record a limit
// the asset is not actually held to.
func CheckResourceConstraints(rc map[string]interface{}, capabilities []string) error {
	granted := map[string]bool{}
	for _, c := range capabilities {
		granted[c] = true
	}
	for capID, v := range rc {
		if !granted[capID] {
			return fmt.Errorf("resource_constraints names %q, which this grant does not give", capID)
		}
		args, ok := v.(map[string]interface{})
		if !ok || len(args) == 0 {
			return fmt.Errorf("resource_constraints[%q] must map at least one argument name to its allowed values", capID)
		}
		for arg, vals := range args {
			list, ok := vals.([]interface{})
			if !ok || len(list) == 0 {
				return fmt.Errorf("resource_constraints[%q][%q] must list at least one allowed value", capID, arg)
			}
			for _, x := range list {
				if _, ok := x.(string); !ok {
					return fmt.Errorf("resource_constraints[%q][%q] must list strings", capID, arg)
				}
			}
		}
	}
	return nil
}
