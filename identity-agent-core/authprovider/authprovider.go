// Package authprovider is the seam between an Identity Agent and whatever
// establishes that the person operating it is the person it belongs to.
//
// There are three separate gates on the way back into an identity, and they
// answer different questions. Keeping them apart is the whole point of this
// package existing.
//
//  1. Do you control the identity?   The recovery phrase answers this. It
//     proves cryptographic control and unlocks
//     the DATA.
//  2. Are you the same person?       An authentication provider answers this,
//     by matching what somebody can produce now
//     against what the recovered data holds —
//     the data being the identity.
//  3. Are you acting freely?         NOTHING here answers this. A person under
//     duress passes every check perfectly. Only
//     time, or another human who knows them,
//     can speak to it.
//
// Holding the phrase used to be the end of it: recovery finished by writing the
// identity straight in, with no second gate at all. That makes the words the
// whole of the security, which is not the design — they are supposed to unlock
// the data, not the door.
//
// The provider is deliberately pluggable. It runs beside the agent rather than
// behind a network call, so this is not a client for a remote service; it is
// the shape any implementation has to present, so that somebody running this
// software can bring their own.
package authprovider

import (
	"fmt"
	"time"
)

// Level is the coarse answer: how well has this person been authenticated.
//
// Called a LEVEL rather than a tier or an identity level, because it is not a
// property of the identity. It is a statement about whoever is operating it,
// right now. The same identity has a different level depending on who is at
// the keyboard and what they can prove, which is the entire reason it can gate
// anything.
type Level string

const (
	// LevelUnknown is what an agent reports when nothing has been measured.
	//
	// Deliberately distinct from "measured and low". An agent with no provider
	// running used to report a middling band and a score of 60, so a number
	// nobody had produced appeared on screen and shortened a waiting period.
	// Unknown is the honest answer, and it is treated as the weakest.
	LevelUnknown Level = "unknown"

	// LevelNone is measured, and nothing was established.
	LevelNone Level = "none"
	// LevelBasic is a self-asserted identity.
	LevelBasic Level = "basic"
	// LevelAuthenticated has working factors but unverified attributes.
	LevelAuthenticated Level = "authenticated"
	// LevelVerified has attributes verified by somebody who checked.
	LevelVerified Level = "verified"
	// LevelHigh is verified to the strongest standard the provider offers.
	LevelHigh Level = "high"
)

// Badge is the red / amber / green a person actually sees.
func (l Level) Badge() string {
	switch l {
	case LevelVerified, LevelHigh:
		return "green"
	case LevelBasic, LevelAuthenticated:
		return "amber"
	default:
		// Unknown shows red, because an unmeasured identity is not an amber
		// one. Nobody has checked.
		return "red"
	}
}

// Known reports whether this is a level this package defines.
//
// A requirement that is not a known level is a typo, and a typo must not
// silently disable a gate. Unrecognised values rank 0 like unknown does, which
// is right for a level a PROVIDER returns — the weakest answer — and exactly
// wrong for a level somebody REQUIRES, because 0 >= 0 makes the requirement
// satisfied by having measured nothing.
func (l Level) Known() bool {
	switch l {
	case LevelUnknown, LevelNone, LevelBasic, LevelAuthenticated, LevelVerified, LevelHigh:
		return true
	}
	return false
}

// AtLeast reports whether this level meets a requirement.
//
// LevelUnknown ranks below everything, including LevelNone, and that ordering
// is the whole mechanism: "we did not measure" must not satisfy a requirement
// of "we measured and found nothing", or an agent with no provider would pass
// gates that an agent with a provider fails — and removing the provider would
// be a way past the gate.
func (l Level) AtLeast(required Level) bool {
	return l.rank() >= required.rank()
}

func (l Level) rank() int {
	switch l {
	case LevelNone:
		return 1
	case LevelBasic:
		return 2
	case LevelAuthenticated:
		return 3
	case LevelVerified:
		return 4
	case LevelHigh:
		return 5
	default:
		return 0
	}
}

// Result is what a provider says about the person operating this agent.
type Result struct {
	Level Level `json:"level"`
	// Score is the granular form, 0 to 100, and is only meaningful when
	// Measured is true.
	Score int `json:"score"`
	// Measured distinguishes an answer from the absence of one. A zero score
	// with Measured false means nobody was asked; with Measured true it means
	// somebody was asked and could establish nothing.
	Measured bool `json:"measured"`
	// At is when this was established. An authentication is a statement about
	// a moment, and a stale one is not evidence about now.
	At time.Time `json:"at"`
	// Provider names who answered, so a person can tell which software made a
	// claim about them.
	Provider string `json:"provider,omitempty"`
	// Why carries the provider's own words when it could not establish
	// anything, so a screen can say what is missing rather than only that
	// something is.
	Why string `json:"why,omitempty"`
}

// Unmeasured is the result an agent reports when no provider answered.
func Unmeasured(why string) Result {
	return Result{Level: LevelUnknown, Measured: false, Why: why}
}

// Fresh reports whether this result is recent enough to act on.
//
// An authentication is about a moment. Treating one from last month as current
// is how a gate becomes a formality — and the moment that matters most is a
// recovery, which is exactly when the answer should be live.
func (r Result) Fresh(within time.Duration) bool {
	if !r.Measured || r.At.IsZero() {
		return false
	}
	return time.Since(r.At) <= within
}

// Provider establishes how well the person operating this agent is
// authenticated.
//
// Implementations run alongside the agent. There is no assumption of a network
// call, a third party, or a commercial service: an implementation that asks the
// person questions only the identity's own data could answer is as valid as one
// that reads a hardware token.
type Provider interface {
	// Name identifies the implementation.
	Name() string
	// Authenticate establishes a result, or explains why it could not.
	Authenticate() (Result, error)
}

// NotConfigured is the provider an agent has when nobody supplied one.
//
// It answers honestly rather than failing: an agent with no provider is not
// broken, it is unmeasured, and the difference decides whether the gates above
// it should refuse or should fall back to their most cautious setting.
type NotConfigured struct{}

func (NotConfigured) Name() string { return "none" }

func (NotConfigured) Authenticate() (Result, error) {
	return Unmeasured("no authentication provider is configured on this agent"), nil
}

// Of returns what the provider says, never an invented answer.
//
// A provider that errors produces an unmeasured result carrying the reason,
// rather than a level. Somewhere above this, a gate decides what to do about
// not knowing; that decision is not this function's to make quietly.
func Of(p Provider) Result {
	if p == nil {
		return Unmeasured("no authentication provider is configured on this agent")
	}
	res, err := p.Authenticate()
	if err != nil {
		return Unmeasured(fmt.Sprintf("%s could not establish who is here: %v", p.Name(), err))
	}
	if res.Provider == "" {
		res.Provider = p.Name()
	}
	if res.Measured && res.At.IsZero() {
		res.At = time.Now().UTC()
	}
	return res
}
