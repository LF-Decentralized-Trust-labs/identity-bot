package permission

import (
	"fmt"

	"identity-agent-core/authprovider"
)

// The one check every governed action passes.
//
// A person acting through a controller and an AI agent invoking a capability
// are judged by this one function (ADR-050), so the rule is written once.
//
// It asks two questions, in order:
//
//  1. Is this person's identity score at least the action's minimum? The
//     minimum is 80 unless the action sets another.
//  2. May this person do this action? Always yes until roles are built.
//
// It compares a score with a number, never one named level with another. A
// level is a rounded-off copy of the score, kept for display.
//
// What it does not decide: the owner-only actions, which no score opens. Those
// are refused before this is asked (see the controller rules in the server).

// DefaultMinimumScore is what an action needs when it sets nothing else.
const DefaultMinimumScore = 80

// Action is something a person asks to do.
type Action struct {
	// Name says which action, for the refusal and the record: a capability's
	// id, or a route as "METHOD /pattern".
	Name string
	// MinimumScore is the score the action needs. Zero means
	// DefaultMinimumScore. A negative value is a mistake in whatever set it,
	// and refuses everybody rather than quietly letting everybody through.
	MinimumScore int
}

// TheScoreItNeeds is the action's minimum with the default applied.
func (a Action) TheScoreItNeeds() int {
	if a.MinimumScore == 0 {
		return DefaultMinimumScore
	}
	return a.MinimumScore
}

// Person is who is asking, as far as the check needs.
type Person struct {
	// AID identifies the person, or the AI agent acting under one.
	AID string
	// Authenticated is how sure this Identity Agent is that it is them.
	Authenticated authprovider.Result
}

// MayThisPersonDoThis is the one check. It returns why when it refuses, naming
// which of the two questions failed, so the person is told what would let them
// through rather than only that something stopped them.
func MayThisPersonDoThis(action Action, who Person) (bool, string) {
	if action.MinimumScore < 0 {
		return false, fmt.Sprintf(
			"%s is set to need a score of %d, which is not a score, so nobody may do it until that is corrected",
			action.Name, action.MinimumScore)
	}
	if !who.Authenticated.Measured {
		return false, "nothing has measured how sure we are this is the person"
	}
	needs := action.TheScoreItNeeds()
	if who.Authenticated.Score < needs {
		return false, fmt.Sprintf(
			"this needs an identity score of at least %d, and this person's is %d",
			needs, who.Authenticated.Score)
	}
	if ok, why := whatThisPersonMayDo(action, who); !ok {
		return false, why
	}
	return true, ""
}

// whatThisPersonMayDo is the permission question: may this person do this
// action at all, whatever their score.
//
// A placeholder that always says yes, because roles (owner, admin, employee)
// are not built yet. When they are, this is the one function that changes.
func whatThisPersonMayDo(Action, Person) (bool, string) {
	return true, ""
}
