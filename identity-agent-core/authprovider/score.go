package authprovider

import "time"

// The score is what a decision compares. The badge and the level are derived
// from it for display, and never the other way round: a badge cannot be turned
// back into a score, so anything that gated on one would be gating on a
// rounded-off copy of the number it should have read.

// Score bands for display: green from GreenFromScore up, amber from
// AmberFromScore up, red below.
const (
	GreenFromScore = 80
	AmberFromScore = 40
)

// BadgeForScore is the colour a score is shown in: green at 80 and above,
// amber from 40 to 79, red below 40.
func BadgeForScore(score int) string {
	switch {
	case score >= GreenFromScore:
		return "green"
	case score >= AmberFromScore:
		return "amber"
	default:
		return "red"
	}
}

// LevelForScore names a score's band as a Level, for anything that still shows
// one. For display only: no authorisation decision may compare the result.
func LevelForScore(score int) Level {
	switch {
	case score >= GreenFromScore:
		return LevelVerified
	case score >= AmberFromScore:
		return LevelAuthenticated
	default:
		return LevelNone
	}
}

// PlaceholderProvider names the stand-in below wherever a result is recorded,
// so nothing that reads who was checked and how can mistake it for a
// measurement of the person.
const PlaceholderProvider = "placeholder-until-human-authentication"

// PlaceholderScore is the score every person has until human authentication is
// built.
const PlaceholderScore = 80

// UntilHumanAuthenticationIsBuilt is how sure this Identity Agent is that a
// person is who they say, while nothing yet measures it: a score of 80 for
// everybody.
//
// The same in every build. A development build and a production build
// authorise identically; what differs between them is attestation and nothing
// else. Replacing this with real human authentication changes this one
// function and nothing that calls it.
func UntilHumanAuthenticationIsBuilt(now time.Time) Result {
	return Result{
		Level:    LevelForScore(PlaceholderScore),
		Score:    PlaceholderScore,
		Measured: true,
		At:       now.UTC(),
		Provider: PlaceholderProvider,
		Why:      "human authentication is not built yet, so every person scores 80",
	}
}
