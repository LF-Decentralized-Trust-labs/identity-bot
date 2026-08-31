package backup

import "fmt"

// Whether a backup survives losing the PLACE, and not just the machine.
//
// Reach already answers "does this outlive the device writing to it", and it
// answers it well. It is not the whole question. A phone backing up to the
// laptop on the same desk satisfies it completely — the phone can be dropped in
// a river and everything is still there — and a house fire, a burglary or a
// flood takes both, because they were in the same room the entire time.
//
// So there are two axes and only one was being measured. Two destinations that
// both survive their own device read as protected, and a person who has done
// exactly what the screen asked can still lose everything to one ordinary
// domestic accident. A destination that shares a room with the original is a
// copy, not a backup.
//
// WHAT SOFTWARE CAN AND CANNOT KNOW. It cannot know where anything physically
// is. It can know what KIND of thing a destination is, and two of those kinds
// answer the question on their own: a folder on this machine is definitely
// here, and a remote service is definitely not. A paired machine is the
// interesting one — usually in the same building, occasionally not, and never
// knowable from here. So it is "cannot tell", and cannot-tell must not be
// counted as protection, because the common case is that it is not.
//
// That is the opposite of how Reach treats an unclassifiable filesystem path,
// and deliberately. There, the person chose a path and knows what it is, so
// assuming the worst nags somebody who did the right thing. Here, nobody chose
// anything — a paired machine becomes a destination automatically — so
// assuming the best reassures somebody who has done nothing.

// Elsewhere says whether a destination survives the loss of this PLACE.
type Elsewhere int

const (
	// ElsewhereUnknown is a destination that might be in the same building.
	// Never counted as protection against losing the place.
	ElsewhereUnknown Elsewhere = iota
	// ElsewhereSamePlace is definitely here, and dies with the room.
	ElsewhereSamePlace
	// ElsewhereYes is somewhere a local disaster does not reach.
	ElsewhereYes
)

// ElsewhereOf classifies one destination by whether it is somewhere else.
func ElsewhereOf(d Destination, dataDir string) Elsewhere {
	// The owner's own answer, which outranks anything guessed from the type.
	// They are the only one who knows, and a destination they have told us is
	// elsewhere is elsewhere — including a filesystem path, which is how a
	// drive kept at an office gets counted.
	if d.Elsewhere {
		return ElsewhereYes
	}
	switch d.Type {
	case DestCloudUser, DestCloudHosted:
		// A remote service, wherever it is, is not in this room.
		return ElsewhereYes
	case DestPairedAgent:
		// The machine on the other side of the desk, most of the time. It may
		// be at an office or a relative's house, and there is no way to tell
		// from here — so it is not counted, and the person is asked.
		return ElsewhereUnknown
	case DestLocalPath:
		if d.LocalPath == "" || isInside(d.LocalPath, dataDir) {
			return ElsewhereSamePlace
		}
		// An external drive is in the same room until somebody carries it out
		// of it, and a network share may be anywhere.
		return ElsewhereUnknown
	default:
		return ElsewhereUnknown
	}
}

// WhatALocalDisasterWouldTake says what a fire, a burglary or a flood in this
// one place would leave, and returns the empty string when there is nothing to
// say.
//
// Kept separate from ProtectionOf rather than folded into it. They answer
// different questions — one about losing a machine, one about losing a room —
// and a person can be fine on the first and ruined on the second, so a single
// sentence covering both would have to be vague enough to be useless.
func WhatALocalDisasterWouldTake(dests []Destination, dataDir string) string {
	enabled, elsewhere, maybe, here := 0, 0, 0, 0
	for _, d := range dests {
		if !d.Enabled {
			continue
		}
		enabled++
		switch ElsewhereOf(d, dataDir) {
		case ElsewhereYes:
			elsewhere++
		case ElsewhereUnknown:
			maybe++
		case ElsewhereSamePlace:
			here++
		}
	}

	switch {
	case enabled == 0:
		// ProtectionOf already says this one, and louder. Saying it twice in
		// different words reads as two problems.
		return ""
	case elsewhere > 0:
		return ""
	case maybe == 0:
		return fmt.Sprintf(
			"Every copy is in one place (%d). A fire, a burglary or a flood there takes "+
				"the original and every backup together. Add somewhere else — a cloud "+
				"account, or a machine that lives somewhere you do not.", here)
	default:
		return "Nothing here is known to be somewhere else. A paired machine usually sits " +
			"in the same room as the one it is backing up, and one accident takes both. " +
			"If one of these really is elsewhere, say so; if not, add one."
	}
}
