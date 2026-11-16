package agentpeer

import (
	"errors"
	"strings"
	"unicode"
)

// A directory is the AI agents one Identity Agent holds that a contact may
// reach, by the names this Identity Agent gives them, so the contact can write
// "name@alias" (ADR-085). It tells the contact nothing about any
// other AI agent. The envelope it arrives in says which Identity Agent it is
// from; it holds no signature of its own, because it grants nothing: what a
// contact may reach is the owner's rule, held and checked by the Identity Agent
// that holds the AI agent, whatever a directory says.
type Directory struct {
	Agents []DirectoryEntry `json:"agents"`
}

// DirectoryEntry is one AI agent a contact may reach.
type DirectoryEntry struct {
	// AID is the AI agent's identifier, as a statement names it.
	AID string `json:"aid"`
	// Name is what its Identity Agent calls it. It is shown as a name and written
	// before the "@", so it holds none, and no line break or space-like control.
	Name string `json:"name"`
	Role string `json:"role,omitempty"`
}

// MaxDirectory bounds how many AI agents one Identity Agent lists to a contact.
const MaxDirectory = 200

const maxName = 64

// shown says whether text is only what can be read as itself: no control, format
// (right-to-left overrides, zero-width), private-use or unassigned characters. A
// look-alike letter from another script is not caught: a name is the contact's
// word, shown beside the alias the owner chose.
func shown(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Check refuses a directory that cannot be shown as it stands: too long, a name
// that could be read as something else, or two entries of one name (a contact
// writing "name@alias" must mean one AI agent).
func (d Directory) Check() error {
	if len(d.Agents) > MaxDirectory {
		return errors.New("a directory lists at most 200 AI agents")
	}
	names, aids := map[string]bool{}, map[string]bool{}
	for _, a := range d.Agents {
		n := strings.TrimSpace(a.Name)
		switch {
		case !plain(a.AID):
			return ErrField
		case n == "" || n != a.Name || len(n) > maxName || strings.Contains(n, "@") || !shown(n):
			return errors.New("an AI agent's name is one to sixty-four characters, with no @ and no line break")
		case len(a.Role) > 200 || !shown(a.Role):
			return errors.New("an AI agent's role is one short line")
		case names[strings.ToLower(a.Name)] || aids[a.AID]:
			return errors.New("a directory names each AI agent once, under a name of its own")
		}
		names[strings.ToLower(a.Name)], aids[a.AID] = true, true
	}
	return nil
}
