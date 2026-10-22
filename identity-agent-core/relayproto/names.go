package relayproto

import (
	"regexp"
	"strings"
)

// NameRule says in plain words what a public name may be, for anyone telling a
// person why a name was refused.
const NameRule = "A name is 3 to 32 lowercase letters, digits and single hyphens, starting and ending with a letter or digit."

// A public name is something a person can read aloud and type, and a single
// DNS label: 3 to 32 lowercase letters, digits and hyphens, with a letter or
// digit at each end and never two hyphens together (which would read as an
// encoded international name).
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

// ValidName reports whether n is a public name a relay accepts. A relay checks
// it, and so does an Identity Agent before asking, so a name that cannot be had
// is refused at once and the same way everywhere.
func ValidName(n string) bool {
	return nameRE.MatchString(n) && !strings.Contains(n, "--")
}
