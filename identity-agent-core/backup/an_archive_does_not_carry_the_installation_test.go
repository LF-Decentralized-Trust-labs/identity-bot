package backup

import (
	"strings"
	"testing"
)

// A backup is of an identity, never of an installation (ADR-039).
//
// Nothing tested this. The rule was implemented as two branches of skipReason
// and a comment arguing for them, which is exactly the shape that keeps
// compiling after somebody rewrites the condition — and one of the two failure
// modes here is silent by construction: a guard that no longer matches its file
// looks identical to a guard that works, because both simply return.
//
// The stakes differ between the two names, which is why both are asserted
// rather than one standing in for the other. Carrying the grant record is the
// resurrection ADR-039 closes: take an archive, revoke a machine, restore, and
// the machine may act again with nothing having said so. Carrying the machine
// key is dead weight that also puts a key belonging to one processor into a
// file meant to travel.
func TestAnArchiveDoesNotCarryWhatBelongsToTheInstallation(t *testing.T) {
	notCarried := []struct {
		file string
		why  string
	}{
		{"controller_grants.json", "which machines may act is decided after a restore, not restored"},

		// THE CASE THAT FAILED BEFORE THIS TEST EXISTED. save() writes the
		// temporary name and renames over the real one, so a walk landing inside
		// that window met a guard testing for equality and carried the whole
		// grant list. Inert on restore — load() reads only the real name — but it
		// is still every machine that may act for this identity, written into an
		// archive that is meant to travel.
		{"controller_grants.json.tmp", "the rename window must not leak what the rule excludes"},

		{"secureenclave/machine_key.sep", "a key one processor holds is useless anywhere else"},
	}

	for _, c := range notCarried {
		if reason := skipReason(c.file); reason == "" {
			t.Errorf("%s is carried into archives, but %s", c.file, c.why)
		}
	}
}

// The exclusion must not swallow the identity's own data.
//
// The opposite failure, and the more expensive one: a prefix rule that reaches
// too far silently drops something an owner needs, and nothing reports it until
// a restore comes up short. Asserting the negative keeps the rule honest about
// its own width.
func TestTheExclusionDoesNotReachTheIdentitysOwnData(t *testing.T) {
	carried := []string{
		"secureenclave/root_seed.key",
		"contacts.json",
		"credentials.json",
	}

	for _, f := range carried {
		reason := skipReason(f)
		if reason == "" {
			continue // carried with no note, which is the ordinary case
		}
		// root_seed.key is named by skipReason, but to say it is captured
		// elsewhere rather than dropped. "captured" and "not carried" are
		// different answers and only the second is a failure here.
		if !strings.HasPrefix(reason, "captured") {
			t.Errorf("%s is not carried (%q), but an identity's own data must be", f, reason)
		}
	}
}
