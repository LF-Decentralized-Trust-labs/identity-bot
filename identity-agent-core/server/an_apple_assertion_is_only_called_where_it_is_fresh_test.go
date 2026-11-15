package server

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// An Apple App Attest assertion carries a signature counter that
// secureenclave.VerifyAppleAssertion returns and does not judge. That is safe
// only while every place that checks an assertion has freshness of its own, so
// a captured assertion cannot be replayed:
//
//   - verifyKeyPossession (an_installed_apps_attestation_is_fresh.go): the
//     assertion is over a statement carrying the core's own challenge, and the
//     ask that issued it is spent, single use, before anything is checked.
//   - keysSpeakingAt.VerifyAssertion (a_browsers_key_speaks_for_the_person_who_signed_in.go):
//     the assertion is over a person's statement that is held to a 5 minute
//     window (trail.CheckFresh) and remembered as used (rememberPersonStatement).
//
// A NEW place that checks an assertion with no nonce or single-use ask of its
// own must also persist the last counter per key and refuse one that does not
// rise. This test fails when such a place appears, so that decision is made on
// purpose and not by omission.
func TestEveryPlaceAnAppleAssertionIsCheckedIsOneThatIsFreshOnItsOwn(t *testing.T) {
	// file, from identity-agent-core -> why a call there needs no counter.
	// Adding to this list is the review: say what makes the proof fresh, or add
	// the counter check instead.
	fresh := map[string]string{
		"server/an_installed_apps_attestation_is_fresh.go":             "the proof is over the core's own challenge and the ask is spent first",
		"server/a_browsers_key_speaks_for_the_person_who_signed_in.go": "the statement is held to the skew and is used once",
		"server/an_installed_apps_key_is_proved_in_hardware.go":        "binds the verifier variable only; the calls are listed above",
	}
	// The walk covers identity-agent-core and the modules nested in it. A module
	// beside it that imports secureenclave is not seen here, so a caller there
	// owes the same decision.
	root := ".." // identity-agent-core
	call := regexp.MustCompile(`\b(verifyAppleInstalledAssertion|secureenclave\.VerifyAppleAssertion)\b`)
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		// secureenclave defines it, and it judges nothing there by design.
		if strings.Contains(filepath.ToSlash(p), "/secureenclave/") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if call.Match(raw) {
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var unknown []string
	for f := range found {
		if _, ok := fresh[f]; !ok {
			unknown = append(unknown, f)
		}
	}
	sort.Strings(unknown)
	if len(unknown) > 0 {
		t.Fatalf("%v now checks an Apple App Attest assertion. If its proof has no nonce or single-use ask of its own, "+
			"persist the last signature counter per key and refuse one that does not rise; if it is fresh, add it to the list here and say why.", unknown)
	}
	for f := range fresh {
		if !found[f] {
			t.Errorf("%s is listed as an assertion check but no longer is one: remove it from the list", f)
		}
	}
}
