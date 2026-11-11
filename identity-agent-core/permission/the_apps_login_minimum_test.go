package permission

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The apps log a person in with a placeholder for the authentication provider,
// and it answers the bare minimum. No core runs for a logged-out identity, so
// the apps cannot ask one; this holds the number they carry to the one the core
// holds, so the two cannot drift.
func TestTheAppsLoginPlaceholderAnswersTheDefaultMinimumScore(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "packages", "agent_client",
		"lib", "services", "identity_profiles.dart"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`static const minimumScore = (\d+);`).FindSubmatch(src)
	if m == nil {
		t.Fatal("identity_profiles.dart no longer declares minimumScore")
	}
	if got, _ := strconv.Atoi(string(m[1])); got != DefaultMinimumScore {
		t.Fatalf("the apps' placeholder answers %d, the core's minimum is %d", got, DefaultMinimumScore)
	}
}
