package addon_test

import (
	"testing"

	"identity-agent-core/addon"
)

// The server implements every method of the handle: Of and Shared assert it,
// and would panic for any method the server's side lacks.
func TestTheServerGivesTheWholeHandle(t *testing.T) {
	if addon.Of(nil) == nil || addon.Shared() == nil {
		t.Fatal("the server gave no handle")
	}
}
