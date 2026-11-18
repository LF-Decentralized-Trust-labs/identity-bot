package secureenclave

import (
	"context"
	"errors"
	"os"
	"testing"
)

// No test in this package may reach Google's revocation list. Unless a test
// stands its own list (googleStatusListIs, googleIsUnreachable), a fetch fails
// as it would with no network, so a test that needs a list and forgot to say so
// fails the same on every machine, online or not.
func TestMain(m *testing.M) {
	// Asked by TestTheTPMPinsAreNotReadAsTheProgramStarts, this run only says what init did.
	reportWhetherInitReadTheTPMPins()
	// Read the pinned TPM package before any test, so a test that stands its own pins in
	// their place is not overwritten by the first read.
	loadTPMPins()
	fetchStatusList = func(context.Context) ([]byte, error) {
		return nil, errors.New("tests do not use the network: this test did not stand a revocation list")
	}
	os.Exit(m.Run())
}
