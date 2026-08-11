package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Checking that a witness is who the registry says it is, before designating it.
//
// Two wrong ways to do this, and the right one is neither.
//
// TRUSTING THE URL. Ask the service who it is and write that into the inception
// event. Then whoever controls the hostname at that moment chooses who
// witnesses the identity — a hijacked domain, an expired registration, a
// compromised host — and the choice is permanent, because an inception event
// cannot be amended. The attacker does not need to break any cryptography; they
// need the name to resolve to them for the few seconds an identity is founded.
//
// TRUSTING THE PIN ALONE. Write the identifier the registry names and never
// look. Then the day a service is redeployed onto a new volume, or rotates its
// key, every identity founded afterwards designates a witness that no longer
// exists — permanently, and silently, because nothing compared the two. That is
// not hypothetical: it is what these entries were doing.
//
// So the registry pins WHO IS EXPECTED, and this checks the service actually
// answering is that party. A pin makes changing the default a deliberate,
// reviewable edit to a committed file rather than something a DNS answer can do
// on its own. The check makes the pin worth having.
//
// A mismatch is refused rather than resolved in either direction. Preferring the
// live answer would defeat the pin; preferring the pin would designate a key
// that cannot receipt. Both are worse than declining to designate and saying so.

// identityCheckTimeout bounds the question. A service too slow to say who it is
// is not one to write permanently into an inception event.
const identityCheckTimeout = 10 * time.Second

// IdentityChecker asks a service which identity it is answering as.
//
// Replaceable so a test does not need a network, and so a deployment can impose
// its own timeouts and proxying.
type IdentityChecker func(ctx context.Context, baseURL string) (string, error)

// LiveIdentityOf reads the identifier a witness service is currently answering
// as, from the address it is reached at.
func LiveIdentityOf(ctx context.Context, baseURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		witnessBase(baseURL)+"/health", nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: identityCheckTimeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered %d", baseURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}
	var doc struct {
		ServiceAID string `json:"service_aid"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("%s did not answer with a readable identity: %w", baseURL, err)
	}
	if doc.ServiceAID == "" {
		return "", fmt.Errorf("%s does not say which identity it answers as", baseURL)
	}
	return doc.ServiceAID, nil
}

// ConfirmWitnessIdentity checks a service is the party the registry expects.
//
// Returns the identifier to designate, which is the pinned one — never the live
// one. They are equal when this succeeds; returning the pin makes it impossible
// for a future edit to start trusting the answer by accident.
func ConfirmWitnessIdentity(ctx context.Context, check IdentityChecker, baseURL, pinned string) (string, error) {
	if pinned == "" {
		return "", fmt.Errorf("%s is not pinned to an identity, so there is nothing to check "+
			"the service against and no basis for designating it", baseURL)
	}
	if check == nil {
		check = LiveIdentityOf
	}
	live, err := check(ctx, baseURL)
	if err != nil {
		return "", fmt.Errorf("could not confirm who is answering at %s: %w", baseURL, err)
	}
	if live != pinned {
		return "", fmt.Errorf("%s is answering as %s but is pinned as %s. Designating either "+
			"would be wrong: the live answer is whatever that address currently resolves to, "+
			"and the pin is a key that is no longer receipting. Update the registry if this "+
			"service was legitimately redeployed", baseURL, live, pinned)
	}
	return pinned, nil
}
