package witness

import (
	"context"
	"net/http"
	"time"

	"identity-agent-core/store"
)

// ownerVouchesFor is whether the owner added this contact or accepted it, as
// against one a stranger's message left behind. Only such a contact is a place
// this agent sends key events or asks for them.
//
// A contact an introduction or an Ask created is recorded as "keri" with the
// state of its key log as its status; nothing in that shows the owner ever
// agreed to it, so it counts only once accepted, or when the owner reached out
// first, or when the owner marked it as a witness.
func ownerVouchesFor(c store.ContactRecord) bool {
	if c.ContactSource == ContactSourceInbound || c.Status == "pending_inbound" {
		return false
	}
	if c.ContactSource == "keri" {
		return c.IsWitness || c.Status == "accepted" || c.Status == "pending_outbound"
	}
	return true
}

// ownerRecorded is whether the owner, not a stranger's message, put this
// contact's address on record. It answers only who wrote the address down, which
// is all that decides whether a local address may be dialled; whether the key a
// contact claims for a witness can be believed is the stricter ownerVouchesFor.
func ownerRecorded(c store.ContactRecord) bool {
	return c.ContactSource != ContactSourceInbound && c.Status != "pending_inbound"
}

// ownerLocalFor is whether a call to rawURL, which is a contact's address, may
// reach a local address: only if the URL is itself written as one and the
// owner recorded the contact.
func ownerLocalFor(c store.ContactRecord, rawURL string) bool {
	return ownerRecorded(c) && LiteralIsLocal(hostOf(rawURL))
}

// guardedGet sends a GET to an address that came from a contact or a peer: no
// proxy, no redirect, and the address actually dialled is checked.
func (s *Service) guardedGet(req *http.Request) (*http.Response, error) {
	timeout := 10 * time.Second
	if s.HTTPClient != nil && s.HTTPClient.Timeout > 0 {
		timeout = s.HTTPClient.Timeout
	}
	return guardedClient(timeout, LiteralIsLocal(req.URL.Hostname())).Do(req)
}

// GuardedClient is the client for any call to an address a peer supplied. It
// refuses to dial an internal address (the one actually dialled), follows no
// redirect and uses no proxy. local lets it reach a local address, which only an
// address the owner wrote down themselves may.
func GuardedClient(timeout time.Duration, local bool) *http.Client {
	return guardedClient(timeout, local)
}

// UseDialResolverForTest replaces how a name is turned into addresses at the
// moment of dialling, so a test can make a name answer differently when dialled
// than when it was checked. It returns the function that restores it.
func UseDialResolverForTest(f func(host string) ([]string, error)) (restore func()) {
	old := dialResolve
	dialResolve = func(_ context.Context, host string) ([]string, error) { return f(host) }
	return func() { dialResolve = old }
}

// ownersLocalAllowedFor is ownersLocalAllowed for a POST to a contact's address:
// a local address is allowed only where a contact the owner recorded is written
// as one, never for one a stranger's request left behind.
func (s *Service) ownersLocalAllowedFor(ctx context.Context, c store.ContactRecord, rawURL string) context.Context {
	return context.WithValue(ctx, guardKey{}, ownerLocalFor(c, rawURL))
}

// OwnerRecordedLocal is whether rawURL may be fetched from a local address: it
// is written as one, and it is the address of a contact the owner added or
// accepted.
func OwnerRecordedLocal(c store.ContactRecord, rawURL string) bool {
	return ownerLocalFor(c, rawURL)
}
