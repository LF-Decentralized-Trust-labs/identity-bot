package login

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Front-end kinds a sign-in may name (ADR-072 section 2).
const (
	FrontEndBrowser      = "browser"
	FrontEndInstalledApp = "installed_app"
)

const (
	// DefaultSpentFor is how long a spent sign-in is remembered: the Identity
	// Agent offers a challenge for ten minutes, so it cannot be answered later
	// than that and confirmed later still than the poll that follows.
	DefaultSpentFor = time.Hour
)

// StartRequest is what a site asks of the Identity Agent for one sign-in.
type StartRequest struct {
	// Audience is the site's own origin. The person's approval is for it alone.
	Audience           string
	RequestDisclosures []string
	// BrowserKey is the thumbprint of a key the person's browser holds, when the
	// sign-in is for that key (ADR-066).
	BrowserKey string
	// FrontEnd is FrontEndBrowser or FrontEndInstalledApp, for a utility app's
	// sign-in. Left empty for a website asset.
	FrontEnd string
}

// Started is a sign-in the Identity Agent has begun.
type Started struct {
	// SessionToken names the sign-in and travels in the pointer.
	SessionToken string
	// PointerUrl is what to show the person: scanning it opens the sign-in in
	// their Identity Agent.
	PointerUrl string
	// CollectorSecret stays on the server. ConfirmSession needs it to read who
	// signed in. Keep it out of the page and out of any link.
	CollectorSecret string
}

// Status is the Identity Agent's own word on a sign-in, as it said it, before
// ConfirmSession judges it.
type Status struct {
	State            string
	AppSessionToken  string
	Disclosures      map[string]any
	MemberInfo       *MemberInfo
	Reason           string
	BrowserKey       string
	FrontEnd         string
	IdentityWithheld bool
}

// Agent is how a back end reaches the Identity Agent that holds its asset. The
// contract (what is asked, what each answer means, what is spent) is this
// package's; the transport is the Agent's. HTTPAgent is a site's own: the
// Identity Agent's public login routes. A utility app's machine reaches its
// Identity Agent by sealed, app-signed calls instead, and supplies an Agent
// that makes them, so it gets the same checks and writes none of its own.
type Agent interface {
	// Scope names this Identity Agent and asset, so a spent sign-in is the same
	// one wherever it is confirmed from.
	Scope() string
	// Start begins a sign-in. A refusal is an error that carries the Identity
	// Agent's words.
	Start(ctx context.Context, r StartRequest) (Started, error)
	// Status reads how a sign-in stands, with the collector secret. An answer the
	// Identity Agent gave but that is not ok is Status{State: "pending"}; an error
	// is for a call that could not be made.
	Status(ctx context.Context, sessionToken, collectorSecret string) (Status, error)
}

// StartSession asks the Identity Agent for a sign-in. It is an error for the
// answer to lack a token, a pointer or the secret.
func StartSession(ctx context.Context, a Agent, r StartRequest) (Started, error) {
	if r.RequestDisclosures == nil {
		r.RequestDisclosures = []string{}
	}
	s, err := a.Start(ctx, r)
	if err != nil {
		return Started{}, err
	}
	if s.SessionToken == "" || s.PointerUrl == "" || s.CollectorSecret == "" {
		return Started{}, fmt.Errorf("login: the Identity Agent at %s answered a sign-in without a token, pointer and secret", a.Scope())
	}
	return s, nil
}

// Spent spends a verified sign-in so the same one signs nobody in twice.
// Claim reports true the first time a key is claimed. keepUntil is when the
// store may forget it. A site on more than one process shares one store.
type Spent interface {
	Claim(key string, keepUntil time.Time) (bool, error)
}

// ConfirmOptions asks how a sign-in went.
type ConfirmOptions struct {
	SessionToken string
	// CollectorSecret is what StartSession returned. Without it the Identity
	// Agent reports the state but withholds who signed in.
	CollectorSecret string
	// Spent, when set, spends a verified session: confirming it again is an
	// error. A site that issues its own session on Verified should pass one.
	Spent Spent
	// SpentFor is how long a spent sign-in is remembered; DefaultSpentFor when zero.
	SpentFor time.Duration
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// State is how a sign-in stands.
type State string

const (
	Verified State = "verified"
	Declined State = "declined"
	Pending  State = "pending"
)

// MemberInfo is who the admitting roster says a member is.
type MemberInfo struct {
	Role        string
	DisplayName string
}

// Confirmed is how a sign-in stands. Only a Verified one names a person.
type Confirmed struct {
	State State
	// PairwiseAID is who signed in, on Verified.
	PairwiseAID string
	Disclosures map[string]any
	MemberInfo  *MemberInfo
	// BrowserKey is the browser key the person's approval named (ADR-066), when
	// the sign-in was for one. A back end that binds its session to a browser's
	// key lets that browser in only when this is the thumbprint it started the
	// sign-in with.
	BrowserKey string
	// FrontEnd is the front-end kind the verified assertion repeated (ADR-072).
	FrontEnd string
	// Reason is why a sign-in was declined.
	Reason string
}

// ErrAlreadyUsed is returned when a verified sign-in has been confirmed before.
var ErrAlreadyUsed = errors.New("login: this sign-in has already been used")

// ConfirmSession asks the Identity Agent how the sign-in stands. Issue an
// application session only on Verified. An answer that is not ok, or that
// verifies nobody, is Pending, never Verified.
func ConfirmSession(ctx context.Context, a Agent, o ConfirmOptions) (Confirmed, error) {
	body, err := a.Status(ctx, o.SessionToken, o.CollectorSecret)
	if err != nil {
		return Confirmed{}, err
	}
	// Verified, but this caller could not collect: pending would spin forever
	// and verified would hand back an empty identity.
	if body.State == "verified" && body.IdentityWithheld {
		return Confirmed{}, errors.New("login: the Identity Agent withheld the identity — pass the collectorSecret returned when the session was created")
	}
	if body.State == "verified" && body.AppSessionToken != "" {
		if o.Spent != nil {
			now := time.Now
			if o.Now != nil {
				now = o.Now
			}
			keep := o.SpentFor
			if keep <= 0 {
				keep = DefaultSpentFor
			}
			fresh, err := o.Spent.Claim(a.Scope()+"|"+o.SessionToken, now().Add(keep))
			if err != nil {
				return Confirmed{}, fmt.Errorf("login: the spent-sign-in store failed: %w", err)
			}
			if !fresh {
				return Confirmed{}, ErrAlreadyUsed
			}
		}
		return Confirmed{State: Verified, PairwiseAID: body.AppSessionToken, Disclosures: body.Disclosures,
			MemberInfo: body.MemberInfo, BrowserKey: body.BrowserKey, FrontEnd: body.FrontEnd}, nil
	}
	if body.State == "declined" {
		return Confirmed{State: Declined, Reason: body.Reason}, nil
	}
	return Confirmed{State: Pending}, nil
}

// InMemorySpent is a Spent that forgets on restart and lives in one process.
// A site that restarts, or runs several processes, supplies its own.
type InMemorySpent struct {
	mu   sync.Mutex
	seen map[string]time.Time
	Now  func() time.Time
}

// Claim implements Spent. Entries past their keepUntil are dropped as it goes.
func (s *InMemorySpent) Claim(key string, keepUntil time.Time) (bool, error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	t := now()
	for k, until := range s.seen {
		if !until.After(t) {
			delete(s.seen, k)
		}
	}
	if _, used := s.seen[key]; used {
		return false, nil
	}
	s.seen[key] = keepUntil
	return true, nil
}
