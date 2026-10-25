// Package appcall tells an app who called it, in a form only the Identity
// Agent could have produced.
//
// When the Identity Agent forwards an admitted capability call to the app that
// provides it, the app needs to know who the Identity Agent admitted: the owner
// or an AI agent, which one, from which machine, how it proved itself, under
// which grant and in which of its sessions. Headers alone cannot carry that,
// because anything that can reach the app can set headers. So the Identity Agent
// adds a MAC under a key only it and that app hold, over the capability, a
// digest of the body, the caller, the moment and a fresh nonce. The app refuses
// any call without one that verifies.
//
// The Identity Agent side is Stamp; the app side is Verifier, usually through
// Verifier.Require. An app built in another language implements the same
// canonical string (Canonical) and HMAC-SHA256.
package appcall

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"identity-agent-core/iacrypto"
)

// The headers a forwarded call carries. Every one of them is covered by the MAC
// except the MAC itself.
const (
	HeaderCapability = "X-IA-Call-Capability"
	HeaderKind       = "X-IA-Call-Kind"
	HeaderIdentifier = "X-IA-Call-Identifier"
	HeaderMachine    = "X-IA-Call-Machine"
	HeaderAuthLevel  = "X-IA-Call-Auth-Level"
	HeaderGrant      = "X-IA-Call-Grant"
	HeaderSession    = "X-IA-Call-Session"
	HeaderTime       = "X-IA-Call-Time"
	HeaderNonce      = "X-IA-Call-Nonce"
	HeaderMAC        = "X-IA-Call-MAC"
)

// headerPrefix is what every header above starts with, so anything forwarding
// a request to an app can strip all of them, including ones added later.
const headerPrefix = "X-Ia-Call-"

// What kind of caller the Identity Agent admitted.
const (
	// KindOwner is the person who controls the identity, at their own
	// computer or proving it remotely with the identity's key.
	KindOwner = "owner"
	// KindAIAgent is an AI agent acting under a grant the identity issued it.
	KindAIAgent = "ai_agent"
	// KindToken is a token holder that is not bound to an AI agent.
	KindToken = "token"
	// KindMachine is a machine the identity owns, identified by its signature.
	KindMachine = "machine"
)

// KeyEnv is the environment variable an app launched by the Identity Agent
// finds its key in, base64url without padding.
const KeyEnv = "IDENTITY_AGENT_CALL_KEY"

// Window is how far a call's time may be from the app's clock.
const Window = 2 * time.Minute

// KeySize is the length of a key in bytes.
const KeySize = 32

// Caller is who the Identity Agent admitted.
type Caller struct {
	// Kind is one of the Kind constants.
	Kind string
	// Agent is the caller's identifier: the AI agent's, the owner's when it
	// is known, the token's name for a bare token.
	Identifier string
	// Machine is the machine the call came from, when the caller proved one:
	// an AI agent's body.
	Machine string
	// AuthLevel is how the caller proved itself to the Identity Agent:
	// "local" (the owner at the Identity Agent's own computer),
	// "owner_signed" or "owner_sealed" (the owner, remotely, by the identity's
	// key or inside an envelope only it could seal), "body_signed" (an AI
	// agent's enrolled machine signed the request), "signed_request" (a token
	// plus a per-request signature), "bearer" (a token alone), or
	// "signed_headers" (a machine the identity owns, which is granted nothing
	// for it). An app deciding who may write should require one of the first
	// four.
	AuthLevel string
	// Grant is the credential the caller's authority came from, when there
	// is one.
	Grant string
	// Session is which of the caller's runs made the call, when it said.
	Session string
}

// Canonical is the string the MAC covers. Its first line versions it.
func Canonical(capabilityID, bodyDigest string, c Caller, at, nonce string) string {
	return strings.Join([]string{
		"IA-APP-CALL-V1",
		capabilityID,
		bodyDigest,
		c.Kind,
		c.Identifier,
		c.Machine,
		c.AuthLevel,
		c.Grant,
		c.Session,
		at,
		nonce,
	}, "\n")
}

// NewKey makes a key for one app.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncodeKey is a key in the form KeyEnv carries.
func EncodeKey(k []byte) string { return base64.RawURLEncoding.EncodeToString(k) }

// DecodeKey reads a key in the form KeyEnv carries.
func DecodeKey(s string) ([]byte, error) {
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("the call key is not base64url: %w", err)
	}
	if len(k) != KeySize {
		return nil, fmt.Errorf("the call key is %d bytes, not %d", len(k), KeySize)
	}
	return k, nil
}

// Strip removes every call header from h. Anything forwarding a request it did
// not stamp itself calls this, so a caller cannot hand an app a caller of its
// own choosing.
func Strip(h http.Header) {
	for name := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), headerPrefix) {
			delete(h, name)
		}
	}
}

// IsCallHeader reports whether name is one of the call headers.
func IsCallHeader(name string) bool {
	return strings.HasPrefix(http.CanonicalHeaderKey(name), headerPrefix)
}

// Stamp writes the caller onto h for a call to capabilityID carrying body,
// replacing any call headers already there.
func Stamp(h http.Header, key []byte, capabilityID string, body []byte, c Caller, now time.Time) error {
	if len(key) != KeySize {
		return fmt.Errorf("an app call key must be %d bytes", KeySize)
	}
	if err := plain(capabilityID, c); err != nil {
		return err
	}
	nb := make([]byte, 18)
	if _, err := rand.Read(nb); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	at := now.UTC().Format(time.RFC3339)
	Strip(h)
	h.Set(HeaderCapability, capabilityID)
	set := func(name, v string) {
		if v != "" {
			h.Set(name, v)
		}
	}
	set(HeaderKind, c.Kind)
	set(HeaderIdentifier, c.Identifier)
	set(HeaderMachine, c.Machine)
	set(HeaderAuthLevel, c.AuthLevel)
	set(HeaderGrant, c.Grant)
	set(HeaderSession, c.Session)
	h.Set(HeaderTime, at)
	h.Set(HeaderNonce, nonce)
	h.Set(HeaderMAC, sum(key, Canonical(capabilityID, iacrypto.Blake3QB64Must(body), c, at, nonce)))
	return nil
}

// plain refuses a value that could move a field in the canonical string.
func plain(capabilityID string, c Caller) error {
	for _, v := range []string{capabilityID, c.Kind, c.Identifier, c.Machine, c.AuthLevel, c.Grant, c.Session} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("a call field may not contain a line break")
		}
	}
	return nil
}

func sum(key []byte, canonical string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Verifier is the app's side: it accepts a call only with a MAC under its key,
// fresh, and not seen before.
type Verifier struct {
	key []byte
	// Now is the clock, replaceable in a test.
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewVerifier verifies calls under key.
func NewVerifier(key []byte) (*Verifier, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("an app call key must be %d bytes", KeySize)
	}
	return &Verifier{key: append([]byte(nil), key...), seen: map[string]time.Time{}}, nil
}

// VerifierFromEnv is the verifier for an app the Identity Agent launched, with
// the key it was given in KeyEnv. An app with no key refuses every call rather
// than accepting them unchecked, so this is an error.
func VerifierFromEnv() (*Verifier, error) {
	v := os.Getenv(KeyEnv)
	if v == "" {
		return nil, fmt.Errorf("%s is not set, so no call from the Identity Agent can be checked", KeyEnv)
	}
	k, err := DecodeKey(v)
	if err != nil {
		return nil, err
	}
	return NewVerifier(k)
}

// Verify checks a call to capabilityID carrying body, and returns who made it.
func (v *Verifier) Verify(h http.Header, capabilityID string, body []byte) (Caller, error) {
	var none Caller
	got := h.Get(HeaderMAC)
	if got == "" {
		return none, errors.New("the call carries no MAC from the Identity Agent")
	}
	if h.Get(HeaderCapability) != capabilityID {
		return none, errors.New("the call was stamped for a different capability")
	}
	c := Caller{
		Kind: h.Get(HeaderKind), Identifier: h.Get(HeaderIdentifier), Machine: h.Get(HeaderMachine),
		AuthLevel: h.Get(HeaderAuthLevel), Grant: h.Get(HeaderGrant), Session: h.Get(HeaderSession),
	}
	at, nonce := h.Get(HeaderTime), h.Get(HeaderNonce)
	if nonce == "" {
		return none, errors.New("the call carries no nonce")
	}
	when, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return none, errors.New("the call's time is unreadable")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if d := now.Sub(when); d > Window || d < -Window {
		return none, errors.New("the call's time is outside the window")
	}
	want := sum(v.key, Canonical(capabilityID, iacrypto.Blake3QB64Must(body), c, at, nonce))
	if !hmac.Equal([]byte(got), []byte(want)) {
		return none, errors.New("the call's MAC does not verify")
	}
	if c.Kind == "" {
		return none, errors.New("the call names no kind of caller")
	}
	// Spent on first use, after the MAC holds, so a forged call cannot burn a
	// real one's nonce. Remembered for two windows, because a time up to one
	// window ahead stays valid for two.
	v.mu.Lock()
	defer v.mu.Unlock()
	for n, t := range v.seen {
		if now.Sub(t) > 2*Window {
			delete(v.seen, n)
		}
	}
	if _, used := v.seen[nonce]; used {
		return none, errors.New("this call was already received")
	}
	v.seen[nonce] = now
	return c, nil
}

type callerKey struct{}

// FromContext is the caller Require verified, inside the handler it wraps.
func FromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// capabilityPath is where the Identity Agent posts a capability call.
const capabilityPath = "/v1/capability/"

// MaxBody is the largest body Require reads.
const MaxBody = 8 << 20

// Require serves next only for a call the Identity Agent stamped, to the
// capability its path names, and puts the caller in the request's context.
// Anything else is refused with 401 and never reaches next.
func (v *Verifier) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, capabilityPath)
		if id == r.URL.Path || id == "" || strings.Contains(id, "/") {
			http.Error(w, "not a capability call", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil || len(body) > MaxBody {
			http.Error(w, "the call's body could not be read", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		c, err := v.Verify(r.Header, id, body)
		if err != nil {
			http.Error(w, "refused: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
	})
}
