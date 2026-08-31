package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// Recognising a request from a machine this identity authorised.
//
// The shape is the owner-signature path with one substitution: the key a
// signature is checked against comes from the grant rather than from the owner
// authority. Everything that makes that path safe is kept — the request is
// signed over its own method, path and body, the timestamp bounds the window,
// and a signature is spent once so a captured one cannot be replayed.
//
// WHAT IT NEVER DOES IS SIGN AS THE IDENTITY. A controller signs as ITSELF, with
// the key that never left it, and asks the agent to act. The agent performs its
// own key operations, always. That is why revoking a grant is enough to stop a
// machine: it never held anything of the identity's to keep.

const (
	headerControllerAID       = "X-IA-Controller-AID"
	headerControllerSig       = "X-IA-Controller-Sig"
	headerControllerTimestamp = "X-IA-Controller-Timestamp"

	// How well the person at that machine has been authenticated, as measured
	// there and asserted by the machine.
	//
	// SIGNED OVER, NEVER READ ALONE. These are bound into the canonical string
	// below, so nothing between the controller and the agent can raise a level
	// in flight. What they rest on is that the machine is enclave hardware the
	// owner authorised, running a provider that measures the PERSON — the
	// controller is not choosing a number, it is reporting what its provider
	// found. A thief holding the laptop still has to produce the person's
	// factors.
	headerControllerAuthLevel = "X-IA-Controller-Auth-Level"
	headerControllerAuthAt    = "X-IA-Controller-Auth-At"
	headerControllerAuthScore = "X-IA-Controller-Auth-Score"
)

// controllerContextKey carries which machine acted, for anything downstream that
// needs to record it.
//
// An action taken from an authorised laptop and one taken by the owner at their
// own device are not the same event, and an audit trail that cannot tell them
// apart cannot answer the question somebody asks after a machine is stolen:
// what did it do. Its own type so nothing else can collide with it.
type controllerContextKey struct{}

// TheControllerThatAsked names the machine that signed this request, if one did.
//
// Empty for the owner acting directly, which is the honest answer rather than a
// default — nothing acted for them.
func TheControllerThatAsked(r *http.Request) (ControllerGrant, bool) {
	g, ok := r.Context().Value(controllerContextKey{}).(ControllerGrant)
	return g, ok
}

// controllerActsForTheOwner serves this request if an authorised machine signed
// it and the action is within what the person at that machine has proved.
//
// Reports whether it answered — either by serving or by refusing. False means
// no machine signed this, and the caller should carry on trying whatever else
// might stand in for the owner.
//
// A machine the owner authorised acts for them on everything except the actions
// that change who this identity IS. Those are not shut to it — a controller is
// hardware the owner approved, operated by a person who can be measured — they
// are RAISED, and the person has to authenticate to the level that action needs.
func (s *CoreServer) controllerActsForTheOwner(
	w http.ResponseWriter, r *http.Request, pattern string, next http.Handler,
) bool {
	grant, authenticated, err := s.theControllerBehind(r)
	if err != nil {
		return false
	}
	if ok, why := mayThisControllerDoThis(
		r.Method, pattern, authenticated, time.Now().UTC()); !ok {
		denyAuthorization(w, "this machine may act for you, but "+why)
		return true
	}
	// Carried forward so what this machine did is attributable to it rather than
	// to the owner.
	next.ServeHTTP(w, r.WithContext(
		context.WithValue(r.Context(), controllerContextKey{}, grant)))
	return true
}

// theControllerBehind identifies the machine that signed this request, if a
// machine did and its grant still stands.
//
// The error says which of those failed, because "not a controller" and "your
// authorisation ran out" need different things from the person.
func (s *CoreServer) theControllerBehind(r *http.Request) (ControllerGrant, authprovider.Result, error) {
	var none ControllerGrant
	unmeasured := authprovider.Unmeasured("this machine reported no authentication")

	aid := strings.TrimSpace(r.Header.Get(headerControllerAID))
	sig := strings.TrimSpace(r.Header.Get(headerControllerSig))
	stamp := strings.TrimSpace(r.Header.Get(headerControllerTimestamp))
	if aid == "" || sig == "" {
		return none, unmeasured, fmt.Errorf("this request is not from a controller")
	}
	if stamp == "" {
		return none, unmeasured, fmt.Errorf(
			"a signed request must carry %s", headerControllerTimestamp)
	}
	signedAt, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return none, unmeasured, fmt.Errorf("%s must be RFC3339", headerControllerTimestamp)
	}
	now := time.Now().UTC()
	if diff := now.Sub(signedAt); diff > signedRequestWindow || diff < -signedRequestWindow {
		return none, unmeasured, fmt.Errorf(
			"this request was signed outside the %s window", signedRequestWindow)
	}

	// The grant decides whether this machine is anybody. Checked before the
	// signature is verified only to fail fast; neither answer is given away,
	// because both end in the same refusal.
	grant, live, err := s.controllers().Live(aid, now)
	if err != nil {
		return none, unmeasured, fmt.Errorf(
			"which machines may act for this identity could not be read, so none were admitted: %w", err)
	}
	if !live {
		return none, unmeasured, fmt.Errorf(
			"this machine is not authorised to act for this identity, or its authorisation has ended")
	}

	pub, err := login.DecodeVerkey(grant.PublicKey)
	if err != nil {
		return none, unmeasured, fmt.Errorf("the key recorded for this machine is unusable: %w", err)
	}

	// Read the body to digest it, then put it back — the handler still needs it.
	//
	// A body over the limit is REFUSED, never truncated. Truncating would hand
	// the handler a shortened body and check the signature against that same
	// shortened copy, so the two would agree and the request would succeed while
	// silently doing something other than what was sent — a transfer, a policy,
	// a list, cut off at the limit with nothing reporting it.
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, maxSignedBodyBytes+1))
		if err != nil {
			return none, unmeasured, fmt.Errorf("read body: %w", err)
		}
		if int64(len(body)) > maxSignedBodyBytes {
			return none, unmeasured, fmt.Errorf(
				"this request is larger than the %d bytes a signed request may carry",
				maxSignedBodyBytes)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	asserted := theAuthenticationItAsserts(r)
	ok, err := login.VerifyString(
		canonicalControllerRequest(aid, r.Method, r.URL.Path, stamp, asserted, body), sig, pub)
	if err != nil {
		return none, unmeasured, fmt.Errorf("signature: %w", err)
	}
	if !ok {
		// Also what a tampered authentication level lands on, since the level is
		// inside the signed string.
		return none, unmeasured, fmt.Errorf(
			"this request was not signed by the machine it claims to be from")
	}

	// Valid — and now spent. Checked last so a bad signature cannot burn a good
	// one by presenting it first.
	if rememberSignature(sig, now) {
		return none, unmeasured, fmt.Errorf("this signed request has already been used")
	}
	return grant, asserted, nil
}

// theAuthenticationItAsserts reads what the machine says about the person at it.
//
// Absence is Unmeasured rather than a low level, matching the provider seam: an
// agent that measured nothing must not be treated as one that measured and found
// little, or removing the provider would be a way past a gate.
func theAuthenticationItAsserts(r *http.Request) authprovider.Result {
	level := authprovider.Level(strings.TrimSpace(r.Header.Get(headerControllerAuthLevel)))
	at := strings.TrimSpace(r.Header.Get(headerControllerAuthAt))
	if level == "" || at == "" {
		return authprovider.Unmeasured("this machine reported no authentication")
	}
	when, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return authprovider.Unmeasured("this machine reported when it checked, unreadably")
	}
	if !level.Known() {
		// A level this build does not define is not a level. Treated as nothing
		// measured, so a newer controller inventing a name cannot clear a gate
		// on an older agent.
		return authprovider.Unmeasured(
			"this machine reported an authentication level this agent does not recognise")
	}
	score, _ := strconv.Atoi(strings.TrimSpace(r.Header.Get(headerControllerAuthScore)))
	return authprovider.Result{
		Level:    level,
		Score:    score,
		Measured: true,
		At:       when.UTC(),
		Provider: "controller",
	}
}

// canonicalControllerRequest is the string a controller signs.
//
// Distinct from the owner's canonical string by its first line, so a signature
// made for one can never be presented as the other — the owner path and this one
// admit different keys to different authority, and a string both would accept is
// a way to cross between them.
//
// The asserted authentication is part of it. Left out, a level would be an
// unauthenticated header on an authenticated request, and anything in the middle
// could raise it.
//
// So is the machine's own identifier. The signature is already checked against
// the key recorded for that identifier, so this is not what stops an imposter —
// it stops one machine's signature from being presented under another's name,
// and it keeps two machines from ever producing identical signed bytes for the
// same request, which the replay guard would otherwise treat as a reused one.
func canonicalControllerRequest(
	controllerAID, method, path, timestamp string,
	authenticated authprovider.Result,
	body []byte,
) string {
	measuredAt := ""
	if authenticated.Measured && !authenticated.At.IsZero() {
		measuredAt = authenticated.At.UTC().Format(time.RFC3339)
	}
	level := ""
	if authenticated.Measured {
		level = string(authenticated.Level)
	}
	return strings.Join([]string{
		"IA-CONTROLLER-REQ-V1",
		controllerAID,
		strings.ToUpper(method),
		path,
		timestamp,
		level,
		measuredAt,
		strconv.Itoa(authenticated.Score),
		iacrypto.Blake3QB64Must(body),
	}, "\n")
}
