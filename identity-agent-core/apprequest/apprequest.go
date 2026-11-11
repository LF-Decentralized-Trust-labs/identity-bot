// Package apprequest is the one reading of a request an app's back end signs
// as the app, with its App Body key (ADR-072 section 4, ADR-045 Amendment 1).
// The format is published in contracts/app-request, with vectors
// (app-request-vectors.json) and an independent checker
// (check_app_request_vectors.py).
//
// It checks what is in the request and the two credentials: who the request is
// for, when it was signed, that its key is the App Body's, and that the App
// Grant holds the capability the route needs, within any limit the grant puts
// on it. Which credentials those are,
// whether they are revoked, which routes an app may use and the spending of a
// signature are the Identity Agent's, and are not here.
package apprequest

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"identity-agent-core/agentbody"
)

// Request is a request as it was received: the method and target, the body,
// and the values of the headers an app's back end signs with (agentbody.Header*).
type Request struct {
	Method, Target string
	Body           []byte
	Host           string `json:"host"`
	For            string `json:"for"`
	Timestamp      string `json:"timestamp"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
	WorkItem       string `json:"work_item"`
	Reason         string `json:"reason"`
	Session        string `json:"session"`
}

// Admission is what the Identity Agent holds against which the request is
// read: itself, the time, the App Body credential that names the key, and the
// app's App Grant. ValidUntil is a credential's own end ("" when it has none).
type Admission struct {
	IdentityAgent           string
	Now                     time.Time
	BodyHost, BodyVerkey    string
	BodyValidUntil          string
	GrantCapabilities       []string
	GrantValidUntil         string
	CapabilityTheRouteNeeds string
	// GrantConstraints is what the grant limits that capability to: per
	// argument, the values it may use (the grant's resource_constraints for
	// CapabilityTheRouteNeeds). RouteArguments is the value the route itself
	// gives each argument, which the Identity Agent reads from the target (for
	// agent.message.send, "to" is the identifier the AI agent in the path is
	// addressed by, its pairwise_aid as a person's statement names it, never
	// the asset id the path carries).
	GrantConstraints map[string][]string
	RouteArguments   map[string]string
}

// The reasons a request is refused. Each is a vector's `refused` value.
const (
	NoIdentityAgent    = "names_no_identity_agent"
	OtherIdentityAgent = "other_identity_agent"
	BadTime            = "unreadable_time"
	OutsideWindow      = "outside_window"
	BadNonce           = "bad_nonce"
	WrongKey           = "key_is_not_the_app_bodys"
	BadSignature       = "bad_signature"
	BodyLapsed         = "app_body_lapsed"
	GrantLapsed        = "app_grant_lapsed"
	NoCapability       = "capability_not_held"
	OutsideConstraint  = "outside_the_grants_limit"
	CannotEnforce      = "limit_the_route_cannot_check"
)

// Refusal is a request refused, with the stable code a vector names.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string { return r.Detail }

func refuse(code, format string, a ...any) error {
	return &Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf is the code of a refusal, or "" for any other error.
func CodeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// Check admits the request or refuses it. On success it returns the exact string
// the key signed (agentbody.SignedRequest.Bytes, IA-BODY-REQ-V3), kept as the
// proof of what was asked. Checks run in this order and the first refusal is
// the answer: the Identity Agent it is for, the time, the nonce, the key, the
// signature, the two credentials' ends, the capability.
func Check(r Request, a Admission) (string, error) {
	switch {
	case r.For == "":
		return "", refuse(NoIdentityAgent, "the request does not name the Identity Agent it is for")
	case r.For != a.IdentityAgent:
		return "", refuse(OtherIdentityAgent, "the request was signed for a different Identity Agent")
	}
	when, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		return "", refuse(BadTime, "the request carries no readable timestamp")
	}
	if d := a.Now.Sub(when); d > agentbody.RequestWindow || d < -agentbody.RequestWindow {
		return "", refuse(OutsideWindow, "the request's timestamp is outside the window this Identity Agent accepts")
	}
	if agentbody.CheckNonce(r.Nonce) != nil {
		return "", refuse(BadNonce, "the request carries no nonce")
	}
	if r.Host != a.BodyHost {
		return "", refuse(WrongKey, "the request's key is not the one the App Body names")
	}
	msg := agentbody.SignedRequest{
		For: a.IdentityAgent, Host: r.Host, Method: r.Method, Target: r.Target, Timestamp: r.Timestamp, Nonce: r.Nonce,
		Body: r.Body, WorkItem: r.WorkItem, Reason: r.Reason, Session: r.Session,
	}.Bytes()
	if err := agentbody.Verify(r.Host, a.BodyVerkey, r.Signature, msg); err != nil {
		return "", refuse(BadSignature, "%v", err)
	}
	if lapsed(a.BodyValidUntil, a.Now) {
		return "", refuse(BodyLapsed, "this app's body credential has ended")
	}
	if lapsed(a.GrantValidUntil, a.Now) {
		return "", refuse(GrantLapsed, "this app's grant has ended")
	}
	held := false
	for _, c := range a.GrantCapabilities {
		if c == a.CapabilityTheRouteNeeds {
			held = true
		}
	}
	if !held {
		return "", refuse(NoCapability, "this app's grant does not hold %s, which this route needs", a.CapabilityTheRouteNeeds)
	}
	// A capability the grant limits is used only within the limit. A limit on
	// an argument the route does not give cannot be checked, so the request is
	// refused rather than read as unlimited. Arguments are read in name order,
	// so the first refusal is the same everywhere.
	args := make([]string, 0, len(a.GrantConstraints))
	for arg := range a.GrantConstraints {
		args = append(args, arg)
	}
	sort.Strings(args)
	for _, arg := range args {
		value, given := a.RouteArguments[arg]
		if !given {
			return "", refuse(CannotEnforce, "this app's grant limits %s by %q, which this route does not give, so the limit cannot be checked", a.CapabilityTheRouteNeeds, arg)
		}
		if !slices.Contains(a.GrantConstraints[arg], value) {
			return "", refuse(OutsideConstraint, "this app's grant limits %s to named values of %q, and %q is not one", a.CapabilityTheRouteNeeds, arg, value)
		}
	}
	return string(msg), nil
}

// lapsed is whether a credential's own end has passed. An end that cannot be
// read counts as passed.
func lapsed(until string, now time.Time) bool {
	if until == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, until)
	return err != nil || !now.Before(t)
}
