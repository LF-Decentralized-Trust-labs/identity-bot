// Package permission says who is asking and holds the one check every governed
// action passes. It stands apart from the sandboxed-app runtime, so the core
// can ask it without linking that runtime.
package permission

import "strings"

// Headers that present a caller. The core reads them to know that a caller
// presented something, whichever add-on can then say who that is.
const (
	// HeaderBodyHost names the machine key an AI agent's body signs a request
	// with. A request carrying it presents a body's signature.
	HeaderBodyHost = "X-IA-Body-Host"
	// HeaderSession says which of the caller's runs made a request. It is
	// recorded and passed to the app a call reaches, and decides nothing.
	HeaderSession = "X-IA-Session"
)

// CallerContext is who is invoking a capability, as far as governance needs. Remote
// marks a request that arrived over the network (not the local owner); Scopes are the
// capability ids the caller has been granted. CallerAID identifies the caller for the
// audit trail (a delegated AID once ACDC resolution lands; a token identity or
// "local-owner" until then). CorrelationID is minted at the origin request and
// propagated through every hop so one action's full path is one query. Full caller
// identity + ACDC-scope resolution is wired through the governance gateway + delegated
// identity; this is the minimal governance input the endpoint enforces today.
type CallerContext struct {
	Remote bool
	Scopes []string
	// NoScopesBecause says why a caller has no scopes, when it is something
	// the caller's owner can do something about, so a denial says so.
	NoScopesBecause string
	CallerAID       string
	CorrelationID   string
	Transport       string
	// DelegationChain is the caller's KERI lineage, root-last (e.g.
	// [agentAID, rootAID]) — populated when the caller is a provisioned agent
	// identity, so the audit event proves "owner -> agent". Empty for a bare
	// token or the local owner.
	DelegationChain []string
	// GrantSAID is the SAID of the verified capability-grant credential the
	// caller's authority was derived from — the machine-readable sanction ("why")
	// recorded in the audit event. Empty when scopes came from a bare token
	// ceiling rather than a verified credential.
	GrantSAID string
	// EnvelopeVerified is true when the request carried a valid, fresh, non-replayed
	// signed-request envelope proving the caller signed THIS request (the strongest
	// caller proof). False for a plain bearer-token request.
	EnvelopeVerified bool
	// AuthLevel names how the caller was authenticated: "bearer" (token only) or
	// "signed_request" (token + a verified per-request signature). Recorded in audit.
	AuthLevel string
	// ResourceConstraints are per-capability argument limits carried by the caller's
	// verified capability grant: capabilityID -> {argKey: [allowedValues]}. Enforced
	// against the request arguments at invoke time. Empty = unconstrained.
	ResourceConstraints map[string]interface{}
	// BodyHost, BodyGrade and BodyCredential name the machine an AI agent spoke
	// from, when the request was signed by one of its bodies: the body's key
	// identifier, how strongly that key is held (never above what was checked),
	// and the credential binding it to the AI agent. Empty otherwise.
	BodyHost       string
	BodyGrade      string
	BodyCredential string
	// Owner is true when the gate established that this caller is the owner,
	// by any of the ways an owner proves it: at this computer, by the
	// identity's signature, or inside an envelope only the identity could
	// seal. Remote still says whether the request came over the network, so a
	// remote owner keeps every rule that holds for remote callers — a
	// host_control capability stays local-only — and is let past only the
	// scope check, which exists to bound what somebody OTHER than the owner
	// may do.
	Owner bool
	// Session is which of the caller's runs made the call, when it said.
	// Caller-supplied like WorkItem (signed with the request where the caller
	// signs its requests) and never a governance input; it is passed to the
	// app so the app can tell one run of an AI agent from another.
	Session string
	// OrchestratedBy is the AID of the master orchestrator that dispatched this call,
	// when the invocation is one step of an orchestration. The step still executes
	// under the worker's OWN authority (CallerAID + grant); OrchestratedBy records who
	// coordinated it, so the governance log answers "under whose direction" as well as
	// "under whose authority". Empty for a direct call.
	OrchestratedBy string
	// ParentEventID links this invocation to the orchestration's dispatch event, so a
	// full multi-agent workflow is one parent→children trace. Empty for a direct call.
	ParentEventID string
	// WorkItem is the identifier of the piece of work this call serves — a task ref, a
	// ticket, an orchestrator work-item id. GrantSAID already answers "why was this
	// ALLOWED"; WorkItem answers the different question "what was it FOR". Without it a
	// log can say an AI agent wrote code but not what it was trying to accomplish, which
	// is the difference between a list of events and an account of what happened.
	//
	// Caller-supplied and therefore NOT a governance input: it is never consulted when
	// authorizing, only recorded. A caller can lie about its work item exactly as it can
	// lie in a commit message, and the cost of that is the same — the authority fields
	// beside it (CallerAID, GrantSAID, DelegationChain) are the ones the gateway proves.
	WorkItem string
	// Reason is one line of plain language for a human reading the log later. Same
	// caller-supplied, non-governing status as WorkItem.
	Reason string
}

// IsLoopbackHost reports whether a request host is local (owner) vs remote.
func IsLoopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}
