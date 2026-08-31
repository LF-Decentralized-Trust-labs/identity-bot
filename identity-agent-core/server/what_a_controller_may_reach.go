package server

import (
	"time"

	"identity-agent-core/authprovider"
)

// What a machine acting for this identity may do once it is authorised.
//
// PERMITTED BY DEFAULT, WITH A NAMED LIST OF EXCEPTIONS. That is the opposite
// of how a capability holder is treated, and deliberately so. A controller is
// the owner's own front end: it is the screen they drive their identity from,
// so a route added next month should be reachable from it. A permit-list would
// make every new route invisible until somebody remembered to grant it, and the
// pressure to fix that quickly is pressure to add things without thinking.
//
//	                | a scoped caller     | a controller
//	----------------|---------------------|---------------------------
//	default         | denied              | permitted
//	the list names  | what it MAY do      | what it may NOT do freely
//	a new route     | unreachable         | reachable, which is the point
//	for             | an AI agent         | the owner's front end
//
// THE EXCEPTIONS ARE NOT REFUSALS. This is where a controller differs from a
// browser session, which is simply told no (see sessionForbidden). A session is
// a convenience held by software with no key; a controller is hardware the owner
// authorised, holding a key, operated by a person who can be measured. So a
// high-risk action is not closed to it — it is raised, and the person has to
// authenticate to the level that action needs.
//
// That distinction is the whole design, and it comes from a case that breaks the
// obvious alternative: if the device holding an identity's key is stolen, and a
// controller may not rotate keys, then nobody can ever rotate them and the thief
// keeps the identity. So rotation MUST be reachable from a controller. What
// protects it is the level required, not the door being shut.

// controllerNeedsLevel names the actions a live grant alone is not enough for,
// with the authentication level the person must reach, and why.
//
// Keyed by "METHOD /chi/pattern", the same way publicRoutes and
// sessionForbidden are.
//
// Everything not named here is reachable by any authorised controller. The
// entries are the actions that change who this identity IS — its keys, who may
// sign for it, whether it can be recovered — plus the ones that hand out
// material an identity could be reconstructed from.
var controllerNeedsLevel = map[string]controllerRequirement{
	// --- the root of trust ---
	"POST /api/keystore/root-seed": {authprovider.LevelHigh,
		"installing a root seed decides what this identity is"},
	"POST /api/recovery/root-aid-rotation": {authprovider.LevelHigh,
		"rotating the root identifier replaces the identity's controlling key"},
	"POST /api/rotation": {authprovider.LevelHigh,
		"rotating keys replaces what signs for this identity"},
	"POST /api/reset": {authprovider.LevelHigh,
		"resetting destroys this identity"},

	// --- material an identity can be rebuilt from ---
	// An archive plus a passphrase is the identity to whoever holds both, so
	// pulling one out of this machine is close to taking the identity itself.
	// Three doors to the same room, and raising only the one named "recovery"
	// would have left the other two open.
	"POST /api/recovery/retrieve": {authprovider.LevelHigh,
		"an archive is the identity to anyone who can open it"},
	"POST /api/backup/export": {authprovider.LevelHigh,
		"an archive is the identity to anyone who can open it"},
	"POST /api/backup/pull/{destID}": {authprovider.LevelHigh,
		"this pulls back an archive, and an archive is the identity to anyone who can open it"},

	// --- where this identity's archives go ---
	// Not the identity itself, but the place copies of it are sent. Redirecting
	// that is a quiet way to be handed every future backup, and it would not look
	// like an attack in any log — which is exactly why it is raised.
	"PUT /api/backup/config": {authprovider.LevelVerified,
		"this decides where copies of this identity are sent"},
	"POST /api/backup/destinations": {authprovider.LevelVerified,
		"this adds a place copies of this identity are sent"},
	"DELETE /api/backup/destinations/{id}": {authprovider.LevelVerified,
		"removing a destination can leave this identity with nowhere it survives losing this machine"},
	"POST /api/backup/credentials": {authprovider.LevelVerified,
		"these are the credentials for the place copies of this identity are sent"},
	"PUT /api/backup/offer": {authprovider.LevelVerified,
		"this decides what this machine offers to hold for other people"},
	"DELETE /api/backup/held/{identityAID}": {authprovider.LevelVerified,
		"this destroys backups somebody else is relying on this machine to keep"},

	// --- acting as the identity ---
	// Signing arbitrary content IS the identity speaking, and unlike a credential
	// it carries no shape anybody can reason about afterwards. It belongs with the
	// strongest, beside the routes that replace keys.
	"POST /api/sign": {authprovider.LevelHigh,
		"this signs as the identity, and anything it signs cannot be unsaid"},
	"POST /api/events/signature": {authprovider.LevelVerified,
		"this attaches this identity's signature to an event"},

	// --- what this identity says about other people ---
	"POST /api/credential/issue": {authprovider.LevelVerified,
		"issuing a credential is this identity making a claim other people will rely on"},
	"POST /api/credentials/{said}/revoke": {authprovider.LevelVerified,
		"revoking withdraws something other people are relying on"},

	// --- the keys this identity holds for other services ---
	"POST /api/vault/credentials": {authprovider.LevelVerified,
		"these are the keys this identity holds for other services"},
	"DELETE /api/vault/credentials/{service}": {authprovider.LevelVerified,
		"removing a stored key can cut this identity off from a service it relies on"},

	// --- what it takes to get back in ---
	// The duress policy is the sharpest of these: it says what must happen if
	// the owner is being forced, so anything that could switch it off could
	// disable the protection and then use the recovery it protected against.
	"PUT /api/recovery/duress-policy": {authprovider.LevelHigh,
		"this decides what happens if the owner is being coerced"},
	"PUT /api/recovery/who-holds-this": {authprovider.LevelVerified,
		"this decides what it takes to get back into this identity"},

	// --- taking the identity over ---
	"POST /api/recovery/start": {authprovider.LevelVerified,
		"starting a recovery begins replacing this identity"},
	"POST /api/recovery/sessions/{id}/activate": {authprovider.LevelHigh,
		"activating a recovery replaces this identity and everything it held"},
	"POST /api/recovery/sessions/{id}/rotation": {authprovider.LevelHigh,
		"this rotates the identity's keys"},
	"POST /api/recovery/sessions/{id}/cancel": {authprovider.LevelVerified,
		"stopping a recovery decides whether it happens"},

	// --- bringing an identity into being, and using its key ---
	"POST /api/inception": {authprovider.LevelHigh,
		"this creates the identity itself"},
	// Fulfilling a signing request is the identity's own key being used. A
	// controller never signs as the identity — it asks the agent to — so this is
	// the point where asking becomes the identity having said something.
	"POST /api/signing-requests/{id}/fulfil": {authprovider.LevelVerified,
		"this signs as the identity, and what is signed cannot be unsaid"},

	// --- who may sign for this identity ---
	"POST /api/signer/invites": {authprovider.LevelHigh,
		"inviting a signer decides who else may sign for this identity"},
	"POST /api/signer/invites/{token}/redeem": {authprovider.LevelVerified,
		"redeeming a signer invitation adds somebody who may sign"},

	// --- who belongs to this organisation ---
	"POST /api/employees/{aid}/approve": {authprovider.LevelVerified,
		"approving somebody gives them a credential from this organisation"},
	"POST /api/employees/{aid}/revoke": {authprovider.LevelVerified,
		"revoking somebody takes away what this organisation said about them"},

	// --- who else may act for this identity ---
	// A controller that could freely authorise more controllers is a controller
	// that can make its own access permanent — including after the owner
	// revokes the one they know about.
	"POST /api/controllers": {authprovider.LevelHigh,
		"this decides which other machines may act for this identity"},
	"DELETE /api/controllers/{aid}": {authprovider.LevelVerified,
		"removing another machine's authorisation is the owner's decision"},
}

// controllerRequirement is what one of those actions asks for.
type controllerRequirement struct {
	// Level the person must have reached. Never LevelUnknown — see
	// theLevelThisActionNeeds.
	Level authprovider.Level
	// Why is said to the person when they are stopped, because "denied" leaves
	// somebody with no idea what would let them through.
	Why string
}

// controllerAuthenticationFreshness is how recently the person must have been
// measured for a raised action.
//
// An authentication is a statement about a moment. A level established when the
// controller was first authorised says nothing about who is at that keyboard
// now, and treating it as current is how a threshold becomes a formality — the
// laptop is authorised for months, so the level would be too.
const controllerAuthenticationFreshness = 5 * time.Minute

// theLevelThisActionNeeds reports what a controller must have reached to perform
// this route, and whether it is raised at all.
//
// An unrecognised level in the table is treated as the strongest requirement
// rather than ignored. A typo there would otherwise disable a gate silently, and
// the failure would look exactly like the route not being listed — the one
// mistake in this file that nothing else would catch.
func theLevelThisActionNeeds(method, pattern string) (controllerRequirement, bool) {
	req, ok := controllerNeedsLevel[method+" "+pattern]
	if !ok {
		return controllerRequirement{}, false
	}
	if !req.Level.Known() || req.Level == authprovider.LevelUnknown {
		return controllerRequirement{
			Level: authprovider.LevelHigh,
			Why:   req.Why,
		}, true
	}
	return req, true
}

// mayThisControllerDoThis decides a single request from an authorised machine.
//
// The grant is assumed live — that is a separate question, answered before this
// is called. This answers only the second one: is this particular action within
// what the person at that machine has proved.
//
// Returns the reason when it refuses, so the caller can tell the person what
// would let them through rather than only that something stopped them.
func mayThisControllerDoThis(
	method, pattern string,
	authenticated authprovider.Result,
	now time.Time,
) (bool, string) {

	req, raised := theLevelThisActionNeeds(method, pattern)
	if !raised {
		// Permitted by default. This is the common path and the point of the
		// whole class.
		return true, ""
	}

	if !authenticated.Measured {
		return false, req.Why + ", so this needs you to be authenticated first — " +
			"and nothing has measured who is at this machine"
	}
	if !freshEnough(authenticated, now) {
		return false, req.Why + ", so this needs a recent check of who is at this " +
			"machine, and the last one is too old"
	}
	if !authenticated.Level.AtLeast(req.Level) {
		return false, req.Why + ", so it needs a stronger check of who is at this machine"
	}
	return true, ""
}

// freshEnough is Result.Fresh against this package's window, with the clock
// passed in rather than read, so a test can put a measurement in the past
// without sleeping.
func freshEnough(r authprovider.Result, now time.Time) bool {
	if !r.Measured || r.At.IsZero() {
		return false
	}
	if r.At.After(now) {
		// A measurement from the future is a clock problem or an invention, and
		// neither should satisfy a freshness rule that exists to keep answers
		// current.
		return false
	}
	return now.Sub(r.At) <= controllerAuthenticationFreshness
}
