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
	"POST /api/keystore/root-seed": {alsoRaised, authprovider.LevelHigh,
		"installing a root seed decides what this identity is"},
	"POST /api/recovery/root-aid-rotation": {alsoRaised, authprovider.LevelHigh,
		"rotating the root identifier replaces the identity's controlling key"},
	"POST /api/rotation": {alsoRaised, authprovider.LevelHigh,
		"rotating keys replaces what signs for this identity"},
	"POST /api/reset": {alsoRaised, authprovider.LevelHigh,
		"resetting destroys this identity"},

	// --- material an identity can be rebuilt from ---
	// An archive plus a passphrase is the identity to whoever holds both, so
	// pulling one out of this machine is close to taking the identity itself.
	// Three doors to the same room, and raising only the one named "recovery"
	// would have left the other two open.
	"POST /api/recovery/retrieve": {alsoRaised, authprovider.LevelHigh,
		"an archive is the identity to anyone who can open it"},
	"POST /api/backup/export": {alsoRaised, authprovider.LevelHigh,
		"an archive is the identity to anyone who can open it"},
	"POST /api/backup/pull/{destID}": {alsoRaised, authprovider.LevelHigh,
		"this pulls back an archive, and an archive is the identity to anyone who can open it"},

	// --- where this identity's archives go ---
	// Not the identity itself, but the place copies of it are sent. Redirecting
	// that is a quiet way to be handed every future backup, and it would not look
	// like an attack in any log — which is exactly why it is raised.
	"PUT /api/backup/config": {alsoRaised, authprovider.LevelVerified,
		"this decides where copies of this identity are sent"},
	"POST /api/backup/destinations": {alsoRaised, authprovider.LevelVerified,
		"this adds a place copies of this identity are sent"},
	"DELETE /api/backup/destinations/{id}": {alsoRaised, authprovider.LevelVerified,
		"removing a destination can leave this identity with nowhere it survives losing this machine"},
	"POST /api/backup/credentials": {alsoRaised, authprovider.LevelVerified,
		"these are the credentials for the place copies of this identity are sent"},
	"PUT /api/backup/offer": {alsoRaised, authprovider.LevelVerified,
		"this decides what this machine offers to hold for other people"},
	"DELETE /api/backup/held/{identityAID}": {alsoRaised, authprovider.LevelVerified,
		"this destroys backups somebody else is relying on this machine to keep"},

	// --- acting as the identity ---
	// Signing arbitrary content IS the identity speaking, and unlike a credential
	// it carries no shape anybody can reason about afterwards. It belongs with the
	// strongest, beside the routes that replace keys.
	"POST /api/sign": {alsoRaised, authprovider.LevelHigh,
		"this signs as the identity, and anything it signs cannot be unsaid"},
	"POST /api/events/signature": {alsoRaised, authprovider.LevelVerified,
		"this attaches this identity's signature to an event"},

	// --- what this identity says about other people ---
	"POST /api/credential/issue": {alsoRaised, authprovider.LevelVerified,
		"issuing a credential is this identity making a claim other people will rely on"},
	"POST /api/credentials/{said}/revoke": {alsoRaised, authprovider.LevelVerified,
		"revoking withdraws something other people are relying on"},

	// --- the keys this identity holds for other services ---
	"POST /api/vault/credentials": {alsoRaised, authprovider.LevelVerified,
		"these are the keys this identity holds for other services"},
	"DELETE /api/vault/credentials/{service}": {alsoRaised, authprovider.LevelVerified,
		"removing a stored key can cut this identity off from a service it relies on"},

	// --- what it takes to get back in ---
	// The duress policy is the sharpest of these: it says what must happen if
	// the owner is being forced, so anything that could switch it off could
	// disable the protection and then use the recovery it protected against.
	"PUT /api/recovery/duress-policy": {alsoRaised, authprovider.LevelHigh,
		"this decides what happens if the owner is being coerced"},
	"PUT /api/recovery/who-holds-this": {alsoRaised, authprovider.LevelVerified,
		"this decides what it takes to get back into this identity"},

	// --- taking the identity over ---
	"POST /api/recovery/start": {alsoRaised, authprovider.LevelVerified,
		"starting a recovery begins replacing this identity"},
	"POST /api/recovery/sessions/{id}/activate": {alsoRaised, authprovider.LevelHigh,
		"activating a recovery replaces this identity and everything it held"},
	"POST /api/recovery/sessions/{id}/rotation": {alsoRaised, authprovider.LevelHigh,
		"this rotates the identity's keys"},
	"POST /api/recovery/sessions/{id}/cancel": {alsoRaised, authprovider.LevelVerified,
		"stopping a recovery decides whether it happens"},

	// --- bringing an identity into being, and using its key ---
	"POST /api/inception": {alsoRaised, authprovider.LevelHigh,
		"this creates the identity itself"},
	// Fulfilling a signing request is the identity's own key being used. A
	// controller never signs as the identity — it asks the agent to — so this is
	// the point where asking becomes the identity having said something.
	"POST /api/signing-requests/{id}/fulfil": {alsoRaised, authprovider.LevelVerified,
		"this signs as the identity, and what is signed cannot be unsaid"},

	// --- who may sign for this identity ---
	"POST /api/signer/invites": {alsoRaised, authprovider.LevelHigh,
		"inviting a signer decides who else may sign for this identity"},
	"POST /api/signer/invites/{token}/redeem": {alsoRaised, authprovider.LevelVerified,
		"redeeming a signer invitation adds somebody who may sign"},

	// --- who belongs to this organisation ---
	"POST /api/employees/{aid}/approve": {alsoRaised, authprovider.LevelVerified,
		"approving somebody gives them a credential from this organisation"},
	"POST /api/employees/{aid}/revoke": {alsoRaised, authprovider.LevelVerified,
		"revoking somebody takes away what this organisation said about them"},

	// --- this machine's own enclave ---
	//
	// Closed for the same reason as the group below, one step removed. The file
	// says this route is "owner-only, which on a controller means the app
	// running on it" — which stopped being true the moment an authorised
	// controller began reaching owner-class routes. Left open, anyone holding a
	// grant on this machine, or a browser session on it, could make its enclave
	// sign arbitrary controller requests as this machine, to be replayed at any
	// agent where it is a controller.
	//
	// The app on this computer reaches it as the LOCAL owner, which is a
	// different caller from a controller and is unaffected.
	"POST /api/controller/sign": {neverByAController, authprovider.LevelHigh,
		"asking this computer's secure hardware to sign is for the app running on it, " +
			"not for something reaching it from elsewhere"},

	// The same door, one step worse. This one signs as the OWNER of a machine —
	// a pairwise identity derived from the root seed — so a controller that
	// could reach it would obtain owner signatures and every raised action with
	// them, which is the entire gate this file exists to hold.
	//
	// Reached by the app on this computer as the local owner, which is a
	// different caller and unaffected.
	"POST /api/machines/owner/sign": {neverByAController, authprovider.LevelHigh,
		"signing as the identity that owns a machine is the owner's own key, and a " +
			"machine acting for somebody is not that person"},

	// --- the state that decides WHO THE OWNER IS ---
	//
	// CLOSED, and this group is the one with a rule behind it rather than a
	// judgement. Permitted-by-default is safe only where the thing being
	// permitted cannot change the decision that permitted it. These routes can:
	// each writes state that ownerAuthority() reads to work out whose signature
	// counts as the owner's, and whose statement counts when vouching for an
	// authentication level.
	//
	// The attack, proven on this branch before these were closed: a controller
	// at NO authentication level posts its own key here, becomes the owner
	// authority, signs an IA-AUTH-LEVEL-V1 statement for itself at the strongest
	// level, and every raised gate opens. Worse than that, it is then the owner
	// for isOwner on every route — which survives revoking its grant, because
	// the grant is no longer what it is using.
	//
	// So the rule, and it generalises past these five: A CONTROLLER MAY NOT
	// WRITE ANYTHING THE AUTHORISATION DECISION READS. Anything added later that
	// feeds ownerAuthority — the identity record, the contact records its key is
	// resolved from, the sealed record — belongs here on sight.
	// Its twin, and it was missed for the same reason: the two are the storage
	// pair, adjacent in the router, and one was named here while the other was
	// named nowhere. This one writes key events and publishes them to the
	// witnesses, which is a stronger thing than writing the identity row.
	"POST /api/store/event": {neverByAController, authprovider.LevelHigh,
		"writing key events decides what this identity's own history says, which " +
			"is what every other check is read against"},

	"POST /api/store/identity": {neverByAController, authprovider.LevelHigh,
		"this decides which identity this agent is, and so whose signature counts as its owner's"},
	"POST /api/contacts": {neverByAController, authprovider.LevelHigh,
		"the owner's key is resolved from contacts, so writing one can replace the owner"},
	"PUT /api/contacts/{aid}": {neverByAController, authprovider.LevelHigh,
		"the owner's key is resolved from contacts, so editing one can replace the owner"},
	"POST /api/contacts/resolve": {neverByAController, authprovider.LevelHigh,
		"this fetches a record from an address the caller names and stores the key it returns"},
	// The same primitive by two less obvious doors, both found only by tracing
	// what the handlers CALL rather than by reading their names. handleScanExecute
	// and the ask handlers reach EnsureKeriContact, which fetches an OOBI from an
	// address in the payload and stores the key it gets back — exactly what the
	// contact routes above do. Neither route has "contact" in its name, which is
	// the whole lesson: this list cannot be kept correct by reading it.
	"POST /api/scan/execute": {neverByAController, authprovider.LevelHigh,
		"performing a scanned request can write a contact record, and the owner's key is resolved from those"},
	"POST /api/ask/create": {neverByAController, authprovider.LevelHigh,
		"creating a request can write a contact record, and the owner's key is resolved from those"},
	"DELETE /api/contacts/{aid}": {neverByAController, authprovider.LevelHigh,
		"removing the owner's contact record changes how the owner's key is resolved"},

	// --- who else may act for this identity ---
	//
	// ENROLLING A CONTROLLER IS CLOSED TO CONTROLLERS, at any level. It is the
	// only entry here that no authentication opens, and the reason is
	// persistence: the statement vouching for a level names the machine, the
	// level and the moment, but NOT the action. So one high statement, obtained
	// honestly for something the person did intend, can be spent inside its
	// window on enrolling a second machine — and that second grant outlives the
	// revocation of the first. An attacker who briefly holds a controller would
	// leave with permanent access the owner cannot see they gave.
	//
	// It costs nothing to close. The ceremony never routed through here: a grant
	// is created by the device holding the key, which is the owner and is not a
	// controller. The case Rob's ruling protects — a stolen key device, where
	// rotation must stay reachable from a laptop — is rotation, not enrolment.
	"POST /api/controllers": {neverByAController, authprovider.LevelHigh,
		"deciding which other machines may act for this identity is the owner's " +
			"alone, and is done from the device holding the key"},

	// Revoking stays open, at a level. An attacker who reached it could remove
	// the owner's other machines, which is a nuisance and not an escalation —
	// and the case for keeping it is real: somebody whose laptop was stolen
	// removes it from their desktop.
	"DELETE /api/controllers/{aid}": {alsoRaised, authprovider.LevelVerified,
		"removing another machine's authorisation is the owner's decision"},

	// Reading the list is raised because of what it contains: every machine that
	// may act for this identity, its label, and its key. That is a map of the
	// owner's devices, and a machine somebody borrowed for an afternoon should
	// not leave with it.
	"GET /api/controllers": {alsoRaised, authprovider.LevelAuthenticated,
		"this lists every machine that may act for you, and the key each one uses"},
}

// controllerRequirement is what one of those actions asks for.
type controllerRequirement struct {
	// Closed marks an action no authentication level opens to a controller.
	//
	// Distinct from a very high level rather than expressed as one, because they
	// are different statements: a level says "prove more"; this says "not from
	// here, whatever you prove". Written as a level it would silently become
	// reachable the day a stronger level was added.
	Closed bool
	// Level the person must have reached, when the action is open at all. Never
	// LevelUnknown — see theLevelThisActionNeeds.
	Level authprovider.Level
	// Why is said to the person when they are stopped, because "denied" leaves
	// somebody with no idea what would let them through.
	Why string
}

// Named so the table reads as what it means rather than as a bare true/false.
const (
	neverByAController = true
	alsoRaised         = false
)

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
			Closed: req.Closed,
			Level:  authprovider.LevelHigh,
			Why:    req.Why,
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

	// Closed before any level is considered, so no authentication opens it and
	// adding a stronger level later cannot open it by accident.
	if req.Closed {
		return false, req.Why
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
