package server

import (
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/permission"
)

// What a machine acting for this identity may do once it is authorised.
//
// EVERY ACTION, EXCEPT A SHORT OWNER-ONLY LIST. That is the opposite of how a
// capability holder is treated, and deliberately so. A controller is the
// owner's own front end: it is the screen they drive their identity from, so a
// route added next month should be reachable from it. A permit-list would make
// every new route invisible until somebody remembered to grant it, and the
// pressure to fix that quickly is pressure to add things without thinking.
//
//	                | a scoped caller     | a controller
//	----------------|---------------------|---------------------------
//	default         | denied              | permitted, after the one check
//	the list names  | what it MAY do      | what it may NEVER do
//	a new route     | unreachable         | reachable, which is the point
//	for             | an AI agent         | the owner's front end
//
// TWO STEPS, IN THIS ORDER.
//
//  1. The owner-only list. An action on it is done with the owner's keys, on
//     the device holding them, and no score opens it to a controller. Checked
//     first, so nothing about the person can reach it.
//  2. The one check, shared with AI agents' capability calls in the governance
//     gateway (permission.MayThisPersonDoThis): is the person's identity score at
//     least the action's minimum (80 unless set in controllerMinimumScore),
//     and may this person do this action (always yes until roles are built).
//
// THE OWNER-ONLY LIST IS NOT A VERY HIGH SCORE, and is kept apart from the
// minimums for that reason. A minimum says "prove more"; the list says "not
// from here, whatever you prove". Written as a score it would silently become
// reachable the day somebody scored high enough.
//
// The owner-only list, and why rotation and recovery are on it, are recorded
// in ADR-050.

// controllerOwnerOnly names the actions closed to a controller at any score,
// each with the reason a person stopped by it is told.
//
// Keyed by "METHOD /chi/pattern", the same way publicRoutes is.
var controllerOwnerOnly = map[string]string{
	// --- the lock of a logged-out identity (ADR-074) ---
	// A peer never opens or closes this device's identity: a locked phone is
	// unlocked by its person logging in on it, and a controller asking a locked
	// phone is refused, not served.
	"GET /api/lock/state":     "whether this device's identity is open is for the person at this device",
	"POST /api/lock/unlock":   "a phone never unlocks because a peer asked; its person logs in on it",
	"POST /api/lock/lock":     "logging an identity out of this device is for the person at this device",
	"PUT /api/lock/secret":    "the secret that locks this identity is for the person at this device",
	"DELETE /api/lock/secret": "the secret that locks this identity is for the person at this device",

	// --- the root of trust ---
	"POST /api/keystore/root-seed":                      "installing a root seed decides what this identity is",
	"PUT /api/keystore/recovery-phrase":                 "whoever reads the recovery phrase becomes the identity",
	"GET /api/keystore/recovery-phrase":                 "whoever reads the recovery phrase becomes the identity",
	"POST /api/keystore/recovery-phrase/open":           "whoever reads the recovery phrase becomes the identity",
	"DELETE /api/keystore/recovery-phrase":              "whoever reads the recovery phrase becomes the identity",
	"PUT /api/keystore/recovery-phrase/moving-to":       "whoever reads the phrase being moved to becomes the identity",
	"GET /api/keystore/recovery-phrase/moving-to":       "whoever reads the phrase being moved to becomes the identity",
	"POST /api/keystore/recovery-phrase/moving-to/open": "whoever reads the phrase being moved to becomes the identity",
	"DELETE /api/keystore/recovery-phrase/moving-to":    "whoever reads the phrase being moved to becomes the identity",
	"POST /api/recovery/root-aid-rotation":              "rotating the root identifier replaces the identity's controlling key",
	"POST /api/rotation":                                "rotating keys replaces what signs for this identity",
	"POST /api/reset":                                   "resetting destroys this identity",
	"POST /api/inception":                               "this creates the identity itself",
	"POST /api/hybrid-inception":                        "this creates the identity itself",
	"POST /api/messaging-keys/prepare":                  "this derives the keys an identity commits to from the root seed, before it is founded",
	"POST /api/owners/ceremony":                         "bringing new owners in decides who the owner is",
	"DELETE /api/owners/ceremony":                       "abandoning a ceremony decides who the owner is",

	// Who would witness a founding: the founding names them for good, and the
	// owner's device confirms each before it does.
	"GET /api/events/witnesses-for-a-founding": "the witnesses a founding names are written into the identity for good, and are the owner's to confirm",

	// --- material an identity can be rebuilt from ---
	// An archive plus a passphrase is the identity to whoever holds both, so
	// pulling one out of this machine is close to taking the identity itself.
	// Three doors to the same room, and closing only the one named "recovery"
	// would have left the other two open.
	"POST /api/recovery/retrieve":    "an archive is the identity to anyone who can open it",
	"POST /api/backup/export":        "an archive is the identity to anyone who can open it",
	"POST /api/backup/pull/{destID}": "this pulls back an archive, and an archive is the identity to anyone who can open it",

	// --- acting as the identity ---
	// Signing arbitrary content IS the identity speaking, and unlike a
	// credential it carries no shape anybody can reason about afterwards. A
	// controller never signs as the identity: it asks the Identity Agent to act,
	// and these are the points where asking would become the identity having
	// said something.
	"POST /api/sign":                         "this signs as the identity, and anything it signs cannot be unsaid",
	"POST /api/events/signature":             "this attaches this identity's signature to an event",
	"POST /api/events/prepare":               "a key event writes the state that decides who the owner is",
	"POST /api/identity/restore":             "installing an identity decides what this Identity Agent is",
	"POST /api/keystore/messaging-seed":      "this installs the keys an identity is reached on",
	"POST /api/events/commit":                "a key event writes the state that decides who the owner is",
	"POST /api/signing-requests/{id}/fulfil": "this signs as the identity, and what is signed cannot be unsaid",
	// Refusing is the key device's answer too, and a refused withdrawal is left
	// to the owner for good: one controller could keep another's revoked grant
	// valid in the key log by refusing its withdrawal.
	"POST /api/signing-requests/{id}/refuse":      "refusing is the key device's answer, and a refused withdrawal is never asked for again",
	"POST /api/signing-requests/sign-for-another": "this signs with the identity's key and records it in its key log",
	"POST /api/signing-requests/adopt":            "this takes events into the identity's key log",
	"POST /api/key-log/unsigned-events/discard":   "this rewinds the identity's key log, setting events aside that it holds",
	"POST /api/assets/{id}/approval":              "this asks the device that holds the identity's key to approve an identity delegated from it",
	"POST /api/interact":                          "this signs an interaction event with the identity's key, and key events are the owner's",

	// --- what it takes to get back in, and taking the identity over ---
	// The duress policy is the sharpest of these: it says what must happen if
	// the owner is being forced, so anything that could switch it off could
	// disable the protection and then use the recovery it protected against.
	"PUT /api/recovery/duress-policy":           "this decides what happens if the owner is being coerced",
	"PUT /api/recovery/who-holds-this":          "this decides what it takes to get back into this identity",
	"POST /api/recovery/start":                  "starting a recovery begins replacing this identity",
	"POST /api/recovery/sessions/{id}/activate": "activating a recovery replaces this identity and everything it held",
	"POST /api/recovery/sessions/{id}/rotation": "this rotates the identity's keys",
	"POST /api/recovery/sessions/{id}/cancel":   "stopping a recovery decides whether it happens",
	"POST /api/recovery/verify":                 "this opens a recovery archive, the first step of replacing this identity",
	// Holding part of somebody else's recovery: agreeing to hold a share,
	// approving the recovery it serves, and giving it up. Each is a recovery
	// decision the owner makes from the device holding the key.
	"POST /api/recovery/holdings":         "agreeing to hold part of somebody's recovery is a commitment the owner makes",
	"POST /api/recovery/holdings/approve": "approving a recovery is the whole of what a human gate decides",
	"POST /api/recovery/holdings/stop":    "giving up a share makes somebody else's backups unopenable by this machine",

	// --- who may sign for this identity ---
	"POST /api/signer/invites":                "inviting a signer decides who else may sign for this identity",
	"POST /api/signer/invites/{token}/redeem": "redeeming a signer invitation adds somebody who may sign",
	"POST /api/redeemed-invites/published":    "only the agent that redeemed an invite may ask the inviting app for what it published against it, signing with the key it redeemed with",

	// --- this machine's own enclave ---
	//
	// The app on this computer reaches it as the LOCAL owner, which is a
	// different caller from a controller and is unaffected. Left open, anyone
	// holding a grant on this machine could make its enclave sign arbitrary
	// controller requests as this machine, to be replayed at any Identity Agent
	// where it is a controller.
	"POST /api/controller/sign": "asking this computer's secure hardware to sign is for the app running on it, " +
		"not for something reaching it from elsewhere",

	// Which half this computer is running. Written from the machine itself, by
	// the app on it, and never from elsewhere. It decides whether this core
	// answers about an identity at all: a controller that could set it would
	// make an Identity Agent refuse its own owner, and one that could clear it
	// would put a front end back to answering about nobody. Reading it is not
	// on this list: a machine acting for somebody may reasonably want to know
	// which half it is talking to.
	"POST /api/controller/front-end-for":   "which half a computer is running is set on that computer, by the app on it",
	"DELETE /api/controller/front-end-for": "which half a computer is running is set on that computer, by the app on it",

	// The same door, one step worse. This one signs as the OWNER of a machine —
	// a pairwise identity derived from the root seed — so a controller that
	// could reach it would obtain owner signatures, which is the entire gate
	// this file exists to hold. Reached by the app on this computer as the
	// local owner, which is a different caller and unaffected.
	"POST /api/machines/owner/sign": "signing as the identity that owns a machine is the owner's own key, and a " +
		"machine acting for somebody is not that person",
	"POST /api/machines/owner-identity": "minting the identity that owns a machine makes a key that signs as its owner, and " +
		"a machine acting for somebody is not that person",
	// Adopting a machine mints its owner identity, signs a claim with it, and
	// accepts the measurements the caller says the machine may run: the same
	// door as the two above.
	"POST /api/pairing/adopt": "adopting a machine mints the identity that owns it and signs as that owner, and " +
		"a machine acting for somebody is not that person",

	// --- the state that decides WHO THE OWNER IS ---
	//
	// This group is the one with a rule behind it rather than a judgement.
	// Permitted-by-default is safe only where the thing being permitted cannot
	// change the decision that permitted it. These routes can: each writes
	// state that ownerAuthority() reads to work out whose signature counts as
	// the owner's, and whose statement counts when vouching for a score.
	//
	// The attack, proven before these were closed: a controller posts its own
	// key here, becomes the owner authority, signs an IA-AUTH-LEVEL-V2
	// statement for itself at the strongest score, and is then the owner for
	// isOwner on every route — which survives revoking its grant, because the
	// grant is no longer what it is using.
	//
	// So the rule, and it generalises past these: A CONTROLLER MAY NOT WRITE
	// ANYTHING THE AUTHORISATION DECISION READS. Anything added later that feeds
	// ownerAuthority — the identity record, the contact records its key is
	// resolved from, the sealed record — belongs here on sight.
	"POST /api/store/event": "writing key events decides what this identity's own history says, which " +
		"is what every other check is read against",
	"POST /api/store/identity":   "this decides which identity this Identity Agent is, and so whose signature counts as its owner's",
	"POST /api/contacts":         "the owner's key is resolved from contacts, so writing one can replace the owner",
	"PUT /api/contacts/{aid}":    "the owner's key is resolved from contacts, so editing one can replace the owner",
	"POST /api/contacts/resolve": "this fetches a record from an address the caller names and stores the key it returns",
	// The same primitive by two less obvious doors, both found only by tracing
	// what the handlers CALL rather than by reading their names. handleScanExecute
	// and the ask handlers reach EnsureKeriContact, which fetches an OOBI from an
	// address in the payload and stores the key it gets back — exactly what the
	// contact routes above do. This list cannot be kept correct by reading it.
	"POST /api/scan/execute":     "performing a scanned request can write a contact record, and the owner's key is resolved from those",
	"POST /api/ask/create":       "creating a request can write a contact record, and the owner's key is resolved from those",
	"DELETE /api/contacts/{aid}": "removing the owner's contact record changes how the owner's key is resolved",
	// A sealed request is served as coming from whoever the envelope says sent
	// it, and the sender's keys are read from this peers file. A peer written
	// under the owner's identifier with the writer's own keys would make the
	// writer's sealed requests the owner's (isSealedOwnerRequest).
	"POST /api/didcomm/peers": "a sealed request is believed to be from whoever the peer record says, so writing one can name the owner",
	// Which witnesses and watchers this agent relies on: they receipt and
	// cross-check the key log every other check is read against.
	"POST /api/providers": "which operators witness and watch this identity's key log decides what its history is checked against",
	// Capabilities are what an AI agent's grant can reach and what the gateway
	// trusts at invoke time, minimum scores included. Defining or arming one
	// writes what an authorisation decision reads.
	"POST /api/capability-registry/packs":        "importing a capability defines what the gateway trusts and what an AI agent may be granted",
	"POST /api/capability-registry/{id}/enabled": "arming a capability changes what the gateway trusts and what an AI agent may be granted",
	"DELETE /api/capability-registry/{id}":       "removing a capability changes what the gateway trusts and what an AI agent may be granted",

	// --- speaking as the identity to another Identity Agent ---
	//
	// A sealed request is served by the agent it reaches as coming from the
	// identity that sealed it, and from the identity that owns a machine it is
	// the owner's own request. This sends one as any identity this agent holds
	// keys for, so it is the owner's signature by another door.
	"POST /api/sealed/send": "this speaks as the identity to another Identity Agent, which serves it as that identity's own request",

	// --- what this agent says about other identities ---
	//
	// Turning the watcher's silence on or off for an identity decides what the
	// owner's agent discloses to every peer that asks, so it is the owner's
	// choice, not a paired machine's at the score every action needs.
	"PUT /api/watcher/opt-out": "this decides whether this agent's watcher tells peers what it has seen of an identity",
	// Which contacts the watcher asks about an identity tells each of them whom
	// this agent is checking on, so choosing them is the owner's. Reading the
	// list is not (like the opt-out read): the owner reads it from any of their
	// own apps.
	"PUT /api/watcher/peers": "this decides which contacts the watcher tells whom this agent is checking on",
	// Who the watcher believes decides what a duplicity check can find, and an
	// alert is the owner's to close: a controller that could clear one could
	// hide a fork from the person it was raised for.
	"PUT /api/watcher/trusted":                  "the watchers this agent trusts decide whose word a duplicity check believes",
	"PUT /api/watcher/hints":                    "the watchers this identity names in its introduction decide whom every new contact is pointed to",
	"POST /api/watcher/alerts/{id}/acknowledge": "an alert is raised for the owner, and what the owner has seen is the owner's to record",
	"POST /api/watcher/alerts/{id}/resolve":     "closing a duplicity alert is the owner's call, and a controller that could close one could hide a fork",

	// --- how a utility app may be signed in to ---
	// Which front ends of an app are switched off decides who can sign in to
	// it, so a change is the owner's, while a paired controller may read what is
	// set (GET /api/assets/{id}/front-ends). Declaring what an older app offers
	// is the same kind of choice, and may be made once.
	"PUT /api/assets/{id}/front-ends":         "this decides which front ends of a utility app people may sign in through",
	"PUT /api/assets/{id}/front-ends/offered": "this declares, once, which front ends a utility app made before it could say offers",
	// A grant that never lapses is the owner's to end, from the device holding the key.
	"DELETE /api/assets/{id}/app-key-grants/{key}": "ending a person's installed-app grant takes away what the owner allowed",

	// --- who else may act for this identity ---
	//
	// Enrolling a controller from a controller is how an attacker who briefly
	// holds one leaves with access that outlives its revocation. A grant is
	// created by the device holding the key, which is the owner and is not a
	// controller, so closing this costs nothing.
	"POST /api/controllers": "deciding which other machines may act for this identity is the owner's " +
		"alone, and is done from the device holding the key",
	// Removing a machine is the owner's decision too, made from the device
	// holding the key.
	"DELETE /api/controllers/{aid}": "removing a machine's authorisation is the owner's decision, made from " +
		"the device holding the key",

	// The events the root rotation is signed over, built before they are added.
	"POST /api/recovery/root-aid-rotation/prepare": "preparing the rotation of the root identifier replaces the identity's controlling key",
}

// controllerMinimumScore names the actions that need a score other than the
// default of 80, keyed the same way, so an action can be set higher, or lower,
// without changing how the decision is made.
//
// Taking control of an AI agent's screen (routeScreenControl, routeScreenInput)
// is its own action so that it can be set to need a higher score than watching
// without changing watching; it is not set here, so it needs the default like
// everything else. This table is the only place a minimum is set
// today; a setting the owner can change is future work.
var controllerMinimumScore = map[string]int{}

// isOwnerOnly reports whether this route is closed to a controller at any
// score, and why.
//
// The core's rules come first; an add-on's own (Addon.ControllerOwnerOnly)
// close its routes the same way.
func isOwnerOnly(method, pattern string) (string, bool) {
	route := method + " " + pattern
	if why, ok := controllerOwnerOnly[route]; ok {
		return why, true
	}
	for _, a := range registeredAddons() {
		if why, ok := a.ControllerOwnerOnly[route]; ok {
			return why, true
		}
	}
	return "", false
}

// minimumScoreFor is the score route needs from a controller: the core's,
// raised by any add-on that asks for more. An add-on cannot lower it, and a
// negative minimum from anyone refuses everybody (permission.Action).
func minimumScoreFor(route string) int {
	min := controllerMinimumScore[route]
	if min < 0 {
		return min
	}
	needs := permission.Action{MinimumScore: min}.TheScoreItNeeds()
	for _, a := range registeredAddons() {
		v, ok := a.ControllerMinimumScore[route]
		if !ok {
			continue
		}
		if v < 0 {
			return v
		}
		if v > needs {
			min, needs = v, v
		}
	}
	return min
}

// everyControllerOwnerOnly is a copy of every rule closing a route to a
// controller: the core's and every add-on's.
func everyControllerOwnerOnly() map[string]string {
	out := make(map[string]string, len(controllerOwnerOnly))
	for _, a := range registeredAddons() {
		for k, v := range a.ControllerOwnerOnly {
			out[k] = v
		}
	}
	for k, v := range controllerOwnerOnly {
		out[k] = v
	}
	return out
}

// everyControllerMinimumScore is a copy of every route's minimum other than
// the default, as minimumScoreFor decides it.
func everyControllerMinimumScore() map[string]int {
	out := map[string]int{}
	for k := range controllerMinimumScore {
		out[k] = minimumScoreFor(k)
	}
	for _, a := range registeredAddons() {
		for k := range a.ControllerMinimumScore {
			out[k] = minimumScoreFor(k)
		}
	}
	return out
}

// controllerAuthenticationFreshness is how recently a vouched statement about
// the person must have been made for it to be used.
//
// An authentication is a statement about a moment. One made when the
// controller was first authorised says nothing about who is at that keyboard
// now, and treating it as current is how a threshold becomes a formality.
const controllerAuthenticationFreshness = 5 * time.Minute

// mayThisControllerDoThis decides a single request from an authorised machine.
//
// The grant is assumed live — that is a separate question, answered before
// this is called. This answers only the second one: is this particular action
// open to a controller, and does the person at it pass the one check.
//
// Returns the reason when it refuses, so the caller can tell the person what
// would let them through rather than only that something stopped them.
func mayThisControllerDoThis(
	method, pattern, who string,
	authenticated authprovider.Result,
) (bool, string) {
	// Closed before the person is considered, so no score opens it.
	if why, closed := isOwnerOnly(method, pattern); closed {
		return false, why + ", so it is done with the owner's keys on the device holding them"
	}
	return permission.MayThisPersonDoThis(
		permission.Action{Name: method + " " + pattern, MinimumScore: minimumScoreFor(method + " " + pattern)},
		permission.Person{AID: who, Authenticated: authenticated},
	)
}

// whyAControllerWasRefused is the reason code for a refusal by
// mayThisControllerDoThis, so an app can say it in its own words.
func whyAControllerWasRefused(method, pattern string, authenticated authprovider.Result) string {
	if _, closed := isOwnerOnly(method, pattern); closed {
		return reasonOwnerOnly
	}
	a := permission.Action{Name: method + " " + pattern, MinimumScore: minimumScoreFor(method + " " + pattern)}
	if a.MinimumScore >= 0 && (!authenticated.Measured || authenticated.Score < a.TheScoreItNeeds()) {
		return reasonScoreTooLow
	}
	return reasonNotAllowed
}

// howSureWeAreItIsThem is the authentication the one check is given for a
// controller's request: a vouched statement where one was made recently and
// verified, otherwise the placeholder every person has until human
// authentication is built. The same in every build.
func howSureWeAreItIsThem(vouched authprovider.Result, now time.Time) authprovider.Result {
	if vouched.Measured && freshEnough(vouched, now) {
		return vouched
	}
	return authprovider.UntilHumanAuthenticationIsBuilt(now)
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
