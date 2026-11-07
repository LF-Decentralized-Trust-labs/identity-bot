package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/permission"
)

// Who is allowed to call what.
//
// Until now every route decided for itself, and most decided nothing: sixteen
// handlers called isLocalOwnerRequest and the other two hundred were reachable
// by anyone who could reach the port. While a tunnel is up, that is the
// internet. This middleware makes authorisation a property of the router rather
// than a habit of the handler.
//
// THE DEFAULT IS OWNER-ONLY. A route is exposed to anyone else only by being
// named in publicRoutes or scopedRoutes below, each with the reason it is there.
// A new route added tomorrow is private without anybody remembering to make it
// so — which is the only default that survives people being busy.

type accessClass string

const (
	// accessOwner is the default: only the person who controls this agent.
	accessOwner accessClass = "owner"
	// accessPublic is deliberately unauthenticated — a counterparty, a browser
	// or a peer agent must be able to reach it without being us.
	accessPublic accessClass = "public"
	// accessScoped is reachable by a caller presenting a credential that carries
	// capability scopes. The handler still checks the specific scope; this class
	// only says "not owner-only".
	accessScoped accessClass = "scoped"
)

// unknownRouteRefusal is how a request under /api that matches no route is
// answered. A route that is mounted but switched off gives the same refusal.
const unknownRouteRefusal = "this request could not be resolved to a known route, " +
	"so it was refused rather than served without a check"

// publicRoutes are unauthenticated by design. Keyed by "METHOD /chi/pattern".
// Each entry states why, because a public route is a decision, not an accident.
var publicRoutes = map[string]string{
	// --- discovery and verification: the OOBI layer ---
	// These answer "who is this AID and how do I verify it". They carry no
	// personal data (see handleOobiServe), and requiring auth would defeat the
	// purpose: a stranger must be able to verify us before any relationship.
	"GET /oobi/{aid}":            "OOBI discovery record",
	"GET /public/oobi/{aid}":     "OOBI discovery record",
	"GET /{aid}/oobi":            "OOBI discovery record (did:webs layout)",
	"GET /{aid}/did.json":        "did:webs document — public key material",
	"GET /public/{aid}/did.json": "did:webs document — public key material",
	"GET /{aid}/kel":             "key event log — public and self-verifying",
	"GET /{aid}/keri.cesr":       "key event log as a CESR stream",
	"GET /api/kerl":              "key event log — public and self-verifying",
	"POST /_register":            "a pairwise signer registers its key, proved by its own key log, so counterparties can resolve it",
	"POST /public/_register":     "a pairwise signer registers its key, proved by its own key log, so counterparties can resolve it",
	// A relying party in another language asks what key a key log establishes,
	// instead of keeping a second implementation of the check. Pure
	// computation over what it is sent: nothing fetched, nothing stored.
	"POST /public/login/key":        "a verifier asking what key an identity's own key log establishes",
	"POST /public/key-state":        "a signer asking what key state a copy of a key log establishes, before it can sign as anyone",
	"GET /public/credential/{said}": "a credential the user chose to publish at a shareable link",
	// A credential names its schema by digest; a verifier fetches the document to
	// confirm what the credential claims. Schemas are public by nature.
	"GET /public/schemas/{said}": "a credential schema document, resolved by its identifier",

	// --- carrying a request nothing in the middle can read ---
	// Open in the same sense the message endpoint is open: what arrives is an
	// envelope, and it is refused unless it comes from a sender this agent
	// already has a relationship with and opens under a key only this agent
	// holds. The request inside is then replayed through the ordinary router,
	// where it meets whatever authorisation it would have met directly — so
	// this carries requests, it does not exempt them.
	"POST /api/sealed": "a request carried inside an envelope only this agent can open",

	// --- handing back a share somebody asked this machine to hold ---
	// Open in the same sense as the envelope above: what arrives carries a
	// share sealed to a key only this machine holds, so opening it is the
	// authentication, and it cannot be forged by somebody who does not already
	// have the backup and the recovery words. Gating it on a session instead
	// would mean a recovering machine — which by definition has no session
	// here, and belongs to somebody this machine may never have met — could
	// never ask, and the shares would protect nothing because nobody could
	// ever gather them.
	"POST /api/recovery/share-requests": "a recovering machine asks for a share sealed to this one",

	// --- proving what machine this agent runs on ---
	// A client verifies a machine in order to decide whether to trust it, so it
	// is not the owner yet and holds no owner key. Gating this would mean that
	// by the time you could ask, you had already trusted the thing you wanted
	// to check. It carries no tenant data: the measurement is the same for
	// every instance of an image, the chip names the machine rather than any
	// tenant, and REPORT_DATA is one-way.
	"GET /api/attestation": "hardware attestation — the evidence a stranger needs to verify this machine",

	// --- proving an address is the agent and not a proxy of its public log ---
	// The asker is deciding whether to trust an address and holds nothing yet.
	// It signs only a fixed form over what the asker chose, for an origin that
	// is this agent's own, with keys the identifier already publishes.
	"GET /api/identity/proof": "proof this address holds the identifier's keys in force — a signed answer to a challenge the asker chose, checked against the identifier's own key log",

	// --- the sign-in handshake: the relying party and the browser drive these ---
	"GET /i/{token}":                                "the scanned pointer — the QR resolves to a signed challenge",
	"POST /api/login/challenge":                     "a site mints a challenge for its own sign-in page",
	"POST /api/login/callback":                      "the completed assertion is posted back by the agent that signed it",
	"GET /api/login/challenge/{token}/status":       "the waiting browser polls for completion",
	"POST /api/login/session/{asset_id}":            "sign-in widget: a browser starts a session",
	"GET /api/login/session/{asset_id}/{token}":     "sign-in widget: the browser polls its own session",
	"OPTIONS /api/login/session/{asset_id}":         "CORS preflight for the sign-in widget",
	"OPTIONS /api/login/session/{asset_id}/{token}": "CORS preflight for the sign-in widget",

	// --- agent-to-agent protocol: another Identity Agent is the caller ---
	// These are how a peer reaches us at all. They are authenticated by what
	// they carry (a signed event, an encrypted archive), not by who connects.

	// --- joining something the owner published: the login SDK is the caller ---
	// Mounted as public since they were written, and never declared public here,
	// so the router refused every one with 403 before the handler ran. The login
	// SDK calls the first two from a relying party's browser, which is nobody's
	// owner, so its invite flow has never worked.
	//
	// Safe to reach because the token IS the credential: it is unguessable, the
	// record it returns contains only what its holder already knows, and an
	// invalid or revoked token discloses nothing. Gating them on being the owner
	// would be a deadlock: the person joining is not the person who published.
	"GET /api/invites/{token}":         "somebody holding an invite reads what they were invited to",
	"POST /api/invites/{token}/redeem": "somebody holding an invite accepts it",
	// Asking is public; granting is not. This only queues a request for the
	// owner to approve or refuse, exactly as a contact introduction does — and
	// like that route, it is unauthenticated write surface with no rate limit
	// yet, so a stranger can fill an approval queue.
	"POST /api/assets/{id}/requests": "a stranger asks the owner for access to something they published",

	// The same omission a third time, and the reason to stop finding these one
	// at a time. Mounted under "Public: the accepting employee's agent looks up
	// + redeems here", never declared, so an employee's agent was refused and
	// onboarding could not complete.
	//
	// The token gates both, the invite carries a use limit, and redeeming only
	// creates a PENDING employee — the owner still has to approve it, and that
	// approval is owner-only. So what a stranger with a valid token can do is
	// put themselves in a queue.
	"GET /api/employees/invites/{token}":         "the invited person's agent reads what they were invited to",
	"POST /api/employees/invites/{token}/redeem": "the invited person's agent accepts, becoming a pending member",

	// The same argument, for the invitation that brings in an OWNER.
	//
	// The ownership ceremony mints one of these per incoming owner and shows it
	// as a QR code. The person who scans it is by definition NOT the current
	// owner — they are the one being added — so gating their acceptance behind
	// the owner's signature asked them to already be what they were being
	// invited to become. Every ceremony therefore sat at "collecting" forever,
	// with the invited owner's agent receiving 403 and nothing explaining why.
	//
	// What a stranger holding a valid token can do is bounded the same way as
	// above: the token is single-use, it was minted by the owner for one named
	// person, and the acceptance it records only goes into a ceremony that does
	// not apply until EVERY invitee has accepted. It cannot displace the owner
	// the identity named at inception either — the log answers before any file
	// does, so re-sealing changes nothing.
	"POST /api/signer/invites/{token}/redeem": "an invited owner's agent accepts, committing the keys they will sign with",

	// A machine enrolling itself with the key it generated. It is not the owner
	// and never will be — that is the point of it holding its own key — so it
	// cannot be owner-gated. The enrolment token authorises it: single-use,
	// time-bounded, and it names in advance what may enrol. ISSUING a token
	// stays owner-only, which is where the decision actually is.
	// The pattern is the FULL path chi matches. mountAssetRoutes closes its
	// /assets block before this route, so enrol is mounted at /api/enrol —
	// and an entry spelled "/api/assets/enrol" silently does nothing, because
	// classify does an exact string match and then falls through to owner-only.
	// The route answers 403 to the machine it exists for, no error is logged,
	// and it looks in review as though it was opened.
	//
	// That is not hypothetical: this entry named the /assets path from the day
	// the warning above it was written, so enrolment answered 403 for as long
	// as the note explaining how to avoid it sat directly on top. A comment
	// cannot check a path. TestEveryOpenRouteIsMountedWhereItSaysItIs can, and
	// now does.
	"POST /api/enrol": "a machine presents the key it generated and the token it was given",

	// A DID document is public key material — that is the whole idea of one.
	// Not being reachable meant two agents could never establish a relationship
	// without somebody hand-copying keys between them, which is why every
	// cross-machine DIDComm peer had to be registered by an owner.
	//
	// The handler already assumed a non-owner would call it: it returns 404
	// rather than minting when the caller is not the owner and no keyset exists.
	// That check was unreachable, and it is exactly the right one — a stranger
	// can read a key that exists and cannot cause one to be generated.
	"GET /api/didcomm/did": "an agent reads the public keys it needs to encrypt to us",
	// A machine this agent owns asks it to deliver a message. Not owner-gated,
	// because the machine is not the owner — it signs with the key it enrolled
	// with, and that signature carries the same replay protection the owner's
	// does. It cannot say who it is: the sender on the delivered message comes
	// from the verified signature, never from the body.
	"POST /api/notify": "a machine this agent owns asks it to tell somebody something",
	// Agent-to-agent messaging. Unreachable until now: the route was registered
	// as public and never listed here, so the router refused every peer with 403
	// before the handler ran and no message from another agent ever arrived.
	//
	// Safe to reach because the envelope carries its own proof and the handler
	// checks it before doing anything: an unregistered sender is refused, the
	// recipient key must be one of ours, and UnpackAuthcrypt verifies the
	// signature, the key agreement and the body hash against the sender's known
	// DID. Expiry and replay are checked after that. A stranger who is not
	// already a peer gets no further than the first of those.
	"POST /didcomm":             "an agent we know posts an encrypted envelope, authenticated by what it carries",
	"POST /api/witness/request": "witnessing protocol — a controller asks us to witness",
	"POST /api/witness/accept":  "witnessing protocol — a witness answers our request, signed by its key",
	// The other half of the witnessing protocol. Enrolment above is public and
	// standing down was not, so a peer relationship could be created remotely
	// and never ended remotely: RequestWithdrawal got 403 from the peer it asked.
	//
	// Safe to reach because the request carries its own proof. A request to stop
	// is only acknowledged, and changes nothing. A confirmation changes the
	// witness's state only when it names a rotation that is for that
	// controller, signed by the keys in force, and already in the key log the
	// witness holds (T-595) — an unsigned or foreign blob is refused.
	"POST /api/witness/withdraw":         "witnessing protocol — a witness tells the controller it wishes to stop",
	"POST /api/witness/withdraw/confirm": "witnessing protocol — a controller sends its own signed rotation, which the witness checks against its log",
	// A witness receives the controller's events here, and a controller (or a
	// peer cross-checking) reads back what the witness holds. Both were owner
	// gated, so a peer's BroadcastEvent got 403 and no witness ever stored a
	// rotation — which made the withdrawal check above refuse every real
	// withdrawal with "not in the key log".
	//
	// Safe to reach because nothing here is trusted on who sent it. The event
	// is verified against the controller's own signature and the key log before
	// it is stored (ReceiveEvent), and a witness that is not witnessing that
	// identity refuses it. The reads are answered from what is held only to the
	// identity itself or the one it is delegated from, proven by a signature
	// (witness.MayRead); everybody else gets the answer for a log not held, so
	// the routes cannot be used to learn who this agent witnesses. That is not
	// the same data as GET /{aid}/kel: a root identity is held here and is never
	// published there. All four share one bounded rate limiter.
	"POST /api/witness/event":                      "witnessing protocol — a controller sends a signed event, verified before it is stored",
	"GET /api/witness/kel/{signer_aid}":            "the key log this witness holds, to the identity itself or its delegator, signed — anybody else is told it is not held",
	"GET /api/witness/kel/{signer_aid}/tip":        "how far this witness holds an identity's key log, signed with a nonce — to anybody else, as for a log not held",
	"GET /api/witness/tel/{issuer_aid}":            "the registry logs of an identity this witness witnesses, from a place in its key log, to the identity, its delegator or a verifier presenting its inception — anybody else is told it is not held; never by credential",
	"GET /api/witness/tel/{issuer_aid}/head":       "where an identity's registry log is held to and the digest of its latest event, on the same terms as the log — never by credential",
	"POST /api/witness/tel/{issuer_aid}":           "an issuer's registry events, each stored only when the key log this witness holds for it seals exactly that event",
	"GET /api/witness/kel/{signer_aid}/event/{sn}": "one event of a key log this witness holds, to the identity itself or its delegator, signed — anybody else is told it is not held",
	// A controller publishes where it can be reached, and a counterparty whose
	// stored address has died asks where it is now. Both were owner gated, so a
	// witness never held a record and nobody could ask for one; and the
	// publishing route stored whatever it was handed without checking any
	// signature, which is why it could not simply be opened.
	//
	// Safe to reach because nothing here is trusted on who sent it. A record is
	// stored only when it is the identifier's own statement: the one spelling of
	// the form (endpointrecord), signed by the key the key log this witness holds
	// for it names now, issued after the record already held, for an identifier
	// this witness holds a verifiable log for. The read serves that record as it
	// was signed, and the asker checks it against the identifier's own key log,
	// so a witness cannot move anybody. Both share the witness reads' limiter.
	"POST /api/witness/endpoint":                 "witnessing protocol — a controller publishes where it can be reached, a signed record verified against its key log before it is stored",
	"GET /api/witness/endpoint/{controller_aid}": "the newest signed record of where an identity can be reached, which the asker verifies against the identity's own key log",
	// Mounted on the root router under /public/ and never declared, so every
	// peer cross-check got 403, which the caller records as the peer being
	// "unavailable" — the whole peer layer degraded silently.
	//
	// Safe to reach because they answer only from the watcher's own first-seen
	// records, are rate limited per caller, and honour an identity's opt-out.
	// The digest of a public key log is public and self-verifying.
	"GET /public/kel-digest":                                "a peer watcher asks what digest we first saw for an identity at a sequence number",
	"POST /public/kel-check":                                "a peer watcher compares its digest with ours (L3 cross-check)",
	"POST /api/backup/receive":                              "a peer pushes an opaque, already-encrypted archive",
	"GET /api/backup/receive/{identityAID}":                 "the owning agent lists its own archives during recovery",
	"GET /api/backup/receive/{identityAID}/download/{name}": "the owning agent retrieves an opaque archive during recovery",

	// --- liveness and the app shell ---
	"GET /api/health": "liveness probe — reveals nothing",
	// Answered to anyone, because the app asking has not yet decided this is
	// its core. It reveals a MAC of the asker's nonce bound to this core's own
	// port, which neither discloses the secret nor helps a program on another
	// port pass as this core.
	"GET /api/local-owner/proof": "proves this core holds the local owner secret, before an app sends it",

	// The one endpoint that must answer before an owner exists. A freshly
	// provisioned instance has no identity and no owner, so it cannot be
	// owner-gated; it discloses a pairwise AID that is about to be published as
	// an OOBI anyway, nothing else, and it stops answering once paired.
	"POST /api/provisioning/expect": "whoever provisioned a box says which claim it will accept, before it has an owner to authenticate",
	"GET /api/provisioning/pairing": "a newly provisioned instance offers itself for pairing, before any owner exists",
	// The adoption ceremony itself. Same reasoning and the same window: an
	// instance with no owner cannot gate these on being the owner. Both refuse
	// the moment the instance has an identity, so the window closes on success.
	// Unauthenticated for the same reason, and additionally refused unless the
	// request is genuinely local — the code it returns is meant for this
	// machine's own screen, not for the network.
	"POST /api/pairing/offer-this-computer": "a computer with no owner yet issues the claim code shown on its own screen",
	"GET /api/pairing/this-computer":        "the screen showing that code reads back what has happened to it, before any owner exists",
	"POST /api/pairing/begin":               "an unpaired computer offers its own public key material so an owner can be sealed into its first event",
	"POST /api/pairing/complete":            "an unpaired computer founds its identity over that key and seals in who owns it",
}

// scopedRoutes are reachable by a caller presenting capability scopes rather
// than being the owner. The handler enforces the specific scope. The core
// serves none of its own today: the add-ons that serve such routes list them,
// and the path prefixes they open the same way (Addon.ScopedRoutes and
// Addon.ScopedPrefixes).
var scopedRoutes = map[string]string{}

// classify returns the access class for a matched route pattern.
func classify(method, pattern string) accessClass {
	key := method + " " + pattern
	if _, ok := publicRoutes[key]; ok {
		return accessPublic
	}
	if _, ok := addonRouteEntry(func(a Addon) map[string]string { return a.PublicRoutes }, key); ok {
		return accessPublic
	}
	if _, ok := scopedRoutes[key]; ok {
		return accessScoped
	}
	if _, ok := addonRouteEntry(func(a Addon) map[string]string { return a.ScopedRoutes }, key); ok {
		return accessScoped
	}
	for _, p := range addonScopedPrefixes() {
		if underPrefix(pattern, p) {
			return accessScoped
		}
	}
	return accessOwner
}

// authorize is the router-wide gate. It runs before every handler, resolves the
// matched route, and refuses anything the caller has no standing to reach.
//
// routes is the router itself: chi fills the route pattern during dispatch,
// which is after middleware, so we match once up front to learn which route we
// are about to serve.
func (s *CoreServer) authorize(routes chi.Routes) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A CORS preflight carries no credentials by definition and is
			// answered by the CORS middleware; gating it would break every
			// browser client without protecting anything.
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			pattern := matchedRoutePattern(routes, r)
			if pattern == "" {
				// No route matched HERE. That is normally a 404 waiting to
				// happen, and letting the router answer it avoids telling an
				// unauthenticated caller which paths exist.
				//
				// But "this middleware could not match it" and "chi will not
				// serve it" are not the same statement, and treating them as
				// one was an unauthenticated way into every owner-only handler
				// with a {param} in its pattern: a caller who could make the
				// two matchers disagree — an escaped separator was enough —
				// got no authorisation check at all and a handler that ran.
				//
				// So anything under /api is refused rather than passed on. A
				// 404 that this cannot classify is worth losing; an owner route
				// served without a check is not.
				if strings.HasPrefix(r.URL.Path, "/api/") ||
					strings.HasPrefix(r.URL.EscapedPath(), "/api/") {
					denyAuthorization(w, unknownRouteRefusal)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			r = withSignedBodyBound(r, pattern)

			class := classify(r.Method, pattern)
			if _, ok := s.extraOpen[r.Method+" "+pattern]; ok && class == accessOwner {
				class = accessPublic
			}
			switch class {
			case accessPublic:
				next.ServeHTTP(w, r)
			case accessScoped:
				how, proofErr := s.theProofOfTheOwner(r)
				if refuseTheBody(w, proofErr) {
					return
				}
				if how != "" {
					// The owner at this computer is recognised again by the
					// handler. An owner proving it remotely cannot be: the
					// signature is spent here, so the handler would find a
					// remote caller with no scopes and refuse the person who
					// grants them. So the gate says who it admitted.
					r = r.WithContext(context.WithValue(r.Context(), theGateAdmittedTheOwnerKey{}, how))
					if how == ownerAtThisComputer {
						next.ServeHTTP(w, r)
						return
					}
					next.ServeHTTP(w, withResolvedCaller(r, s.theOwnerAsACaller(r, how)))
					return
				}
				if cc := s.resolveCaller(r); len(cc.Scopes) > 0 {
					next.ServeHTTP(w, withResolvedCaller(r, cc))
					return
				}
				// A controller acts for the owner, so it reaches these for the
				// same reason the owner does. Left out, the owner's own front end
				// would be the one caller that could not use a route an AI agent
				// could — the exact inversion this class exists to avoid.
				if served := s.controllerActsForTheOwner(w, r, pattern, next); served {
					return
				}
				if s.ownerKeyStateIsStale(r) {
					writeStaleKeyState(w)
					return
				}
				denyAuthorization(w, "this endpoint needs a token carrying the capability scope for it")
			default:
				how, proofErr := s.theProofOfTheOwner(r)
				if refuseTheBody(w, proofErr) {
					return
				}
				if how != "" {
					// Said, as on the scoped routes, so a handler that names
					// its caller names the owner the gate admitted: an owner
					// signature is spent here and cannot be checked again.
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), theGateAdmittedTheOwnerKey{}, how)))
					return
				}
				// A person's session at an app, signed with the browser key it is
				// bound to, on the talk routes only. Never a controller, so it is
				// asked before one and answers for itself.
				if s.anAppSessionSpeaks(w, r, pattern, next) {
					return
				}
				if served := s.controllerActsForTheOwner(w, r, pattern, next); served {
					return
				}
				if s.ownerKeyStateIsStale(r) {
					writeStaleKeyState(w)
					return
				}
				denyAuthorization(w, "this endpoint is for the owner of this agent; sign the request with the owner key or call it locally")
			}
		})
	}
}

// matchedRoutePattern resolves which registered route would serve this request.
func matchedRoutePattern(routes chi.Routes, r *http.Request) string {
	// MATCH THE STRING CHI WILL ROUTE ON, NOT A DIFFERENT ONE.
	//
	// chi dispatches on RawPath when the URL carries escaped characters, and on
	// Path otherwise. Matching only on Path meant the two could disagree — and
	// on exactly the requests where they disagree, this returned "" while chi
	// went on to serve a handler. See the caller for why that was an
	// unauthenticated way in.
	//
	// Raw first, because that is what chi prefers when it is set.
	if raw := r.URL.EscapedPath(); raw != "" && raw != r.URL.Path {
		rctx := chi.NewRouteContext()
		if routes.Match(rctx, r.Method, raw) {
			return rctx.RoutePattern()
		}
	}
	rctx := chi.NewRouteContext()
	if !routes.Match(rctx, r.Method, r.URL.Path) {
		return ""
	}
	return rctx.RoutePattern()
}

func denyAuthorization(w http.ResponseWriter, detail string) {
	denyAuthorizationBecause(w, "", detail)
}

// The reason codes a refusal at the gate can carry, for an app to turn into
// its own words rather than read the detail.
const (
	// reasonScoreTooLow is a controller whose person has not proved enough
	// for the action.
	reasonScoreTooLow = "score_too_low"
	// reasonOwnerOnly is an action only the owner's keys may do.
	reasonOwnerOnly = "owner_only"
	// reasonNotAllowed is any other refusal by the one check.
	reasonNotAllowed = "not_allowed"
)

// denyAuthorizationBecause is denyAuthorization with a reason code.
func denyAuthorizationBecause(w http.ResponseWriter, reason, detail string) {
	body := map[string]string{"error": "not_authorized", "detail": detail}
	if reason != "" {
		body["reason"] = reason
	}
	jsonreply.Write(w, http.StatusForbidden, body)
}

// isOwner answers the only question the default class asks: is this the person
// who controls this agent?
//
// Three ways to be the owner, and they are not alternatives so much as the same
// claim proved differently. On a machine you are sitting at, a request that
// originates on that machine is you. On hardware you rent — where you are
// remote by definition and the local test can never be true — you prove it
// either by signing the request with the owner key sealed into the box at
// provisioning, or by sending it inside an envelope only the owner's identity
// could have sealed.
func (s *CoreServer) isOwner(r *http.Request) bool {
	return s.howThisIsTheOwner(r) != ""
}

// isOwnerOrItsController is the check a handler makes when it needs to know the
// caller acts for the owner: the owner, or a machine the owner authorised that
// the gate admitted.
//
// HANDLERS DO NOT RE-CHECK OWNERSHIP FOR WHAT THE GATE OPENED TO CONTROLLERS
// (ADR-050). The gate opens every owner-class route to an authorised controller
// except the owner-only list, so a handler that asks isOwner alone closes the
// route again, and nothing reports it: the org app on a controller was refused
// its own stored keys that way. A route that must stay closed to a controller
// belongs on controllerOwnerOnly, where the gate refuses it with the reason.
//
// No to a caller holding a scoped token, which the gate admits too but which
// is not the owner acting.
//
// Where a handler records WHO acted, it names the controller rather than the
// owner (TheControllerThatAsked, as whoDecided does).
func (s *CoreServer) isOwnerOrItsController(r *http.Request) bool {
	if theGateAdmittedTheOwner(r) {
		return true
	}
	if _, ok := TheControllerThatAsked(r); ok {
		return true
	}
	return s.isOwner(r)
}

// How a request proved it is the owner's.
const (
	ownerAtThisComputer = "local"
	ownerSealed         = "owner_sealed"
	ownerSigned         = "owner_signed"
)

// howThisIsTheOwner is isOwner, saying which proof held, or "" when none did.
// Asked once per request: an owner signature is spent when it verifies.
func (s *CoreServer) howThisIsTheOwner(r *http.Request) string {
	how, _ := s.theProofOfTheOwner(r)
	return how
}

// theProofOfTheOwner is howThisIsTheOwner, and also says when the proof failed
// because of the body -- over the bound for its route, or not the one the
// request signed (X-IA-Body-Digest): the failures the caller can fix by sending
// something else, so they are carried out rather than thrown away. The error is
// only ever a requestTooLarge or a bodyDoesNotMatchItsDigest, and only with
// how == "".
func (s *CoreServer) theProofOfTheOwner(r *http.Request) (string, error) {
	if s.isLocalOwnerRequest(r) {
		return ownerAtThisComputer, nil
	}
	if s.isSealedOwnerRequest(r) {
		return ownerSealed, nil
	}
	err := s.verifyOwnerSignature(r)
	if err == nil {
		return ownerSigned, nil
	}
	var tooLarge requestTooLarge
	if errors.As(err, &tooLarge) {
		return "", tooLarge
	}
	var mismatched bodyDoesNotMatchItsDigest
	if errors.As(err, &mismatched) {
		return "", mismatched
	}
	return "", nil
}

// refuseTheBody answers 413 when err is the size refusal and 400 when it is a
// body that is not the one the request signed, and says whether it did. A body
// is not a signature: telling them apart lets a client that signed correctly
// learn it should send less, or send what it signed, not that its key is wrong.
func refuseTheBody(w http.ResponseWriter, err error) bool {
	var tooLarge requestTooLarge
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "Request too large", tooLarge.Error())
		return true
	}
	var mismatched bodyDoesNotMatchItsDigest
	if errors.As(err, &mismatched) {
		writeError(w, http.StatusBadRequest, "Body does not match its digest", mismatched.Error())
		return true
	}
	return false
}

// theGateAdmittedTheOwnerKey marks a request the gate admitted on a route open
// to scoped callers because it is the owner's, and says how it was proved.
type theGateAdmittedTheOwnerKey struct{}

// theGateAdmittedTheOwner reports whether the gate admitted r as the owner's.
// For a handler on a route any scoped caller reaches that must still serve
// only the owner, or one that names its caller, and cannot ask again: an owner
// signature is spent at the gate.
func theGateAdmittedTheOwner(r *http.Request) bool {
	how, _ := r.Context().Value(theGateAdmittedTheOwnerKey{}).(string)
	return how != ""
}

// theOwnerAsACaller is the caller a remote owner is, for a route that asks who
// is calling rather than only whether they may.
//
// Remote, because the request came over the network and every rule that holds
// for a remote caller still holds — a capability that drives this computer's
// screen stays local-only. Owner, because the scope check exists to bound what
// somebody other than the owner may do, and the owner is who grants scopes.
func (s *CoreServer) theOwnerAsACaller(r *http.Request, how string) permission.CallerContext {
	cc := permission.CallerContext{
		Remote: true, Owner: true, AuthLevel: how,
		CorrelationID: requestCorrelationID(r), Transport: "owner",
	}
	if oa, err := s.ownerAuthority(); err == nil && oa != nil {
		cc.CallerAID = oa.AID
	}
	applyCallerWhy(r, &cc)
	return cc
}

// isSealedOwnerRequest reports whether this request arrived inside an envelope
// sealed by the identity this agent belongs to.
//
// Unsealing the envelope ALREADY proved who sent it — that is what the sender's
// key agreement establishes, and nothing weaker gets past the transport. What
// was missing is that being a known peer answered "may you talk to me" and was
// never carried through to "may you do this". So an owner holding the key this
// machine was sealed to could reach it and still be refused everything, which
// left an owner unable to ask their own machine anything at all.
//
// TWO CONDITIONS, AND THE FIRST IS WHAT MAKES THE SECOND SAFE. The header alone
// is an assertion, and an assertion in a header is worth nothing: anybody could
// send one. It counts only on a request the sealed transport itself replayed,
// which is what the address marks — a caller cannot choose the address their
// connection came from, and the transport strips any copy of the header a
// sender tried to supply. Read either condition alone and this is an
// authentication bypass; read together they are the transport's own finding.
func (s *CoreServer) isSealedOwnerRequest(r *http.Request) bool {
	if r.RemoteAddr != sealedRemoteAddr {
		return false
	}
	sender := r.Header.Get(headerSealedFrom)
	if sender == "" {
		return false
	}
	owner, err := s.ownerAuthority()
	if err != nil || owner == nil || owner.AID == "" {
		// An agent nobody has adopted has no owner to match, so nobody is it.
		return false
	}
	return sender == owner.AID
}

// IsOwner is the exported owner check for overlays (owner-only management routes).
func (s *CoreServer) IsOwner(r *http.Request) bool { return s.isOwner(r) }

// IsOwnerOrItsController is isOwnerOrItsController for overlays: the check an
// overlay route that is not owner-only by ADR-050 makes instead of IsOwner.
func (s *CoreServer) IsOwnerOrItsController(r *http.Request) bool { return s.isOwnerOrItsController(r) }

// --- replay window ---

// signedRequestWindow is how far a signed request's timestamp may be from now.
// Long enough to survive clock skew and a slow link, short enough that a
// captured request stops being useful quickly.
const signedRequestWindow = 2 * time.Minute

var (
	seenSignaturesMu sync.Mutex
	seenSignatures   = map[string]time.Time{}
)

// rememberSignature records a signature as spent and reports whether it was
// already used. Within the window a signed request works exactly once, so
// capturing one off the wire buys nothing.
func rememberSignature(sig string, now time.Time) (alreadyUsed bool) {
	seenSignaturesMu.Lock()
	defer seenSignaturesMu.Unlock()
	// Remembered for twice the window. A timestamp is accepted up to the window
	// on EITHER side of now, so a request stamped in the future stays valid
	// for up to two windows after it is first used; forgetting it after one
	// would let it be replayed in the gap.
	for s, t := range seenSignatures {
		if now.Sub(t) > 2*signedRequestWindow {
			delete(seenSignatures, s)
		}
	}
	if _, ok := seenSignatures[sig]; ok {
		return true
	}
	seenSignatures[sig] = now
	return false
}

// bearerToken pulls a token out of the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
