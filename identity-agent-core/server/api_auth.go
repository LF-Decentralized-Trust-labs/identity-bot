package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/sandbox"
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
	"GET /public/credential/{said}": "a credential the user chose to publish at a shareable link",
	// A credential names its schema by digest; a verifier fetches the document to
	// confirm what the credential claims. Schemas are public by nature.
	"GET /public/schemas/{said}": "a credential schema document, resolved by its identifier",
	// A machine asking to become an AI agent's body has no standing yet: it
	// presents a one-time secret and signs with the key it offers, and nothing
	// is granted until a person compares six words and approves. The status
	// route answers only the machine that signs for it.
	"POST /api/agent-host/enrol":  "a machine asking, with a one-time secret, to become an AI agent's body",
	"GET /api/agent-host/binding": "a machine asking, signed by its own key, whether it was approved",
	// An AI agent's body sending and collecting messages. Each handler admits
	// only a request the sealed transport opened from a live body's keys and
	// that the body signed with its machine key; the gateway checks inside
	// decide what that AI agent may say and to whom.
	"POST /api/agent-host/messages":           "an AI agent's body speaking in a conversation, sealed and signed by its key",
	"GET /api/agent-host/inbox":               "an AI agent's body collecting its messages, sealed and signed by its key",
	"GET /api/agent-host/agents":              "an AI agent's body asking which AI agents it may message, sealed and signed",
	"GET /api/agent-host/conversations/{cid}": "an AI agent's body reading a conversation it is in, sealed and signed",
	// A body borrowing its AI agent's brain sign-in for one run, renewing it
	// and giving it back. Each handler admits only a sealed request a live
	// body signed, and the sign-in travels back sealed to that body's keys.
	"POST /api/agent-host/brain-sign-in":        "an AI agent's body borrowing its brain's sign-in for one run, sealed and signed",
	"POST /api/agent-host/brain-sign-in/renew":  "an AI agent's body keeping a borrowed sign-in while its run goes on, sealed and signed",
	"POST /api/agent-host/brain-sign-in/return": "an AI agent's body giving back a borrowed sign-in, sealed and signed",
	// A body saying whether it has a screen and waiting to be watched, and
	// sending pictures of it while somebody does. Each handler admits only a
	// sealed request a live body signed, and a picture is kept only for a
	// viewing of that body.
	routeBodyScreen:      "an AI agent's body saying what screen it has and waiting to be watched, sealed and signed",
	routeBodyScreenFrame: "an AI agent's body sending a picture of its screen while watched, sealed and signed",
	// A body borrowing GitHub access for one run, and giving it back. Each
	// handler admits only a sealed request a live body signed; the token
	// travels back sealed to that body's keys.
	"POST /api/agent-host/github":        "an AI agent's body borrowing GitHub access for one run, sealed and signed",
	"POST /api/agent-host/github/return": "an AI agent's body giving back the GitHub access it borrowed, sealed and signed",
	// A body that makes machines for other AI agents collecting that work and
	// reporting on it. Each handler admits only a sealed request a live body
	// signed, whose AI agent's grant lets it make machines; an enrolment
	// string travels back sealed to that body's keys.
	"GET /api/agent-host/machine-requests":                  "a body that makes machines collecting the machines it is asked for, sealed and signed",
	"POST /api/agent-host/machine-requests/{rid}":           "a body that makes machines saying how one is going, sealed and signed",
	"POST /api/agent-host/machine-requests/{rid}/enrolment": "a body that makes machines asking for the enrolment string of one it is making, sealed and signed",

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

	// --- reaching your own agent from a browser ---
	// Nobody is authenticated yet, which is the entire problem these solve. The
	// flow's security is not in gating these: it is that granting requires the
	// owner key, and that collecting requires a secret the browser never
	// displayed. Gating the start of a login behind being logged in would be
	// the deadlock this exists to break.
	"POST /api/session/challenge": "starts a browser login; the caller cannot be authenticated yet, by definition",
	"POST /api/session/claim":     "collects a session the owner already granted, and needs the browser's own secret to do it",
	"POST /api/session/end":       "signing out must work with the session itself, not the device that started it",

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
	// is the same deadlock the browser-login routes above describe — the person
	// joining is not the person who published.
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
	// approval is owner-only and additionally refused to browser sessions. So
	// what a stranger with a valid token can do is put themselves in a queue.
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
	"POST /didcomm":                                         "an agent we know posts an encrypted envelope, authenticated by what it carries",
	"POST /api/witness/request":                             "witnessing protocol — a controller asks us to witness",
	"POST /api/witness/accept":                              "witnessing protocol — a witness answers our request, signed by its key",
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
	"GET /*":                                "the Flutter web UI itself; the API it calls is still authorised",
}

// scopedRoutes are reachable by a caller presenting capability scopes rather
// than being the owner. The handler enforces the specific scope.
var scopedRoutes = map[string]string{
	"POST /api/mcp":                      "MCP clients act under a minted token with explicit scopes",
	"POST /api/capabilities/{id}/invoke": "capability invocation is gated by the grant, not by locality",
}

// sandboxEgressPrefixes are the container-facing namespaces. A sandboxed app
// reaches these from the container network, so it is neither the owner nor a
// token holder; the handlers behind them are their own gate (LLM egress is
// structurally denied except the static model catalogue).
var sandboxEgressPrefixes = []string{
	"/sandbox/llm/v1",
	"/apps/{app_id}/",
}

// classify returns the access class for a matched route pattern.
func classify(method, pattern string) accessClass {
	key := method + " " + pattern
	if _, ok := publicRoutes[key]; ok {
		return accessPublic
	}
	if _, ok := scopedRoutes[key]; ok {
		return accessScoped
	}
	for _, p := range sandboxEgressPrefixes {
		if len(pattern) >= len(p) && pattern[:len(p)] == p {
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

			switch classify(r.Method, pattern) {
			case accessPublic:
				next.ServeHTTP(w, r)
			case accessScoped:
				if how := s.howThisIsTheOwner(r); how != "" {
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
				denyAuthorization(w, "this endpoint needs a token carrying the capability scope for it")
			default:
				if how := s.howThisIsTheOwner(r); how != "" {
					// Said, as on the scoped routes, so a handler that names
					// its caller names the owner the gate admitted: an owner
					// signature is spent here and cannot be checked again.
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), theGateAdmittedTheOwnerKey{}, how)))
					return
				}
				// Tried before the browser session because a request can carry
				// both, and the controller signature is the stronger claim: it
				// proves this request came from that machine, where a session
				// proves only that somebody holds a cookie.
				if served := s.controllerActsForTheOwner(w, r, pattern, next); served {
					return
				}
				// A browser session stands in for the owner on everything
				// except the routes that change the identity itself. Those go
				// back to the device holding the key — a convenience should not
				// be able to give the identity away.
				if s.hasBrowserSession(r) {
					if reason, forbidden := requiresTheKeyItself(r.Method, pattern); forbidden {
						denyAuthorizationBecause(w, reasonBrowserSession, "a browser session cannot do this: "+reason+
							". Use the device that holds this identity's key")
						return
					}
					next.ServeHTTP(w, r)
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
	// reasonBrowserSession is a route a browser session may not reach.
	reasonBrowserSession = "browser_session"
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	body := map[string]string{"error": "not_authorized", "detail": detail}
	if reason != "" {
		body["reason"] = reason
	}
	_ = json.NewEncoder(w).Encode(body)
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
// No to a browser session and to a caller holding a scoped token, which the
// gate admits too but which are not the owner acting.
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
	if s.isLocalOwnerRequest(r) {
		return ownerAtThisComputer
	}
	if s.isSealedOwnerRequest(r) {
		return ownerSealed
	}
	if s.verifyOwnerSignature(r) == nil {
		return ownerSigned
	}
	return ""
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
func (s *CoreServer) theOwnerAsACaller(r *http.Request, how string) sandbox.CallerContext {
	cc := sandbox.CallerContext{
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

// sessionForbidden names what a browser session may NOT do, and why.
//
// The list is the point of having sessions at all. A session is a convenience
// carried by software that holds no key, granted once and then usable for
// hours by whoever has the browser. What it must not be able to do is change
// who this identity IS — its keys, who may sign for it, who witnesses it, or
// where its root of trust lives. Those need the device holding the key, every
// time, because that is the only proof that survives a stolen session.
//
// Deliberately a list of what is forbidden rather than a list of what is
// allowed. An allow-list would mean a route added tomorrow is unreachable from
// a browser until somebody remembers to add it, and the pressure to fix that
// quickly is pressure to add things without thinking. A deny-list means a new
// route is reachable — and the ones that matter are already named here.
//
// Keyed by "METHOD /chi/pattern", the same way publicRoutes is.
var sessionForbidden = map[string]string{
	// --- the root of trust ---
	"POST /api/keystore/root-seed": "installing a root seed decides what this identity is",
	// Which half this computer is running. A browser is not the app on this
	// machine, and this decides whether this core answers about an identity at
	// all — a session that could set it would make the machine refuse its own
	// owner, and one that could clear it would put a front end back to giving
	// answers about nobody.
	"POST /api/controller/front-end-for":   "which half a computer is running is set on that computer, by the app on it",
	"DELETE /api/controller/front-end-for": "which half a computer is running is set on that computer, by the app on it",
	// Retrieval hands back the bytes of an archive. A browser session is
	// something the owner grants for a while and that whoever holds the browser
	// then has; it must not be enough to pull an identity's sealed backups out
	// of this machine, because the archive plus a guessable passphrase, or the
	// archive plus later possession of the phrase, is the identity.
	"POST /api/recovery/retrieve":          "retrieval hands back an archive, and an archive is the identity to anyone who can open it",
	"POST /api/recovery/root-aid-rotation": "rotating the root AID replaces the identity's controlling key",
	// The keys this device holds for the machines it owns. A session that
	// could ask for a signature, or for a new owning identity, would hold the
	// owner's authority over every machine this device adopted.
	"POST /api/machines/owner/sign":     "a signature as a machine's owner is the owner's authority over that machine",
	"POST /api/machines/owner-identity": "minting the identity that owns a machine is the owner's to do",
	// Everything that starts, finishes, stops or weakens a recovery.
	//
	// A recovery replaces this identity's key material and everything it held,
	// so it belongs on this list for the same reason installing a root seed
	// does — a browser session is something the owner grants for a while and
	// that whoever holds the browser then has.
	//
	// The duress policy is the sharpest of these. It is the control that says
	// what must happen if the owner may be being forced, and a session that
	// could turn it off could disable the protection and then use the recovery
	// it was protecting against.
	"PUT /api/recovery/duress-policy":           "this decides what happens if the owner is being coerced",
	"POST /api/recovery/start":                  "starting a recovery begins replacing this identity",
	"POST /api/recovery/sessions/{id}/activate": "activating a recovery replaces this identity and everything it held",
	"POST /api/recovery/sessions/{id}/cancel":   "stopping a recovery decides whether it happens",
	"POST /api/recovery/sessions/{id}/rotation": "this rotates the identity's keys",
	// Reading is forbidden too, which the writes above are not enough for.
	//
	// A recovery in progress is the fact that somebody is taking this identity
	// over, and when it can be completed. Anything holding a browser session
	// could watch the clock and time itself against the window, or simply
	// learn that a recovery is running — which is exactly what the window
	// exists to give the owner, and nobody else, a chance to act on.
	// Agreeing to hold a share, and approving a release, are the owner's
	// decisions about their own machine.
	"POST /api/recovery/holdings":         "agreeing to hold part of somebody's recovery is a commitment",
	"POST /api/recovery/holdings/approve": "approving a recovery is the whole of what a human gate decides",
	"POST /api/recovery/holdings/stop":    "giving up a share makes somebody else's backups unopenable by this machine",
	"PUT /api/recovery/who-holds-this":    "this decides what it takes to get back into this identity",

	"GET /api/recovery/sessions":      "a recovery in progress says this identity is being taken over, and when",
	"GET /api/recovery/sessions/{id}": "a recovery in progress says this identity is being taken over, and when",
	// Founding and rotation outside recovery, for the same reason.
	"POST /api/inception": "founding an identity decides what this agent is",
	"POST /api/rotation":  "rotation replaces the keys this identity signs with",

	// --- who may act for this identity ---
	"POST /api/signer/invites":                "inviting a signer decides who may bring this organisation into existence",
	"POST /api/signer/invites/{token}/redeem": "redeeming a signer invite makes somebody an owner",
	"POST /api/employees/{aid}/approve":       "approving a member decides who may act as this organisation",
	"POST /api/employees/{aid}/revoke":        "revoking a member decides who may act as this organisation",

	// --- answering for the key ---
	"POST /api/signing-requests/{id}/fulfil": "these exist precisely because only the key-holding device can answer them",
	"POST /api/signing-requests/{id}/refuse": "refusing is the key-holding device's answer, and a refused withdrawal is never asked for again",

	// --- destruction ---
	"POST /api/reset": "resetting destroys the identity, and a session should never be enough for that",

	// A session is software holding a cookie. Letting it drive this machine's
	// enclave would make the enclave reachable by whatever holds that cookie,
	// which is the opposite of what keeping the key in hardware is for.
	"POST /api/controller/sign": "asking this computer's secure hardware to sign is for the app running on it",

	// --- minting durable credentials for AI agents ---
	//
	// Provisioning an agent and minting its token both create a bearer credential
	// that outlives the session: the session can be ended, but a token it minted
	// keeps working. A session is a convenience the owner grants for a while; it
	// must not be able to leave behind permanent agent access. The owner's app on a
	// device that holds the key does this.
	"POST /api/mcp/agents": "provisioning an agent mints a durable token that outlives the session that made it",
	"POST /api/mcp/tokens": "minting a token creates durable bearer access that outlives the session that made it",
	// Re-issuing an agent's grant is the one place its ceiling can be changed
	// after it exists. A session that could reach it could widen what an agent
	// may do and leave that standing after the session ends — the same durable
	// grant as minting, by a different door.
	"PUT /api/mcp/agents/{id}/capabilities": "re-issuing an agent's grant can widen what it may do, and that outlives the session that changed it",
	// An AI agent's configuration says where its model is reached and with which
	// stored key, and whether it must run attested. A session that changed those
	// could point the AI agent at an endpoint it controls, and the change would
	// outlive the session.
	"PATCH /api/mcp/agents/{id}": "changing where an AI agent's model is reached, and with which key, outlives the session that changed it",
	// The same, by the brain's sign-in: its key, its account, and a local
	// model server's address.
	"PUT /api/mcp/agents/{id}/brain-sign-in":    "signing an AI agent's brain in, with which key and at which address, outlives the session that did it",
	"DELETE /api/mcp/agents/{id}/brain-sign-in": "removing an AI agent's sign-in outlives the session that removed it",
	// Revoking an AI agent cannot be undone: it is never granted anything
	// again, and its machines are ended.
	"POST /api/mcp/agents/{id}/revoke": "revoking an AI agent cannot be undone, and outlives the session that did it",
	// Checking a sign-in sends a request from this Identity Agent to an address
	// the caller names. Only the owner's own app may ask for that, so a session
	// cannot use this Identity Agent to reach into the network it sits on.
	"POST /api/mcp/brain-sign-in/test":             "checking a sign-in makes this Identity Agent reach an address the caller names",
	"POST /api/mcp/agents/{id}/brain-sign-in/test": "checking a sign-in makes this Identity Agent reach the address it names",
	// The organisation's GitHub App: its private key lets this Identity Agent
	// make tokens for the organisation's repositories, so connecting one,
	// disconnecting it and using it are for the owner's own app. Granting an
	// AI agent repositories re-issues its grant, which outlives the session.
	"PUT /api/github":                 "connecting a GitHub App keeps a key that makes tokens for the organisation's repositories, after the session ends",
	"DELETE /api/github":              "disconnecting the GitHub App ends every AI agent's access to the organisation's repositories",
	"GET /api/github/repositories":    "listing the repositories makes this Identity Agent use the GitHub App's key",
	"PUT /api/mcp/agents/{id}/github": "granting an AI agent repositories re-issues its grant, which outlives the session that changed it",
	// An enrolment string, and approving a body, let a machine speak as an AI
	// agent from then on — standing access that outlives the session.
	"POST /api/mcp/agents/{id}/body-enrolment":       "an enrolment string lets a machine ask to speak as an AI agent, after the session that made it ends",
	"POST /api/mcp/agents/{id}/bodies/{bid}/approve": "approving a body lets a machine speak as an AI agent, after the session that approved it ends",
	"POST /api/mcp/agents/{id}/bodies/{bid}/reject":  "rejecting a body hands back a fresh enrolment string, which outlives the session that asked for it",
	// Watching an AI agent's screen is open to a session; taking control of it
	// is not. Whoever clicks and types on the AI agent's machine can do what
	// that machine can, which is more than a convenience granted for a while
	// should carry.
	routeScreenControl: "taking control of an AI agent's screen lets whoever holds the session click and type on its machine",
	routeScreenInput:   "clicking and typing on an AI agent's machine is done from a device that can take control, not a session",
}

// requiresTheKeyItself reports whether a route is one a browser session must
// not perform, and the reason to tell the person.
func requiresTheKeyItself(method, pattern string) (string, bool) {
	reason, forbidden := sessionForbidden[method+" "+pattern]
	return reason, forbidden
}
