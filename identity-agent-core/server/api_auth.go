package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
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

// publicRoutes are unauthenticated by design. Keyed by "METHOD /chi/pattern".
// Each entry states why, because a public route is a decision, not an accident.
var publicRoutes = map[string]string{
	// --- discovery and verification: the OOBI layer ---
	// These answer "who is this AID and how do I verify it". They carry no
	// personal data (see handleOobiServe), and requiring auth would defeat the
	// purpose: a stranger must be able to verify us before any relationship.
	"GET /oobi/{aid}":               "OOBI discovery record",
	"GET /public/oobi/{aid}":        "OOBI discovery record",
	"GET /{aid}/oobi":               "OOBI discovery record (did:webs layout)",
	"GET /{aid}/did.json":           "did:webs document — public key material",
	"GET /public/{aid}/did.json":    "did:webs document — public key material",
	"GET /{aid}/kel":                "key event log — public and self-verifying",
	"GET /{aid}/keri.cesr":          "key event log as a CESR stream",
	"GET /api/kerl":                 "key event log — public and self-verifying",
	"POST /_register":               "a pairwise signer registers its key so counterparties can resolve it",
	"POST /public/_register":        "a pairwise signer registers its key so counterparties can resolve it",
	"GET /public/credential/{said}": "a credential the user chose to publish at a shareable link",

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
	"POST /api/exchange":                                    "a peer posts an introduction we consented to receive",
	"POST /api/witness/request":                             "witnessing protocol — a controller asks us to witness",
	"POST /api/witness/accept":                              "witnessing protocol — a receipt comes back",
	"POST /api/receipt/submit":                              "a witness submits a receipt for an event",
	"POST /api/backup/receive":                              "a peer pushes an opaque, already-encrypted archive",
	"GET /api/backup/receive/{identityAID}":                 "the owning agent lists its own archives during recovery",
	"GET /api/backup/receive/{identityAID}/download/{name}": "the owning agent retrieves an opaque archive during recovery",

	// --- liveness and the app shell ---
	"GET /api/health": "liveness probe — reveals nothing",

	// The one endpoint that must answer before an owner exists. A freshly
	// provisioned instance has no identity and no owner, so it cannot be
	// owner-gated; it discloses a pairwise AID that is about to be published as
	// an OOBI anyway, nothing else, and it stops answering once paired.
	"GET /api/provisioning/pairing": "a newly provisioned instance offers itself for pairing, before any owner exists",
	// The adoption ceremony itself. Same reasoning and the same window: an
	// instance with no owner cannot gate these on being the owner. Both refuse
	// the moment the instance has an identity, so the window closes on success.
	"POST /api/pairing/begin":    "an unadopted instance offers its own public key material for delegation",
	"POST /api/pairing/complete": "an unadopted instance accepts a delegation over that key and seals its owner",
	"GET /*":                     "the Flutter web UI itself; the API it calls is still authorised",
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
				// No route matched — let the router answer 404 rather than
				// telling an unauthenticated caller which paths exist.
				next.ServeHTTP(w, r)
				return
			}

			switch classify(r.Method, pattern) {
			case accessPublic:
				next.ServeHTTP(w, r)
			case accessScoped:
				if s.isOwner(r) || len(s.resolveCaller(r).Scopes) > 0 {
					next.ServeHTTP(w, r)
					return
				}
				denyAuthorization(w, "this endpoint needs a token carrying the capability scope for it")
			default:
				if s.isOwner(r) {
					next.ServeHTTP(w, r)
					return
				}
				// A browser session stands in for the owner on everything
				// except the routes that change the identity itself. Those go
				// back to the device holding the key — a convenience should not
				// be able to give the identity away.
				if s.hasBrowserSession(r) {
					if reason, forbidden := requiresTheKeyItself(r.Method, pattern); forbidden {
						denyAuthorization(w, "a browser session cannot do this: "+reason+
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
	rctx := chi.NewRouteContext()
	if !routes.Match(rctx, r.Method, r.URL.Path) {
		return ""
	}
	return rctx.RoutePattern()
}

func denyAuthorization(w http.ResponseWriter, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "not_authorized",
		"detail": detail,
	})
}

// isOwner answers the only question the default class asks: is this the person
// who controls this agent?
//
// Two ways to be the owner, and they are not alternatives so much as the same
// claim proved differently. On a machine you are sitting at, a request that
// originates on that machine is you. On hardware you rent — where you are
// remote by definition and the local test can never be true — you prove it by
// signing the request with the owner key sealed into the box at provisioning.
func (s *CoreServer) isOwner(r *http.Request) bool {
	if isLocalOwnerRequest(r) {
		return true
	}
	return s.verifyOwnerSignature(r) == nil
}

// IsOwner is the exported owner check for overlays (owner-only management routes).
func (s *CoreServer) IsOwner(r *http.Request) bool { return s.isOwner(r) }

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
	for s, t := range seenSignatures {
		if now.Sub(t) > signedRequestWindow {
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
	"POST /api/keystore/root-seed":         "installing a root seed decides what this identity is",
	"POST /api/recovery/root-aid-rotation": "rotating the root AID replaces the identity's controlling key",

	// --- who may act for this identity ---
	"POST /api/signer/invites":                "inviting a signer decides who may bring this organisation into existence",
	"POST /api/signer/invites/{token}/redeem": "redeeming a signer invite makes somebody an owner",
	"POST /api/employees/{aid}/approve":       "approving a member decides who may act as this organisation",
	"POST /api/employees/{aid}/revoke":        "revoking a member decides who may act as this organisation",

	// --- answering for the key ---
	"POST /api/signing-requests/{id}/fulfil": "these exist precisely because only the key-holding device can answer them",

	// --- destruction ---
	"POST /api/reset": "resetting destroys the identity, and a session should never be enough for that",
}

// requiresTheKeyItself reports whether a route is one a browser session must
// not perform, and the reason to tell the person.
func requiresTheKeyItself(method, pattern string) (string, bool) {
	reason, forbidden := sessionForbidden[method+" "+pattern]
	return reason, forbidden
}
