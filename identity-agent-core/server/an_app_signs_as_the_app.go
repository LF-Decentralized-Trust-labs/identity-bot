package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/apprequest"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

// An app's back end reaches its owner's Identity Agent as the app (ADR-072
// section 4, ADR-045 Amendment 1), never as a controller.
//
// It signs each request with its App Body key, in the form an AI agent's body
// signs (ADR-046, agentbody.SignedRequest), and this file is the whole of what
// the core checks of it:
//
//   - the machine key is the one an App Body credential names (host and verkey),
//     that credential is held by an app asset of this Identity Agent, issued by
//     it, and still in force;
//   - the app holds an App Grant in force, and the route is one an app may use
//     (coreAppRoutes, and each add-on's AppRoutes) and needs a capability the
//     grant holds, used within any limit the grant puts on it (resource_constraints,
//     read against the route's own {params});
//   - the signature covers this Identity Agent, the method, the target, the
//     time, a nonce and a digest of the body, within agentbody.RequestWindow,
//     and is spent once.
//
// An app's key is refused on every route not in that table: that is every
// route a controller may use, and every owner-only one. Nothing about an app is
// a controller's grant, so no score and no signer is involved.
//
// The published contract is contracts/app-request/app-request.md, with vectors
// and an independent checker.

// AppRoute is a route an app's back end may use: the capability its App Grant
// must hold, and which {param} of the route gives each argument of that
// capability, so the grant's limits (resource_constraints) can be held to what
// the route is asked for. A grant that limits an argument the route does not
// give is refused on that route: a limit the gate cannot check is not read as
// no limit.
type AppRoute struct {
	Capability string
	Arguments  map[string]string // capability argument -> route {param}
}

// coreAppRoutes is the routes the core itself lets an app use, keyed
// "METHOD /chi/pattern" as the core's other route tables are. A route in
// neither this nor an add-on's AppRoutes is not an app's.
//
// Only the route that carries a person's words is here: it is accepted only
// with the person's own statement beside the app's signature
// (an_app_speaks_for_a_person_who_signed.go), and a grant that limits whom the
// app may message ("to") is held to the AI agent the path names, by the
// identifier its entries are addressed to. The reads of a
// conversation are not here, because the core has no per-person check on a read
// an app makes; an add-on lists them in AppRoutes once it enforces one.
func coreAppRoutes() map[string]AppRoute {
	return map[string]AppRoute{
		"POST /api/mcp/agents/{id}/conversations": {Capability: "agent.message.send", Arguments: map[string]string{"to": "id"}},
	}
}

// appRoutesOf is every route an app may use: the core's, then each add-on's.
// A route the core lists keeps the core's entry.
func appRoutesOf(addons []Addon) map[string]AppRoute {
	routes := coreAppRoutes()
	for _, a := range addons {
		for route, r := range a.AppRoutes {
			if _, taken := routes[route]; !taken && r.Capability != "" {
				routes[route] = r
			}
		}
	}
	return routes
}

// AppCaller is the app behind a request its back end signed, as the gate
// proved it. It is what TheAppThatAsked returns.
type AppCaller struct {
	// Asset is the app's asset id; AID its identifier, which holds the App Body
	// and the App Grant.
	Asset, AID string
	// Host and Verkey are the machine key that signed. Body and Grant are the
	// App Body and App Grant credentials it was admitted on.
	Host, Verkey, Body, Grant string
	// Params are the route's {params} as chi reads them from the path, the
	// same values the grant's limits were checked against.
	Params map[string]string
	// The request the key signed is checked here, at request time, and is not
	// carried on: the words of a conversation live only in the app, never in
	// the Identity Agent (ADR-068), so what a handler needs of the body it
	// reads from the request itself.
}

type appContextKey struct{}

// TheAppThatAsked is the app whose back end signed this request, if one did.
func TheAppThatAsked(r *http.Request) (AppCaller, bool) {
	a, ok := r.Context().Value(appContextKey{}).(AppCaller)
	return a, ok
}

// anAppRefusedHere is a refusal of a request that does carry an app's key.
type anAppRefusedHere struct{ code, message string }

func (e anAppRefusedHere) Error() string { return e.message }

// appActsAsTheApp serves this request if an app's back end signed it with its
// App Body key and every check above holds, and refuses it, saying why, if the
// key is an app's and any does not. It reports false only for a request that
// carries no app's key, which the caller then judges as it always has: a
// request naming a machine key no App Body names is an AI agent's, or nobody's.
func (s *CoreServer) appActsAsTheApp(w http.ResponseWriter, r *http.Request, pattern string, params map[string]string, next http.Handler) bool {
	host := strings.TrimSpace(r.Header.Get(agentbody.HeaderHost))
	if host == "" {
		return false
	}
	body, bodyAttrs := s.appBodyOf(host)
	if body == nil {
		return false
	}
	app, err := s.theAppBehind(r, pattern, params, appRoutesOf(registeredAddons()), body, bodyAttrs)
	if err != nil {
		var refused anAppRefusedHere
		if RefuseAnAppOverItsRate(w, err) {
			return true
		}
		if errors.As(err, &refused) {
			denyAuthorizationBecause(w, refused.code, refused.message)
		} else if !refuseTheBody(w, err) {
			denyAuthorization(w, err.Error())
		}
		return true
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), appContextKey{}, app)))
	return true
}

// theAppBehind checks everything about a request that carries an app's key.
func (s *CoreServer) theAppBehind(r *http.Request, pattern string, params map[string]string, routes map[string]AppRoute, body *store.CredentialRecord, attrs map[string]interface{}) (AppCaller, error) {
	none := AppCaller{}
	// One kind of signer to a request. A request that also claims to be a
	// controller's, the owner's or a token holder's is not read as any of them.
	for _, h := range []string{headerControllerAID, headerControllerSig, headerOwnerSig, headerOwnerAID, "Authorization", "X-IA-Token", envSigHeader, LocalOwnerSecretHeader, headerSealedFrom} {
		if r.Header.Get(h) != "" {
			return none, anAppRefusedHere{reasonNotAllowed, "a request is signed by one key: an app's back end signs with its App Body key, and carries no token, owner or controller credential beside it"}
		}
	}
	route := r.Method + " " + pattern
	appRoute, mayUse := routes[route]
	if !mayUse {
		why := "an app's key is for the routes an app may use, and " + route + " is not one of them"
		if _, owner := isOwnerOnly(r.Method, pattern); owner {
			return none, anAppRefusedHere{reasonOwnerOnly, why + ": it is for the owner's own keys, and no utility app controls an Identity Agent"}
		}
		return none, anAppRefusedHere{reasonNotAllowed, why + ": no utility app controls an Identity Agent"}
	}

	appAID := body.HolderAID
	asset, ok := s.theAppAsset(appAID)
	if !ok {
		return none, errors.New("this machine key is the body of no app of this Identity Agent")
	}

	// The app's grant is what it may ask: the newest one in force.
	var grant *store.CredentialRecord
	var grantAttrs map[string]interface{}
	// Only the newest grant counts: if it is revoked the app holds none, and an
	// older one that was never revoked does not come back.
	if held := s.credentialsOfAnyHeldBy(appAID, []string{schemas.AppGrant.Schema.SAID}, s.OwnerRootAID(), false); len(held) > 0 && isUsableStatus(held[0].Status) {
		if a := credentialAttributes(&held[0]); a != nil {
			grant, grantAttrs = &held[0], a
		}
	}
	if grant == nil {
		return none, errors.New("this app holds no App Grant in force, so it may ask for nothing")
	}
	var caps []string
	var limits map[string][]string
	if raw, _ := grantAttrs["capabilities"].([]interface{}); raw != nil {
		for _, c := range raw {
			if name, ok := c.(string); ok {
				caps = append(caps, name)
			}
		}
	}

	// What the grant limits the capability to, per argument, and what this
	// route gives each of those arguments.
	// A limit that is present but not an object cannot be read, and an app is not
	// unlimited for want of one it can be read against.
	unreadable := anAppRefusedHere{reasonNotAllowed, "this app's grant limits what it may use in a form that cannot be read, so it may use nothing (" + route + ")"}
	if rawAll, present := grantAttrs["resource_constraints"]; present {
		all, ok := rawAll.(map[string]interface{})
		if !ok {
			return none, unreadable
		}
		if rawOne, present := all[appRoute.Capability]; present {
			one, ok := rawOne.(map[string]interface{})
			if !ok {
				return none, unreadable
			}
			limits = map[string][]string{}
			for arg, raw := range one {
				values := []string{} // a limit that cannot be read allows nothing
				if list, ok := raw.([]interface{}); ok {
					for _, v := range list {
						if name, ok := v.(string); ok {
							values = append(values, name)
						}
					}
				}
				limits[arg] = values
			}
		}
	}
	given := map[string]string{}
	for arg, param := range appRoute.Arguments {
		v, ok := params[param]
		if !ok {
			continue
		}
		if arg == "to" {
			// A limit names an AI agent by the identifier its entries are addressed
			// to, as a person's statement does, never by the asset id the route
			// carries. A route that names no such AI agent gives no value, and a
			// limit on "to" then cannot be checked, which refuses the request.
			if agent, isAgent := s.theAIAgentARouteNames(v); isAgent {
				given[arg] = agent
			}
			continue
		}
		given[arg] = v
	}

	payload, err := readSignedBody(r)
	if err != nil {
		return none, err
	}
	verkey, _ := attrs["verkey"].(string)
	until := func(a map[string]interface{}) string { u, _ := a["valid_until"].(string); return u }
	_, err = apprequest.Check(apprequest.Request{
		Method: r.Method, Target: r.URL.RequestURI(), Body: payload,
		Host: r.Header.Get(agentbody.HeaderHost), For: r.Header.Get(agentbody.HeaderFor),
		Timestamp: r.Header.Get(agentbody.HeaderTimestamp), Nonce: r.Header.Get(agentbody.HeaderNonce),
		Signature: r.Header.Get(agentbody.HeaderSignature), WorkItem: r.Header.Get(agentbody.HeaderWorkItem),
		Reason: r.Header.Get(agentbody.HeaderReason), Session: r.Header.Get(agentbody.HeaderSession),
	}, apprequest.Admission{
		IdentityAgent: s.thisIdentityAgentsIdentifier(), Now: time.Now(),
		BodyHost: hostOf(attrs), BodyVerkey: verkey, BodyValidUntil: until(attrs),
		GrantCapabilities: caps, GrantValidUntil: until(grantAttrs), CapabilityTheRouteNeeds: appRoute.Capability,
		GrantConstraints: limits, RouteArguments: given,
	})
	if err != nil {
		if code := apprequest.CodeOf(err); code == apprequest.NoCapability || code == apprequest.OutsideConstraint || code == apprequest.CannotEnforce {
			return none, anAppRefusedHere{reasonNotAllowed, err.Error() + " (" + route + ")"}
		}
		return none, err
	}
	// A signature is spent once, and before the rate is charged: a replayed copy
	// is refused here and cannot use up the app's rate. Only a request that is
	// otherwise admitted spends it, so a bad one cannot burn a good one.
	sig := r.Header.Get(agentbody.HeaderSignature)
	if rememberSignature(sig, time.Now()) {
		return none, errors.New("this signed request was already used")
	}
	// An app is held to its rate on every route it may use, the add-ons' too.
	if err := s.holdAppToItsRate(asset); err != nil {
		return none, err
	}
	return AppCaller{
		Asset: asset, AID: appAID, Host: hostOf(attrs), Verkey: verkey, Body: body.SAID, Grant: grant.SAID, Params: params,
	}, nil
}

func hostOf(attrs map[string]interface{}) string { h, _ := attrs["host"].(string); return h }

// appBodyOf is the App Body credential in force that names host, and what it
// says. Nil when none does, which is what an AI agent's body or an unknown key
// looks like here.
func (s *CoreServer) appBodyOf(hostID string) (*store.CredentialRecord, map[string]interface{}) {
	if s.DataStore == nil {
		return nil, nil
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return nil, nil
	}
	for i := range creds {
		c := &creds[i]
		if c.SchemaSAID != schemas.AppBody.Schema.SAID || !isUsableStatus(c.Status) || c.IssuerAID != s.OwnerRootAID() {
			continue
		}
		if a := credentialAttributes(c); a != nil && hostOf(a) == hostID {
			return c, a
		}
	}
	return nil, nil
}

// theAppAsset is the id of the app asset whose identifier is aid.
func (s *CoreServer) theAppAsset(aid string) (string, bool) {
	if s.assetHandler == nil || aid == "" {
		return "", false
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return "", false
	}
	for _, a := range assets {
		if a.AssetType == "app" && a.PairwiseAID == aid && !a.ApprovalPending {
			return a.ID, true
		}
	}
	return "", false
}

// credentialAttributes is the attribute block a stored credential carries, or nil.
func credentialAttributes(rec *store.CredentialRecord) map[string]interface{} {
	raw, err := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if err != nil {
		return nil
	}
	var acdc struct {
		A map[string]interface{} `json:"a"`
	}
	if json.Unmarshal(raw, &acdc) != nil {
		return nil
	}
	return acdc.A
}
