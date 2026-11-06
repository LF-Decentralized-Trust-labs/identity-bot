package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/internal/coretypes"
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/login"
)

// A person signed in to an app the organisation hosts (ADR-066) may speak to an
// AI agent from that app's page, as the person the sign-in names and as nobody
// else, with a session the app's back end opened here (OpenAppSession).
//
// What makes a request one of theirs is not the session token alone. A token is
// a bearer secret, and one copied from a log or an address bar must let nobody
// in, so the request must also be signed with the browser key the session is
// bound to (login.BrowserProofString), freshly and once. The key the session is
// bound to is the key the person's own Identity Agent approved at sign-in, and
// is named here by its RFC 7638 thumbprint.
//
// What it is NOT is a controller. A controller can do nearly everything the
// owner can, and a web page must never be one: an app session is admitted at
// the gate for the talk routes below and nowhere else, carries no grant, and
// reaches nothing a controller reaches by being one. On any other route the
// request is judged as it was before, and a session token is no credential
// there.

// talkRoutes are the routes an app session may take: a person talking to an AI
// agent, and reading what was said. The conversation's export and the record's
// settings are not among them.
var talkRoutes = map[string]bool{
	"POST /api/mcp/agents/{id}/conversations": true,
	"GET /api/mcp/agents/{id}/conversations":  true,
	"GET /api/mcp/conversations/{cid}":        true,
}

// appSessionProofWindow is how far a proof's time may be from now, either way.
const appSessionProofWindow = 2 * time.Minute

// AppSession is a person's session at one app, as the app's back end opened it.
type AppSession struct {
	// AppID is the asset id of the app the session is for, and the only app
	// whose origin may use it.
	AppID string
	// Person is who the session speaks as.
	Person coretypes.Signer
	// Thumbprint names the browser key the session is bound to.
	Thumbprint string
	// Expires is when the session ends.
	Expires time.Time

	key *ecdsa.PublicKey
}

// AppSessionAsking is the session a request was admitted on, for a handler that
// must scope what it shows to the person.
type AppSessionAsking struct {
	AppID      string
	Person     coretypes.Signer
	Thumbprint string
}

type theAppSessionThatAskedKey struct{}

type anAdmittedAppSession struct {
	who   AppSessionAsking
	proof *coretypes.ControllerProof
}

// TheAppSessionThatAsked is the app session a request was admitted on, if it
// was admitted on one and not on a controller's signature.
func TheAppSessionThatAsked(r *http.Request) (AppSessionAsking, bool) {
	a, ok := r.Context().Value(theAppSessionThatAskedKey{}).(anAdmittedAppSession)
	return a.who, ok
}

// appSessionBook is the sessions open here, by the SHA-256 of the token
// (login.BrowserSessionBinding). The zero value is ready to use.
type appSessionBook struct {
	mu       sync.Mutex
	sessions map[string]*AppSession
	nonces   map[string]time.Time
}

// OpenAppSession opens a session for a person at an app, bound to the P-256
// key whose JWK coordinates are x and y. tokenHash is the SHA-256 of the
// session token as login.BrowserSessionBinding gives it: the token itself is
// never given here. It returns the key's thumbprint.
func (s *CoreServer) OpenAppSession(appID, tokenHash, x, y string, person coretypes.Signer, expires time.Time) (string, error) {
	if appID == "" || person.AID == "" {
		return "", errors.New("an app session names its app and its person")
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(tokenHash); err != nil || len(raw) != 32 {
		return "", errors.New("an app session is opened with the SHA-256 of its token")
	}
	if !expires.After(time.Now()) {
		return "", errors.New("an app session is opened for a time to come")
	}
	pub, tp, err := login.BrowserKeyFromJWK(x, y)
	if err != nil {
		return "", err
	}
	b := &s.appSessions
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sessions == nil {
		b.sessions = map[string]*AppSession{}
	}
	b.sessions[tokenHash] = &AppSession{AppID: appID, Person: person, Thumbprint: tp, Expires: expires, key: pub}
	return tp, nil
}

// EndAppSession ends the session with this token hash, if there is one.
func (s *CoreServer) EndAppSession(tokenHash string) {
	b := &s.appSessions
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, tokenHash)
}

// EndAppSessionsOf ends every session of a person, and says how many.
func (s *CoreServer) EndAppSessionsOf(personAID string) int {
	b := &s.appSessions
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, v := range b.sessions {
		if v.Person.AID == personAID {
			delete(b.sessions, k)
			n++
		}
	}
	return n
}

func (b *appSessionBook) get(tokenHash string, now time.Time) (AppSession, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := b.sessions[tokenHash]
	if v == nil {
		return AppSession{}, false
	}
	if !now.Before(v.Expires) {
		delete(b.sessions, tokenHash)
		return AppSession{}, false
	}
	return *v, true
}

// spend records a proof's nonce, and says false if it was already used.
func (b *appSessionBook) spend(binding, nonce string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.nonces == nil {
		b.nonces = map[string]time.Time{}
	}
	for k, t := range b.nonces {
		if now.Sub(t) > 2*appSessionProofWindow {
			delete(b.nonces, k)
		}
	}
	k := binding + "\x00" + nonce
	if _, used := b.nonces[k]; used {
		return false
	}
	b.nonces[k] = now
	return true
}

func sameOrigin(a, b string) bool {
	norm := func(o string) string { return strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/")) }
	return a != "" && norm(a) == norm(b)
}

// originsOfApp are the origins an app's pages are served from, which is the
// only list a browser is answered for: the app's own origin.
func (s *CoreServer) originsOfApp(appID string) []string {
	if s.assetHandler == nil {
		return nil
	}
	a, ok, err := s.assetHandler.Store.GetAsset(appID)
	if err != nil || !ok || a.AssetType != "app" || a.Origin == "" {
		return nil
	}
	return []string{a.Origin}
}

// anAppListsThisOrigin says whether any app the organisation hosts lists the
// origin. It decides nothing about a person: it only lets a browser read an
// answer, which the session and its key still have to earn.
func (s *CoreServer) anAppListsThisOrigin(origin string) bool {
	if origin == "" || s.assetHandler == nil {
		return false
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return false
	}
	for _, a := range assets {
		if a.AssetType == "app" && sameOrigin(a.Origin, origin) {
			return true
		}
	}
	return false
}

// isATalkPath says a path is one of the talk routes', whatever its method, for
// the CORS preflight, which carries neither a session nor a route match.
func isATalkPath(p string) bool {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch len(parts) {
	case 4: // api/mcp/conversations/{cid}
		return parts[0] == "api" && parts[1] == "mcp" && parts[2] == "conversations" && parts[3] != ""
	case 5: // api/mcp/agents/{id}/conversations
		return parts[0] == "api" && parts[1] == "mcp" && parts[2] == "agents" && parts[3] != "" && parts[4] == "conversations"
	}
	return false
}

// anAppSessionSpeaks admits a request from an app session onto a talk route.
// It reports whether it answered: false means the request is not an app
// session's, and the gate carries on as it always has. Once a request carries
// an app session's token or a browser proof for a talk route it is answered
// here, served or refused, and never falls through to be judged as something
// else.
func (s *CoreServer) anAppSessionSpeaks(w http.ResponseWriter, r *http.Request, pattern string, next http.Handler) bool {
	if !talkRoutes[r.Method+" "+pattern] {
		return false
	}
	token := bearerToken(r)
	sig := strings.TrimSpace(r.Header.Get(login.HeaderBrowserProof))
	binding := ""
	if token != "" {
		binding = login.BrowserSessionBinding(token)
	}
	now := time.Now()
	sess, known := AppSession{}, false
	if binding != "" {
		sess, known = s.appSessions.get(binding, now)
	}
	if !known && sig == "" {
		return false
	}
	refuse := func(code int, why string) bool {
		jsonreply.Write(w, code, map[string]string{"error": "not_authorized", "detail": why})
		return true
	}
	if !known {
		return refuse(http.StatusUnauthorized, "this session is not known or has ended")
	}
	// The app the session is for, and only that app, is answered. A session of
	// one app never speaks from another's page.
	origins := s.originsOfApp(sess.AppID)
	if len(origins) == 0 {
		return refuse(http.StatusForbidden, "the app this session is for is not one this organisation hosts")
	}
	if o := r.Header.Get("Origin"); o != "" {
		listed := false
		for _, l := range origins {
			listed = listed || sameOrigin(l, o)
		}
		if !listed {
			return refuse(http.StatusForbidden, "this session is for another app than the page it was used from")
		}
	}
	if sig == "" {
		return refuse(http.StatusUnauthorized, "a session token alone lets nobody in: the request must be signed with the browser key the session is bound to")
	}
	body, err := readSignedBody(r)
	if err != nil {
		return refuse(http.StatusBadRequest, "the request cannot be read")
	}
	ts, nonce := r.Header.Get(login.HeaderBrowserProofTime), r.Header.Get(login.HeaderBrowserProofNonce)
	at, err := time.Parse(time.RFC3339, ts)
	if err != nil || now.Sub(at) > appSessionProofWindow || at.Sub(now) > appSessionProofWindow {
		return refuse(http.StatusUnauthorized, "the proof's time is outside the window this Identity Agent accepts")
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce); err != nil || len(nonce) < 8 || len(nonce) > 64 || len(raw) == 0 {
		return refuse(http.StatusUnauthorized, "the proof carries no usable nonce")
	}
	signed := login.BrowserProofString(r.Method, r.URL.RequestURI(), ts, nonce, binding, body)
	if !login.VerifyBrowserSignature(sess.key, signed, sig) {
		return refuse(http.StatusUnauthorized, "the proof was not made with the browser key this session is bound to")
	}
	if !s.appSessions.spend(binding, nonce, now) {
		return refuse(http.StatusUnauthorized, "this proof was already used")
	}
	// The person is asked about now, not as they were when they signed in: one
	// who has been removed speaks no more, whatever is left of their session.
	if !s.personStillStands(sess.Person) {
		s.EndAppSession(binding)
		return refuse(http.StatusUnauthorized, "this session is not known or has ended")
	}
	pub := sess.key
	point := make([]byte, 0, 65)
	point = append(point, 4)
	point = append(point, pub.X.FillBytes(make([]byte, 32))...)
	point = append(point, pub.Y.FillBytes(make([]byte, 32))...)
	proof := &coretypes.ControllerProof{
		Controller: "browser:" + sess.Thumbprint, PublicKey: base64.RawURLEncoding.EncodeToString(point),
		SignedString: signed, Signature: sig, RequestBytes: body, Scheme: coretypes.BrowserKeyScheme,
	}
	admitted := anAdmittedAppSession{
		who:   AppSessionAsking{AppID: sess.AppID, Person: sess.Person, Thumbprint: sess.Thumbprint},
		proof: proof,
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), theAppSessionThatAskedKey{}, admitted)))
	return true
}

// thePersonAnAppSessionIs is the person behind a request admitted on an app
// session, and the browser key's signature as proof of what they said.
func thePersonAnAppSessionIs(r *http.Request) (coretypes.Signer, *coretypes.ControllerProof, bool) {
	a, ok := r.Context().Value(theAppSessionThatAskedKey{}).(anAdmittedAppSession)
	if !ok {
		return coretypes.Signer{}, nil, false
	}
	return a.who.Person, a.proof, true
}
