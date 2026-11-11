package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
	"identity-agent-core/endpoint"

	"github.com/go-chi/chi/v5"
)

var checkStamp atomic.Int64

// asAPublicWatcherWithAContact makes the watcher answer what it has seen, as one
// opted in as a public watcher service does, and accept EContact as a contact.
func asAPublicWatcherWithAContact(t *testing.T, s *CoreServer) {
	t.Helper()
	if err := s.WatcherService.Store.SetConfig("public_watcher_service", "true"); err != nil {
		t.Fatal(err)
	}
	withAContactWhoMetEAIDAt(s)
}

// serveLog makes the agent serve a two-event log for aid, as a minted pairwise
// identifier is, and returns its digest at 1.
func serveLog(aid string) string {
	kel := []map[string]interface{}{{"t": "icp", "i": aid, "s": "0"}, {"t": "rot", "i": aid, "s": "1"}}
	registerPairwiseKEL(aid, kel)
	d, err := witnessproto.KelDigestAtSeq(kel, 1)
	if err != nil {
		panic(err)
	}
	return d
}

// withAContactWhoMetEAIDAt makes EContact an accepted contact and gives the agent the address it is reached
// at, which a signed request must name. Signatures are not checked here.
func withAContactWhoMetEAIDAt(s *CoreServer) {
	s.WatcherService.VerifyRequester = func(requester, _, _ string) bool { return requester == "EContact" }
	s.EndpointService = endpoint.New(nil, 0)
	s.EndpointService.SetOverrideURL("https://us.example")
}

// routesThatAnswerFromTheWatcher are the routes that tell a caller what this
// agent's watcher has seen of an identity, each with a request asking about aid.
// They read through the opt-out check (watcher.Service.Disclosable and
// DisclosableAll).
var routesThatAnswerFromTheWatcher = map[string]func(aid, digest string) *http.Request{
	"GET /public/kel-digest": func(aid, _ string) *http.Request {
		return remote("GET", "/public/kel-digest?aid="+aid+"&seq=1", "")
	},
	// Asked as a contact, because a stranger is answered "no match" whatever it
	// asks (see TestAStrangerGetsNothingFromEitherPublicRoute). The request is
	// stamped a second later each time so none is refused as a repeat.
	"POST /public/kel-check": func(aid, digest string) *http.Request {
		at := time.Now().Unix() + checkStamp.Add(1)
		return remote("POST", "/public/kel-check", fmt.Sprintf(
			`{"aid":%q,"seq":1,"digest":%q,"requester":"EContact","at":%d,"signature":"sig"}`, aid, digest, at))
	},
	"GET /debug/watcher/first-seen": func(aid, _ string) *http.Request {
		return local("GET", "/debug/watcher/first-seen?aid="+aid, "")
	},
}

// An opt-out honoured on one route and not another is not an opt-out. Every
// route a caller other than the owner can reach (public, or mounted outside
// /api) is walked, whatever its path, and must be either a route that answers
// from the watcher (above, tested below) or named here with why it says nothing
// the watcher saw. A route added later fails here until somebody decides which
// it is. This proves the routes were looked at; it cannot prove a handler
// named here never starts reading the watcher, which the watcher package's
// unexported reads guard instead.
func TestEveryWatcherRouteHonoursAnOptOut(t *testing.T) {
	t.Setenv("WATCHER_DEBUG", "true")
	s := watcherAgent(t, "EAID", 1, "Edigest")

	const (
		discovery    = "serves this agent's own key log, keys or discovery record, never an observation of another identity"
		signIn       = "the sign-in handshake; a credential it checks runs the watcher on the issuer's key log and is refused with one fixed phrase (ADR-024, opt-out section)"
		witness      = "the witness protocol: receipts and replicas of key logs this agent witnesses, not the watcher's first-seen records"
		pairing      = "pairing or provisioning this computer"
		backup       = "a backup held for, or handed back to, another identity"
		computation  = "computes over what it is sent; nothing the watcher holds is read"
		carried      = "carries a sealed request or message, which then meets its own route's check"
		notIdentity  = "says nothing about any identity"
		publication  = "a document the owner chose to publish"
		watcherOther = "a coverage summary with no per-identity data"
	)
	saysNothingTheWatcherSaw := map[string]string{
		"GET /oobi/{aid}":            discovery,
		"GET /public/oobi/{aid}":     discovery,
		"GET /{aid}/oobi":            discovery,
		"GET /{aid}/did.json":        discovery,
		"GET /public/{aid}/did.json": discovery,
		"GET /{aid}/kel":             discovery,
		"GET /{aid}/keri.cesr":       discovery,
		"GET /api/kerl":              discovery,
		"GET /api/didcomm/did":       discovery,
		"GET /api/identity/proof":    discovery,
		"GET /api/attestation":       discovery,
		"GET /api/local-owner/proof": discovery,

		"GET /i/{token}":                                signIn,
		"POST /api/login/challenge":                     signIn,
		"POST /api/login/callback":                      signIn,
		"GET /api/login/challenge/{token}/status":       signIn,
		"POST /api/login/session/{asset_id}":            signIn,
		"GET /api/login/session/{asset_id}/{token}":     signIn,
		"OPTIONS /api/login/session/{asset_id}":         signIn,
		"OPTIONS /api/login/session/{asset_id}/{token}": signIn,

		"GET /api/witness/endpoint/{controller_aid}":            witness,
		"POST /api/witness/endpoint":                            witness,
		"GET /api/witness/kel/{signer_aid}":                     witness,
		"GET /api/witness/kel/{signer_aid}/event/{sn}":          witness,
		"GET /api/witness/kel/{signer_aid}/tip":                 witness,
		"GET /api/witness/tel/{issuer_aid}":                     witness,
		"GET /api/witness/tel/{issuer_aid}/head":                witness,
		"POST /api/witness/tel/{issuer_aid}":                    witness,
		"POST /api/witness/accept":                              witness,
		"POST /api/witness/event":                               witness,
		"POST /api/witness/request":                             witness,
		"POST /api/witness/withdraw":                            witness,
		"POST /api/witness/withdraw/confirm":                    witness,
		"GET /api/pairing/this-computer":                        pairing,
		"POST /api/pairing/begin":                               pairing,
		"POST /api/pairing/complete":                            pairing,
		"POST /api/pairing/offer-this-computer":                 pairing,
		"GET /api/provisioning/pairing":                         pairing,
		"POST /api/provisioning/expect":                         pairing,
		"GET /api/backup/receive/{identityAID}":                 backup,
		"GET /api/backup/receive/{identityAID}/download/{name}": backup,
		"POST /api/backup/receive":                              backup,
		"POST /api/recovery/share-requests":                     backup,
		"POST /public/login/key":                                computation,
		"OPTIONS /public/login/key":                             computation,
		"POST /public/key-state":                                computation,
		"POST /_register":                                       computation,
		"POST /public/_register":                                computation,
		"POST /api/sealed":                                      carried,
		"POST /didcomm":                                         carried,
		"GET /api/health":                                       notIdentity,
		"GET /public/credential/{said}":                         publication,
		"GET /public/schemas/{said}":                            publication,
		"GET /debug/watcher/coverage":                           watcherOther,
	}

	walked := map[string]bool{}
	if err := chi.Walk(s.buildRouter(), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := method + " " + route
		if classify(method, route) != accessPublic && strings.HasPrefix(route, "/api/") {
			return nil // owner-only, or a paired controller's: not answered to a stranger
		}
		walked[key] = true
		_, answers := routesThatAnswerFromTheWatcher[key]
		if _, says := saysNothingTheWatcherSaw[key]; !answers && !says {
			t.Errorf("%s can be reached by somebody other than the owner and this test does not say whether it answers from the watcher: "+
				"add it to routesThatAnswerFromTheWatcher with a request, or to saysNothingTheWatcherSaw with why", key)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for key := range routesThatAnswerFromTheWatcher {
		if !walked[key] {
			t.Errorf("%s is listed as answering from the watcher but the router does not serve it to a caller", key)
		}
	}
	for key := range saysNothingTheWatcherSaw {
		if !walked[key] {
			t.Errorf("%s is listed but the router does not serve it to a caller: drop it", key)
		}
	}
}

// An opted-out identity must look exactly like one never seen. On every route
// that answers from the watcher, the answer about an identity it has seen must
// first differ from the answer about one never seen (so the route is really
// disclosing something to hide), and once that identity opts out the two must
// be byte for byte the same with the identifier set aside, status code
// included. A status, an error body or a field that exists only for the
// opted-out one fails here.
func TestAnOptedOutIdentityIsAnsweredExactlyAsOneNeverSeen(t *testing.T) {
	t.Setenv("WATCHER_DEBUG", "true")
	const seen, neverSeen = "ESeenAID", "ENeverSeenAID"
	digest := serveLog(seen)
	s := watcherAgent(t, seen, 1, digest)
	asAPublicWatcherWithAContact(t, s)
	s.WatcherService.SignDigest = func(stmt string) (string, string, error) {
		return "Ewatcher", "signature-over-" + stmt, nil
	}
	router := s.buildRouter()
	answer := func(ask func(aid, digest string) *http.Request, aid string) (int, string) {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, ask(aid, digest))
		return rec.Code, strings.ReplaceAll(rec.Body.String(), aid, "<AID>")
	}

	for route, ask := range routesThatAnswerFromTheWatcher {
		c1, b1 := answer(ask, seen)
		c2, b2 := answer(ask, neverSeen)
		if c1 != http.StatusOK || c2 != http.StatusOK || b1 == b2 {
			t.Fatalf("%s: before opting out the identity it has seen should be answered differently from one never seen, "+
				"or this test proves nothing:\n seen: %d %s\n never seen: %d %s", route, c1, b1, c2, b2)
		}
	}
	if err := s.WatcherService.Store.SetOptOut(seen, true); err != nil {
		t.Fatal(err)
	}
	for route, ask := range routesThatAnswerFromTheWatcher {
		c1, b1 := answer(ask, seen)
		c2, b2 := answer(ask, neverSeen)
		if c1 != c2 || b1 != b2 {
			t.Errorf("%s tells an opted-out identity from one never seen:\n opted out: %d %s\n never seen: %d %s", route, c1, b1, c2, b2)
		}
	}
	if _, b := answer(routesThatAnswerFromTheWatcher["GET /public/kel-digest"], seen); !strings.Contains(b, `"signature":"signature-over-`) {
		t.Errorf("the empty answer for an opted-out identity must be signed, as the one for a never-seen identity is: %s", b)
	}
}
