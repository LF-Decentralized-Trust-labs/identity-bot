package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/login"
)

// A person lists their own conversations across utility apps with a statement
// they sign (ADR-072 Amendment 7). The core lists for the person the statement
// names, only to a utility app the owner gave the capability, only once, only
// for this request, and only the metadata the Identity Agent holds.

// aListingAddon holds Ann's conversations in two utility apps and Bob's in one,
// and records every party it was asked for.
func aListingAddon(asked *[]string) Addon {
	return Addon{ID: "lists", Name: "lists", ConversationsOfAPerson: func(_ *CoreServer, party string) ([]ConversationOfAPerson, error) {
		*asked = append(*asked, party)
		switch party {
		case agentmessage.Person("Eann"):
			return []ConversationOfAPerson{
				{Conversation: "c_b", App: "app-b", Head: "Eh2", Count: 2},
				{Conversation: "c_a", App: theAppsAsset, Head: "Eh5", Count: 5, OpenAsk: true},
			}, nil
		case agentmessage.Person("Eann-b"):
			return []ConversationOfAPerson{{Conversation: "c_t", App: "app-b", Head: "Eh3", Count: 3}}, nil
		case agentmessage.Person("Ebob"):
			return []ConversationOfAPerson{{Conversation: "c_bob", App: theAppsAsset, Head: "Eh1", Count: 1}}, nil
		}
		return []ConversationOfAPerson{}, nil
	}}
}

type aListRequest struct {
	who, key   string // key: "ann" or "bob" or "other"
	audience   string // the utility app the list is for; the presenting one when empty
	mutate     func(*agentmessage.PersonStatement)
	query      func(nonce string) string
	salt       []byte
	words      string
	noState    bool
	path       string
	nonceOfReq string
}

func (w *anAppWorld) list(t *testing.T, keys map[string]aBrowsersKey, q aListRequest) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, w.aListRequest(t, keys, q))
	return rec
}

// aListRequest is what the utility app's back end would send, not yet sent.
func (w *anAppWorld) aListRequest(t *testing.T, keys map[string]aBrowsersKey, q aListRequest) *http.Request {
	t.Helper()
	nonce := fmt.Sprintf("list-%d", w.calls+1)
	if q.nonceOfReq != "" {
		nonce = q.nonceOfReq
	}
	target := "/api/people/me/conversations?nonce=" + url.QueryEscape(nonce)
	if q.query != nil {
		target = "/api/people/me/conversations" + q.query(nonce)
	}
	if q.path != "" {
		target = q.path
	}
	r := w.signedAsTheApp(t, http.MethodGet, target, "")
	key := keys[q.key]
	salt := q.salt
	if salt == nil {
		salt, _ = agentmessage.NewSalt()
	}
	fp, _ := agentmessage.Fingerprint(salt, []byte(q.words))
	id, vk, _ := agentbody.Identity(key)
	audience := theAppsAsset
	if q.audience != "" {
		audience = q.audience
	}
	st := agentmessage.PersonStatement{
		Agent: w.cw.s.thisIdentityAgentsIdentifier(), Conversation: agentmessage.ListConversation, MessageID: nonce,
		Kind: agentmessage.PersonKindList, From: q.who, Signer: id, Audience: audience,
		Nonce: "nonce-0123456789abcdef" + nonce, Time: time.Now().UTC().Format(time.RFC3339),
		FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp,
	}
	if q.mutate != nil {
		q.mutate(&st)
	}
	sig, err := agentbody.Sign(key, st.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(agentmessage.PersonProof{Statement: st, Verkey: vk, Signature: sig})
	r.Header.Set(headerSpeakingFor, q.who)
	if !q.noState {
		r.Header.Set(headerPersonStatement, base64.RawURLEncoding.EncodeToString(js))
	}
	r.Header.Set(headerPersonSalt, base64.RawURLEncoding.EncodeToString(salt))
	return r
}

func aListWorld(t *testing.T, asked *[]string) (*anAppWorld, map[string]aBrowsersKey) {
	t.Helper()
	onlyAddons(t, aListingAddon(asked))
	w := newAnAppWorld(t)
	_ = w.cw.s.DataStore.DeleteCredential("Egrant")
	w.enrolApp(t, w.cw.s, []string{CapabilityConversationListRead})
	keys := map[string]aBrowsersKey{"ann": newBrowsersKey(t), "bob": newBrowsersKey(t), "other": newBrowsersKey(t), "unknown": newBrowsersKey(t), "ann-b": newBrowsersKey(t)}
	// A second utility app, where Ann is known by another
	// identifier (ADR-066): her key there speaks at that asset only.
	st := w.cw.s.assetHandler.Store
	if err := st.UpsertAsset(asset.Asset{ID: "app-b", DisplayName: "app-b", AssetType: "app", Origin: "https://b.example", PairwiseAID: "Eappb"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMember(asset.AssetMember{AssetID: "app-b", PairwiseAID: "Eann-b", JoinedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := w.cw.s.browserKeys().Record("app-b", "Eann-b", thumbOf(t, keys["ann-b"]), time.Now().Add(time.Hour), time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	w.signedIn(t, "Eann", keys["ann"], time.Hour)
	w.signedIn(t, "Ebob", keys["bob"], time.Hour)
	return w, keys
}

func TestAPersonIsListedTheirOwnConversationsAndNobodyElses(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"})
	if rec.Code != http.StatusOK {
		t.Fatalf("a person's list was refused: %d %s", rec.Code, rec.Body)
	}
	var got ThePeopleConversationsReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []ConversationOfAPerson{
		{Conversation: "c_a", App: theAppsAsset, Head: "Eh5", Count: 5, OpenAsk: true},
		{Conversation: "c_b", App: "app-b", Head: "Eh2", Count: 2},
	}
	if fmt.Sprint(got.Conversations) != fmt.Sprint(want) {
		t.Fatalf("listed %+v, want %+v", got.Conversations, want)
	}
	if strings.Contains(rec.Body.String(), "Ebob") || strings.Contains(rec.Body.String(), "c_bob") {
		t.Fatal("Ann was told of Bob's conversation")
	}
	if len(asked) != 1 || asked[0] != agentmessage.Person("Eann") {
		t.Fatalf("the add-on was asked for %v, want only Ann", asked)
	}
	// Bob, with his own key and statement, is listed his; the grant is the app's.
	rec = w.list(t, keys, aListRequest{who: "Ebob", key: "bob"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "c_bob") || strings.Contains(rec.Body.String(), "c_a") {
		t.Fatalf("Bob was answered %d %s", rec.Code, rec.Body)
	}
	// A person with none is told an empty list, not null.
	onlyAddons(t, Addon{ID: "none", Name: "none", ConversationsOfAPerson: func(*CoreServer, string) ([]ConversationOfAPerson, error) { return nil, nil }})
	if rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"conversations":[]`) {
		t.Fatalf("an empty list was answered %d %s", rec.Code, rec.Body)
	}
}

// Every way a request can be bent is refused, and none of them reaches an
// add-on, which would be asked for somebody's conversations.
func TestAListIsRefusedWhenAnythingAboutItIsNotThePersons(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	// A key another utility app's sign-in recorded: the key speaks at that asset only.
	if err := w.cw.s.browserKeys().Record("other-app", "Eann", thumbOf(t, keys["other"]), time.Now().Add(time.Hour), time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	// The app puts something in the body of a GET: a list carries no words.
	withBody := w.aListRequest(t, keys, aListRequest{who: "Eann", key: "ann"})
	withBody = w.copyWithBody(t, withBody, "all of them")
	if rec := serve(w, withBody); rec.Code == http.StatusOK || len(asked) != 0 {
		t.Errorf("a list with a body was admitted: %d %s", rec.Code, rec.Body)
	}
	staleTime := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for name, c := range map[string]struct {
		q    aListRequest
		want string
	}{
		"the app vouches, sending no statement":           {aListRequest{who: "Eann", key: "ann", noState: true}, "all needed"},
		"a statement from somebody else than named":       {aListRequest{who: "Ebob", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.From = "Eann" }}, "somebody else"},
		"Ann's key signing as Bob":                        {aListRequest{who: "Ebob", key: "ann"}, "does not speak for"},
		"a key that speaks at another utility app only":   {aListRequest{who: "Eann", key: "other"}, "does not speak for"},
		"a key nobody signed in with":                     {aListRequest{who: "Eann", key: "unknown"}, "does not speak for"},
		"a message signed for the list route":             {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindMessage, "Eagent1" }}, "kind"},
		"a close signed for the list route":               {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindClose }}, "kind"},
		"a list for a conversation":                       {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.Conversation = "c_a" }}, "conversation"},
		"a list naming a recipient":                       {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.To = "Eagent1" }}, "to nobody"},
		"a list for another request than this one":        {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.MessageID = "another" }}, "another request"},
		"a list for another Identity Agent":               {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.Agent = "Eelsewhere" }}, "another Identity Agent"},
		"a stale list":                                    {aListRequest{who: "Eann", key: "ann", mutate: func(s *agentmessage.PersonStatement) { s.Time = staleTime }}, "5 minutes"},
		"a list over words, so not the empty fingerprint": {aListRequest{who: "Eann", key: "ann", words: "all of them"}, "other words"},
		"a list with no nonce in the request":             {aListRequest{who: "Eann", key: "ann", query: func(string) string { return "" }}, "nonce"},
		"a list with another thing in the query":          {aListRequest{who: "Eann", key: "ann", query: func(n string) string { return "?nonce=" + n + "&person=Ebob" }}, "nonce"},
		"a list naming the nonce twice":                   {aListRequest{who: "Eann", key: "ann", query: func(n string) string { return "?nonce=" + n + "&nonce=x" }}, "nonce"},
	} {
		before := len(asked)
		rec := w.list(t, keys, c.q)
		switch {
		case rec.Code == http.StatusOK:
			t.Errorf("%s was admitted: %s", name, rec.Body)
		case !strings.Contains(rec.Body.String(), c.want):
			t.Errorf("%s was refused for another reason than %q: %d %s", name, c.want, rec.Code, rec.Body)
		}
		if len(asked) != before {
			t.Errorf("%s reached the add-on", name)
		}
	}
}

// The person's own Identity Agent signs one list per utility app, each under
// the key of that app's sign-in, each for the one that presents it: the core
// answers each for that one party, tagged with the asset it is for, and never
// merges two (ADR-072 Amendment 8).
func TestAListSignedUnderAnotherAppsKeyListsThatPartyAndOnlyThatOne(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	rec := w.list(t, keys, aListRequest{who: "Eann-b", key: "ann-b"})
	if rec.Code != http.StatusOK {
		t.Fatalf("a list under the second utility app's key was refused: %d %s", rec.Code, rec.Body)
	}
	var got ThePeopleConversationsReply
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ListedAt != "app-b" || len(got.Conversations) != 1 || got.Conversations[0].Conversation != "c_t" {
		t.Fatalf("answered %+v, want only the second utility app's c_t, listed at app-b", got)
	}
	if strings.Contains(rec.Body.String(), "c_a") || strings.Contains(rec.Body.String(), "Eann") {
		t.Fatal("the answer for one party carried another's")
	}
	if len(asked) != 1 || asked[0] != agentmessage.Person("Eann-b") {
		t.Fatalf("the add-on was asked for %v, want only the party at app-b", asked)
	}
	// Ann's answer at the presenting app says it is for that one.
	rec = w.list(t, keys, aListRequest{who: "Eann", key: "ann"})
	var own ThePeopleConversationsReply
	_ = json.Unmarshal(rec.Body.Bytes(), &own)
	if own.ListedAt != theAppsAsset {
		t.Fatalf("listed at %q, want %q", own.ListedAt, theAppsAsset)
	}
}

// What stops the cross-app list reaching further than the person meant: the
// audience is signed and is the presenter, the key and the person name one
// record, and the asset must still stand.
func TestACrossAppListIsRefusedWhenItIsForAnotherAudienceOrAnotherPerson(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	for name, c := range map[string]struct {
		q    aListRequest
		want string
	}{
		"a list signed for the second utility app, presented by the first": {aListRequest{who: "Eann-b", key: "ann-b", audience: "app-b"}, "another utility app"},
		"a list for a made-up audience":                                    {aListRequest{who: "Eann-b", key: "ann-b", audience: "nobody"}, "another utility app"},
		"a list with its audience taken out":                               {aListRequest{who: "Eann-b", key: "ann-b", mutate: func(s *agentmessage.PersonStatement) { s.Audience = "" }}, "another utility app"},
		"a message that names an audience":                                 {aListRequest{who: "Eann-b", key: "ann-b", mutate: func(s *agentmessage.PersonStatement) { s.Kind, s.To = agentmessage.PersonKindMessage, "Eagent1" }}, "kind"},
		"the second utility app's key claiming Ann's first identifier":     {aListRequest{who: "Eann", key: "ann-b"}, "does not speak for"},
		"Ann's first key claiming her second identifier":                   {aListRequest{who: "Eann-b", key: "ann"}, "does not speak for"},
		"Ann's second key claiming to be Bob":                              {aListRequest{who: "Ebob", key: "ann-b"}, "does not speak for"},
	} {
		before := len(asked)
		rec := w.list(t, keys, c.q)
		switch {
		case rec.Code == http.StatusOK:
			t.Errorf("%s was admitted: %s", name, rec.Body)
		case !strings.Contains(rec.Body.String(), c.want):
			t.Errorf("%s was refused for another reason than %q: %d %s", name, c.want, rec.Code, rec.Body)
		}
		if len(asked) != before {
			t.Errorf("%s reached the add-on", name)
		}
	}
	// The audience is in the signed bytes: one list presented with another
	// audience written over it fails the signature, not only the audience check.
	r := w.aListRequest(t, keys, aListRequest{who: "Eann-b", key: "ann-b", audience: "app-b"})
	raw, _ := base64.RawURLEncoding.DecodeString(r.Header.Get(headerPersonStatement))
	var proof agentmessage.PersonProof
	_ = json.Unmarshal(raw, &proof)
	proof.Statement.Audience = theAppsAsset
	js, _ := json.Marshal(proof)
	r.Header.Set(headerPersonStatement, base64.RawURLEncoding.EncodeToString(js))
	if rec := serve(w, r); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "does not hold") {
		t.Errorf("a list with its audience rewritten after signing was answered %d %s", rec.Code, rec.Body)
	}
	// A key that lapsed, or an asset that stopped standing behind the person, speaks no more.
	if err := w.cw.s.assetHandler.Store.RemoveMember("app-b", "Eann-b"); err != nil {
		t.Fatal(err)
	}
	if rec := w.list(t, keys, aListRequest{who: "Eann-b", key: "ann-b"}); rec.Code == http.StatusOK {
		t.Errorf("a person the second utility app no longer admits was listed: %s", rec.Body)
	}
	if len(asked) != 0 {
		t.Errorf("the add-on was asked %d times for refused lists", len(asked))
	}
}

// A key said to speak for one person at two assets cannot be told apart, so it
// speaks for none: the core does not choose which party was meant.
func TestAListUnderAKeyThatSpeaksForOnePersonAtTwoAssetsIsRefused(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	// Both assets admit her, so only the ambiguity can refuse it.
	if err := w.cw.s.assetHandler.Store.AddMember(asset.AssetMember{AssetID: "app-b", PairwiseAID: "Eann", JoinedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := w.cw.s.browserKeys().Record("app-b", "Eann", thumbOf(t, keys["ann"]), time.Now().Add(time.Hour), time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"}); rec.Code == http.StatusOK || len(asked) != 0 {
		t.Fatalf("an ambiguous key was answered %d %s", rec.Code, rec.Body)
	}
}

// Nothing to ask is not an empty list (review of 2026-11-13, finding 2).
func TestAListWithNoAddOnThatKeepsConversationsIsRefusedNotEmpty(t *testing.T) {
	w, keys := aListWorld(t, new([]string))
	onlyAddons(t, Addon{ID: "plain", Name: "plain"})
	rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"})
	if rec.Code != http.StatusNotImplemented || strings.Contains(rec.Body.String(), `"conversations"`) {
		t.Fatalf("with no add-on to ask the answer was %d %s", rec.Code, rec.Body)
	}
}

func thumbOf(t *testing.T, k aBrowsersKey) string {
	t.Helper()
	_, vk, err := agentbody.Identity(k)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := login.BrowserKeyThumbprintOfMachineKey(vk)
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// A statement is spent once: the request sent again byte for byte, or the same
// statement on a request the app signs afresh, is refused.
func TestAListStatementIsSpentOnce(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	r := w.aListRequest(t, keys, aListRequest{who: "Eann", key: "ann"})
	if rec := serve(w, w.copyOf(r)); rec.Code != http.StatusOK {
		t.Fatalf("the first was refused: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(w, w.copyOf(r)); rec.Code == http.StatusOK {
		t.Fatalf("the same request was admitted twice: %s", rec.Body)
	}
	fresh := w.signedAsTheApp(t, http.MethodGet, r.URL.RequestURI(), "")
	for _, h := range []string{headerSpeakingFor, headerPersonStatement, headerPersonSalt} {
		fresh.Header.Set(h, r.Header.Get(h))
	}
	if rec := serve(w, fresh); rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "already used") {
		t.Fatalf("a spent statement on a new request was admitted: %d %s", rec.Code, rec.Body)
	}
	if len(asked) != 1 {
		t.Fatalf("the add-on was asked %d times, want once", len(asked))
	}
}

func serve(w *anAppWorld, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

// The grant is the owner's choice: an app without the capability, or one whose
// grant limits an argument this route cannot give, is refused by the gate.
func TestOnlyAnAppTheOwnerMadeTheCentralPlaceMayList(t *testing.T) {
	var asked []string
	onlyAddons(t, aListingAddon(&asked))
	w := newAnAppWorld(t) // holds agent.message.send and agent.message.read only
	keys := map[string]aBrowsersKey{"ann": newBrowsersKey(t)}
	w.signedIn(t, "Eann", keys["ann"], time.Hour)
	rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CapabilityConversationListRead) || len(asked) != 0 {
		t.Fatalf("an app without the capability was answered %d %s", rec.Code, rec.Body)
	}
	// A grant that limits the AI agents it may message is not read as no limit on this route.
	_ = w.cw.s.DataStore.DeleteCredential("Egrant")
	w.enrolAppLimited(t, w.cw.s, []string{CapabilityConversationListRead}, map[string]map[string][]string{CapabilityConversationListRead: {"to": {"Eagent1"}}})
	if rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"}); rec.Code == http.StatusOK || len(asked) != 0 {
		t.Fatalf("a grant with a limit this route cannot check was served: %d %s", rec.Code, rec.Body)
	}
}

// The owner's own keys are not a person listing through a utility app, a
// controller is read as its signer, and the statement is for this route only.
func TestOnlyAUtilityAppsBackEndIsAnsweredAndTheStatementIsForThisRouteOnly(t *testing.T) {
	var asked []string
	w, keys := aListWorld(t, &asked)
	r := httptest.NewRequest(http.MethodGet, "/api/people/me/conversations?nonce=x", nil)
	r.RemoteAddr = "127.0.0.1:51000"
	r.Header.Set(LocalOwnerSecretHeader, testOwnerSecret)
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	if rec.Code == http.StatusOK || len(asked) != 0 {
		t.Fatalf("the owner was answered a person's list: %d %s", rec.Code, rec.Body)
	}
	// A paired controller reads as the signer it belongs to (ADR-050), as it does
	// on every route made for it, and is listed that signer's conversations and
	// nobody's else.
	cr := asThatMachineTo(t, w.target, w.cw.ctlAID, http.MethodGet, "/api/people/me/conversations", "", w.cw.ctlSeed, authprovider.Level(""), time.Now())
	cr.RemoteAddr = "203.0.113.9:51000"
	if crec := serve(w, cr); crec.Code != http.StatusOK || len(asked) != 1 || asked[0] != agentmessage.Person(talkSigner) {
		t.Fatalf("a controller was answered %d %s, and the add-on was asked for %v", crec.Code, crec.Body, asked)
	}
	asked = asked[:0]
	if got := classify(http.MethodGet, "/api/people/me/conversations"); got != accessOwner {
		t.Fatalf("the route is classed %v, so a caller holding scopes may reach it", got)
	}
	// A list statement carried on the route that carries a person's words, or on
	// a close, is not admitted there, and nothing reaches the add-on's trail.
	list := w.aListRequest(t, keys, aListRequest{who: "Eann", key: "ann", nonceOfReq: "list-9"})
	for _, path := range []string{talkPath, "/api/mcp/conversations/c_a/close"} {
		r := w.signedAsTheApp(t, http.MethodPost, path, `{"to":"Eagent1","body":"","nonce":"list-9"}`)
		for _, h := range []string{headerSpeakingFor, headerPersonStatement, headerPersonSalt} {
			r.Header.Set(h, list.Header.Get(h))
		}
		if rec := serve(w, r); rec.Code == http.StatusOK {
			t.Errorf("a list was admitted on %s: %s", path, rec.Body)
		}
	}
	if *w.served != 0 {
		t.Fatalf("a list statement reached a route that is not the list's %d times", *w.served)
	}
	if len(asked) != 0 {
		t.Fatalf("the add-on was asked %d times", len(asked))
	}
}

// An add-on that fails, holds a conversation twice, or reports what does not fit
// is an error and never a shorter list; the error says none of why.
func TestABrokenAddOnIsAnErrorAndNeverAShorterList(t *testing.T) {
	w, keys := aListWorld(t, new([]string))
	for name, fn := range map[string]func(*CoreServer, string) ([]ConversationOfAPerson, error){
		"fails": func(*CoreServer, string) ([]ConversationOfAPerson, error) {
			return nil, errors.New("the store at /secret is down")
		},
		"a head and no count": func(*CoreServer, string) ([]ConversationOfAPerson, error) {
			return []ConversationOfAPerson{{Conversation: "c_a", Head: "Eh"}}, nil
		},
		"a negative count": func(*CoreServer, string) ([]ConversationOfAPerson, error) {
			return []ConversationOfAPerson{{Conversation: "c_a", Head: "Eh", Count: -1}}, nil
		},
		"a count and no head": func(*CoreServer, string) ([]ConversationOfAPerson, error) {
			return []ConversationOfAPerson{{Conversation: "c_a", Count: 2}}, nil
		},
		"a conversation named list": func(*CoreServer, string) ([]ConversationOfAPerson, error) {
			return []ConversationOfAPerson{{Conversation: agentmessage.ListConversation}}, nil
		},
		"a conversation twice": func(*CoreServer, string) ([]ConversationOfAPerson, error) {
			return []ConversationOfAPerson{{Conversation: "c_a"}, {Conversation: "c_a"}}, nil
		},
	} {
		onlyAddons(t, Addon{ID: "x", Name: "x", ConversationsOfAPerson: fn})
		rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"})
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "c_a") {
			t.Errorf("%s: answered %d %s", name, rec.Code, rec.Body)
		}
	}
	// One add-on failing fails the answer even when another listed some.
	good := aListingAddon(new([]string))
	onlyAddons(t, good, Addon{ID: "bad", Name: "bad", ConversationsOfAPerson: func(*CoreServer, string) ([]ConversationOfAPerson, error) { return nil, errors.New("down") }})
	if rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"}); rec.Code != http.StatusInternalServerError {
		t.Errorf("a list left short by a failing add-on was answered %d %s", rec.Code, rec.Body)
	}
	// And two add-ons that each hold a conversation of one id is an error.
	same := func(*CoreServer, string) ([]ConversationOfAPerson, error) {
		return []ConversationOfAPerson{{Conversation: "c_a"}}, nil
	}
	onlyAddons(t, Addon{ID: "a", Name: "a", ConversationsOfAPerson: same}, Addon{ID: "b", Name: "b", ConversationsOfAPerson: same})
	if rec := w.list(t, keys, aListRequest{who: "Eann", key: "ann"}); rec.Code != http.StatusInternalServerError {
		t.Errorf("a conversation held by two add-ons was answered %d %s", rec.Code, rec.Body)
	}
}

// copyWithBody is the request with a body the app signed too, as a request that
// carries words would be.
func (w *anAppWorld) copyWithBody(t *testing.T, r *http.Request, body string) *http.Request {
	t.Helper()
	b := w.signedAsTheApp(t, r.Method, r.URL.RequestURI(), body)
	for _, h := range []string{headerSpeakingFor, headerPersonStatement, headerPersonSalt} {
		b.Header.Set(h, r.Header.Get(h))
	}
	return b
}
