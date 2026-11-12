package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
)

// A person says a conversation is done, takes that back, or raises its turn
// limit through an app with their own signed statement of it (ADR-077). The core
// admits the statement on the conversation's route only for the one kind that
// route is for, to nobody, over that conversation, and for the words it carries.
func TestAPersonsCloseThroughAnAppIsAdmittedOnlyAsWhatTheRouteIs(t *testing.T) {
	w := newAnAppWorld(t)
	key := newBrowsersKey(t)
	w.signedIn(t, "Eann", key, time.Hour)

	send := func(route, kind, conv, words string, mutate func(*agentmessage.PersonStatement)) *httptest.ResponseRecorder {
		t.Helper()
		w.calls++
		nonce := fmt.Sprintf("ctl-%d", w.calls)
		body, _ := json.Marshal(agentmessage.PersonMessage{Conversation: conv, Body: words, Nonce: nonce})
		r := w.signedAsTheApp(t, http.MethodPost, "/api/mcp/conversations/"+conv+"/"+route, string(body))
		salt, _ := agentmessage.NewSalt()
		fp, _ := agentmessage.Fingerprint(salt, []byte(words))
		id, vk, _ := agentbody.Identity(key)
		st := agentmessage.PersonStatement{
			Agent: w.cw.s.thisIdentityAgentsIdentifier(), Conversation: conv, MessageID: nonce, Kind: kind, From: "Eann", Signer: id,
			Nonce: "nonce-0123456789abcdef" + nonce, Time: time.Now().UTC().Format(time.RFC3339),
			FingerprintVersion: agentmessage.FingerprintV1, Fingerprint: fp,
		}
		if mutate != nil {
			mutate(&st)
		}
		sig, err := agentbody.Sign(key, st.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		js, _ := json.Marshal(agentmessage.PersonProof{Statement: st, Verkey: vk, Signature: sig})
		r.Header.Set(headerSpeakingFor, "Eann")
		r.Header.Set(headerPersonStatement, base64.RawURLEncoding.EncodeToString(js))
		r.Header.Set(headerPersonSalt, base64.RawURLEncoding.EncodeToString(salt))
		rec := httptest.NewRecorder()
		w.h.ServeHTTP(rec, r)
		return rec
	}
	served := func() int { return *w.served }

	before := served()
	for route, kind := range map[string]string{
		agentmessage.PersonKindClose:  agentmessage.PersonKindClose,
		agentmessage.PersonKindReopen: agentmessage.PersonKindReopen,
	} {
		if rec := send(route, kind, "c1", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("a %s was refused: %d %s", route, rec.Code, rec.Body)
		}
	}
	if rec := send("limit", agentmessage.PersonKindLimit, "c1", "80", nil); rec.Code != http.StatusOK {
		t.Fatalf("a limit was refused: %d %s", rec.Code, rec.Body)
	}
	if served()-before != 3 {
		t.Fatalf("served %d of the three", served()-before)
	}

	before = served()
	for name, c := range map[string]struct {
		route, kind, words string
		mutate             func(*agentmessage.PersonStatement)
		want               string
	}{
		"a close signed as a message":           {"close", agentmessage.PersonKindMessage, "", func(s *agentmessage.PersonStatement) { s.To = "Eagent1" }, "is not what this route takes"},
		"a close signed as a reopen":            {"close", agentmessage.PersonKindReopen, "", nil, "is not what this route takes"},
		"a close naming a recipient":            {"close", agentmessage.PersonKindClose, "", func(s *agentmessage.PersonStatement) { s.To = "Eagent1" }, "to nobody"},
		"a close for another conversation":      {"close", agentmessage.PersonKindClose, "", func(s *agentmessage.PersonStatement) { s.Conversation = "c2" }, "another conversation"},
		"a close carrying words":                {"close", agentmessage.PersonKindClose, "bye", nil, "carries no words"},
		"a limit carrying no words":             {"limit", agentmessage.PersonKindLimit, "", nil, "the new limit"},
		"a close for another message than sent": {"close", agentmessage.PersonKindClose, "", func(s *agentmessage.PersonStatement) { s.MessageID = "other" }, "another message"},
	} {
		rec := send(c.route, c.kind, "c1", c.words, c.mutate)
		if rec.Code == http.StatusOK {
			t.Errorf("%s was admitted: %s", name, rec.Body)
		} else if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s was refused for another reason than %q: %s", name, c.want, rec.Body)
		}
	}
	if served() != before {
		t.Fatalf("a refused statement reached the add-on %d times", served()-before)
	}
}
