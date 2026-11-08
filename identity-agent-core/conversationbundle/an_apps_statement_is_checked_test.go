package conversationbundle

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentmessage"
	"identity-agent-core/schemas"
)

// An entry a person sent through an app's back end carries the person's own
// statement. checkPersonSpoke holds that statement to the organisation and the
// time, and reads which app's back end carried it from the machine's Controller
// Grant, 1.2.0 of which names the app (app_asset); a 1.1.0 grant names none, and
// the bundle then says so rather than guess.
func TestAnAppsStatementIsCheckedAndTheAppIsNamedByItsGrant(t *testing.T) {
	const (
		person  = "EALICE"
		machine = "EMACHINE"
		app     = "app-asset-1"
		grantID = "EGRANT"
	)
	at := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	stamp := at.Format(time.RFC3339)

	grant := func(schema string, attrs map[string]string) map[string]*credential {
		c := &credential{said: grantID, schema: schema, holder: machine, issued: at.Add(-time.Hour), attrs: map[string]json.RawMessage{}}
		c.attrs["public_key"], _ = json.Marshal("KEY")
		for k, v := range attrs {
			c.attrs[k], _ = json.Marshal(v)
		}
		return map[string]*credential{grantID: c}
	}
	statement := func(edit func(*agentmessage.PersonStatement)) *agentmessage.PersonProof {
		s := agentmessage.PersonStatement{Agent: rootAID, Conversation: "c1", MessageID: "n1", Kind: "message", From: person, To: "EBOT", Time: stamp}
		if edit != nil {
			edit(&s)
		}
		return &agentmessage.PersonProof{Statement: s}
	}
	cases := []struct {
		name      string
		creds     map[string]*credential
		statement *agentmessage.PersonProof
		fault     string // "" = none
		app       string // the app the message is shown to be from
		appNote   bool   // the bundle says which app is the Identity Agent's word
	}{
		{"1.2.0 grant names the app", grant(schemas.ControllerGrant.Schema.SAID, map[string]string{"app_asset": app}), statement(nil), "", app, false},
		{"1.1.0 grant names none", grant(schemas.ControllerGrantV11.Schema.SAID, nil), statement(nil), "", "", true},
		{"1.2.0 grant of a machine bound to no app", grant(schemas.ControllerGrant.Schema.SAID, nil), statement(nil), "", "", true},
		{"statement for another Identity Agent", grant(schemas.ControllerGrant.Schema.SAID, map[string]string{"app_asset": app}),
			statement(func(s *agentmessage.PersonStatement) { s.Agent = "EOTHER" }), "not for this organisation", app, false},
		{"statement signed long before", grant(schemas.ControllerGrant.Schema.SAID, map[string]string{"app_asset": app}),
			statement(func(s *agentmessage.PersonStatement) { s.Time = at.Add(-time.Hour).Format(time.RFC3339) }), "was not signed within", app, false},
		{"an app's machine speaking with no statement", grant(schemas.ControllerGrant.Schema.SAID, map[string]string{"app_asset": app}),
			nil, "speaks only with a person's own statement", app, false},
		{"a grant naming both an app and a signer", grant(schemas.ControllerGrant.Schema.SAID, map[string]string{"app_asset": app, "signer": person}),
			statement(nil), "one or the other", app, false},
		{"a signer's machine carrying a statement", grant(schemas.ControllerGrant.Schema.SAID, map[string]string{"signer": person}),
			statement(nil), "names " + person + " as the person it acts as", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signed := strings.Join([]string{"IA-CONTROLLER-REQ-V3", machine, rootAID, "https://app.example", "POST", "/api/conversations",
				stamp, "", "", "", "DIGEST"}, "\n")
			rec := agentmessage.Record{
				Conversation: "c1", Seq: 1, From: agentmessage.Person(person), To: "EBOT",
				Person: &agentmessage.PersonRef{AID: person},
				ControllerProof: &agentmessage.ControllerProof{Controller: machine, PublicKey: "KEY", SignedString: signed,
					ControllerGrant: grantID, PersonStatement: c.statement},
			}
			v := &verifier{b: &Bundle{Root: rootAID}, r: &Report{}, creds: c.creds, notes: map[string]bool{}}
			var m Message
			v.checkPersonSpoke("entry 1", rec, at, &m)
			got := openingFaults(v)
			if c.fault == "" && len(v.r.Faults) != 0 || c.fault != "" && !strings.Contains(got, c.fault) {
				t.Fatalf("faults %q, want %q", got, c.fault)
			}
			if m.App != c.app {
				t.Fatalf("the message is shown from app %q, want %q", m.App, c.app)
			}
			if c.fault == "" {
				said := strings.Contains(strings.Join(v.r.CannotRuleOut, "\n"), "Which app's back end")
				if said != c.appNote {
					t.Fatalf("the report says which app is the Identity Agent's word: %v, want %v (%v)", said, c.appNote, v.r.CannotRuleOut)
				}
			}
		})
	}
}
