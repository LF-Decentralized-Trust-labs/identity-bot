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
// statement alone, never the request the back end signed as the app (ADR-072),
// which holds their words. checkAppSpoke holds the key to the App Body
// credential the bundle carries, and the statement to the organisation and the
// time; an entry that keeps the request is refused.
func TestAnAppsStatementIsCheckedAndTheAppIsNamedByItsBody(t *testing.T) {
	const (
		person = "EALICE"
		host   = "BHOST"
		app    = "EAPP"
		bodyID = "EBODY"
	)
	at := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	stamp := at.Format(time.RFC3339)

	body := func(schema string, attrs map[string]string) map[string]*credential {
		c := &credential{said: bodyID, schema: schema, holder: app, issued: at.Add(-time.Hour), attrs: map[string]json.RawMessage{}}
		for k, v := range attrs {
			c.attrs[k], _ = json.Marshal(v)
		}
		return map[string]*credential{bodyID: c}
	}
	named := map[string]string{"host": host, "verkey": "KEY"}
	statement := func(edit func(*agentmessage.PersonStatement)) *agentmessage.PersonProof {
		s := agentmessage.PersonStatement{Agent: rootAID, Conversation: "c1", MessageID: "n1", Kind: "message", From: person, To: "EBOT", Time: stamp}
		if edit != nil {
			edit(&s)
		}
		return &agentmessage.PersonProof{Statement: s}
	}
	// What an app's back end signed, which no entry keeps.
	good := strings.Join([]string{"IA-BODY-REQ-V3", rootAID, host, "POST", "/api/mcp/agents/EBOT/conversations", stamp, "NONCE", "DIGEST", "", "", ""}, "\n")
	cases := []struct {
		name      string
		creds     map[string]*credential
		signed    string
		statement *agentmessage.PersonProof
		fault     string // "" = none
		app       string // the app the message is shown to be from
	}{
		{"an app's signed request kept with the statement", body(schemas.AppBody.Schema.SAID, named), good, statement(nil), "carries the app's signed request", ""},
		{"an app's signed request kept without a statement", body(schemas.AppBody.Schema.SAID, named), good, nil, "carries the app's signed request", ""},
		{"an app speaking with no statement", body(schemas.AppBody.Schema.SAID, named), "", nil, "speaks only with a person's own statement", ""},
		// An entry for a person keeps their statement, not the request: nothing
		// of the app's signature is there to read, and the statement carries the time.
		{"statement alone, an App Body names the key", body(schemas.AppBody.Schema.SAID, named), "", statement(nil), "", app},
		{"statement alone, another key", body(schemas.AppBody.Schema.SAID, map[string]string{"host": host, "verkey": "OTHER"}), "", statement(nil), "a key the App Body does not name", ""},
		{"statement alone, no App Body in the bundle", map[string]*credential{}, "", statement(nil), "does not carry the App Body", ""},
		{"statement alone, for another Identity Agent", body(schemas.AppBody.Schema.SAID, named), "",
			statement(func(s *agentmessage.PersonStatement) { s.Agent = "EOTHER" }), "not for this organisation", app},
		{"statement alone, signed long before", body(schemas.AppBody.Schema.SAID, named), "",
			statement(func(s *agentmessage.PersonStatement) { s.Time = at.Add(-time.Hour).Format(time.RFC3339) }), "was not signed within", app},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := agentmessage.Record{
				Conversation: "c1", Seq: 1, From: agentmessage.Person(person), To: "EBOT",
				Person: &agentmessage.PersonRef{AID: person},
				ControllerProof: &agentmessage.ControllerProof{Controller: host, PublicKey: "KEY", SignedString: c.signed,
					AppBody: bodyID, PersonStatement: c.statement},
			}
			v := &verifier{b: &Bundle{Root: rootAID}, r: &Report{}, creds: c.creds, notes: map[string]bool{}}
			var m Message
			v.checkPersonSpoke("entry 1", rec, at, &m)
			got := openingFaults(v)
			if c.fault == "" && len(v.r.Faults) != 0 || c.fault != "" && !strings.Contains(got, c.fault) {
				t.Fatalf("faults %q, want %q", got, c.fault)
			}
			if m.AppAID != c.app {
				t.Fatalf("the message is shown from app %q, want %q", m.AppAID, c.app)
			}
		})
	}
}

// A Controller Grant that names an app is not honoured: an app's back end is
// not a controller.
func TestAControllerGrantNamingAnAppIsAFault(t *testing.T) {
	at := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	c := &credential{said: "EGRANT", schema: schemas.ControllerGrant.Schema.SAID, holder: "EMACHINE", issued: at.Add(-time.Hour), attrs: map[string]json.RawMessage{}}
	c.attrs["public_key"], _ = json.Marshal("KEY")
	c.attrs["app_asset"], _ = json.Marshal("app-1")
	signed := strings.Join([]string{"IA-CONTROLLER-REQ-V3", "EMACHINE", rootAID, "https://app.example", "POST", "/api/conversations", at.Format(time.RFC3339), "", "", "", "DIGEST"}, "\n")
	rec := agentmessage.Record{
		Conversation: "c1", Seq: 1, From: agentmessage.Person("EALICE"), To: "EBOT", Person: &agentmessage.PersonRef{AID: "EALICE"},
		ControllerProof: &agentmessage.ControllerProof{Controller: "EMACHINE", PublicKey: "KEY", SignedString: signed, ControllerGrant: "EGRANT"},
	}
	v := &verifier{b: &Bundle{Root: rootAID}, r: &Report{}, creds: map[string]*credential{"EGRANT": c}, notes: map[string]bool{}}
	var m Message
	v.checkPersonSpoke("entry 1", rec, at, &m)
	if got := openingFaults(v); !strings.Contains(got, "no longer a controller") {
		t.Fatalf("faults %q", got)
	}
}
