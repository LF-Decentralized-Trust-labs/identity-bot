package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/schemas"
	"identity-agent-core/store"
)

func fetchSchema(t *testing.T, s *CoreServer, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleFetchCredentialSchema(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return w
}

// A server asked for one schema must not be able to answer with another: a
// widened schema that accepts a forgery would be cached under the identifier
// the credential names.
func TestAFetchedSchemaIsCachedOnlyUnderTheIdentifierItDigestsTo(t *testing.T) {
	t.Setenv("IA_ALLOW_LOCAL_SITES", "1")
	s := agentWithDerivedIdentity(t)
	real := schemas.Guardianship
	other := schemas.ProofOfAge
	forged := strings.Replace(real.JSON, `"required":["d","dependent_name","guardian_type"]`, `"required":["d"]`, 1)
	if forged == real.JSON {
		t.Fatal("the forged document is the genuine one")
	}
	serve := map[string]string{"/real": real.JSON, "/other": other.JSON, "/forged": forged, "/junk": `{"$id":"EGuardianship__placeholder__v1"}`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(serve[r.URL.Path]))
	}))
	defer srv.Close()

	for _, c := range []struct{ name, path, said string }{
		{"a different schema than the one asked for", "/other", real.SAID},
		{"a widened schema under the identifier asked for", "/forged", real.SAID},
		{"a placeholder document", "/junk", "EGuardianship__placeholder__v1"},
		{"a placeholder document with no identifier asked for", "/junk", ""},
	} {
		body := `{"url":"` + srv.URL + c.path + `"`
		if c.said != "" {
			body += `,"said":"` + c.said + `"`
		}
		w := fetchSchema(t, s, body+`}`)
		if w.Code == http.StatusOK {
			t.Errorf("%s was accepted", c.name)
		}
		if c.said != "" {
			if cached, _ := s.DataStore.GetCredentialSchema(c.said); cached != nil {
				t.Errorf("%s was cached under %s", c.name, c.said)
			}
		}
	}

	w := fetchSchema(t, s, `{"url":"`+srv.URL+`/real","said":"`+real.SAID+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("the genuine schema was refused: %d %s", w.Code, w.Body)
	}
	if cached, _ := s.DataStore.GetCredentialSchema(real.SAID); cached == nil || cached.SchemaJson != real.JSON {
		t.Fatal("the genuine schema was not cached")
	}
	// By URL alone it is cached under the identifier it digests to.
	w = fetchSchema(t, s, `{"url":"`+srv.URL+`/other"}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), other.SAID) {
		t.Fatalf("a genuine schema fetched by URL: %d %s", w.Code, w.Body)
	}
}

// A document cached before fetched schemas were checked is not served for an
// identifier it does not digest to.
func TestACachedSchemaThatDoesNotDigestToItsIdentifierIsNotServed(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	bad := schemas.ProofOfAge.JSON
	if err := s.DataStore.SaveCredentialSchema(store.CredentialSchemaRecord{SAID: schemas.Guardianship.SAID, SchemaJson: bad}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IA_ALLOW_LOCAL_SITES", "")
	w := fetchSchema(t, s, `{"said":"`+schemas.Guardianship.SAID+`","url":"http://127.0.0.1:1/x"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("served a cached document that is not the schema: %s", w.Body)
	}
}

func TestACredentialIsNotIssuedUnderAPlaceholderSchema(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	w := httptest.NewRecorder()
	s.handleIssueCredential(w, httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"claims":{"org_name":"x"},"schema_said":"EEmployeeAuth__placeholder__v1"}`)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), schemas.EmployeeAuthorization.SAID) {
		t.Fatalf("got %d %s; the refusal must name the identifier to issue under", w.Code, w.Body)
	}
}

// A gate set up before the identifiers were real names the placeholder, and a
// credential issued before names it too; one issued since names the real one.
// Neither side is refused for the other's form.
func TestAGateAcceptsBothFormsOfASchemaIdentifier(t *testing.T) {
	emp := schemas.EmployeeAuthorization.SAID
	old := "EEmployeeAuth__placeholder__v1"
	for _, c := range []struct {
		name, presented, required string
		want                      bool
	}{
		{"an old credential at an old gate", old, old, true},
		{"a new credential at an old gate", emp, old, true},
		{"an old credential at a new gate", old, emp, true},
		{"a new credential at a new gate", emp, emp, true},
		{"another schema's placeholder", "EGuardianship__placeholder__v1", emp, false},
		{"another schema's real identifier", schemas.Guardianship.SAID, old, false},
	} {
		got := presentsRequiredCredential([]interface{}{credACDC(c.presented, "A", "issued")}, c.required, "")
		if got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func issueWith(t *testing.T, s *CoreServer, claims, schemaSAID string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleIssueCredential(w, httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"claims":`+claims+`,"schema_said":"`+schemaSAID+`"}`)))
	return w
}

// Employee Authorization needs more than an organisation name, and declares no
// salary: a strict verifier would refuse either, so the core does not issue it.
func TestACredentialThatFailsItsSchemaIsNotIssued(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	emp := schemas.EmployeeAuthorization.SAID
	w := issueWith(t, s, `{"org_name":"x"}`, emp)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `\"org_aid\"`) {
		t.Fatalf("missing fields: %d %s", w.Code, w.Body)
	}
	w = issueWith(t, s, `{"org_name":"x","org_aid":"E1","employee_name":"n","role":"r","salary":"1"}`, emp)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `\"salary\"`) {
		t.Fatalf("undeclared field: %d %s", w.Code, w.Body)
	}
}

// The guardianship credential issued automatically is held to the schema too:
// a type the schema does not allow makes no guardianship and no credential.
func TestAGuardianshipOutsideTheSchemasValuesIsRefused(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	w := httptest.NewRecorder()
	s.handleCreateGuardianship(w, httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"type":"parent","dependent_name":"Kid"}`)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "guardian_type") {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if recs, _ := s.DataStore.GetGuardianships(); len(recs) != 0 {
		t.Fatalf("a guardianship was saved: %v", recs)
	}
}

// Entries cached before fetched schemas were checked are not listed.
func TestTheCachedSchemaListOmitsEntriesThatDoNotDigestToTheirKey(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	good := schemas.Guardianship
	s.DataStore.SaveCredentialSchema(store.CredentialSchemaRecord{SAID: good.SAID, SchemaJson: good.JSON})
	s.DataStore.SaveCredentialSchema(store.CredentialSchemaRecord{SAID: schemas.ProofOfAge.SAID, SchemaJson: good.JSON})
	w := httptest.NewRecorder()
	s.handleGetCredentialSchemas(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var out struct {
		Count   int                            `json:"count"`
		Schemas []store.CredentialSchemaRecord `json:"schemas"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || len(out.Schemas) != 1 || out.Schemas[0].SAID != good.SAID {
		t.Fatalf("listed %+v", out)
	}
}
