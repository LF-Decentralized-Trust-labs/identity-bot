package modelcall

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"identity-agent-core/internal/contractcheck"
)

// Every published outcome is what this package decides of its request, and
// every other derived value is what it produces: a change to what a call may
// be, what travels on, a status or a field name breaks this test before it
// breaks another implementation.
func TestThePublishedModelCallVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		writeModelCallVectors(t)
	}
	set, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Routes) == 0 || len(set.Starts) == 0 || len(set.Headers) == 0 || len(set.Collections) == 0 ||
		len(set.CollectionQueries) == 0 || len(set.Refusals) == 0 || len(set.Answers) == 0 {
		t.Fatal("the vector file is missing a section")
	}
	// Recomputed into a second copy read from the file, so nothing the
	// recomputation writes can reach the values it is compared with.
	want, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if err := fillModelCallVectors(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set, want) {
		got, _ := json.MarshalIndent(set, "", "  ")
		recomputed, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("the published model-call vectors are not what this package produces:\n file:\n%s\n recomputed:\n%s", got, recomputed)
	}

	// Both outcomes are published, and every refusal status is.
	allowed, refused := 0, map[Reason]bool{}
	for _, s := range set.Starts {
		if s.Outcome.Allowed {
			allowed++
		} else {
			refused[s.Outcome.Reason] = true
		}
	}
	for _, r := range []Reason{NoLease, TooLarge, NotAllowed, AllowanceRule} {
		if !refused[r] {
			t.Errorf("no start is refused as %s", r)
		}
	}
	if allowed == 0 {
		t.Error("no start is allowed")
	}
	if len(set.Refusals) != len(Reasons) {
		t.Errorf("%d refusals published, %d reasons", len(set.Refusals), len(Reasons))
	}
}

// The objects the exchange sends are the ones the schema in
// contracts/model-call describes, and every object it defines is one of them.
func TestTheModelCallSchemaDescribesTheseTypes(t *testing.T) {
	s, err := contractcheck.Read("../contracts/model-call/model-call.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]any{
		"request": Request{},
		"answer":  Answer{},
		"refusal": Refusal{},
		"stopped": Stopped{},
		// The provider's headers are a map of names to values, not a type.
		"header": nil,
	}
	var faults []string
	for def, v := range held {
		if v != nil {
			faults = append(faults, s.Matches(def, v)...)
		}
	}
	faults = append(faults, s.Unheld(held)...)
	for _, f := range faults {
		t.Error(f)
	}
}

// An implementation written from the schema's prose, in another language,
// agrees with the vector file.
func TestAnIndependentImplementationAgreesWithTheModelCallVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_model_call_vectors.py", "model-call-vectors.json")
}

// A refusal that this package's checks make is always an *Error.
func TestEveryRefusalHasAReason(t *testing.T) {
	set, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range set.Starts {
		if s.Outcome.Allowed {
			continue
		}
		_, err := Rules{Routes: set.Routes, Model: s.Model, Allowance: s.Allowance}.Check(startRequest(s))
		var e *Error
		if !errors.As(err, &e) || e.Why == "" {
			t.Errorf("%s: refused without a reason or a sentence: %v", s.Name, err)
		}
	}
}

// A part of an answer is at most PartLargest bytes, and is base64.
func TestAnAnswerCarriesAtMostOnePart(t *testing.T) {
	if b, err := (Answer{DataB64: base64.StdEncoding.EncodeToString(make([]byte, PartLargest))}).Data(); err != nil || len(b) != PartLargest {
		t.Fatalf("a whole part was refused: %v", err)
	}
	if _, err := (Answer{DataB64: base64.StdEncoding.EncodeToString(make([]byte, PartLargest+1))}).Data(); err == nil {
		t.Fatal("a part a byte too large was read")
	}
	if _, err := (Answer{DataB64: "not base64!"}).Data(); err == nil {
		t.Fatal("a part that is not base64 was read")
	}
}

// startBody is a start's body as it is sent.
func startBody(s StartVector) []byte {
	b := []byte(s.Body)
	if s.PadTo > len(b) {
		b = append(b, bytes.Repeat([]byte(" "), s.PadTo-len(b))...)
	}
	return b
}

// startRequest is a start's request as it is sent, its body included.
func startRequest(s StartVector) Request {
	q := s.Request
	if s.Body != "" {
		q.BodyB64 = base64.StdEncoding.EncodeToString(startBody(s))
	}
	return q
}

// fillModelCallVectors computes every derived value in set from its inputs.
func fillModelCallVectors(set *VectorSet) error {
	set.Limits = Limits{RequestLargest: RequestLargest, StartLargest: StartLargest, PartLargest: PartLargest, PathLongest: PathLongest,
		AnswerLongest: AnswerLongest, CollectionWaitSeconds: int(CollectionWait.Seconds())}
	set.HeaderNames = append([]string(nil), HeaderNames...)
	set.AnswerHeaderNames = append([]string(nil), AnswerHeaderNames...)
	set.QueryParameters = QueryParameters()
	set.AnswerBoundNames = append([]string(nil), AnswerBoundNames...)
	set.AnswerCountNames = append([]string(nil), AnswerCountNames...)
	for i := range set.Starts {
		s := &set.Starts[i]
		q := startRequest(*s)
		if s.Body != "" {
			s.Request.BodyB64 = q.BodyB64
			if s.PadTo > 0 {
				s.Request.BodyB64 = ""
			}
		}
		c, err := Rules{Routes: set.Routes, Model: s.Model, Allowance: s.Allowance}.Check(q)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				return err
			}
			s.Outcome = Outcome{Reason: e.Reason, Status: e.Reason.Status(), Refused: e.Reason.Refusal("").Refused}
			continue
		}
		c.Body = nil
		s.Outcome = Outcome{Allowed: true, Call: &c}
	}
	for i := range set.Headers {
		set.Headers[i].Passed = Headers(set.Headers[i].Sent)
	}
	for i := range set.Collections {
		c := &set.Collections[i]
		c.Path = Collection{From: c.From, Lease: c.Lease, Head: c.Head}.Path(c.CallID)
	}
	for i := range set.CollectionQueries {
		c := &set.CollectionQueries[i]
		v, _ := url.ParseQuery(c.Query)
		got := ParseCollection(v)
		c.From, c.Lease, c.Head = got.From, got.Lease, got.Head
	}
	set.Refusals = nil
	for _, r := range Reasons {
		f := r.Refusal("")
		set.Refusals = append(set.Refusals, RefusalVector{Reason: r, Status: r.Status(), Refused: f.Refused, NoCall: f.NoCall})
	}
	for i := range set.Answers {
		a := &set.Answers[i]
		a.Answer.DataB64 = ""
		if a.Data != "" {
			a.Answer.DataB64 = base64.StdEncoding.EncodeToString([]byte(a.Data))
		}
		a.Answer.Next = a.From + int64(len(a.Data))
	}
	return nil
}

// writeModelCallVectors writes the vector file from the inputs below.
func writeModelCallVectors(t *testing.T) {
	t.Helper()
	var set VectorSet
	set.About = "Model calls a body makes through the Identity Agent that keeps the API key, worked through; " +
		"the rules are in contracts/model-call/model-call.schema.json. Each start is checked against routes, under " +
		"its model (the model chosen for the AI agent, where one is) and allowance (whether its model calls are " +
		"held to an allowance). Each outcome is what the request alone decides; what only the Identity Agent knows " +
		"(the lease, the AI agent's standing, what an allowance has left) is not in it."
	set.Routes = []Route{
		{"POST", "/v1/messages"},
		{"POST", "/v1/messages/count_tokens"},
		{"POST", "/v1/chat/completions"},
		{"GET", "/v1/models"},
	}
	const lease = "lease-0001"
	call := func(method, path string) Request { return Request{LeaseID: lease, Method: method, Path: path} }
	with := func(q Request, f func(*Request)) Request { f(&q); return q }
	type start = StartVector
	msg := call("POST", "/v1/messages")
	chat := call("POST", "/v1/chat/completions")
	models := call("GET", "/v1/models")
	const chosen = "example-model-1"
	set.Starts = []start{
		// Allowed.
		{Name: "a model call", Body: `{"model":"example-model-1","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}`,
			Request: with(msg, func(q *Request) {
				q.Query = "beta=true"
				q.Header = map[string]string{"content-type": "application/json", "Anthropic-Version": "2023-06-01",
					"Authorization": "Bearer run-token", "X-Api-Key": "run-token", "User-Agent": "a-program/1.0"}
			})},
		{Name: "the method in lower case", Body: `{"model":"m","messages":[]}`, Request: with(chat, func(q *Request) { q.Method = "post" })},
		{Name: "the list of models, paged", Request: with(models, func(q *Request) { q.Query = "limit=20&after_id=model-a" })},
		{Name: "one model by a name holding a slash", Request: call("GET", "/v1/models/vendor/example-model:latest")},
		{Name: "one model by a name holding a letter outside ASCII", Request: call("GET", "/v1/models/modèle")},
		{Name: "the query is sent on sorted", Request: with(models, func(q *Request) { q.Query = "limit=5&beta=true" })},
		{Name: "an empty query value of the paging", Request: with(models, func(q *Request) { q.Query = "limit=&after_id=" })},
		{Name: "a path of 256 bytes", Request: call("GET", "/v1/models/"+strings.Repeat("a", 256-len("/v1/models/")))},
		{Name: "the chosen model", Model: chosen, Body: `{"model":"example-model-1","messages":[]}`, Request: msg},
		{Name: "a chosen model does not bind a read", Model: chosen, Request: models},
		{Name: "no model chosen: the body is not read", Body: `not json`, Request: msg},
		{Name: "no model chosen: a list of models to fall back on passes", Body: `{"models":["a","b"]}`, Request: chat},
		{Name: "a body of exactly 3 MB", Body: `{"model":"m","messages":[]}`, PadTo: RequestLargest, Request: msg},
		{Name: "an allowance: the largest answer length counts", Allowance: true,
			Body: `{"model":"m","max_tokens":1024,"max_completion_tokens":2048}`, Request: chat},
		{Name: "an allowance: one answer, asked for as 1", Allowance: true,
			Body: `{"model":"m","max_output_tokens":32768,"n":1,"best_of":1.0}`, Request: chat},
		{Name: "an allowance: a whole number written with an exponent", Allowance: true,
			Body: `{"model":"m","max_tokens":1e3}`, Request: msg},
		{Name: "an allowance: only the object's own fields are read", Allowance: true,
			Body: `{"model":"m","max_tokens":10,"metadata":{"n":5,"max_tokens":99999}}`, Request: msg},
		{Name: "an allowance: a read is not held to it", Allowance: true, Request: models},
		{Name: "an allowance and a chosen model", Allowance: true, Model: chosen,
			Body: `{"model":"example-model-1","max_tokens":1}`, Request: msg},

		// Refused: the request.
		{Name: "no lease", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.LeaseID = "" })},
		{Name: "no lease, and a body that is not base64", Request: with(msg, func(q *Request) { q.LeaseID = ""; q.BodyB64 = "not base64!" })},
		{Name: "a body that is not base64", Request: with(msg, func(q *Request) { q.BodyB64 = "not base64!" })},
		{Name: "a body in base64 broken across lines", Request: with(msg, func(q *Request) { q.BodyB64 = "e30=\n" })},
		{Name: "a method named with a letter outside ASCII", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Method = "po\u017ft" })},
		{Name: "a body of 3 MB and a byte", Body: `{"model":"m","messages":[]}`, PadTo: RequestLargest + 1, Request: msg},

		// Refused: the route.
		{Name: "a route the sign-in does not have", Body: `{"model":"m"}`, Request: call("POST", "/v1/embeddings")},
		{Name: "the right path with the wrong method", Request: call("GET", "/v1/messages")},
		{Name: "a method the exchange has no route for", Request: call("DELETE", "/v1/models")},
		{Name: "one model by name is only read", Body: `{}`, Request: call("POST", "/v1/models/example-model")},
		{Name: "an escaped path", Body: `{"model":"m"}`, Request: call("POST", "/v1/messages%2Fcount_tokens")},
		{Name: "a path that cleaning changes", Request: call("GET", "/v1/models/../messages")},
		{Name: "a path with an empty segment", Body: `{"model":"m"}`, Request: call("POST", "//v1/messages")},
		{Name: "a path with a trailing slash", Body: `{"model":"m"}`, Request: call("POST", "/v1/messages/")},
		{Name: "a path holding a query", Body: `{"model":"m"}`, Request: call("POST", "/v1/messages?beta=true")},
		{Name: "a path holding a fragment", Request: call("GET", "/v1/models#x")},
		{Name: "a path not starting with a slash", Request: call("GET", "v1/models")},
		{Name: "a path of 257 bytes", Request: call("GET", "/v1/models/"+strings.Repeat("a", 257-len("/v1/models/")))},
		{Name: "no path", Request: call("GET", "")},

		// Refused: the query.
		{Name: "a query parameter not allowed", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Query = "stream=true" })},
		{Name: "beta other than true", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Query = "beta=false" })},
		{Name: "a query parameter given twice", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Query = "beta=true&beta=true" })},
		{Name: "a limit of five digits", Request: with(models, func(q *Request) { q.Query = "limit=12345" })},
		{Name: "a limit that is not digits", Request: with(models, func(q *Request) { q.Query = "limit=-1" })},
		{Name: "a query parameter in another case", Request: with(models, func(q *Request) { q.Query = "Limit=5" })},
		{Name: "a query split by a semicolon", Request: with(models, func(q *Request) { q.Query = "limit=5;beta=true" })},
		{Name: "a query with a broken escape", Request: with(models, func(q *Request) { q.Query = "after_id=%zz" })},
		{Name: "a paging id holding a space", Request: with(models, func(q *Request) { q.Query = "after_id=a+b" })},
		{Name: "a paging id of 129 bytes", Request: with(models, func(q *Request) { q.Query = "before_id=" + strings.Repeat("b", 129) })},

		// Refused: the chosen model.
		{Name: "another model than the one chosen", Model: chosen, Body: `{"model":"another-model"}`, Request: msg},
		{Name: "no model named, with one chosen", Model: chosen, Body: `{"messages":[]}`, Request: msg},
		{Name: "the model named twice", Model: chosen, Body: `{"model":"example-model-1","model":"another-model"}`, Request: msg},
		{Name: "the model named in another case", Model: chosen, Body: `{"Model":"example-model-1"}`, Request: msg},
		{Name: "a list of models to fall back on, with one chosen", Model: chosen,
			Body: `{"model":"example-model-1","models":["another-model"]}`, Request: chat},
		{Name: "a model that is not a name", Model: chosen, Body: `{"model":["example-model-1"]}`, Request: msg},
		{Name: "a field named with a letter outside ASCII is not a list of models", Model: chosen,
			Body: "{\"model\":\"example-model-1\",\"model\u017f\":[\"a\"]}", Request: chat},
		{Name: "a body that is not one JSON object, with a model chosen", Model: chosen,
			Body: `{"model":"example-model-1"} {"model":"another-model"}`, Request: msg},

		// Refused: an allowance.
		{Name: "an allowance: no answer length", Allowance: true, Body: `{"model":"m","messages":[]}`, Request: msg},
		{Name: "an allowance: an answer length of 0", Allowance: true, Body: `{"model":"m","max_tokens":0}`, Request: msg},
		{Name: "an allowance: an answer length over 32768", Allowance: true, Body: `{"model":"m","max_tokens":32769}`, Request: msg},
		{Name: "an allowance: an answer length that is not whole", Allowance: true, Body: `{"model":"m","max_tokens":1.5}`, Request: msg},
		{Name: "an allowance: an answer length as a string", Allowance: true, Body: `{"model":"m","max_tokens":"100"}`, Request: msg},
		{Name: "an allowance: an answer length spelt in another case", Allowance: true, Body: `{"model":"m","Max_Tokens":100}`, Request: msg},
		{Name: "an allowance: an answer length given twice", Allowance: true,
			Body: `{"model":"m","max_tokens":100,"max_tokens":200}`, Request: msg},
		{Name: "an allowance: two answers", Allowance: true, Body: `{"model":"m","max_tokens":100,"n":2}`, Request: chat},
		{Name: "an allowance: two answers, asked for in another case", Allowance: true,
			Body: `{"model":"m","max_tokens":100,"N":2}`, Request: chat},
		{Name: "an allowance: the best of three", Allowance: true, Body: `{"model":"m","max_tokens":100,"best_of":3}`, Request: chat},
		{Name: "an allowance: a number of answers that is not a number", Allowance: true,
			Body: `{"model":"m","max_tokens":100,"n":null}`, Request: chat},
		{Name: "an allowance: something after the object", Allowance: true, Body: `{"model":"m","max_tokens":100} x`, Request: msg},
		{Name: "an allowance: an object cut short", Allowance: true, Body: `{"model":"m","max_tokens":100`, Request: msg},
		{Name: "an allowance: an array", Allowance: true, Body: `[{"model":"m","max_tokens":100}]`, Request: msg},
		{Name: "an allowance: an empty body", Allowance: true, Request: msg},
		{Name: "an allowance: a body that is not UTF-8", Allowance: true,
			Request: with(msg, func(q *Request) {
				q.BodyB64 = base64.StdEncoding.EncodeToString([]byte("{\"model\":\"m\",\"max_tokens\":5,\"x\":\"\xff\"}"))
			})},
		{Name: "an allowance: a number of answers named with a letter outside ASCII is not one", Allowance: true,
			Body: "{\"model\":\"m\",\"max_tokens\":5,\"be\u017ft_of\":3}", Request: chat},
		{Name: "an allowance: counting tokens is a POST, so it is held to it", Allowance: true,
			Body: `{"model":"m","messages":[]}`, Request: call("POST", "/v1/messages/count_tokens")},
	}
	set.Headers = []HeaderVector{
		{Name: "what describes the call travels; how the brain proved itself does not", Sent: map[string]string{
			"Content-Type": "application/json", "Accept": "text/event-stream", "Anthropic-Version": "2023-06-01",
			"Anthropic-Beta": "a-beta-feature", "Openai-Beta": "assistants=v2", "Authorization": "Bearer run-token",
			"X-Api-Key": "run-token", "Cookie": "a=b", "User-Agent": "a-program/1.0"}},
		{Name: "names in any case travel as the exchange names them", Sent: map[string]string{
			"content-type": "application/json", "ANTHROPIC-VERSION": "2023-06-01", "openai-beta": "responses=v1"}},
		{Name: "only ASCII letters fold", Sent: map[string]string{"Anthropic-Ver\u017fion": "2023-06-01", "Accept": "application/json"}},
		{Name: "a header with no value does not travel", Sent: map[string]string{"Content-Type": "", "Accept": "application/json"}},
		{Name: "one header named twice: the first name by byte order with a value", Sent: map[string]string{
			"accept": "text/plain", "Accept": "application/json", "ACCEPT": "", "content-type": "text/plain", "Content-type": "application/json"}},
		{Name: "nothing travels", Sent: map[string]string{"Authorization": "Bearer run-token"}},
	}
	set.Collections = []CollectionVector{
		{Name: "the first collection", CallID: "call-0001", From: 0, Lease: lease},
		{Name: "a later collection, with the status and headers in hand", CallID: "call-0001",
			From: 1234, Lease: lease, Head: true},
		{Name: "a lease and a call that must be escaped", CallID: "call/0004 a", From: 7, Lease: "lease 2/+&", Head: true},
	}
	set.CollectionQueries = []CollectionQueryVector{
		{Name: "a collection", Query: "from=1234&lease=lease-0001&head=1"},
		{Name: "no from", Query: "lease=lease-0001"},
		{Name: "a from below nothing", Query: "from=-5&lease=lease-0001"},
		{Name: "a from that is not a number", Query: "from=abc&lease=lease-0001"},
		{Name: "a from in hexadecimal", Query: "from=0x10&lease=lease-0001"},
		{Name: "a from with a sign", Query: "from=+5&lease=lease-0001"},
		{Name: "a from too large", Query: "from=99999999999999999999&lease=lease-0001"},
		{Name: "head other than 1", Query: "from=5&lease=lease-0001&head=true"},
		{Name: "an escaped lease", Query: "from=5&lease=lease+2%2F%2B%26"},
		{Name: "an unreadable piece is skipped", Query: "from=5&x;y&%zz=1&lease=lease-0001&head=1"},
	}
	set.Answers = []AnswerVector{
		{Name: "the start, with the status, the headers and the first part", From: 0,
			Data: "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
			Answer: Answer{CallID: "call-0001", Status: 200,
				Header: map[string]string{"Content-Type": "text/event-stream", "Request-Id": "req_0001"}}},
		{Name: "a collection with nothing new yet", From: 55,
			Answer: Answer{CallID: "call-0001", Status: 200,
				Header: map[string]string{"Content-Type": "text/event-stream", "Request-Id": "req_0001"}}},
		{Name: "the last part", From: 55, Data: "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			Answer: Answer{CallID: "call-0001", Status: 200,
				Header: map[string]string{"Content-Type": "text/event-stream", "Request-Id": "req_0001"}, Done: true}},
		{Name: "an answer stopped because the AI agent may no longer act", From: 2048,
			Answer: Answer{CallID: "call-0001", Status: 200,
				Header: map[string]string{"Content-Type": "text/event-stream"}, Done: true,
				Error: "this AI agent was revoked"}},
		{Name: "a call whose provider could not be reached", From: 0,
			Answer: Answer{CallID: "call-0002", Done: true,
				Error: "the model's provider could not be reached"}},
		{Name: "the provider's own refusal, passed on", From: 0,
			Data: `{"error":{"message":"Too many requests"}}`,
			Answer: Answer{CallID: "call-0003", Status: 429,
				Header: map[string]string{"Content-Type": "application/json", "Retry-After": "30"}, Done: true}},
	}
	if err := fillModelCallVectors(&set); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(set); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("model-call-vectors.json", out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
