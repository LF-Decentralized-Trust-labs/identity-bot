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
	if len(set.Profile.Routes) == 0 || len(set.Starts) == 0 || len(set.Headers) == 0 || len(set.Collections) == 0 ||
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
		"request":         Request{},
		"answer":          Answer{},
		"refusal":         Refusal{},
		"stopped":         Stopped{},
		"borrowing":       Borrowing{},
		"borrowed":        Borrowed{},
		"lease_request":   LeaseRequest{},
		"renewed":         Renewed{},
		"returned":        Returned{},
		"borrow_refusal":  BorrowRefusal{},
		"profile":         Profile{},
		"route":           Route{},
		"query_parameter": QueryParameter{},
		// The provider's headers are a map of names to values, not a type.
		"header": nil,
	}
	// A request and an answer are read ignoring fields the reader does not
	// know, so their definitions must not refuse them.
	open := map[string]bool{"request": true, "answer": true, "borrowing": true, "borrowed": true, "lease_request": true,
		"renewed": true, "returned": true, "borrow_refusal": true}
	var faults []string
	for def, v := range held {
		switch {
		case v == nil:
		case open[def]:
			faults = append(faults, s.MatchesOpen(def, v)...)
		default:
			faults = append(faults, s.Matches(def, v)...)
		}
	}
	faults = append(faults, s.Unheld(held)...)
	for _, f := range faults {
		t.Error(f)
	}
}

// The borrow vectors are written with the field names the Go types write:
// each, read into its type and written again, is the same JSON.
func TestTheBorrowVectorsAreTheseTypes(t *testing.T) {
	var file struct {
		Borrow map[string]json.RawMessage `json:"borrow"`
	}
	if err := json.Unmarshal(modelCallVectors, &file); err != nil {
		t.Fatal(err)
	}
	set, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	b := set.Borrow
	for name, v := range map[string]any{"request": b.Request, "answer": b.Answer, "renew": b.Renew, "renewed": b.Renewed,
		"return": b.Return, "returned": b.Returned, "lease_gone": b.LeaseGone, "update_agent_host": b.UpdateAgentHost} {
		again, _ := json.Marshal(v)
		var x, y any
		_ = json.Unmarshal(file.Borrow[name], &x)
		_ = json.Unmarshal(again, &y)
		if !reflect.DeepEqual(x, y) {
			t.Errorf("borrow %s: the file has %s, the type writes %s", name, file.Borrow[name], again)
		}
	}
	if len(file.Borrow) != 8 {
		t.Errorf("%d borrow vectors; this test holds 8", len(file.Borrow))
	}
	if !b.Request.ThroughIdentityAgent() || b.Renewed.LeaseID != b.Answer.LeaseID {
		t.Error("the borrow vectors do not borrow through the Identity Agent, or renew another lease")
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
		_, err := checkStart(set, s)
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
	if s.Nest > 0 {
		return []byte(`{"model":"m","max_answer_tokens":5,"x":` + strings.Repeat("[", s.Nest-1) + strings.Repeat("]", s.Nest-1) + "}")
	}
	b := []byte(s.Body)
	if s.PadTo > len(b) {
		b = append(b, bytes.Repeat([]byte(" "), s.PadTo-len(b))...)
	}
	return b
}

// startRequest is a start's request as it is sent, its body included.
func startRequest(s StartVector) Request {
	q := s.Request
	if s.Body != "" || s.Nest > 0 {
		q.BodyB64 = base64.StdEncoding.EncodeToString(startBody(s))
	}
	return q
}

// startArrives is a start as it arrives: Raw, or the request as JSON, padded
// with spaces to RawPadTo.
func startArrives(s StartVector) ([]byte, error) {
	raw := []byte(s.Raw)
	if s.Raw == "" {
		var err error
		if raw, err = json.Marshal(startRequest(s)); err != nil {
			return nil, err
		}
	}
	if s.RawPadTo > len(raw) {
		raw = append(raw, bytes.Repeat([]byte(" "), s.RawPadTo-len(raw))...)
	}
	return raw, nil
}

// checkStart is what Check decides of a start as it arrives.
func checkStart(set VectorSet, s StartVector) (Call, error) {
	raw, err := startArrives(s)
	if err != nil {
		return Call{}, err
	}
	q, err := ParseRequest(raw)
	if err != nil {
		return Call{}, err
	}
	rules := Rules{Profile: set.Profile, Model: s.Model, Allowance: s.Allowance}
	if s.Profile != nil {
		rules.Profile = *s.Profile
	}
	return rules.Check(q)
}

// profileOf is own, or the example profile where own is nil.
func profileOf(set VectorSet, own *Profile) Profile {
	if own != nil {
		return *own
	}
	return set.Profile
}

// fillModelCallVectors computes every derived value in set from its inputs.
func fillModelCallVectors(set *VectorSet) error {
	set.Limits = Limits{RequestLargest: RequestLargest, StartLargest: StartLargest, PartLargest: PartLargest, PathLongest: PathLongest,
		AnswerLongest: AnswerLongest, DepthDeepest: DepthDeepest, CollectionWaitSeconds: int(CollectionWait.Seconds())}
	b := &set.Borrow
	b.Request = Borrowing{ModelCalls: ThroughIdentityAgent}
	b.Answer.ModelCalls = ThroughIdentityAgent
	b.Renew = LeaseRequest{LeaseID: b.Answer.LeaseID}
	b.Renewed.LeaseID = b.Answer.LeaseID
	b.Return = LeaseRequest{LeaseID: b.Answer.LeaseID}
	b.Returned = Returned{Returned: true}
	b.LeaseGone.NoLease, b.LeaseGone.UpdateAgentHost = true, false
	b.UpdateAgentHost.NoLease, b.UpdateAgentHost.UpdateAgentHost = false, true
	for i := range set.Starts {
		s := &set.Starts[i]
		if s.Body != "" || s.Nest > 0 {
			s.Request.BodyB64 = startRequest(*s).BodyB64
			if s.PadTo > 0 || s.Nest > 0 {
				s.Request.BodyB64 = ""
			}
		}
		c, err := checkStart(*set, *s)
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
		h := &set.Headers[i]
		h.Passed = profileOf(*set, h.Profile).PassedHeaders(h.Sent)
	}
	for i := range set.AnswerHeaders {
		h := &set.AnswerHeaders[i]
		h.Passed = profileOf(*set, h.Profile).AnswerHeadersBack(h.Sent)
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
		"the rules are in contracts/model-call/model-call.schema.json. Each start arrives as its request written as " +
		"JSON (or as raw, padded to raw_pad_to) and is checked against example_profile, or its own profile, under its " +
		"model (the model chosen for the AI agent, where one is) and allowance (whether its model calls are held to " +
		"an allowance). example_profile is made up for these vectors: it is not any provider's, and the routes, " +
		"headers, query parameters and answer-length names in it are not part of the exchange. Each outcome is what " +
		"the request alone decides; what only the Identity Agent knows (the lease, the AI agent's standing, what an " +
		"allowance has left) is not in it."
	set.Profile = Profile{
		Routes: []Route{
			{Method: "POST", Path: "/v1/generate"},
			{Method: "POST", Path: "/v1/generate/count", Counts: true},
			{Method: "POST", Path: "/v1/complete"},
			{Method: "GET", Path: "/v1/models"},
		},
		ModelsPath:    "/v1/models",
		Headers:       []string{"Content-Type", "Accept", "Example-Version", "Example-Beta", "Example-Preview"},
		AnswerHeaders: []string{"Content-Type", "Retry-After", "Request-Id", "X-Request-Id"},
		Parameters: []QueryParameter{
			{Name: "preview", Value: "true"},
			{Name: "page_size", Digits: 4},
			{Name: "page_after", Plain: 128},
			{Name: "page_before", Plain: 128},
		},
		AnswerBoundNames: []string{"max_answer_tokens", "answer_limit", "answer_tokens"},
		AnswerCountNames: []string{"answer_count", "candidates"},
	}
	// with is the example profile changed by f.
	withProfile := func(f func(*Profile)) *Profile {
		p := set.Profile
		p.Routes = append([]Route(nil), p.Routes...)
		p.Headers = append([]string(nil), p.Headers...)
		p.AnswerHeaders = append([]string(nil), p.AnswerHeaders...)
		p.Parameters = append([]QueryParameter(nil), p.Parameters...)
		p.AnswerBoundNames = append([]string(nil), p.AnswerBoundNames...)
		p.AnswerCountNames = append([]string(nil), p.AnswerCountNames...)
		f(&p)
		return &p
	}
	withPUT := withProfile(func(p *Profile) { p.Routes = append([]Route{{Method: "PUT", Path: "/v1/models"}}, p.Routes...) })
	credentials := withProfile(func(p *Profile) {
		p.Headers = append(p.Headers, NeverPassedOn...)
		p.AnswerHeaders = append(p.AnswerHeaders, NeverPassedBack...)
	})
	const lease = "lease-0001"
	call := func(method, path string) Request { return Request{LeaseID: lease, Method: method, Path: path} }
	with := func(q Request, f func(*Request)) Request { f(&q); return q }
	type start = StartVector
	msg := call("POST", "/v1/generate")
	chat := call("POST", "/v1/complete")
	models := call("GET", "/v1/models")
	const chosen = "example-model-1"
	set.Starts = []start{
		// Allowed.
		{Name: "a model call", Body: `{"model":"example-model-1","max_answer_tokens":1024,"input":[{"role":"user","content":"Hello"}]}`,
			Request: with(msg, func(q *Request) {
				q.Query = "preview=true"
				q.Header = map[string]string{"content-type": "application/json", "Example-Version": "2023-06-01",
					"Authorization": "Bearer run-token", "X-Api-Key": "run-token", "User-Agent": "a-program/1.0"}
			})},
		{Name: "the method in lower case", Body: `{"model":"m","input":[]}`, Request: with(chat, func(q *Request) { q.Method = "post" })},
		{Name: "the list of models, paged", Request: with(models, func(q *Request) { q.Query = "page_size=20&page_after=model-a" })},
		{Name: "one model by a name holding a slash", Request: call("GET", "/v1/models/vendor/example-model:latest")},
		{Name: "the query is sent on sorted", Request: with(models, func(q *Request) { q.Query = "page_size=5&preview=true" })},
		{Name: "an empty query value of the paging", Request: with(models, func(q *Request) { q.Query = "page_size=&page_after=" })},
		{Name: "a path of 256 bytes", Request: call("GET", "/v1/models/"+strings.Repeat("a", 256-len("/v1/models/")))},
		{Name: "the chosen model", Model: chosen, Body: `{"model":"example-model-1","input":[]}`, Request: msg},
		{Name: "a chosen model does not bind a read", Model: chosen, Request: models},
		{Name: "no model chosen: the body is not read", Body: `not json`, Request: msg},
		{Name: "no model chosen: a list of models to fall back on passes", Body: `{"models":["a","b"]}`, Request: chat},
		{Name: "a body of exactly 3 MB", Body: `{"model":"m","input":[]}`, PadTo: RequestLargest, Request: msg},
		{Name: "an allowance: the largest answer length counts", Allowance: true,
			Body: `{"model":"m","max_answer_tokens":1024,"answer_limit":2048}`, Request: chat},
		{Name: "an allowance: one answer, asked for as 1", Allowance: true,
			Body: `{"model":"m","answer_tokens":32768,"answer_count":1,"candidates":1.0}`, Request: chat},
		{Name: "an allowance: a whole number written with an exponent", Allowance: true,
			Body: `{"model":"m","max_answer_tokens":1e3}`, Request: msg},
		{Name: "an allowance: only the object's own fields are read", Allowance: true,
			Body: `{"model":"m","max_answer_tokens":10,"metadata":{"answer_count":5,"max_answer_tokens":99999}}`, Request: msg},
		{Name: "an allowance: a read is not held to it", Allowance: true, Request: models},
		{Name: "an allowance and a chosen model", Allowance: true, Model: chosen,
			Body: `{"model":"example-model-1","max_answer_tokens":1}`, Request: msg},

		// Refused: the request.
		{Name: "no lease", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.LeaseID = "" })},
		{Name: "a start that is not JSON", Raw: "not json", Request: msg},
		{Name: "a start that is not an object", Raw: `["lease-0001"]`, Request: msg},
		{Name: "a start whose lease is not a string", Raw: `{"lease_id":1,"method":"GET","path":"/v1/models"}`, Request: msg},
		{Name: "a start naming its fields in another case", Raw: `{"LEASE_ID":"lease-0001","method":"GET","path":"/v1/models"}`, Request: msg},
		{Name: "a start with a field it does not know", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","extra":{"a":1}}`, Request: msg},
		{Name: "a start with nulls for its strings", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","query":null,"header":{"Accept":null},"body_b64":null}`, Request: msg},
		{Name: "a start escaping a lone surrogate in a header", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","header":{"Accept":"\ud800"}}`, Request: msg},
		{Name: "a start escaping a lone low surrogate in its lease", Raw: `{"lease_id":"\udc00","method":"GET","path":"/v1/models"}`, Request: msg},
		{Name: "a start escaping a surrogate pair", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","header":{"Accept":"\ud83d\ude00"}}`, Request: msg},
		{Name: "a start escaping a backslash before a u", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","header":{"Accept":"\\ud800"}}`, Request: msg},
		{Name: "a start nested 1000 deep", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","extra":` + strings.Repeat("[", DepthDeepest-1) + strings.Repeat("]", DepthDeepest-1) + `}`, Request: msg},
		{Name: "a start nested 1001 deep", Raw: `{"lease_id":"lease-0001","method":"GET","path":"/v1/models","extra":` + strings.Repeat("[", DepthDeepest) + strings.Repeat("]", DepthDeepest) + `}`, Request: msg},
		{Name: "a start of exactly 6 MB", RawPadTo: StartLargest, Request: models},
		{Name: "a start of 6 MB and a byte", RawPadTo: StartLargest + 1, Request: models},
		{Name: "no lease, and a body that is not base64", Request: with(msg, func(q *Request) { q.LeaseID = ""; q.BodyB64 = "not base64!" })},
		{Name: "a body that is not base64", Request: with(msg, func(q *Request) { q.BodyB64 = "not base64!" })},
		{Name: "a body in base64 broken across lines", Request: with(msg, func(q *Request) { q.BodyB64 = "e30=\n" })},
		{Name: "a method named with a letter outside ASCII", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Method = "po\u017ft" })},
		{Name: "a body of 3 MB and a byte", Body: `{"model":"m","input":[]}`, PadTo: RequestLargest + 1, Request: msg},

		// Refused: the route.
		{Name: "a route the sign-in does not have", Body: `{"model":"m"}`, Request: call("POST", "/v1/embeddings")},
		{Name: "the right path with the wrong method", Request: call("GET", "/v1/generate")},
		{Name: "a method the exchange has no route for", Request: call("DELETE", "/v1/models")},
		{Name: "one model by name is only read", Body: `{}`, Request: call("POST", "/v1/models/example-model")},
		{Name: "an escaped path", Body: `{"model":"m"}`, Request: call("POST", "/v1/generate%2Fcount")},
		{Name: "a path that cleaning changes", Request: call("GET", "/v1/models/../generate")},
		{Name: "a path with an empty segment", Body: `{"model":"m"}`, Request: call("POST", "//v1/generate")},
		{Name: "a path with a trailing slash", Body: `{"model":"m"}`, Request: call("POST", "/v1/generate/")},
		{Name: "a path holding a query", Body: `{"model":"m"}`, Request: call("POST", "/v1/generate?preview=true")},
		{Name: "a path holding a fragment", Request: call("GET", "/v1/models#x")},
		{Name: "a path not starting with a slash", Request: call("GET", "v1/models")},
		{Name: "a path holding a letter outside ASCII", Request: call("GET", "/v1/models/mod\u00e8le")},
		{Name: "a path holding a letter newer than some Unicode tables", Request: call("GET", "/v1/models/a\U00010D50")},
		{Name: "a method other than GET or POST, though the profile lists it", Profile: withPUT, Request: call("PUT", "/v1/models")},
		{Name: "a profile naming a route's method in lower case allows no call",
			Profile: withProfile(func(p *Profile) { p.Routes = append(p.Routes, Route{Method: "get", Path: "/v1/other"}) }), Request: models},
		{Name: "a profile naming a header with a space in it allows no call",
			Profile: withProfile(func(p *Profile) { p.Headers = append(p.Headers, "Authorization ") }), Request: models},
		{Name: "a profile naming a header with a colon in it allows no call",
			Profile: withProfile(func(p *Profile) { p.AnswerHeaders = append(p.AnswerHeaders, "Set-Cookie:") }), Request: models},
		{Name: "a profile naming a header with a letter outside ASCII allows no call",
			Profile: withProfile(func(p *Profile) { p.Headers = append(p.Headers, "C\u00f6okie") }), Request: models},
		{Name: "a profile naming one header twice, ignoring case, allows no call",
			Profile: withProfile(func(p *Profile) { p.Headers = append(p.Headers, "ACCEPT") }), Request: models},
		{Name: "a profile naming one answer-length field twice, ignoring case, allows no call", Allowance: true,
			Profile: withProfile(func(p *Profile) { p.AnswerBoundNames = append(p.AnswerBoundNames, "MAX_ANSWER_TOKENS") }),
			Body:    `{"model":"m","max_answer_tokens":5}`, Request: msg},
		{Name: "a profile naming one query parameter twice, ignoring case, allows no call",
			Profile: withProfile(func(p *Profile) { p.Parameters = append(p.Parameters, QueryParameter{Name: "Preview", Value: "1"}) }), Request: models},
		{Name: "a profile whose query parameter gives two rules allows no call",
			Profile: withProfile(func(p *Profile) { p.Parameters[0].Digits = 2 }), Request: models},
		{Name: "a profile whose query parameter gives no rule allows no call",
			Profile: withProfile(func(p *Profile) { p.Parameters[0].Value = "" }), Request: models},
		{Name: "a path of 257 bytes", Request: call("GET", "/v1/models/"+strings.Repeat("a", 257-len("/v1/models/")))},
		{Name: "no path", Request: call("GET", "")},

		// Refused: the query.
		{Name: "a query parameter not allowed", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Query = "stream=true" })},
		{Name: "a fixed value other than its own", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Query = "preview=false" })},
		{Name: "a query parameter given twice", Body: `{"model":"m"}`, Request: with(msg, func(q *Request) { q.Query = "preview=true&preview=true" })},
		{Name: "a page size of five digits", Request: with(models, func(q *Request) { q.Query = "page_size=12345" })},
		{Name: "a page size that is not digits", Request: with(models, func(q *Request) { q.Query = "page_size=-1" })},
		{Name: "a query parameter in another case", Request: with(models, func(q *Request) { q.Query = "Page_Size=5" })},
		{Name: "a query split by a semicolon", Request: with(models, func(q *Request) { q.Query = "page_size=5;preview=true" })},
		{Name: "a query with a broken escape", Request: with(models, func(q *Request) { q.Query = "page_after=%zz" })},
		{Name: "a paging id holding a space", Request: with(models, func(q *Request) { q.Query = "page_after=a+b" })},
		{Name: "a paging id holding a letter outside ASCII", Request: with(models, func(q *Request) { q.Query = "page_after=mod%C3%A8le" })},
		{Name: "a paging id of 129 bytes", Request: with(models, func(q *Request) { q.Query = "page_before=" + strings.Repeat("b", 129) })},

		// Refused: the chosen model.
		{Name: "another model than the one chosen", Model: chosen, Body: `{"model":"another-model"}`, Request: msg},
		{Name: "no model named, with one chosen", Model: chosen, Body: `{"input":[]}`, Request: msg},
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
		{Name: "an allowance: no answer length", Allowance: true, Body: `{"model":"m","input":[]}`, Request: msg},
		{Name: "an allowance: an answer length of 0", Allowance: true, Body: `{"model":"m","max_answer_tokens":0}`, Request: msg},
		{Name: "an allowance: an answer length over 32768", Allowance: true, Body: `{"model":"m","max_answer_tokens":32769}`, Request: msg},
		{Name: "an allowance: an answer length that is not whole", Allowance: true, Body: `{"model":"m","max_answer_tokens":1.5}`, Request: msg},
		{Name: "an allowance: an answer length as a string", Allowance: true, Body: `{"model":"m","max_answer_tokens":"100"}`, Request: msg},
		{Name: "an allowance: an answer length spelt in another case", Allowance: true, Body: `{"model":"m","Max_Answer_Tokens":100}`, Request: msg},
		{Name: "an allowance: an answer length given twice", Allowance: true,
			Body: `{"model":"m","max_answer_tokens":100,"max_answer_tokens":200}`, Request: msg},
		{Name: "an allowance: two answers", Allowance: true, Body: `{"model":"m","max_answer_tokens":100,"answer_count":2}`, Request: chat},
		{Name: "an allowance: two answers, asked for in another case", Allowance: true,
			Body: `{"model":"m","max_answer_tokens":100,"ANSWER_COUNT":2}`, Request: chat},
		{Name: "an allowance: three candidates", Allowance: true, Body: `{"model":"m","max_answer_tokens":100,"candidates":3}`, Request: chat},
		{Name: "an allowance: a number of answers that is not a number", Allowance: true,
			Body: `{"model":"m","max_answer_tokens":100,"answer_count":null}`, Request: chat},
		{Name: "an allowance: something after the object", Allowance: true, Body: `{"model":"m","max_answer_tokens":100} x`, Request: msg},
		{Name: "an allowance: an object cut short", Allowance: true, Body: `{"model":"m","max_answer_tokens":100`, Request: msg},
		{Name: "an allowance: an array", Allowance: true, Body: `[{"model":"m","max_answer_tokens":100}]`, Request: msg},
		{Name: "an allowance: an empty body", Allowance: true, Request: msg},
		{Name: "an allowance: a body that is not UTF-8", Allowance: true,
			Request: with(msg, func(q *Request) {
				q.BodyB64 = base64.StdEncoding.EncodeToString([]byte("{\"model\":\"m\",\"max_answer_tokens\":5,\"x\":\"\xff\"}"))
			})},
		{Name: "an allowance: a number of answers named with a letter outside ASCII is not one", Allowance: true,
			Body: "{\"model\":\"m\",\"max_answer_tokens\":5,\"candidate\u017f\":3}", Request: chat},
		{Name: "an allowance: a body nested 1000 deep", Allowance: true, Nest: DepthDeepest, Request: msg},
		{Name: "an allowance: a body nested 1001 deep", Allowance: true, Nest: DepthDeepest + 1, Request: msg},
		{Name: "a chosen model: a body nested 1001 deep", Model: "m", Nest: DepthDeepest + 1, Request: msg},
		{Name: "an allowance: a counting route is not held to it", Allowance: true,
			Body: `{"model":"m","input":[]}`, Request: call("POST", "/v1/generate/count")},
	}
	set.Headers = []HeaderVector{
		{Name: "what describes the call travels; how the brain proved itself does not", Sent: map[string]string{
			"Content-Type": "application/json", "Accept": "text/event-stream", "Example-Version": "2023-06-01",
			"Example-Beta": "a-beta-feature", "Example-Preview": "v2", "Authorization": "Bearer run-token",
			"X-Api-Key": "run-token", "Cookie": "a=b", "User-Agent": "a-program/1.0"}},
		{Name: "names in any case travel as the exchange names them", Sent: map[string]string{
			"content-type": "application/json", "EXAMPLE-VERSION": "2023-06-01", "example-preview": "v1"}},
		{Name: "only ASCII letters fold", Sent: map[string]string{"Example-Ver\u017fion": "2023-06-01", "Accept": "application/json"}},
		{Name: "a header with no value does not travel", Sent: map[string]string{"Content-Type": "", "Accept": "application/json"}},
		{Name: "one header named twice: the first name by byte order with a value", Sent: map[string]string{
			"accept": "text/plain", "Accept": "application/json", "ACCEPT": "", "content-type": "text/plain", "Content-type": "application/json"}},
		{Name: "nothing travels", Sent: map[string]string{"Authorization": "Bearer run-token"}},
		{Name: "credentials and connection headers never travel, though the profile lists them", Profile: credentials,
			Sent: map[string]string{"Authorization": "Bearer run-token", "proxy-authorization": "Basic x", "Cookie": "a=b",
				"X-API-KEY": "run-token", "Api-Key": "run-token", "Host": "elsewhere.example", "Content-Length": "9",
				"Transfer-Encoding": "chunked", "Connection": "close", "Keep-Alive": "timeout=5", "Proxy-Connection": "close",
				"TE": "trailers", "Trailer": "X-Sum", "Upgrade": "websocket", "Expect": "100-continue",
				"Accept": "application/json"}},
		{Name: "an underscore counts as a hyphen: those spellings never travel either",
			Profile: withProfile(func(p *Profile) {
				p.Headers = append(p.Headers, "X_Api_Key", "Proxy_Authorization", "Content_Length", "Transfer_Encoding")
			}),
			Sent: map[string]string{"X_Api_Key": "run-token", "proxy_authorization": "Basic x", "Content_Length": "9",
				"TRANSFER_ENCODING": "chunked", "Accept": "application/json"}},
	}
	set.AnswerHeaders = []HeaderVector{
		{Name: "what describes the answer travels back", Sent: map[string]string{"Content-Type": "text/event-stream",
			"retry-after": "30", "Request-Id": "req_0001", "Server": "example", "X-Internal": "1"}},
		{Name: "a header with no value does not travel back", Sent: map[string]string{"Content-Type": "", "Request-Id": "req_0001"}},
		{Name: "one header named twice: the first name by byte order with a value", Sent: map[string]string{
			"request-id": "b", "Request-Id": "a", "REQUEST-ID": ""}},
		{Name: "credentials and connection headers never travel back, though the profile lists them", Profile: credentials,
			Sent: map[string]string{"Set-Cookie": "session=x", "set-cookie2": "session=y", "Authorization": "Bearer key",
				"X-Api-Key": "key", "Connection": "close", "Transfer-Encoding": "chunked", "Content-Length": "10",
				"Content-Type": "application/json"}},
		{Name: "an underscore counts as a hyphen: those spellings never travel back either",
			Profile: withProfile(func(p *Profile) { p.AnswerHeaders = append(p.AnswerHeaders, "Set_Cookie", "Content_Length") }),
			Sent:    map[string]string{"Set_Cookie": "session=x", "content_length": "10", "Request-Id": "req_0001"}},
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
			Data: "event: part\ndata: {\"text\":\"Hel\"}\n\n",
			Answer: Answer{CallID: "call-0001", Status: 200,
				Header: map[string]string{"Content-Type": "text/event-stream", "Request-Id": "req_0001"}}},
		{Name: "a collection with nothing new yet", From: 36,
			Answer: Answer{CallID: "call-0001", Status: 200,
				Header: map[string]string{"Content-Type": "text/event-stream", "Request-Id": "req_0001"}}},
		{Name: "the last part", From: 36, Data: "event: end\ndata: {\"text\":\"lo\"}\n\n",
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
	set.Borrow.Answer = Borrowed{LeaseID: "lease-0001", LeaseExpiresAt: "2026-10-30T12:05:00Z", RenewEverySeconds: 100}
	set.Borrow.Renewed.LeaseExpiresAt = "2026-10-30T12:06:40Z"
	set.Borrow.LeaseGone.Error = "no such lease"
	set.Borrow.UpdateAgentHost.Error = "this AI agent's key stays with its Identity Agent, and this machine's body is too old to make its model calls through it; update it"
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
