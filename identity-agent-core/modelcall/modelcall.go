// Package modelcall is the exchange by which an AI agent's body makes its
// brain's model calls through the Identity Agent that keeps the API key
// (ADR-057): the requests and answers as they travel, and the checks both
// sides can run on them.
//
// The body starts a call with POST /api/agent-host/model-calls, collects the
// answer in parts with GET /api/agent-host/model-calls/{call}, and gives up on
// it with DELETE on the same path. Every request is sealed and signed by the
// body, as everything it sends the Identity Agent is (ADR-047); that is not
// this package's to do.
//
// What is checked here is what the request alone decides: whether its path,
// query, headers and body are ones the exchange allows, and, where the
// Identity Agent holds the AI agent's model calls to an allowance, whether the
// call says how long an answer it wants and asks for one answer. What the
// Identity Agent alone knows (whether the lease is open, whether the AI agent
// may still act, what an allowance has left) it decides itself, and answers
// with the statuses Reason names.
//
// The published form is contracts/model-call/model-call.schema.json, with
// worked examples in model-call-vectors.json beside this file.
package modelcall

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The routes of the exchange on the Identity Agent.
const (
	// StartPath is where a body starts a call (POST). A call's answer is
	// collected (GET) and the call stopped (DELETE) at CallPath.
	StartPath = "/api/agent-host/model-calls"
)

// CallPath is where one call's answer is collected, and where it is stopped.
func CallPath(callID string) string { return StartPath + "/" + url.PathEscape(callID) }

// The limits of the exchange.
const (
	// RequestLargest bounds a call's request body, decoded.
	RequestLargest = 3 << 20
	// StartLargest bounds what an Identity Agent reads of a start's JSON: a
	// start any longer is unreadable (NoLease, 400), not TooLarge.
	StartLargest = 2 * RequestLargest
	// PartLargest bounds what one collection carries of an answer, decoded.
	PartLargest = 2 << 20
	// CollectionWait is the longest one collection waits for more of an
	// answer before it is answered with what there is.
	CollectionWait = 20 * time.Second
	// PathLongest bounds a call's path, in bytes.
	PathLongest = 256
	// AnswerLongest bounds, in tokens, how long an answer a call under an
	// allowance may ask for.
	AnswerLongest = 32768
)

// Request starts a call: what the body's brain sent, and the run's lease on
// the AI agent's sign-in.
type Request struct {
	LeaseID string            `json:"lease_id"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Header  map[string]string `json:"header,omitempty"`
	BodyB64 string            `json:"body_b64,omitempty"`
}

// Answer is what a start and every collection answer with: the provider's
// status and headers once they have arrived, the part of its answer after
// what the body has collected, where the next collection starts, and whether
// the answer is complete or, in Error, why it ended.
type Answer struct {
	CallID  string            `json:"call_id"`
	Status  int               `json:"status,omitempty"`
	Header  map[string]string `json:"header,omitempty"`
	DataB64 string            `json:"data_b64,omitempty"`
	Next    int64             `json:"next"`
	Done    bool              `json:"done"`
	Error   string            `json:"error,omitempty"`
}

// Data is the part of the answer this collection carries.
func (a Answer) Data() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(a.DataB64)
	if err != nil {
		return nil, errors.New("the part of the answer is not base64")
	}
	if len(b) > PartLargest {
		return nil, fmt.Errorf("the part of the answer is larger than %d bytes", PartLargest)
	}
	return b, nil
}

// Refusal answers a request that was not served, with an HTTP status.
// Error is a sentence the body passes to its brain.
type Refusal struct {
	Error string `json:"error"`
	// Refused says the call was refused for what it asked, or for what the
	// AI agent may do, rather than failing: see Reason.
	Refused bool `json:"refused,omitempty"`
	// NoCall says the Identity Agent no longer knows the call (status 410):
	// the brain's program makes it again.
	NoCall bool `json:"no_call,omitempty"`
}

// Stopped answers a DELETE.
type Stopped struct {
	Stopped bool `json:"stopped"`
}

// Collection is what a collection asks for: the offset to collect from, the
// run's lease, which may have been renewed since the call began, and whether
// the body already has the status and headers.
type Collection struct {
	From  int64
	Lease string
	Head  bool
}

// Path is the collection's path and query on the Identity Agent.
func (c Collection) Path(callID string) string {
	p := CallPath(callID) + "?from=" + strconv.FormatInt(c.From, 10) + "&lease=" + url.QueryEscape(c.Lease)
	if c.Head {
		p += "&head=1"
	}
	return p
}

// ParseCollection reads a collection's query, as url.ParseQuery gives it:
// an unreadable piece of the query is skipped, and where a name is given more
// than once the first counts. A from that is not a base-10 whole number, or
// is below nothing, is read as 0; head is set only by 1.
func ParseCollection(q url.Values) Collection {
	from, err := strconv.ParseInt(q.Get("from"), 10, 64)
	if err != nil || from < 0 {
		from = 0
	}
	return Collection{From: from, Lease: q.Get("lease"), Head: q.Get("head") == "1"}
}

// Reason is why a request was refused. Each answers with one HTTP status, and
// some also say "refused": true (ADR-057, Refusals).
type Reason string

const (
	// NoLease: the request names no lease, or is unreadable. 400.
	NoLease Reason = "no_lease"
	// TooLarge: the call's body is larger than RequestLargest, or is not
	// base64. 413.
	TooLarge Reason = "too_large"
	// NotAllowed: the path, query or model is not one allowed; the lease is
	// not open for this body; the AI agent may no longer act; its sign-in is
	// not a key kept here, has expired or was removed. 403, refused.
	NotAllowed Reason = "not_allowed"
	// AllowanceRule: under an allowance, the call breaks the rules on answer
	// length or the number of answers, or is not one JSON object; the
	// allowance is spent, or stopped because an earlier call's cost is not
	// known; or the provider does not say what a call costs. 403, refused.
	AllowanceRule Reason = "allowance"
	// CollectedAlready: a collection asks for part of the answer before what
	// it already collected. 409.
	CollectedAlready Reason = "collected_already"
	// Gone: the Identity Agent no longer knows the call. 410, no_call.
	Gone Reason = "gone"
	// TooManyHeld: the machine already holds as many calls for this AI agent
	// as it may. 429.
	TooManyHeld Reason = "too_many_held"
	// OneAtATime: under an allowance, another of the AI agent's calls is
	// under way or not yet counted. 429, refused.
	OneAtATime Reason = "one_at_a_time"
	// Unreadable: the AI agent's sign-in, what was lent to the run, or its
	// allowance cannot be read right now. 503, refused.
	Unreadable Reason = "unreadable"
	// NotKept: the allowance cannot be written down before the call is sent,
	// so the call was not made. 503.
	NotKept Reason = "not_kept"
	// Unreachable: no address is known here for the provider the key is
	// for. 503. A provider that is known but cannot be reached is not a
	// refusal: the call's answer ends, done, with an error saying so.
	Unreachable Reason = "unreachable"
)

// Reasons is every Reason, in the order the published table lists them.
var Reasons = []Reason{NoLease, TooLarge, NotAllowed, AllowanceRule, CollectedAlready, Gone, TooManyHeld,
	OneAtATime, Unreadable, NotKept, Unreachable}

// Status is the HTTP status a refusal for r answers with.
func (r Reason) Status() int {
	switch r {
	case NoLease:
		return http.StatusBadRequest
	case TooLarge:
		return http.StatusRequestEntityTooLarge
	case NotAllowed, AllowanceRule:
		return http.StatusForbidden
	case CollectedAlready:
		return http.StatusConflict
	case Gone:
		return http.StatusGone
	case TooManyHeld, OneAtATime:
		return http.StatusTooManyRequests
	case Unreadable, NotKept, Unreachable:
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// Refusal is the answer to a request refused for r, saying why.
func (r Reason) Refusal(why string) Refusal {
	switch r {
	case NotAllowed, AllowanceRule, OneAtATime, Unreadable:
		return Refusal{Error: why, Refused: true}
	case Gone:
		return Refusal{Error: why, NoCall: true}
	}
	return Refusal{Error: why}
}

// Error is a request refused by the checks in this package.
type Error struct {
	Reason Reason
	Why    string
}

func (e *Error) Error() string { return e.Why }

func refuse(r Reason, format string, args ...any) *Error {
	return &Error{Reason: r, Why: fmt.Sprintf(format, args...)}
}

// Route is one call a brain may make with its key: GET or POST, and a path.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// ModelsPath is the provider's list of models. A route GET ModelsPath also
// allows reading one model by name, GET ModelsPath/{model}, whose name may
// hold a slash.
const ModelsPath = "/v1/models"

// PlainPath reports whether p is a path the exchange passes on: at most
// PathLongest bytes, starting with /, holding only letters, digits and
// . - _ : / ~, and unchanged by cleaning (no empty, . or .. segment, and no
// trailing slash). Nothing escaped, no query and no fragment can be in it.
func PlainPath(p string) bool {
	return len(p) <= PathLongest && strings.HasPrefix(p, "/") && plain(p) && path.Clean(p) == p
}

// plain reports whether s holds only letters, digits and . - _ : / ~.
func plain(s string) bool {
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".-_:/~", r)) {
			return false
		}
	}
	return true
}

// RouteAllowed reports whether method p is one of routes: the path must be
// plain (PlainPath) and the method, in any case, GET or POST as the route
// names it. Which routes a sign-in's provider has is the Identity Agent's to
// say; this checks a call against them.
func RouteAllowed(routes []Route, method, p string) bool {
	if !PlainPath(p) {
		return false
	}
	method = asciiUpper(method)
	for _, r := range routes {
		if r.Method != method {
			continue
		}
		if p == r.Path || (method == http.MethodGet && r.Path == ModelsPath && strings.HasPrefix(p, ModelsPath+"/")) {
			return true
		}
	}
	return false
}

// queryParameters are the query parameters a call may carry, by what each
// may be: beta=true, which asks for a provider's beta features, and the
// paging of a list of models.
var queryParameters = map[string]func(string) bool{
	"beta":      func(v string) bool { return v == "true" },
	"limit":     func(v string) bool { return len(v) <= 4 && strings.Trim(v, "0123456789") == "" },
	"after_id":  func(v string) bool { return len(v) <= 128 && plain(v) },
	"before_id": func(v string) bool { return len(v) <= 128 && plain(v) },
}

// QueryParameters are the names of the query parameters a call may carry.
func QueryParameters() []string {
	out := make([]string, 0, len(queryParameters))
	for k := range queryParameters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Query is a call's query as it is sent on, or why it is refused: only the
// parameters QueryParameters names, each at most once, each as it allows
// (beta only as true; limit as at most four digits; after_id and before_id as
// at most 128 bytes of letters, digits and . - _ : / ~). It is sent on
// re-encoded, sorted by name.
func Query(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return "", refuse(NotAllowed, "the call's query is unreadable")
	}
	for _, k := range sortedKeys(v) {
		vals := v[k]
		ok := queryParameters[k]
		if ok == nil || len(vals) != 1 || !ok(vals[0]) {
			return "", refuse(NotAllowed, "the query parameter %q is not one a model call may carry", printable(k, 40))
		}
	}
	return v.Encode(), nil
}

// HeaderNames are the headers of a call that travel on to the provider: what
// describes the call, and never how the brain proved itself, which the
// Identity Agent replaces with the key.
var HeaderNames = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

// AnswerHeaderNames are the headers of the provider's answer that travel back
// to the brain, in an Answer's header; no other does.
var AnswerHeaderNames = []string{"Content-Type", "Retry-After", "Request-Id", "X-Request-Id"}

// Headers are the headers of h that travel on, named as HeaderNames names
// them, matched in any ASCII case. Any other header is dropped, not refused,
// and so is one with no value. Where h names one header more than once, in different cases, the
// first by byte order of its name with a value is the one kept. Nil when
// none travels.
func Headers(h map[string]string) map[string]string {
	var out map[string]string
	keys := sortedKeys(h)
	for _, name := range HeaderNames {
		for _, k := range keys {
			if asciiEqualFold(k, name) && h[k] != "" {
				if out == nil {
					out = map[string]string{}
				}
				out[name] = h[k]
				break
			}
		}
	}
	return out
}

// Body is the call's request body, decoded: refused as TooLarge where it is
// not standard base64 with padding (a line break in it included) or is larger
// than RequestLargest.
func (q Request) Body() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(q.BodyB64)
	if err != nil || strings.ContainsAny(q.BodyB64, "\r\n") || len(b) > RequestLargest {
		return nil, refuse(TooLarge, "this model call is too large or unreadable")
	}
	return b, nil
}

// Reads reports whether a call with method only reads (a list of models, or
// one model asked about by name): it is not a model call, costs nothing, and
// is never held to an allowance. Only a POST is a model call.
func Reads(method string) bool { return asciiUpper(method) != http.MethodPost }

// ModelNamed is the one model a call's body names, read the way a provider
// reads it: the body must be one JSON object naming its model once, as
// "model" spelt exactly, with a string. A second "model", one spelt in
// another ASCII case, or a list of models to fall back on ("models", in any
// ASCII case)
// is refused, so what is checked is what the provider reads. The name is ""
// where none is given.
func ModelNamed(body []byte) (string, error) {
	named, seen := "", false
	err := eachField(body, func(k string, v json.RawMessage) error {
		switch {
		case asciiEqualFold(k, "models"):
			return errors.New("this call names a list of models to fall back on")
		case !asciiEqualFold(k, "model"):
			return nil
		case k != "model" || seen:
			return errors.New("this call names its model more than once, or not as \"model\"")
		}
		seen = true
		if err := json.Unmarshal(v, &named); err != nil {
			return errors.New("this call's model is not a name")
		}
		return nil
	})
	if errors.Is(err, errNotOneObject) {
		return "", errors.New("this call is not one JSON object, so which model it calls is not known")
	}
	return named, err
}

// CheckModel refuses a model call that names a model other than chosen
// (trimmed of white space), or none, or more than one. Where no model is
// chosen (chosen is empty), or the call only reads, any call passes.
func CheckModel(chosen, method string, body []byte) error {
	chosen = strings.TrimSpace(chosen)
	if chosen == "" || Reads(method) {
		return nil
	}
	named, err := ModelNamed(body)
	if err != nil {
		return refuse(NotAllowed, "this AI agent calls only its chosen model, %s; %s", printable(chosen, 128), err.Error())
	}
	if named != chosen {
		if named == "" {
			named = "no model"
		}
		return refuse(NotAllowed, "this AI agent calls only its chosen model, %s; this call named %s",
			printable(chosen, 128), printable(named, 128))
	}
	return nil
}

// AnswerBoundNames are the ways a call says how long an answer it wants.
var AnswerBoundNames = []string{"max_tokens", "max_completion_tokens", "max_output_tokens"}

// AnswerCountNames are the ways a call asks for more than one answer.
var AnswerCountNames = []string{"n", "best_of"}

// AnswerBound is how long an answer a model call asks for, in tokens, as a
// call under an allowance must say it, or why it is refused: the body is one
// JSON object; it gives at least one of AnswerBoundNames, each spelt exactly
// and at most once, as a whole number from 1 to AnswerLongest, and the
// largest given counts; and each of AnswerCountNames it gives, in any ASCII
// case, is 1. Only the object's own fields are read, not those nested in them.
func AnswerBound(body []byte) (int, error) {
	seen := map[string]bool{}
	most := 0
	err := eachField(body, func(k string, v json.RawMessage) error {
		for _, m := range AnswerCountNames {
			if asciiEqualFold(k, m) {
				var n float64
				if err := json.Unmarshal(v, &n); err != nil || n != 1 {
					return fmt.Errorf("this call asks for more than one answer (%s)", m)
				}
			}
		}
		name := ""
		for _, n := range AnswerBoundNames {
			if asciiEqualFold(k, n) {
				name = n
			}
		}
		if name == "" {
			return nil
		}
		if k != name || seen[name] {
			return errors.New("this call says how long an answer it wants more than once, or not as the provider spells it")
		}
		seen[name] = true
		var n float64
		if err := json.Unmarshal(v, &n); err != nil || n != math.Trunc(n) || n < 1 || n > AnswerLongest {
			return fmt.Errorf("this call's answer length is not a whole number of tokens from 1 to %d", AnswerLongest)
		}
		if int(n) > most {
			most = int(n)
		}
		return nil
	})
	if errors.Is(err, errNotOneObject) {
		return 0, refuse(AllowanceRule, "this call is not one JSON object")
	}
	if err != nil {
		return 0, refuse(AllowanceRule, "%s", err.Error())
	}
	if most == 0 {
		return 0, refuse(AllowanceRule, "while an allowance is set, a model call names how long an answer it wants, "+
			"at most %d tokens, so no one call can cost without bound", AnswerLongest)
	}
	return most, nil
}

// errNotOneObject is a body that is not exactly one JSON object.
var errNotOneObject = errors.New("not one JSON object")

// eachField calls f with each of the fields of body's one JSON object, in
// order, keys exactly as written. It refuses with errNotOneObject a body that
// is not UTF-8, or is anything but one whole object, with nothing after it
// but white space.
func eachField(body []byte, f func(k string, v json.RawMessage) error) error {
	if !utf8.Valid(body) {
		return errNotOneObject
	}
	d := json.NewDecoder(bytes.NewReader(body))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return errNotOneObject
	}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return errNotOneObject
		}
		k, _ := t.(string)
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return errNotOneObject
		}
		if err := f(k, v); err != nil {
			return err
		}
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return errNotOneObject
	}
	if _, err := d.Token(); err != io.EOF {
		return errNotOneObject
	}
	return nil
}

// Rules are what a call is checked against: the routes the sign-in's
// provider has, the model chosen for the AI agent (empty for none), and
// whether the AI agent's model calls are held to an allowance.
type Rules struct {
	Routes    []Route `json:"routes"`
	Model     string  `json:"model,omitempty"`
	Allowance bool    `json:"allowance,omitempty"`
}

// Call is a request that passed Check, as the Identity Agent sends it on.
type Call struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  string            `json:"query,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Body   []byte            `json:"-"`
	// Reads says the call only reads, and is never held to an allowance.
	Reads bool `json:"reads,omitempty"`
	// Bound is how long an answer a model call under an allowance asks for,
	// in tokens; 0 when it is not held to one.
	Bound int `json:"bound,omitempty"`
}

// Check is everything the request alone decides, composed in one place: a
// lease is named (NoLease); the body is base64 and not too large (TooLarge);
// the route, query and model are ones allowed (NotAllowed); and, under an
// allowance, a model call says how long an answer it wants and asks for one
// answer (AllowanceRule). Of these, the first broken is the one answered. A
// refusal is an *Error, whose Reason gives the status.
//
// What only the Identity Agent knows (the lease, the AI agent's standing,
// how many calls it holds, what an allowance has left) is not checked here,
// and an Identity Agent may answer its own checks before any of these, or
// between them: it calls the checks below one by one where it needs to, and
// Check is their composed reference, the one the published vectors hold.
func (r Rules) Check(q Request) (Call, error) {
	if q.LeaseID == "" {
		return Call{}, refuse(NoLease, "name the run's lease and the call to make")
	}
	body, err := q.Body()
	if err != nil {
		return Call{}, err
	}
	method := asciiUpper(q.Method)
	if !RouteAllowed(r.Routes, method, q.Path) {
		return Call{}, refuse(NotAllowed, "%s %s is not a model call this AI agent's sign-in may make",
			printable(method, 10), printable(q.Path, 80))
	}
	query, err := Query(q.Query)
	if err != nil {
		return Call{}, err
	}
	if err := CheckModel(r.Model, method, body); err != nil {
		return Call{}, err
	}
	c := Call{Method: method, Path: q.Path, Query: query, Header: Headers(q.Header), Body: body, Reads: Reads(method)}
	if r.Allowance && !c.Reads {
		if c.Bound, err = AnswerBound(body); err != nil {
			return Call{}, err
		}
	}
	return c, nil
}

// asciiEqualFold reports whether a and b are the same but for the case of
// ASCII letters. Nothing outside ASCII folds, so every implementation reads a
// name the same way.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if asciiLower(a[i]) != asciiLower(b[i]) {
			return false
		}
	}
	return true
}

func asciiLower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// asciiUpper is s with its ASCII letters upper-cased, and nothing else.
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// printable is s as a refusal may quote it: at most n bytes, and nothing that
// is not printable on one line.
func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("…")
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
