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
// call says how long an answer it wants and asks for one answer. Which routes,
// headers, query parameters and answer-length fields a provider has is not
// fixed here: the Identity Agent lists them, per provider, in a Profile, and
// the checks are run against it. What the Identity Agent alone knows (whether
// the lease is open, whether the AI agent may still act, what an allowance has
// left) it decides itself, and answers with the statuses Reason names.
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
	// BorrowPath is where a body borrows its AI agent's sign-in for one run
	// (POST), and is given the run's lease. It keeps the lease with POST
	// BorrowPath/renew and gives it back with POST BorrowPath/return, each
	// naming lease_id.
	BorrowPath = "/api/agent-host/brain-sign-in"
)

// CallPath is where one call's answer is collected, and where it is stopped.
func CallPath(callID string) string { return StartPath + "/" + url.PathEscape(callID) }

// ThroughIdentityAgent is the value of model_calls in what a body sends when
// it borrows its AI agent's sign-in, saying it makes its brain's model calls
// through the Identity Agent; the Identity Agent's answer carries the same.
// A body that does not say it is refused (409, "update_agent_host": true) and
// never lent a key that stays with the Identity Agent.
const ThroughIdentityAgent = "through_identity_agent"

// Borrowing is what a body's request to borrow its AI agent's sign-in says of
// how it makes model calls.
type Borrowing struct {
	ModelCalls string `json:"model_calls,omitempty"`
}

// Borrowed answers a borrow: the run's lease, until when it holds unless
// renewed (RFC 3339), how often to renew it, and, for a key that stays with
// the Identity Agent, model_calls saying the calls go through it. No key is
// in it.
type Borrowed struct {
	LeaseID           string `json:"lease_id"`
	LeaseExpiresAt    string `json:"lease_expires_at"`
	RenewEverySeconds int    `json:"renew_every_seconds"`
	ModelCalls        string `json:"model_calls,omitempty"`
}

// LeaseRequest renews (POST BorrowPath/renew) or gives back (POST
// BorrowPath/return) a lease. SignIn, on a return, is a sign-in file the
// run's program refreshed, where the run was lent one; a run whose key stays
// with the Identity Agent has none.
type LeaseRequest struct {
	LeaseID string `json:"lease_id"`
	SignIn  string `json:"sign_in,omitempty"`
}

// Renewed answers a renewal: the same lease, held until a new time.
type Renewed struct {
	LeaseID        string `json:"lease_id"`
	LeaseExpiresAt string `json:"lease_expires_at"`
}

// Returned answers a return.
type Returned struct {
	Returned bool `json:"returned"`
}

// BorrowRefusal answers a borrow, renewal or return that was refused: 404
// with NoLease for a lease the Identity Agent does not hold open (lapsed,
// returned or never lent); 409 with UpdateAgentHost for a body that did not
// say it makes its model calls through the Identity Agent, where the key
// stays there.
type BorrowRefusal struct {
	Error           string `json:"error"`
	NoLease         bool   `json:"no_lease,omitempty"`
	UpdateAgentHost bool   `json:"update_agent_host,omitempty"`
}

// ThroughIdentityAgent reports whether b says model calls go through the
// Identity Agent.
func (b Borrowing) ThroughIdentityAgent() bool { return b.ModelCalls == ThroughIdentityAgent }

// The limits of the exchange.
const (
	// RequestLargest bounds a call's request body, decoded.
	RequestLargest = 3 << 20
	// StartLargest bounds a start's JSON as it arrives: a start any longer
	// is TooLarge (413).
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
	// DepthDeepest bounds how deeply a body read for its fields may nest
	// arrays and objects, the body's own object counting as 1.
	DepthDeepest = 1000
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

// ParseRequest reads a start as it arrives. One longer than StartLargest is
// TooLarge. One that is not UTF-8, nests deeper than DepthDeepest, escapes a
// lone surrogate (\uD800 to \uDFFF not in a pair) anywhere, is not one JSON
// object, or whose lease_id,
// method, path, query or body_b64 is not a string (or null), or whose header
// is not an object of strings (or null), is unreadable (NoLease). Fields are
// matched by exact name; any other field is ignored.
func ParseRequest(raw []byte) (Request, error) {
	if len(raw) > StartLargest {
		return Request{}, refuse(TooLarge, "this model call is too large or unreadable")
	}
	unreadable := refuse(NoLease, "name the run's lease and the call to make")
	if !utf8.Valid(raw) || depth(raw) > DepthDeepest || loneSurrogate(raw) {
		return Request{}, unreadable
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return Request{}, unreadable
	}
	var q Request
	for name, dst := range map[string]*string{"lease_id": &q.LeaseID, "method": &q.Method, "path": &q.Path,
		"query": &q.Query, "body_b64": &q.BodyB64} {
		if v, ok := fields[name]; ok {
			var s *string
			if err := json.Unmarshal(v, &s); err != nil {
				return Request{}, unreadable
			}
			if s != nil {
				*dst = *s
			}
		}
	}
	if v, ok := fields["header"]; ok {
		var h map[string]*string
		if err := json.Unmarshal(v, &h); err != nil {
			return Request{}, unreadable
		}
		for k, s := range h {
			if q.Header == nil {
				q.Header = map[string]string{}
			}
			if s != nil {
				q.Header[k] = *s
			} else {
				q.Header[k] = ""
			}
		}
	}
	return q, nil
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
// is below nothing, is read as 0; head is set only by 1. An empty lease keeps
// the one the call has.
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
	// TooLarge: the start is longer than StartLargest, or the call's body is
	// larger than RequestLargest or is not base64. 413.
	TooLarge Reason = "too_large"
	// NotAllowed: the method, path, query or model is not one allowed; the
	// lease is not open for this body; the AI agent may no longer act; its
	// sign-in is not a key kept here, has expired or was removed. 403,
	// refused.
	NotAllowed Reason = "not_allowed"
	// AllowanceRule: under an allowance, the call breaks the rules on answer
	// length or the number of answers, or is not one JSON object; the
	// allowance is spent, or stopped because an earlier call's cost is not
	// known; or the provider does not say what a call costs. 403, refused.
	AllowanceRule Reason = "allowance"
	// CollectedAlready: a collection asks again for part of the answer it has
	// already collected. 409.
	CollectedAlready Reason = "collected_already"
	// Gone: the Identity Agent no longer knows the call. 410, no_call.
	Gone Reason = "gone"
	// TooManyHeld: the machine already holds as many calls for this AI agent
	// as it may, or the Identity Agent holds as many as it may across all its
	// machines. 429.
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

// Profile is what the Identity Agent lists, for one provider, of the calls a
// brain signed in with that provider's key may make: the routes, the headers
// that travel on and back, the query parameters, and how a model call says
// how long an answer it wants and how many answers. The checks in this
// package are the mechanism; the profile is the provider's data.
type Profile struct {
	Routes []Route `json:"routes"`
	// ModelsPath is the provider's list of models, where it has one: a GET
	// route at it also allows reading one model by name, GET
	// ModelsPath/{model}, whose name may hold a slash.
	ModelsPath string `json:"models_path,omitempty"`
	// Headers are the headers of a call that travel on to the provider:
	// what describes the call, never how the brain proved itself.
	Headers []string `json:"headers"`
	// AnswerHeaders are the headers of the provider's answer that travel
	// back to the brain.
	AnswerHeaders []string         `json:"answer_headers"`
	Parameters    []QueryParameter `json:"query"`
	// AnswerBoundNames are the fields a model call says how long an answer
	// it wants by; AnswerCountNames those it asks for more than one answer
	// by.
	AnswerBoundNames []string `json:"answer_bound_names"`
	AnswerCountNames []string `json:"answer_count_names"`
}

// Validate reports why p is not a profile the checks can read, or nothing:
// each route's method is upper case; each of Headers and AnswerHeaders is
// an HTTP header name (HeaderName); the names in each of Headers,
// AnswerHeaders, Parameters, AnswerBoundNames and AnswerCountNames are
// distinct ignoring ASCII case; and each query parameter gives exactly one of
// Value (not empty), Digits or Plain (each at least 1). A profile that breaks
// these allows no call.
func (pr Profile) Validate() error {
	for _, r := range pr.Routes {
		if r.Method == "" || r.Method != asciiUpper(r.Method) {
			return fmt.Errorf("the profile's route %s %s does not name its method in upper case", printable(r.Method, 10), printable(r.Path, 80))
		}
	}
	for _, h := range append(append([]string(nil), pr.Headers...), pr.AnswerHeaders...) {
		if !HeaderName(h) {
			return fmt.Errorf("the profile's header %q is not an HTTP header name", printable(h, 40))
		}
	}
	names := make([]string, len(pr.Parameters))
	for i, q := range pr.Parameters {
		names[i] = q.Name
		given := 0
		if q.Value != "" {
			given++
		}
		if q.Digits != 0 {
			given++
		}
		if q.Plain != 0 {
			given++
		}
		if given != 1 || q.Digits < 0 || q.Plain < 0 {
			return fmt.Errorf("the profile's query parameter %q does not give exactly one of value, digits or plain", printable(q.Name, 40))
		}
	}
	for what, list := range map[string][]string{"headers": pr.Headers, "answer headers": pr.AnswerHeaders,
		"query parameters": names, "answer-length names": pr.AnswerBoundNames, "answer-count names": pr.AnswerCountNames} {
		for i := range list {
			for j := 0; j < i; j++ {
				if asciiEqualFold(list[i], list[j]) {
					return fmt.Errorf("the profile's %s name %q twice, ignoring case", what, printable(list[i], 40))
				}
			}
		}
	}
	return nil
}

// Route is one call a brain may make with its key: GET or POST, and a path.
// A counting route (Counts) is a POST that costs nothing, such as counting a
// request's tokens: like a read, it is never held to an allowance.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Counts bool   `json:"counts,omitempty"`
}

// QueryParameter is one query parameter a call may carry, and what its value
// may be: exactly Value, where Value is set; or at most Digits of the digits
// 0-9, where Digits is set; or at most Plain bytes of the characters a plain
// path holds, where Plain is set. An empty value is allowed by Digits and by
// Plain.
type QueryParameter struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Digits int    `json:"digits,omitempty"`
	Plain  int    `json:"plain,omitempty"`
}

func (p QueryParameter) allows(v string) bool {
	switch {
	case p.Value != "":
		return v == p.Value
	case p.Digits > 0:
		return len(v) <= p.Digits && strings.Trim(v, "0123456789") == ""
	case p.Plain > 0:
		return len(v) <= p.Plain && plain(v)
	}
	return false
}

// PlainPath reports whether p is a path the exchange passes on: at most
// PathLongest bytes, starting with /, holding only the ASCII letters A-Z and
// a-z, the digits 0-9 and . - _ : / ~, and unchanged by cleaning (no empty,
// . or .. segment, and no trailing slash). Nothing escaped, no query and no
// fragment can be in it.
func PlainPath(p string) bool {
	return len(p) <= PathLongest && strings.HasPrefix(p, "/") && plain(p) && path.Clean(p) == p
}

// plain reports whether s holds only A-Z, a-z, 0-9 and . - _ : / ~.
func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte(".-_:/~", c) >= 0) {
			return false
		}
	}
	return true
}

// Methods are the only methods a call may use, whatever routes a profile
// lists.
var Methods = []string{http.MethodGet, http.MethodPost}

// Route is the route of p's that method p takes, if it takes one: the method,
// in any ASCII case, must be GET or POST and the route's; the path must be
// plain (PlainPath) and the route's, or, for GET, below ModelsPath where a
// GET route is at ModelsPath.
func (pr Profile) Route(method, p string) (Route, bool) {
	method = asciiUpper(method)
	if (method != http.MethodGet && method != http.MethodPost) || !PlainPath(p) {
		return Route{}, false
	}
	for _, r := range pr.Routes {
		if r.Method != method {
			continue
		}
		if p == r.Path ||
			(method == http.MethodGet && pr.ModelsPath != "" && r.Path == pr.ModelsPath && strings.HasPrefix(p, pr.ModelsPath+"/")) {
			return r, true
		}
	}
	return Route{}, false
}

// Query is a call's query as it is sent on, or why it is refused: only the
// parameters the profile names (by exact name), each at most once, each as
// its QueryParameter allows. It is sent on re-encoded, sorted by name.
func (pr Profile) Query(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return "", refuse(NotAllowed, "the call's query is unreadable")
	}
	for _, k := range sortedKeys(v) {
		vals := v[k]
		var allowed *QueryParameter
		for i := range pr.Parameters {
			if pr.Parameters[i].Name == k {
				allowed = &pr.Parameters[i]
				break
			}
		}
		if allowed == nil || len(vals) != 1 || !allowed.allows(vals[0]) {
			return "", refuse(NotAllowed, "the query parameter %q is not one a model call may carry", printable(k, 40))
		}
	}
	return v.Encode(), nil
}

// NeverPassedOn are headers of a call that never travel on, whatever a
// profile lists: what proves who the brain is or would set a credential, and
// what belongs to one connection only. The Identity Agent sets its own. A name is compared
// ignoring ASCII case and counting an underscore as a hyphen.
var NeverPassedOn = []string{"Authorization", "Authentication", "Proxy-Authorization", "Cookie", "Cookie2",
	"Set-Cookie", "Set-Cookie2", "X-Api-Key", "Api-Key", "X-Auth-Token", "Host", "Content-Length",
	"Transfer-Encoding", "Connection", "Keep-Alive", "Proxy-Connection", "TE", "Trailer", "Upgrade", "Expect"}

// NeverPassedBack are headers of the provider's answer that never travel
// back, whatever a profile lists: the same as never travel on, Set-Cookie
// and Set-Cookie2 among them.
var NeverPassedBack = append([]string(nil), NeverPassedOn...)

// PassedHeaders are the headers of h that travel on, named as the profile
// names them, matched in any ASCII case. A header in NeverPassedOn never
// does, whatever the profile lists. Any other header is dropped, not refused,
// and so is one with no value. Where h names one header more than once, in
// different cases, the first by byte order of its name among those with a
// value is the one kept. Nil when none travels.
func (pr Profile) PassedHeaders(h map[string]string) map[string]string {
	return pick(pr.Headers, NeverPassedOn, h)
}

// AnswerHeadersBack are the headers of the provider's answer h that travel
// back to the brain, by the same rule as PassedHeaders, NeverPassedBack in
// place of NeverPassedOn.
func (pr Profile) AnswerHeadersBack(h map[string]string) map[string]string {
	return pick(pr.AnswerHeaders, NeverPassedBack, h)
}

func pick(names, never []string, h map[string]string) map[string]string {
	var out map[string]string
	keys := sortedKeys(h)
	for _, name := range names {
		if neverPassed(name, never) {
			continue
		}
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

// Reads reports whether a call with method only reads: exactly GET, in any
// ASCII case. It is not a model call, costs nothing, and is never held to an
// allowance.
func Reads(method string) bool { return asciiUpper(method) == http.MethodGet }

// ModelNamed is the one model a call's body names, read the way a provider
// reads it: the body must be one JSON object naming its model once, as
// "model" spelt exactly, with a string. A second "model", one spelt in
// another ASCII case, or a list of models to fall back on ("models", in any
// ASCII case) is refused, so what is checked is what the provider reads. The
// name is "" where none is given.
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

// AnswerBound is how long an answer a model call asks for, in tokens, as a
// call under an allowance must say it, or why it is refused: the body is one
// JSON object; it gives at least one of the profile's AnswerBoundNames, each
// spelt exactly and at most once, as a whole number from 1 to AnswerLongest,
// and the largest given counts; and each of its AnswerCountNames it gives, in
// any ASCII case, is 1. Only the object's own fields are read, not those
// nested in them.
func (pr Profile) AnswerBound(body []byte) (int, error) {
	seen := map[string]bool{}
	most := 0
	err := eachField(body, func(k string, v json.RawMessage) error {
		for _, m := range pr.AnswerCountNames {
			if asciiEqualFold(k, m) {
				var n float64
				if err := json.Unmarshal(v, &n); err != nil || n != 1 {
					return fmt.Errorf("this call asks for more than one answer (%s)", m)
				}
			}
		}
		name := ""
		for _, n := range pr.AnswerBoundNames {
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
// is not UTF-8, nests deeper than DepthDeepest, or is anything but one whole
// object, with nothing after it but white space.
func eachField(body []byte, f func(k string, v json.RawMessage) error) error {
	if !utf8.Valid(body) || depth(body) > DepthDeepest {
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

// loneSurrogate reports whether b escapes, anywhere, a UTF-16 surrogate that
// is not half of a pair: \uD800 to \uDBFF not followed by \uDC00 to \uDFFF,
// or \uDC00 to \uDFFF on its own.
func loneSurrogate(b []byte) bool {
	code := func(i int) (rune, bool) {
		if i+6 > len(b) || b[i] != '\\' || b[i+1] != 'u' {
			return 0, false
		}
		n, err := strconv.ParseUint(string(b[i+2:i+6]), 16, 32)
		return rune(n), err == nil
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		r, ok := code(i)
		if !ok {
			i++ // an escaped character, skipped whole
			continue
		}
		switch {
		case 0xD800 <= r && r <= 0xDBFF:
			if lo, ok := code(i + 6); ok && 0xDC00 <= lo && lo <= 0xDFFF {
				i += 11
				continue
			}
			return true
		case 0xDC00 <= r && r <= 0xDFFF:
			return true
		}
		i += 5
	}
	return false
}

// depth is the deepest b nests [ and { outside strings.
func depth(b []byte) int {
	n, most, inString, escaped := 0, 0, false, false
	for _, c := range b {
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case inString && c == '"':
			inString = false
		case inString:
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			n++
			if n > most {
				most = n
			}
		case c == ']' || c == '}':
			n--
		}
	}
	return most
}

// Rules are what a call is checked against: the provider's profile, the
// model chosen for the AI agent (empty for none), and whether the AI agent's
// model calls are held to an allowance.
type Rules struct {
	Profile   Profile `json:"profile"`
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
	// Reads says the call only reads (a GET); Counts that it takes a
	// counting route. Neither is held to an allowance.
	Reads  bool `json:"reads,omitempty"`
	Counts bool `json:"counts,omitempty"`
	// Bound is how long an answer a model call under an allowance asks for,
	// in tokens; 0 when it is not held to one.
	Bound int `json:"bound,omitempty"`
}

// Check is everything the request alone decides, composed in one place: a
// lease is named (NoLease); the body is base64 and not too large (TooLarge);
// the profile is one the checks can read, and the method, route, query and
// model are ones allowed (NotAllowed); and,
// under an allowance, a model call says how long an answer it wants and asks
// for one answer (AllowanceRule). Of these, the first broken is the one
// answered. A refusal is an *Error, whose Reason gives the status.
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
	if err := r.Profile.Validate(); err != nil {
		return Call{}, refuse(NotAllowed, "this AI agent's sign-in allows no call: %s", err.Error())
	}
	method := asciiUpper(q.Method)
	route, ok := r.Profile.Route(method, q.Path)
	if !ok {
		return Call{}, refuse(NotAllowed, "%s %s is not a model call this AI agent's sign-in may make",
			printable(method, 10), printable(q.Path, 80))
	}
	query, err := r.Profile.Query(q.Query)
	if err != nil {
		return Call{}, err
	}
	if err := CheckModel(r.Model, method, body); err != nil {
		return Call{}, err
	}
	c := Call{Method: method, Path: q.Path, Query: query, Header: r.Profile.PassedHeaders(q.Header), Body: body,
		Reads: Reads(method), Counts: route.Counts && !Reads(method)}
	if r.Allowance && !c.Reads && !c.Counts {
		if c.Bound, err = r.Profile.AnswerBound(body); err != nil {
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

// neverPassed reports whether name is in never, ignoring ASCII case and
// counting an underscore as a hyphen, so no spelling of a header that never
// travels gets through.
func neverPassed(name string, never []string) bool {
	for _, x := range never {
		if asciiEqualFold(strings.ReplaceAll(name, "_", "-"), strings.ReplaceAll(x, "_", "-")) {
			return true
		}
	}
	return false
}

// HeaderName reports whether s is a valid HTTP header name (RFC 9110): one
// or more of the token characters A-Z, a-z, 0-9 and ! # $ % & ' * + - . ^ _ ` | ~.
func HeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
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
