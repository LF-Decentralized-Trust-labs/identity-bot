package modelcall

import (
	_ "embed"
	"encoding/json"
)

// modelCallVectors are calls a body might send, each with what the checks in
// this package decide of it, and the exchange's other worked examples: the
// headers that travel on, the collection paths, the refusal statuses and some
// answers. It is the file another implementation of a body, or of an Identity
// Agent's side of the exchange, tests itself against. It ships inside this
// module so a Go implementation reads the same file instead of keeping a copy.
//
//go:embed model-call-vectors.json
var modelCallVectors []byte

// VectorSet is the published set of model-call vectors.
type VectorSet struct {
	About string `json:"about"`

	Limits            Limits   `json:"limits"`
	HeaderNames       []string `json:"header_names"`
	AnswerHeaderNames []string `json:"answer_header_names"`
	QueryParameters   []string `json:"query_parameters"`
	AnswerBoundNames  []string `json:"answer_bound_names"`
	AnswerCountNames  []string `json:"answer_count_names"`

	// Routes are the routes every start below is checked against: an example
	// of a sign-in's provider's routes, not a list any provider has.
	Routes []Route `json:"routes"`

	Starts            []StartVector           `json:"starts"`
	Headers           []HeaderVector          `json:"headers"`
	Collections       []CollectionVector      `json:"collections"`
	CollectionQueries []CollectionQueryVector `json:"collection_queries"`
	Refusals          []RefusalVector         `json:"refusals"`
	Answers           []AnswerVector          `json:"answers"`
}

// Limits are the exchange's limits, as the vectors state them.
type Limits struct {
	RequestLargest        int `json:"request_largest"`
	StartLargest          int `json:"start_largest"`
	PartLargest           int `json:"part_largest"`
	PathLongest           int `json:"path_longest"`
	AnswerLongest         int `json:"answer_longest"`
	CollectionWaitSeconds int `json:"collection_wait_seconds"`
}

// StartVector is one start: the rules it is checked under, the request, and
// what is decided of it.
type StartVector struct {
	Name string `json:"name"`
	// Model is the model chosen for the AI agent, if one is; Allowance says
	// its model calls are held to an allowance.
	Model     string `json:"model,omitempty"`
	Allowance bool   `json:"allowance,omitempty"`
	// Body is the call's body as text, whose base64 is the request's
	// body_b64. Where PadTo is set, the body is Body followed by spaces to
	// PadTo bytes, and body_b64 is left out of the file for its size.
	Body    string  `json:"body,omitempty"`
	PadTo   int     `json:"pad_to,omitempty"`
	Request Request `json:"request"`
	Outcome Outcome `json:"outcome"`
}

// Outcome is what the checks decide of a start: the call as it is sent on,
// or the refusal's reason, status, and whether it says "refused": true.
type Outcome struct {
	Allowed bool   `json:"allowed"`
	Call    *Call  `json:"call,omitempty"`
	Reason  Reason `json:"reason,omitempty"`
	Status  int    `json:"status,omitempty"`
	Refused bool   `json:"refused,omitempty"`
}

// HeaderVector is the headers a body sent, and those that travel on.
type HeaderVector struct {
	Name   string            `json:"name"`
	Sent   map[string]string `json:"sent"`
	Passed map[string]string `json:"passed,omitempty"`
}

// CollectionVector is a collection, and the path it is asked at.
type CollectionVector struct {
	Name   string `json:"name"`
	CallID string `json:"call_id"`
	From   int64  `json:"from"`
	Lease  string `json:"lease"`
	Head   bool   `json:"head"`
	Path   string `json:"path"`
}

// CollectionQueryVector is a collection's query, and what an Identity Agent
// reads from it.
type CollectionQueryVector struct {
	Name  string `json:"name"`
	Query string `json:"query"`
	From  int64  `json:"from"`
	Lease string `json:"lease"`
	Head  bool   `json:"head"`
}

// RefusalVector is one Reason, its status, and what its answer says.
type RefusalVector struct {
	Reason  Reason `json:"reason"`
	Status  int    `json:"status"`
	Refused bool   `json:"refused"`
	NoCall  bool   `json:"no_call"`
}

// AnswerVector is an answer as a start or a collection gives it, to a
// collection from From. Data is the part of the provider's answer it carries,
// as text, so data_b64 is its base64 and next is From plus its length in
// bytes.
type AnswerVector struct {
	Name   string `json:"name"`
	From   int64  `json:"from"`
	Data   string `json:"data"`
	Answer Answer `json:"answer"`
}

// Vectors returns the published model-call vectors.
func Vectors() (VectorSet, error) {
	var v VectorSet
	err := json.Unmarshal(modelCallVectors, &v)
	return v, err
}
