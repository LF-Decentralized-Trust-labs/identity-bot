// Package coretypes holds the plain data the core and the add-ons built in
// this module hand each other: who authorised a request, the people who sign
// for an identity, and references to the assets and grants an identity holds.
// It imports nothing of the server's, so both sides can name them.
package coretypes

// Authority is who authorised a credential.
type Authority struct {
	// ControllerGrant is the Controller Grant of the machine the request came
	// from. Empty for an owner-signed request, and for a machine whose grant
	// is waiting for the device that holds the identity's key.
	ControllerGrant string
	// Request is the request as it was signed. Nil when the identity's own
	// device asked without signing.
	Request *SignedRequest
	// About is what the request named as the thing it acts on.
	About string
}

// SignedRequest is a request exactly as it was signed, with its body.
type SignedRequest struct {
	Kind      string `json:"kind"`
	Signer    string `json:"signer"`
	Signed    string `json:"signed"`
	Signature string `json:"signature"`
	Body      string `json:"body"`
}

// Signer is one of the people who sign for this identity, and how it knows
// them: "owner" (named in its own key log) or "signer". Credential is the
// signature with which they founded the organisation.
type Signer struct {
	AID        string
	Standing   string
	Credential string
	Name       string
}

// ControllerProof is a controller's signature over a request, as proof of what
// the person behind it asked: the controller, its key as its grant records it,
// the string it signed and the signature, the request body byte for byte, and
// its Controller Grant credential.
type ControllerProof struct {
	Controller      string
	PublicKey       string
	SignedString    string
	Signature       string
	RequestBytes    []byte
	ControllerGrant string
}

// AgentRef is an AI agent an identity holds, as its asset names it.
type AgentRef struct {
	ID           string
	PairwiseAID  string
	DelegatorAID string
	Capabilities []string
}

// GrantRef is a grant an identity issued, by its SAID.
type GrantRef struct{ SAID string }

// TB is what a test fixture asks of the test running it: what *testing.T
// gives. It is declared here so the fixtures the core shares with its
// add-ons' tests can be written outside a _test.go file without importing
// the testing package into the server.
type TB interface {
	Helper()
	Name() string
	TempDir() string
	Cleanup(func())
	Setenv(key, value string)
	Log(args ...any)
	Logf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Skip(args ...any)
	Skipf(format string, args ...any)
	Failed() bool
}
