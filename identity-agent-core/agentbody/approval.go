package agentbody

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// A machine the person sets up is approved from its own signed request, rather
// than by a person comparing six words.
//
// After a machine has asked to become a body (handleBodyEnrol has its sealed,
// proven request and holds a pending binding for its key K), the machine also
// shows a short, self-verifying string: K's identifier and verkey, the AI agent
// and Identity Agent it is for, and a signature by K over all of it. A person
// reads it off the machine — pasted, or a camera on the QR — into their
// Identity Agent, which checks the signature and matches it to the pending
// binding for that key, and approves in one action.
//
// The string proves itself, so how it reaches the approver carries no authority
// and is not trusted: a tampered copy fails the signature, and a copy of another
// machine's request names that machine's key, not the one in front of the
// person, so it is simply not the one they capture. This is the same protection
// the six words gave — tying "the machine in front of me" to "the key that
// asked" — with the check done by the Identity Agent instead of by eye.

// ApprovalPrefix marks a string as an AI agent body approval request, version 1.
const ApprovalPrefix = "iaapprove1."

// ApprovalRequest is what a machine shows for a person to approve it: enough to
// find the pending binding (the key K), name what is being approved, and prove
// the request was made by the holder of K.
type ApprovalRequest struct {
	Version int `json:"v"`
	// URL and IdentityAgent name the Identity Agent that holds the pending
	// binding and will issue the body credential.
	URL           string `json:"url"`
	IdentityAgent string `json:"ia"`
	// Agent and AgentName name the AI agent the machine asked to be the body of.
	Agent     string `json:"agent"`
	AgentName string `json:"name"`
	// Host is K's identifier and Verkey is K in the form a signature is checked
	// against — the same key that signed the enrolment and holds the pending
	// binding.
	Host   string `json:"host"`
	Verkey string `json:"verkey"`
	// Nonce makes the signature distinct; Signature is K's over ApprovalProof.
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// ApprovalProof is the string K signs to show it is the machine asking to
// become this AI agent's body. It names the Identity Agent and AI agent it is
// for, K itself, and a fresh nonce, so a signature shown for one approval cannot
// be replayed into another.
func ApprovalProof(identityAgent, agent, host, verkey, nonce string) []byte {
	return []byte(strings.Join([]string{
		"IA-BODY-APPROVE-V1",
		identityAgent,
		agent,
		host,
		verkey,
		nonce,
	}, "\n"))
}

// Encode renders the string a machine shows and a person captures.
func (a ApprovalRequest) Encode() (string, error) {
	if a.Version == 0 {
		a.Version = 1
	}
	b, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return ApprovalPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseApprovalRequest reads an approval request string, refusing anything
// incomplete. It does not check the signature — the Identity Agent that holds
// the pending binding does that, because only it knows the key to check against.
func ParseApprovalRequest(s string) (ApprovalRequest, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, ApprovalPrefix) {
		return ApprovalRequest{}, fmt.Errorf("this is not an AI agent body approval request")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, ApprovalPrefix))
	if err != nil {
		return ApprovalRequest{}, fmt.Errorf("the approval request is damaged: %w", err)
	}
	var a ApprovalRequest
	if err := json.Unmarshal(raw, &a); err != nil {
		return ApprovalRequest{}, fmt.Errorf("the approval request is damaged: %w", err)
	}
	if a.Version != 1 {
		return ApprovalRequest{}, fmt.Errorf("approval request version %d is not one this program reads", a.Version)
	}
	if a.IdentityAgent == "" || a.Agent == "" || a.Host == "" || a.Verkey == "" || a.Signature == "" {
		return ApprovalRequest{}, fmt.Errorf("the approval request is missing a field it must carry")
	}
	if err := CheckNonce(a.Nonce); err != nil {
		return ApprovalRequest{}, err
	}
	return a, nil
}

// Check verifies that this approval request was made by the holder of the key
// it names, for the given Identity Agent. The caller then matches Host to a
// pending binding; a request whose key has no pending binding here is refused
// there, not here.
func (a ApprovalRequest) Check(identityAgent string) error {
	if a.IdentityAgent != identityAgent {
		return fmt.Errorf("this approval request names a different Identity Agent")
	}
	return Verify(a.Host, a.Verkey, a.Signature, ApprovalProof(a.IdentityAgent, a.Agent, a.Host, a.Verkey, a.Nonce))
}
