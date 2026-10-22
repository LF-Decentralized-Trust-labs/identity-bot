// Package authorisation checks that a credential rests on the request that
// authorised it.
//
// An AI agent's grant and the credential that makes a machine its body carry
// the request that authorised them, exactly as it was signed, and, when it came
// from a machine acting for a signer, an edge to that machine's Controller
// Grant. Check is the rule a verifier applies to those, with nothing but the
// credential, the grant it names and the grant's transaction log: the
// signature, who made it, what it asked for, and when.
//
// It is pure: no network, no store, no running Identity Agent. The Identity
// Agent applies it to what it issues, and an offline verifier applies the same
// function to an exported record.
package authorisation

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

// Skew is how far a signed request's time may run ahead of the issuance it
// authorised: the clocks of the signing machine and the Identity Agent differ,
// and a request is accepted within this window of the Identity Agent's time.
const Skew = 5 * time.Minute

// Input is everything the check needs.
type Input struct {
	// Credential is the credential as issued.
	Credential []byte
	// Grant and GrantLog are the Controller Grant the credential's edge names
	// and its transaction log, in order. Needed for a request a machine made.
	Grant    []byte
	GrantLog [][]byte
	// OwnerKey is the key the identity's own key log named when an
	// owner-signed request was made. Needed for a request the identity's own
	// key signed.
	OwnerKey string
}

// ErrNoRequest is a credential that carries no authorising request: one the
// identity issued on its own key, from the device that holds it. Nothing
// further can be checked about who asked, and a caller says so rather than
// reporting it checked.
var ErrNoRequest = errors.New("the credential carries no authorising request")

type request struct {
	Kind      string `json:"kind"`
	Signer    string `json:"signer"`
	Signed    string `json:"signed"`
	Signature string `json:"signature"`
	Body      string `json:"body"`
}

type acdc struct {
	SAID   string                     `json:"d"`
	Schema string                     `json:"s"`
	A      map[string]json.RawMessage `json:"a"`
	E      map[string]json.RawMessage `json:"e"`
}

// Check applies the rule:
//
//   - the request is signed by who it says, over the exact string kept, and
//     that string carries the digest of the body kept;
//   - a machine's request is signed by the key its Controller Grant names, the
//     grant is the one the credential's edge names, and its holder is the
//     signer; an owner-signed request is signed by the identity's own key;
//   - what was asked for is what was issued: the same capabilities and
//     limits, the same AI agent or the same waiting machine;
//   - the request was made while the grant was in force, before the
//     credential was issued, and the grant had not been revoked by then.
func Check(in Input) error {
	// The credential is the one issued: its identifier is the digest of what
	// it says, so nothing in it, the request included, was changed since.
	if _, err := keri.VerifyCredential(in.Credential); err != nil {
		return fmt.Errorf("the credential does not verify: %w", err)
	}
	var cred acdc
	if err := json.Unmarshal(in.Credential, &cred); err != nil {
		return fmt.Errorf("the credential is unreadable: %w", err)
	}
	raw, ok := cred.A["request"]
	if !ok {
		return ErrNoRequest
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("the request is unreadable: %w", err)
	}
	issuedAt, err := timeAttr(cred.A, "dt")
	if err != nil {
		return fmt.Errorf("the credential's issue time: %w", err)
	}

	var method, path, stamp, digest string
	switch req.Kind {
	case "controller":
		lines := strings.Split(req.Signed, "\n")
		if len(lines) != 9 || lines[0] != "IA-CONTROLLER-REQ-V1" {
			return fmt.Errorf("the signed string is not a machine's request")
		}
		if lines[1] != req.Signer {
			return fmt.Errorf("the request was signed by %s, not %s", lines[1], req.Signer)
		}
		method, path, stamp, digest = lines[2], lines[3], lines[4], lines[8]
		if err := checkGrant(in, cred, req, stamp, issuedAt); err != nil {
			return err
		}
	case "owner":
		lines := strings.Split(req.Signed, "\n")
		if len(lines) != 5 || lines[0] != "IA-REQ-V1" {
			return fmt.Errorf("the signed string is not an owner's request")
		}
		method, path, stamp, digest = lines[1], lines[2], lines[3], lines[4]
		pub, err := login.DecodeVerkey(in.OwnerKey)
		if err != nil {
			return fmt.Errorf("the owner's key: %w", err)
		}
		if ok, err := login.VerifyString(req.Signed, req.Signature, pub); err != nil || !ok {
			return fmt.Errorf("the request is not signed by the identity's key")
		}
	default:
		return fmt.Errorf("a request of kind %q is not one this check knows", req.Kind)
	}
	if iacrypto.Blake3QB64Must([]byte(req.Body)) != digest {
		return fmt.Errorf("the body kept is not the body that was signed")
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return fmt.Errorf("the request's time is unreadable")
	}
	if at.After(issuedAt.Add(Skew)) {
		return fmt.Errorf("the request was made after the credential was issued")
	}
	return checkAskedFor(cred, method, path, req.Body)
}

// checkGrant checks a machine's request against its Controller Grant.
func checkGrant(in Input, cred acdc, req request, stamp string, issuedAt time.Time) error {
	edgeRaw, ok := cred.E["authorised_by"]
	if !ok {
		return fmt.Errorf("a machine's request with no edge to its grant")
	}
	var edge struct {
		N string `json:"n"`
		S string `json:"s"`
	}
	if err := json.Unmarshal(edgeRaw, &edge); err != nil {
		return fmt.Errorf("the edge is unreadable: %w", err)
	}
	if edge.S != schemas.ControllerGrant.Schema.SAID {
		return fmt.Errorf("the edge names a credential that is not a Controller Grant")
	}
	g, err := keri.VerifyCredential(in.Grant)
	if err != nil {
		return fmt.Errorf("the Controller Grant does not verify: %w", err)
	}
	if g.SAID != edge.N {
		return fmt.Errorf("the grant given is %s, not the %s the edge names", g.SAID, edge.N)
	}
	var grant acdc
	if err := json.Unmarshal(in.Grant, &grant); err != nil {
		return err
	}
	if grant.Schema != schemas.ControllerGrant.Schema.SAID {
		return fmt.Errorf("the grant given is not a Controller Grant")
	}
	holder, key := stringAttr(grant.A, "i"), stringAttr(grant.A, "public_key")
	if holder != req.Signer {
		return fmt.Errorf("the request was signed by %s, but the grant is %s's", req.Signer, holder)
	}
	if ok, err := iacrypto.VerifyMachineSignature(key, req.Signature, []byte(req.Signed)); err != nil || !ok {
		return fmt.Errorf("the request is not signed by the key the grant names")
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return fmt.Errorf("the request's time is unreadable")
	}
	from, err := timeAttr(grant.A, "dt")
	if err != nil {
		return fmt.Errorf("the grant's issue time: %w", err)
	}
	if at.Add(Skew).Before(from) {
		return fmt.Errorf("the request was made before the machine was granted")
	}
	if until, err := timeAttr(grant.A, "valid_until"); err == nil && !at.Before(until) {
		return fmt.Errorf("the request was made after the machine's grant lapsed")
	}
	if _, err := keri.CredentialStatus(g.SAID, in.GrantLog); err != nil {
		return fmt.Errorf("the grant's log: %w", err)
	}
	for _, ev := range in.GrantLog {
		e, err := keri.VerifyTELEvent(ev)
		if err != nil {
			return err
		}
		if e.Ilk == "rev" {
			revokedAt, err := time.Parse("2006-01-02T15:04:05.000000-07:00", e.DateTime)
			if err != nil || !revokedAt.After(issuedAt) {
				return fmt.Errorf("the machine's grant was revoked before the credential was issued")
			}
		}
	}
	return nil
}

// checkAskedFor checks that what the request asked for is what was issued.
func checkAskedFor(cred acdc, method, path, body string) error {
	var asked map[string]json.RawMessage
	if body != "" {
		if err := json.Unmarshal([]byte(body), &asked); err != nil {
			return fmt.Errorf("the request's body is unreadable: %w", err)
		}
	}
	about := stringAttr(cred.A, "about")
	segments := strings.Split(strings.Trim(path, "/"), "/")
	switch cred.Schema {
	case schemas.AIAgentGrant.Schema.SAID:
		switch {
		case method == "POST" && path == "/api/mcp/agents":
			if stringOf(asked["name"]) != stringAttr(cred.A, "name") {
				return fmt.Errorf("the request asked for an AI agent named differently")
			}
		case method == "PUT" && len(segments) == 5 && segments[2] == "agents" && segments[4] == "capabilities":
			if segments[3] != about {
				return fmt.Errorf("the request was about %s, the credential about %s", segments[3], about)
			}
		default:
			return fmt.Errorf("%s %s is not a request that grants an AI agent anything", method, path)
		}
		if !sameSet(asked["capabilities"], cred.A["capabilities"]) {
			return fmt.Errorf("the request asked for other capabilities than were granted")
		}
		if rc, ok := asked["resource_constraints"]; ok && !sameJSON(rc, cred.A["resource_constraints"]) {
			return fmt.Errorf("the request asked for other limits than were granted")
		}
	case schemas.AIAgentBody.Schema.SAID:
		if method != "POST" || len(segments) != 7 || segments[4] != "bodies" || segments[6] != "approve" {
			return fmt.Errorf("%s %s is not a request that approves a machine", method, path)
		}
		if segments[5] != about {
			return fmt.Errorf("the request approved machine %s, the credential is about %s", segments[5], about)
		}
	default:
		return fmt.Errorf("the credential is not one an authorising request is checked for")
	}
	return nil
}

func stringAttr(a map[string]json.RawMessage, name string) string { return stringOf(a[name]) }

func stringOf(raw json.RawMessage) string {
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

func timeAttr(a map[string]json.RawMessage, name string) (time.Time, error) {
	v := stringAttr(a, name)
	if v == "" {
		return time.Time{}, fmt.Errorf("no %s", name)
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000000-07:00"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%s %q is unreadable", name, v)
}

func sameSet(a, b json.RawMessage) bool {
	var x, y []string
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(b, &y)
	sort.Strings(x)
	sort.Strings(y)
	return reflect.DeepEqual(append([]string{}, x...), append([]string{}, y...))
}

func sameJSON(a, b json.RawMessage) bool {
	var x, y interface{}
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(b, &y)
	if m, ok := x.(map[string]interface{}); ok && len(m) == 0 {
		x = nil
	}
	if m, ok := y.(map[string]interface{}); ok && len(m) == 0 {
		y = nil
	}
	return reflect.DeepEqual(x, y)
}
