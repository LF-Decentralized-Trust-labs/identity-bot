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
	"strconv"
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
	// Body is the request's body, from the issuer's record or an export. The
	// credential does not carry it, because it can hold what is nobody else's
	// business. Without it, what the request asked for cannot be tied to what
	// was signed, and Check says so with ErrBodyWithheld.
	Body     string
	HaveBody bool
	// IssuerKEL is the issuer's key log, as published, and CredentialLog the
	// credential's own transaction log. With them, the order in which the grant
	// was issued, the credential was issued and the grant was revoked is read
	// from where each is anchored in the issuer's key log, which the issuer
	// cannot rearrange, rather than from the times the events assert. The
	// caller validates the key log itself (its signatures and its witnesses)
	// before relying on it.
	IssuerKEL     [][]byte
	CredentialLog [][]byte
}

// ErrBodyWithheld is a check that held in every respect it could, without the
// request's body: the signature, the signer, the grant, the times, and that
// what the credential says was asked for is what was issued. What it could not
// show is that what was asked for is what was signed. Given the body, Check
// shows that too.
var ErrBodyWithheld = errors.New("the request's body was not given, so what it asked for is not tied to what was signed")

// askedFields are what a credential keeps of its request's body: what was
// asked for, and nothing else the body may carry.
var askedFields = []string{"name", "capabilities", "resource_constraints", "nonce",
	"controller_aid", "public_key", "grade", "label", "signer", "expires_at"}

// Asked is what a request's body asked for, as a credential keeps it. The one
// definition the issuer uses to write it and a verifier uses to check it.
func Asked(body string) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	if strings.TrimSpace(body) == "" {
		return out, nil
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &all); err != nil {
		return nil, fmt.Errorf("the request's body is unreadable: %w", err)
	}
	for _, f := range askedFields {
		if v, ok := all[f]; ok {
			out[f] = v
		}
	}
	return out, nil
}

// RequestDigest identifies a credential's request. One request authorises one
// credential: a verifier holding several refuses a digest that appears twice.
func RequestDigest(credential []byte) (string, error) {
	var cred acdc
	if err := json.Unmarshal(credential, &cred); err != nil {
		return "", err
	}
	var req request
	if err := json.Unmarshal(cred.A["request"], &req); err != nil || req.Signed == "" {
		return "", ErrNoRequest
	}
	return iacrypto.Blake3QB64Must([]byte(req.Signed)), nil
}

// ErrNoRequest is a credential that carries no authorising request: one the
// identity issued on its own key, from the device that holds it. Nothing
// further can be checked about who asked, and a caller says so rather than
// reporting it checked.
var ErrNoRequest = errors.New("the credential carries no authorising request")

type request struct {
	Kind      string                     `json:"kind"`
	Signer    string                     `json:"signer"`
	Signed    string                     `json:"signed"`
	Signature string                     `json:"signature"`
	Asked     map[string]json.RawMessage `json:"asked"`
}

type acdc struct {
	SAID   string                     `json:"d"`
	Issuer string                     `json:"i"`
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
		switch {
		case len(lines) == 10 && lines[0] == "IA-CONTROLLER-REQ-V2":
			// The second form names the Identity Agent the request was for,
			// which is the one that issued on it: a request signed for another
			// Identity Agent authorised nothing here.
			if lines[2] != cred.Issuer {
				return fmt.Errorf("the request was signed for %s, not for the issuer %s", lines[2], cred.Issuer)
			}
			lines = append(lines[:2], lines[3:]...)
		case len(lines) == 9 && lines[0] == "IA-CONTROLLER-REQ-V1":
			// The first form, kept so a credential issued before requests named
			// their Identity Agent still checks. No Identity Agent admits a
			// request in this form any more.
		default:
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
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return fmt.Errorf("the request's time is unreadable")
	}
	if at.After(issuedAt.Add(Skew)) {
		return fmt.Errorf("the request was made after the credential was issued")
	}
	if at.Before(issuedAt.Add(-Skew)) {
		return fmt.Errorf("the request was made long before the credential was issued")
	}
	if err := checkAskedFor(cred, method, path, req.Asked); err != nil {
		return err
	}
	if !in.HaveBody {
		return ErrBodyWithheld
	}
	if iacrypto.Blake3QB64Must([]byte(in.Body)) != digest {
		return fmt.Errorf("the body given is not the body that was signed")
	}
	fromBody, err := Asked(in.Body)
	if err != nil {
		return err
	}
	if len(fromBody) != len(req.Asked) {
		return fmt.Errorf("what the credential says was asked for is not what the signed body asked for")
	}
	for k, v := range fromBody {
		if !sameJSON(v, req.Asked[k]) {
			return fmt.Errorf("what the credential says was asked for is not what the signed body asked for")
		}
	}
	return nil
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
	if grant.Issuer != cred.Issuer {
		return fmt.Errorf("the machine's grant was issued by %s, the credential by %s", grant.Issuer, cred.Issuer)
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
	if len(in.IssuerKEL) > 0 {
		return checkKELOrder(in, g.SAID, cred.SAID)
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

// checkKELOrder reads, from where each is anchored in the issuer's key log,
// that the grant was issued before the credential and not revoked before it.
func checkKELOrder(in Input, grantSAID, credSAID string) error {
	place := func(log [][]byte, subject string) (iss, rev int, err error) {
		iss, rev = -1, -1
		for _, raw := range log {
			ev, err := keri.VerifyTELEvent(raw)
			if err != nil {
				return 0, 0, err
			}
			at, ok := anchoredAt(in.IssuerKEL, subject, ev.SN, ev.SAID)
			if !ok {
				return 0, 0, fmt.Errorf("the %s of %s is not anchored in the issuer's key log", ev.Ilk, subject)
			}
			if ev.Ilk == "rev" {
				rev = at
			} else {
				iss = at
			}
		}
		return iss, rev, nil
	}
	gIss, gRev, err := place(in.GrantLog, grantSAID)
	if err != nil {
		return err
	}
	if len(in.CredentialLog) == 0 {
		return fmt.Errorf("the credential's own log is needed to place its issue in the issuer's key log")
	}
	cIss, _, err := place(in.CredentialLog, credSAID)
	if err != nil {
		return err
	}
	if gIss < 0 || cIss < 0 || gIss >= cIss {
		return fmt.Errorf("the machine's grant was not issued before the credential")
	}
	if gRev >= 0 && gRev < cIss {
		return fmt.Errorf("the machine's grant was revoked before the credential was issued")
	}
	return nil
}

// anchoredAt is the place in the key log of the event that seals subject's
// transaction event sn with digest said.
func anchoredAt(kel [][]byte, subject string, sn int, said string) (int, bool) {
	want := strconv.FormatInt(int64(sn), 16)
	for _, raw := range kel {
		var ev struct {
			S string                   `json:"s"`
			A []map[string]interface{} `json:"a"`
		}
		if json.Unmarshal(raw, &ev) != nil {
			continue
		}
		for _, seal := range ev.A {
			if seal["i"] == subject && seal["s"] == want && seal["d"] == said {
				n, err := strconv.ParseInt(ev.S, 16, 64)
				return int(n), err == nil
			}
		}
	}
	return 0, false
}

// checkAskedFor checks that what the request asked for is what was issued.
func checkAskedFor(cred acdc, method, path string, asked map[string]json.RawMessage) error {
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
	case schemas.ControllerGrant.Schema.SAID:
		if method != "POST" || path != "/api/controllers" {
			return fmt.Errorf("%s %s is not a request that grants a machine", method, path)
		}
		if strings.TrimSpace(stringOf(asked["controller_aid"])) != stringAttr(cred.A, "i") {
			return fmt.Errorf("the request granted another machine than the credential names")
		}
		for _, f := range []string{"public_key", "grade", "label"} {
			if strings.TrimSpace(stringOf(asked[f])) != strings.TrimSpace(stringAttr(cred.A, f)) {
				return fmt.Errorf("the request asked for another %s than was granted", f)
			}
		}
		// A signer the request named is the one granted; one it left to be
		// settled may be the organisation's only signer, set when granted.
		if asked := strings.TrimSpace(stringOf(asked["signer"])); asked != "" && asked != stringAttr(cred.A, "signer") {
			return fmt.Errorf("the request asked for another signer than was granted")
		}
		if !sameInstant(strings.TrimSpace(stringOf(asked["expires_at"])), stringAttr(cred.A, "valid_until")) {
			return fmt.Errorf("the request asked for another end to the grant than was granted")
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

// sameInstant reports whether two stated times are the same moment, both
// absent counting as the same.
func sameInstant(a, b string) bool {
	if a == "" || b == "" {
		return a == "" && b == ""
	}
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)
	return errA == nil && errB == nil && ta.Equal(tb)
}
