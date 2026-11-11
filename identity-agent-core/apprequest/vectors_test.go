package apprequest

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/internal/contractcheck"
)

// The published vectors (app-request-vectors.json) are the request an app's
// back end signs as the app, worked from fixed inputs: the file another
// implementation tests itself against. Ed25519 signs deterministically, so the
// file is reproduced exactly from its inputs and a changed value fails here.
//
//go:embed app-request-vectors.json
var published []byte

type vectorRequest struct {
	Method    string `json:"method"`
	Target    string `json:"target"`
	BodyHex   string `json:"body_hex"`
	Host      string `json:"host"`
	For       string `json:"for"`
	Timestamp string `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	WorkItem  string `json:"work_item"`
	Reason    string `json:"reason"`
	Session   string `json:"session"`
}

type vectorAdmission struct {
	BodyHost                string   `json:"body_host"`
	BodyVerkey              string   `json:"body_verkey"`
	BodyValidUntil          string   `json:"body_valid_until"`
	GrantCapabilities       []string `json:"grant_capabilities"`
	GrantValidUntil         string   `json:"grant_valid_until"`
	CapabilityTheRouteNeeds string   `json:"capability_the_route_needs"`
	// GrantConstraints is the grant's limit on that capability, per argument;
	// RouteArguments is what the route gives each argument.
	GrantConstraints map[string][]string `json:"grant_constraints,omitempty"`
	RouteArguments   map[string]string   `json:"route_arguments,omitempty"`
}

type vector struct {
	Name      string          `json:"name"`
	Request   vectorRequest   `json:"request"`
	Admission vectorAdmission `json:"admission"`
	// Signed is the string the key signed, when the request is admitted.
	Signed string `json:"signed,omitempty"`
	// Refused is the reason code, when it is not.
	Refused string `json:"refused,omitempty"`
}

type vectorSet struct {
	About         string   `json:"about"`
	SeedHex       string   `json:"seed_hex"`
	Host          string   `json:"host"`
	Verkey        string   `json:"verkey"`
	IdentityAgent string   `json:"identity_agent"`
	Now           string   `json:"now"`
	Vectors       []vector `json:"vectors"`
}

type seedKey struct{ priv ed25519.PrivateKey }

func (k seedKey) PublicKey() ([]byte, error)    { return k.priv.Public().(ed25519.PublicKey), nil }
func (k seedKey) Sign(d []byte) ([]byte, error) { return ed25519.Sign(k.priv, d), nil }

func keyOf(b byte) seedKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return seedKey{ed25519.NewKeyFromSeed(seed)}
}

const (
	ia      = "EIdentityAgentAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	nowText = "2026-11-10T12:00:00Z"
	talk    = "/api/mcp/agents/agent-1/conversations"
	words   = `{"to":"agent-1","body":"hello","nonce":"m-1"}`
)

func at(d time.Duration) string {
	n, _ := time.Parse(time.RFC3339, nowText)
	return n.Add(d).UTC().Format(time.RFC3339)
}

func requestOf(v vector) Request {
	body, _ := hex.DecodeString(v.Request.BodyHex)
	r := v.Request
	return Request{Method: r.Method, Target: r.Target, Body: body, Host: r.Host, For: r.For, Timestamp: r.Timestamp,
		Nonce: r.Nonce, Signature: r.Signature, WorkItem: r.WorkItem, Reason: r.Reason, Session: r.Session}
}

func admissionOf(set vectorSet, v vector) Admission {
	now, _ := time.Parse(time.RFC3339, set.Now)
	a := v.Admission
	return Admission{IdentityAgent: set.IdentityAgent, Now: now, BodyHost: a.BodyHost, BodyVerkey: a.BodyVerkey, BodyValidUntil: a.BodyValidUntil,
		GrantCapabilities: a.GrantCapabilities, GrantValidUntil: a.GrantValidUntil, CapabilityTheRouteNeeds: a.CapabilityTheRouteNeeds,
		GrantConstraints: a.GrantConstraints, RouteArguments: a.RouteArguments}
}

// sign is key's signature over the request as the vector states it.
func sign(key seedKey, v vector) string {
	r := requestOf(v)
	msg := agentbody.SignedRequest{For: r.For, Host: r.Host, Method: r.Method, Target: r.Target, Timestamp: r.Timestamp,
		Nonce: r.Nonce, Body: r.Body, WorkItem: r.WorkItem, Reason: r.Reason, Session: r.Session}.Bytes()
	sig, _ := agentbody.Sign(key, msg)
	return sig
}

// written builds the file: each vector is signed as the app's back end signs
// it, and then bent by its edit. A vector that is wrong in what it says is
// signed again after the edit; one that is wrong in how it is signed is not
// (the signature is the unbent request's) or is signed by another key.
func written() vectorSet {
	key := keyOf(1)
	host, verkey, _ := agentbody.Identity(key)
	set := vectorSet{
		About: "A request an app's back end signs as the app, with its App Body key (ADR-072), read as apprequest.Check reads it: " +
			"the string the key signs is IA-BODY-REQ-V3 (agentbody.SignedRequest), the time is `now`, and a vector is admitted, with the string signed, " +
			"or refused with the first reason that applies. A vector's request is the header values and the body; its admission is what the Identity Agent " +
			"holds. The key is Ed25519 from the 32-byte seed seed_hex; the vectors are reproducible from it.",
		SeedHex: hex.EncodeToString(func() []byte {
			b := make([]byte, 32)
			for i := range b {
				b[i] = 1 + byte(i)
			}
			return b
		}()),
		Host: host, Verkey: verkey, IdentityAgent: ia, Now: nowText,
	}
	const (
		again = iota // signed after the edit
		keep         // the signature of the request before the edit
		other        // signed by another key after the edit
	)
	add := func(name string, how int, edit func(*vectorRequest), adm func(*vectorAdmission)) {
		v := vector{Name: name,
			Request: vectorRequest{Method: "POST", Target: talk, BodyHex: hex.EncodeToString([]byte(words)), Host: host, For: ia,
				Timestamp: at(0), Nonce: "nonce-0123456789ab"},
			Admission: vectorAdmission{BodyHost: host, BodyVerkey: verkey, GrantCapabilities: []string{"agent.message.send", "agent.message.read"},
				CapabilityTheRouteNeeds: "agent.message.send"}}
		if edit != nil {
			v.Request.Signature = sign(key, v)
			edit(&v.Request)
		}
		if adm != nil {
			adm(&v.Admission)
		}
		switch how {
		case again:
			v.Request.Signature = sign(key, v)
		case other:
			v.Request.Signature = sign(keyOf(9), v)
		case keep:
		}
		if signed, err := Check(requestOf(v), admissionOf(set, v)); err == nil {
			v.Signed = signed
		} else {
			v.Refused = CodeOf(err)
		}
		set.Vectors = append(set.Vectors, v)
	}
	add("a person's words to an AI agent", again, nil, nil)
	add("a read, no body, with a query, a work item, a reason and a session", again, func(r *vectorRequest) {
		r.Method, r.Target, r.BodyHex = "GET", "/api/mcp/agents/agent-1/conversations?limit=20&after=m-4", ""
		r.WorkItem, r.Reason, r.Session = "item-1", "show the chat", "run-7"
	}, func(a *vectorAdmission) { a.CapabilityTheRouteNeeds = "agent.message.read" })
	add("a body and a grant that never end are in force", again, nil, func(a *vectorAdmission) { a.BodyValidUntil, a.GrantValidUntil = "", "" })
	add("a grant that ends later is in force", again, nil, func(a *vectorAdmission) { a.GrantValidUntil = at(time.Hour) })
	add("names no Identity Agent", again, func(r *vectorRequest) { r.For = "" }, nil)
	add("signed for another Identity Agent", again, func(r *vectorRequest) { r.For = "EAnotherIdentityAgentAAAAAAAAAAAAAAAAAAAAAAA" }, nil)
	add("an unreadable time", again, func(r *vectorRequest) { r.Timestamp = "yesterday" }, nil)
	add("signed three minutes ago", again, func(r *vectorRequest) { r.Timestamp = at(-3 * time.Minute) }, nil)
	add("signed three minutes ahead", again, func(r *vectorRequest) { r.Timestamp = at(3 * time.Minute) }, nil)
	add("a nonce that is too short", again, func(r *vectorRequest) { r.Nonce = "short" }, nil)
	add("a key the App Body does not name", again, func(r *vectorRequest) {
		h, _, _ := agentbody.Identity(keyOf(5))
		r.Host = h
	}, nil)
	add("a signature by another key under the app's name", other, func(r *vectorRequest) {}, nil)
	add("a body changed after it was signed", keep, func(r *vectorRequest) {
		r.BodyHex = hex.EncodeToString([]byte(`{"to":"agent-2","body":"hello","nonce":"m-1"}`))
	}, nil)
	add("a route changed in transit", keep, func(r *vectorRequest) { r.Target = "/api/mcp/agents/agent-2/conversations" }, nil)
	add("a stated reason changed in transit", keep, func(r *vectorRequest) { r.Reason = "something else" }, nil)
	add("an App Body that has ended", again, nil, func(a *vectorAdmission) { a.BodyValidUntil = at(-time.Second) })
	add("an App Grant that ends this second", again, nil, func(a *vectorAdmission) { a.GrantValidUntil = at(0) })
	add("an App Grant that does not hold the capability", again, nil, func(a *vectorAdmission) { a.GrantCapabilities = []string{"agent.message.read"} })
	toAgent1 := func(a *vectorAdmission) { a.RouteArguments = map[string]string{"to": "Eagent1"} }
	limitedTo := func(names ...string) func(*vectorAdmission) {
		return func(a *vectorAdmission) {
			toAgent1(a)
			a.GrantConstraints = map[string][]string{"to": names}
		}
	}
	add("a grant limited to this AI agent admits it", again, nil, limitedTo("Eagent2", "Eagent1"))
	add("a grant limited to another AI agent refuses this one", again, nil, limitedTo("Eagent2"))
	add("a limit on an argument the route does not give", again, nil, func(a *vectorAdmission) {
		toAgent1(a)
		a.GrantConstraints = map[string][]string{"to": {"Eagent1"}, "topic": {"billing"}}
	})
	return set
}

func TestThePublishedAppRequestVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		raw, err := json.MarshalIndent(written(), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("app-request-vectors.json", append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		published = append(raw, '\n')
	}
	var set vectorSet
	if err := json.Unmarshal(published, &set); err != nil {
		t.Fatal(err)
	}
	// What the file says is what the file would be written as: the key, the
	// vectors and every signature, from the seed, so no value stands unchecked.
	if want := written(); !reflect.DeepEqual(set, want) {
		got, _ := json.MarshalIndent(set, "", "  ")
		re, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("the published app request vectors are not what this package produces:\n file:\n%s\n recomputed:\n%s", got, re)
	}
	admitted, refused := 0, map[string]bool{}
	for _, v := range set.Vectors {
		signed, err := Check(requestOf(v), admissionOf(set, v))
		if (err == nil) != (v.Signed != "") || err == nil && signed != v.Signed || err != nil && CodeOf(err) != v.Refused {
			t.Errorf("%s: Check says %q, %v; the file says signed %q, refused %q", v.Name, signed, err, v.Signed, v.Refused)
		}
		if v.Signed != "" {
			admitted++
		} else {
			refused[v.Refused] = true
		}
	}
	for _, code := range []string{NoIdentityAgent, OtherIdentityAgent, BadTime, OutsideWindow, BadNonce, WrongKey, BadSignature, BodyLapsed, GrantLapsed, NoCapability, OutsideConstraint, CannotEnforce} {
		if !refused[code] {
			t.Errorf("no vector is refused for %s", code)
		}
	}
	if admitted < 3 {
		t.Fatalf("only %d vectors are admitted", admitted)
	}
}

func TestTheAppRequestVectorsAreCheckedIndependently(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_app_request_vectors.py", "app-request-vectors.json", "blake3")
}
