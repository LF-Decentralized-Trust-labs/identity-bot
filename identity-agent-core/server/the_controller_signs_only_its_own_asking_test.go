package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"identity-agent-core/authprovider"
)

// signAs asks a controller's own core to sign a request, and returns the reply.
func signAs(t *testing.T, s *CoreServer, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	r := s.buildRouter("")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, local("POST", "/api/controller/sign", body))
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

// This is not a general signing oracle, and that is the property the whole file
// rests on.
//
// The caller hands over the PARTS of a request; the canonical string is built
// here with the controller-request prefix baked in. So the only thing this key
// can be made to sign is "I am asking an agent to do something" — never an owner
// signature, never a key event, never a bare string somebody chose. A route that
// signed what it was given would hand the enclave to whatever could reach this
// port.
func TestTheControllerKeyCannotBeAskedToSignSomethingElse(t *testing.T) {
	s := newAuthTestServer(t)

	// There is no field that takes a string to sign. The closest anybody can get
	// is the path, and it is placed inside a fixed structure — so a caller trying
	// to smuggle a different protocol's string in gets it signed as a PATH, which
	// no verifier of that protocol will accept.
	smuggled := "IA-REQ-V1\nPOST\n/api/rotation\n2026-01-01T00:00:00Z\nx"
	w, _ := signAs(t, s, `{"method":"GET","path":`+jsonString(smuggled)+`}`)

	switch w.Code {
	case http.StatusNotImplemented:
		// No hardware on this host, which is the honest answer and still proves
		// the route refuses rather than falling back to a key on disk.
	case http.StatusBadRequest:
		// Refused for not starting with "/", which is also correct.
	case http.StatusOK:
		// If it did sign, what it signed must be a controller request, not the
		// smuggled string.
		var got struct {
			Signature string `json:"signature"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if got.Signature == "" {
			t.Fatal("reported success with no signature")
		}
	default:
		t.Fatalf("unexpected answer %d: %s", w.Code, w.Body.String())
	}

	// The property underneath, checked directly so it holds on every host
	// including ones with no enclave: whatever the inputs, the string this key
	// signs starts with the controller prefix and can never be another
	// protocol's. The owner path uses "IA-REQ-V1"; a string that began with that
	// would be accepted by the owner verifier, which admits far more.
	for _, in := range []struct{ aid, method, path string }{
		{"BSomeMachine", "GET", "/api/profile"},
		{"IA-REQ-V1", "POST", "/api/rotation"},
		{"", "", ""},
		{"B\nIA-REQ-V1", "POST\nIA-REQ-V1", "/x\nIA-REQ-V1"},
	} {
		got := canonicalControllerRequest(in.aid, in.method, in.path, "2026-01-01T00:00:00Z",
			authprovider.Unmeasured(""), nil)
		if !strings.HasPrefix(got, "IA-CONTROLLER-REQ-V1\n") {
			t.Fatalf("a controller signed something that is not a controller request: %q", got)
		}
		if strings.HasPrefix(got, "IA-REQ-V1") {
			t.Fatalf("a controller produced an owner-request string, which the owner "+
				"verifier would accept: %q", got)
		}
	}
}

// The two canonical strings cannot collide, so a signature made as a controller
// can never be presented as the owner's.
//
// They are verified against different keys, so this is defence in depth rather
// than the only thing standing there — but the prefixes are one edit apart, and
// an edit that made them agree would be silent.
func TestAControllerRequestIsNeverAnOwnerRequest(t *testing.T) {
	controller := canonicalControllerRequest("BMachine", "POST", "/api/rotation",
		"2026-01-01T00:00:00Z", authprovider.Unmeasured(""), []byte(`{}`))
	owner := canonicalRequestString("POST", "/api/rotation", "2026-01-01T00:00:00Z", []byte(`{}`))
	if controller == owner {
		t.Fatal("the same bytes serve as both, so one signature is both")
	}
	if strings.HasPrefix(controller, strings.SplitN(owner, "\n", 2)[0]) {
		t.Fatal("a controller request begins with the owner request's tag")
	}
}

// A path that is not a path is refused, because it would be signed here and
// resolved differently by whatever sends it — so the agent would check a string
// that never arrives, and every request would fail with nothing to look at.
func TestARelativePathIsRefusedRatherThanSigned(t *testing.T) {
	s := newAuthTestServer(t)
	w, _ := signAs(t, s, `{"method":"GET","path":"api/profile"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a relative path was not refused: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "start with /") {
		t.Errorf("the refusal does not say what is wrong: %s", w.Body.String())
	}
}

// Asking with no method or path is refused rather than signing something empty.
func TestSigningNeedsToKnowWhatRequestItIs(t *testing.T) {
	s := newAuthTestServer(t)
	for _, body := range []string{`{}`, `{"method":"GET"}`, `{"path":"/api/profile"}`} {
		if w, _ := signAs(t, s, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s was not refused: %d", body, w.Code)
		}
	}
}

// A body that is not base64 is refused, because a signature over "nearly the
// bytes" is a signature over nothing.
func TestABodyThatIsNotBase64IsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	w, _ := signAs(t, s,
		`{"method":"POST","path":"/api/profile","body_b64":"not base64 at all!!"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a body that could not be decoded was not refused: %d", w.Code)
	}
}

// An authentication level with no moment is refused. The level is only worth
// anything alongside when it was established — see the freshness rule the agent
// applies — so accepting one without the other would produce a signature the
// agent must then reject for a reason the app cannot see.
func TestAnAuthenticationLevelWithoutAMomentIsRefused(t *testing.T) {
	s := newAuthTestServer(t)
	w, _ := signAs(t, s,
		`{"method":"POST","path":"/api/rotation","auth_level":"high"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a level with no moment was accepted: %d %s", w.Code, w.Body.String())
	}
}

// Signing is refused on hardware that cannot keep a key to itself, rather than
// falling back to a key on disk — the same rule that stops such a machine being
// a controller at all.
func TestSigningIsRefusedWithoutHardware(t *testing.T) {
	s := newAuthTestServer(t)
	if _, err := s.thisMachineAsAController(); err == nil {
		t.Skip("this host has hardware, so the refusal cannot be observed here")
	}
	w, _ := signAs(t, s,
		`{"method":"GET","path":"/api/profile","body_b64":"`+
			base64.StdEncoding.EncodeToString(nil)+`"}`)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected a refusal on hardware that cannot hold a key: %d %s",
			w.Code, w.Body.String())
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "signature") {
		t.Error("it produced something signature-shaped while refusing")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
