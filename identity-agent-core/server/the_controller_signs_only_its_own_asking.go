package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// The one thing a controller's own computer does for it.
//
// A CONTROLLER IS A FACE, NOT A BRAIN. Everything an Identity Agent does happens
// on the agent — the device holding the root identity, or the primary computer
// paired to it. A machine in controller mode contributes the screen and nothing
// else: no roster, no policy, no credential, no key operation belonging to the
// identity. It asks, and something else decides and acts.
//
// The single exception is this file, and it is an exception about the controller
// ITSELF rather than about the identity. The controller's key lives in this
// machine's enclave and cannot leave it, so a request signed by that key has to
// be signed here. That is managing its own instance, not doing the agent's work.
//
// WHAT MAKES IT SAFE IS THAT IT IS NOT A GENERAL SIGNING ORACLE. The caller hands
// over the parts of a request; this builds the canonical string itself, with the
// controller-request prefix baked in. So the only thing this key can ever be made
// to sign is "I am asking an agent to do something" — never an owner signature,
// never a key event, never a credential, never a bare string somebody chose. A
// route that signed what it was given would hand the enclave to whatever could
// reach this port.

// handleSignAsThisController signs one request as this machine.
//
// Owner-only, like everything unlisted, which on a controller means the app
// running on it. The app then sends the signed request to the agent, which
// checks it against the key recorded in the grant.
func (s *CoreServer) handleSignAsThisController(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method    string `json:"method"`
		Path      string `json:"path"`
		Timestamp string `json:"timestamp"`
		// BodyB64 is the exact bytes that will be sent. Base64 because a request
		// body is not always text, and a signature over "nearly the bytes" is a
		// signature over nothing.
		BodyB64 string `json:"body_b64"`

		// What the device holding the root key said about the person, carried
		// through so it is inside the signature. This machine does not decide
		// these — it cannot; see theAuthenticationSomebodyVouchedFor.
		AuthLevel string `json:"auth_level"`
		AuthAt    string `json:"auth_at"`
		AuthScore int    `json:"auth_score"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignedBodyBytes+1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	path := strings.TrimSpace(req.Path)
	if method == "" || path == "" {
		writeError(w, http.StatusBadRequest,
			"a request to sign must say which method and path it is", "")
		return
	}
	if !strings.HasPrefix(path, "/") {
		// A relative path would be signed here and resolved differently by
		// whatever sends it, so the agent would check a different string than the
		// one that arrives and every request would fail for no visible reason.
		writeError(w, http.StatusBadRequest,
			"the path must start with / — it is signed exactly as the agent will see it", "")
		return
	}

	body, err := base64.StdEncoding.DecodeString(req.BodyB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "body_b64 is not base64", err.Error())
		return
	}
	if int64(len(body)) > maxSignedBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge,
			"this request is larger than a signed request may carry", "")
		return
	}

	// The timestamp is this machine's unless the caller pinned one, so an app
	// cannot accidentally sign for a moment that has passed.
	stamp := strings.TrimSpace(req.Timestamp)
	if stamp == "" {
		stamp = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339", err.Error())
		return
	}

	asserted := authprovider.Unmeasured("")
	if lvl := strings.TrimSpace(req.AuthLevel); lvl != "" {
		when, err := time.Parse(time.RFC3339, strings.TrimSpace(req.AuthAt))
		if err != nil {
			writeError(w, http.StatusBadRequest,
				"auth_at must be RFC3339 when an authentication level is carried", err.Error())
			return
		}
		asserted = authprovider.Result{
			Level:    authprovider.Level(lvl),
			Score:    req.AuthScore,
			Measured: true,
			At:       when.UTC(),
		}
	}

	me, err := s.thisMachineAsAController()
	if err != nil {
		writeError(w, http.StatusNotImplemented,
			"this computer cannot act for an identity", err.Error())
		return
	}

	signer := secureenclave.NewPlatformSigner(s.DataDir)
	if !secureenclave.UsingHardware(signer) {
		writeError(w, http.StatusNotImplemented,
			"this computer cannot act for an identity",
			"the key that would sign this is not held by hardware")
		return
	}

	// Built here, from the parts, so the only string this key ever signs is a
	// controller asking an agent for something.
	sig, err := signer.Sign([]byte(
		canonicalControllerRequest(me.AID, method, path, stamp, asserted, body)))
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"this computer's secure hardware would not sign", err.Error())
		return
	}
	// The code follows the key, and it has to be asked rather than assumed.
	//
	// An Ed25519 signature and a P-256 signature are both 64 bytes, so naming a
	// machine's signature with the Ed25519 code encodes cleanly, is the right
	// length, and claims to be something it is not. No length check can catch
	// that; only deciding from the key can, which is why this asks.
	pub, err := signer.PublicKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"this computer's key could not be read", err.Error())
		return
	}
	sigQB64, err := iacrypto.MachineSignatureQB64(pub, sig)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"this computer's signature could not be encoded", err.Error())
		return
	}

	writeJSON(w, map[string]any{
		"controller_aid": me.AID,
		"signature":      sigQB64,
		"timestamp":      stamp,
		// Echoed so the caller sends exactly what was signed rather than
		// reformatting a time and breaking its own signature.
		"auth_level": headerValueFor(asserted, func(a authprovider.Result) string {
			return string(a.Level)
		}),
		"auth_at": headerValueFor(asserted, func(a authprovider.Result) string {
			return a.At.UTC().Format(time.RFC3339)
		}),
		"auth_score": headerValueFor(asserted, func(a authprovider.Result) string {
			return strconv.Itoa(a.Score)
		}),
	})
}

// headerValueFor returns the value only when something was actually measured, so
// an unmeasured request carries no authentication headers at all rather than
// empty ones — which is the difference the agent reads.
func headerValueFor(a authprovider.Result, of func(authprovider.Result) string) string {
	if !a.Measured {
		return ""
	}
	return of(a)
}
