package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Signing a request to a machine you own, as the identity that owns it.
//
// A machine on hardware somebody rents cannot tell who is calling from the
// connection: its owner is remote by definition, so every owner route there
// answers "sign this". The key that satisfies it is NOT the root key. A machine
// is adopted by a pairwise identity this device minted for that machine alone
// -- see mintAnIdentityToClaimAMachineWith -- and that identity is what the
// machine sealed and what it checks against. Signing with the root produces a
// signature that verifies nowhere.
//
// THE KEY IS NEVER HANDED OUT, which is why this is a route rather than a
// getter. It is derived from the root seed at an index this device wrote down,
// used, and dropped. The index is deliberately never sent anywhere: the app
// names the identity, and this side looks up where its key came from.
//
// It signs only as an identity THIS DEVICE MINTED. Asked for anything else it
// refuses, so a caller cannot name an identity it merely knows of -- a pairwise
// AID travels to a provisioning host and to the machine, so knowing one proves
// nothing at all.

type signAsMachineOwnerRequest struct {
	// OwnerAID names which of this device's minted identities to sign as. The
	// app learns it from the machine itself, which reports the owner it sealed.
	OwnerAID string `json:"owner_aid"`

	Method string `json:"method"`
	Path   string `json:"path"`
	// BodyB64 is the exact bytes that will be sent. Base64 because a request
	// body is not always text, and a signature over nearly the bytes is a
	// signature over nothing.
	BodyB64 string `json:"body_b64"`
	// Timestamp, when the caller pins one. Normally left out: it is inside the
	// signature, so the moment this side signs is the moment that must travel.
	Timestamp string `json:"timestamp"`
}

type signAsMachineOwnerResponse struct {
	OwnerAID  string `json:"owner_aid"`
	Signature string `json:"signature"`
	// Timestamp is echoed rather than left for the caller to format again. A
	// second formatting that differs by a millisecond or a zone would produce a
	// signature over a string the machine never sees.
	Timestamp string `json:"timestamp"`
}

func (s *CoreServer) handleSignAsAMachineOwner(w http.ResponseWriter, r *http.Request) {
	var req signAsMachineOwnerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignedBodyBytes+1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}

	ownerAID := strings.TrimSpace(req.OwnerAID)
	if ownerAID == "" {
		writeError(w, http.StatusBadRequest,
			"say which identity to sign as — this device has one per machine, and "+
				"a signature from the wrong one is refused by the machine", "")
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
		// whatever sends it, so the machine would check a different string than
		// the one that arrives, and every request would fail for no visible
		// reason.
		writeError(w, http.StatusBadRequest,
			"the path must start with / — it is signed exactly as the machine will see it", "")
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

	stamp := strings.TrimSpace(req.Timestamp)
	if stamp == "" {
		stamp = time.Now().UTC().Format(time.RFC3339)
	} else if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339", err.Error())
		return
	}

	// Where this identity's key came from. Unknown means this device did not
	// mint it, and the refusal is the point: a pairwise AID is not a secret, so
	// naming one must not be enough to be signed for.
	idx, known, err := s.DataStore.MachineOwnerIndex(ownerAID)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not look up where that identity's key came from", err.Error())
		return
	}
	if !known {
		writeError(w, http.StatusForbidden,
			"this device did not mint that identity, so it holds no key for it",
			"only an identity minted here to own a machine can be signed as")
		return
	}

	seed, err := s.pairwiseSigningSeed(idx)
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not derive the key for that identity", err.Error())
		return
	}

	sig, err := SignOwnerRequest(method, path, stamp, body, seed)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not sign", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signAsMachineOwnerResponse{
		OwnerAID:  ownerAID,
		Signature: sig,
		Timestamp: stamp,
	})
}
