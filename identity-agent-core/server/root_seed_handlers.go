package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"identity-agent-core/secureenclave"
)

// One root of trust: the onboarding mnemonic. The client layer (which generates
// and holds the mnemonic) hands its standard BIP39 seed to the local core here,
// once, at identity creation or recovery. Every HD-derived key — pairwise
// contacts, login relationships, asset signing, audit signing, the
// credential-vault key — then derives from the same root the identity itself
// does, so the seed phrase alone recovers everything. The core never sees the
// mnemonic words, only the derived 64-byte seed; the seed is never returned by
// any endpoint.

type rootSeedRequest struct {
	SeedB64 string `json:"seed_b64"`
}

// handleSetRootSeed installs the mnemonic-derived root seed. Local owner only.
// Idempotent for the same seed; a DIFFERENT established seed is refused — the
// HD root of an identity must never silently rotate.
func (s *CoreServer) handleSetRootSeed(w http.ResponseWriter, r *http.Request) {
	// A root seed only goes onto a machine that can protect it.
	//
	// This used to be enforced in the client, which checked that it was talking
	// to a loopback address before handing anything over. That is a convention,
	// not a control: the check lives in the caller, so anything able to sign as
	// the owner could install a seed from anywhere and the agent would accept
	// it. The rule belongs here, where it cannot be bypassed by not asking.
	//
	// Loopback is also the wrong rule. A root key may legitimately live on a
	// rented machine — that is the whole point of sealed infrastructure, and it
	// is the answer for somebody whose only device cannot protect a key. What
	// makes it safe is not where the machine is but whether it can hold a key
	// that cannot be copied off it.
	//
	// So the question asked is the one that matters: can this hardware protect
	// a key? A machine that cannot is refused, because a seed written there is
	// a file, and whoever copies that file becomes its owner permanently, with
	// nothing to detect and no rotation possible.
	//
	// It refuses only on a PROVEN answer. Unknown — a platform whose detector
	// is not written yet, or a machine we could not read — is allowed through
	// with a warning, because refusing on a non-measurement is precisely the
	// defect the detector exists to end. Turning "we did not look" into "you
	// may not use this software" would be the same wrong answer wearing
	// authority. The warning is what makes the gap visible until the detectors
	// land, at which point this tightens by itself.
	switch cap := secureenclave.DetectCapability(); cap.Status {
	case secureenclave.Absent, secureenclave.Present:
		// One way past this, and it is deliberately awkward to reach.
		//
		// Hardware that can protect a key is not always available when the work
		// is: an enclave on order, a test box that will never have one. Refusing
		// outright in that window does not make anybody safer, it just stops the
		// software being worked on, so there is a switch — named for exactly
		// what it gives up, and unable to be set by accident.
		//
		// It permits INSTALLING a seed, and nothing else. It does not invent
		// one: a seed the owner brought is still recoverable from their phrase,
		// where a generated one would leave every identity founded here
		// committed to keys nobody can ever reproduce. Unprotected is
		// recoverable-but-copyable; invented is neither.
		//
		// The identity records that it was founded this way, because a
		// counterparty deciding what to trust should be told, and because
		// nothing that is only a log line survives contact with a busy month.
		if allowUnprotectedRootKey() {
			log.Printf("[keystore] WARNING: installing a root seed on a machine with NO hardware key "+
				"protection (%s) because %s is set. Anyone who copies this file becomes this identity, "+
				"permanently and undetectably. Acceptable while waiting for hardware; not a way to run.",
				cap.String(), envAllowUnprotectedRootKey)
			break
		}
		jsonError(w,
			"this machine cannot protect a root key ("+cap.String()+"), so an identity stored here could be "+
				"copied off it — put the root on a device with hardware key protection and pair this one to it",
			http.StatusPreconditionFailed)
		return
	case secureenclave.Unknown:
		log.Printf("[keystore] WARNING: installing a root seed on a machine whose key protection could not be determined (%s) — "+
			"this is allowed because we did not check, not because we checked and approved", cap.String())
	}
	if !s.isOwner(r) {
		jsonError(w, "keystore management is for the owner of this agent", http.StatusForbidden)
		return
	}
	var req rootSeedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SeedB64 == "" {
		jsonError(w, "body must be {\"seed_b64\": \"<base64 BIP39 seed>\"}", http.StatusBadRequest)
		return
	}
	seed, err := base64.StdEncoding.DecodeString(req.SeedB64)
	if err != nil {
		jsonError(w, "seed_b64 is not valid base64", http.StatusBadRequest)
		return
	}
	if len(seed) < 32 || len(seed) > 64 {
		jsonError(w, "seed must be 32-64 bytes (the standard BIP39 seed is 64)", http.StatusBadRequest)
		return
	}

	if existing, lerr := secureenclave.LoadRootSeed(s.DataDir); lerr == nil {
		if bytes.Equal(existing, seed) {
			jsonResponse(w, map[string]any{"status": "unchanged"})
			return
		}
		jsonError(w, "a different root seed is already established on this agent — recover with the original seed phrase, or reset the agent's data directory to start over", http.StatusConflict)
		return
	}

	if err := secureenclave.StoreRootSeed(s.DataDir, seed); err != nil {
		jsonError(w, "failed to store root seed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"status": "stored"})
}

// handleRootSeedStatus reports whether a root seed is established (never the
// seed itself). Local owner only. Lets the client decide whether a handoff is
// still needed.
func (s *CoreServer) handleRootSeedStatus(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "keystore management is for the owner of this agent", http.StatusForbidden)
		return
	}
	_, err := secureenclave.LoadRootSeed(s.DataDir)
	jsonResponse(w, map[string]any{"established": err == nil})
}
