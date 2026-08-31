package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// detectKeyProtection is the gate's view of this machine, behind a seam so the
// refusal can be tested on any host.
//
// It used to call secureenclave.DetectCapability directly, and the test for the
// refusal relied on the HOST being unable to answer — which was true on every
// platform when this was written and is true on none of them now. A test whose
// precondition is our own missing code stops testing anything the day that code
// is written, and it stopped silently: the install simply succeeded and the
// assertion about refusing never ran.
var detectKeyProtection = secureenclave.DetectCapability

// handleSetRootSeed installs the mnemonic-derived root seed. Local owner only.
// Idempotent for the same seed; a DIFFERENT established seed is refused — the
// HD root of an identity must never silently rotate.
func (s *CoreServer) handleSetRootSeed(w http.ResponseWriter, r *http.Request) {
	// A MACHINE THAT ANSWERS TO SOMEBODY ELSE TAKES NO ROOT SEED. Ever.
	//
	// This is the hole the pairing work left open. A paired computer holds its
	// own key and names its owner in the event that founded it — the owner's
	// root belongs on the owner's own device and nowhere else. Installing it
	// here would put the identifier that identifies a person in every
	// relationship they have onto a machine they do not carry, and from which
	// it can be copied; and it would do so silently, because everything would
	// keep working.
	//
	// Refused rather than gated. The old protection was that the client checked
	// it was talking to a loopback address before handing anything over, which
	// is a convention in the caller and not a control: anything able to sign as
	// the owner could install a seed from anywhere. Asking the question here,
	// about this machine's own state, cannot be bypassed by not asking.
	//
	// It does not stop the case this endpoint exists for. A computer that IS
	// the identity — no phone, keys on this machine — answers to nobody else,
	// so it is unaffected. That is the whole distinction: whose root this is.
	if owner, oerr := s.ownerAuthority(); oerr == nil && owner != nil {
		self := ""
		if identity, ierr := s.DataStore.GetIdentity(); ierr == nil && identity != nil {
			self = identity.AID
		}
		if owner.AID != "" && owner.AID != self {
			writeError(w, http.StatusConflict, "This computer answers to somebody",
				"it holds its own key and names "+owner.AID+" as its owner, so a root seed "+
					"has no business here — that key belongs on the device its owner carries, "+
					"and a copy of it on this machine could never be taken back")
			return
		}
	}

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
	// Anything but a PROVEN usable answer refuses. Including unknown.
	//
	// Unknown used to pass with a warning, on the reasoning that refusing over
	// a non-measurement turns "we did not look" into "you may not use this
	// software". That reasoning is wrong here, and the reason it is wrong is
	// the reason unknown is usually returned: not that the machine could not
	// answer, but that the detector for this platform has not been written.
	// That is our gap, and shipping onto a platform we have not taught this
	// software to inspect is a decision to not know.
	//
	// The consequence of being wrong is total and permanent. A seed on a
	// machine that cannot protect it is a file, and whoever copies that file
	// becomes the identity, undetectably, with no rotation possible. There is
	// no partial version of that failure to trade against the inconvenience of
	// refusing.
	//
	// So a platform without a detector cannot hold a root key, and the way to
	// change that is to write the detector rather than to widen the gate.
	// Superseded 2026-08-19: unknown does NOT proceed.
	//
	// ASKED AS RootKeyPermitted, NOT AS A LIST OF STATUSES TO REFUSE. capability.go
	// ships that method and enclave_detect.go says why: it is "the question
	// everything downstream actually asks, so it is answered here rather than
	// left to each caller to re-derive from the status and get subtly wrong."
	// A list of bad statuses fails open — a fifth status added later, or a
	// zero-value Capability whose Status is "", matches none of them and
	// installs the seed. Asking for the one good answer cannot do that.
	if cap := detectKeyProtection(); !cap.RootKeyPermitted() {
		// No way past THIS ROUTE any more, and that is the change.
		//
		// There used to be one: IA_ALLOW_UNPROTECTED_ROOT_KEY, so that work
		// could continue on a platform whose detector had never been written.
		// That reason has expired — every supported platform answers now — so
		// what remained was a named, documented way to write a root seed onto a
		// machine that cannot protect it. The consequence of using it is total
		// and permanent: the seed is a file, whoever copies that file becomes
		// the identity, and no rotation undoes it. An escape hatch nobody needs
		// is one somebody will use.
		//
		// WHAT THIS DOES NOT COVER, said here because the sentence above reads
		// like it does. This is one of five places that store a root seed and
		// the only one that asks this question. restoreTheKeyMaterial in
		// recovery/service.go writes the owner's phrase-derived seed straight
		// out of an archive; getOrCreateRelationship in login/handlers.go and
		// ensureRootSeed in ask_sign_layer.go each mint a device-local one.
		// None consults the capability, and StoreRootSeed itself degrades to an
		// unwrapped envelope rather than refusing. So recovering onto a machine
		// that cannot protect a key still does what this route now forbids.
		//
		// The way to run this software on hardware this route refuses is to fix
		// the hardware, or to hold the identity somewhere else and control it
		// from here. It is not to tell the Identity Agent to stop checking.
		jsonError(w, refusalFor(cap), http.StatusPreconditionFailed)
		return
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
	// AFTER the seed is stored, never before. Claiming a phrase-derived seed
	// this machine does not have would make it mark its backups with a key
	// nobody can check them against — and of the two ways to be wrong, that is
	// the one there is no way back from.
	if err := secureenclave.RecordSeedOrigin(s.DataDir, secureenclave.SeedFromPhrase); err != nil {
		jsonError(w, "failed to record where this seed came from", http.StatusInternalServerError)
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
