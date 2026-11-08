package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/secureenclave"
)

// THE RECOVERY PHRASE IS HELD HERE, UNDER THE SAME WRAPPER AS THE ROOT SEED.
//
// The phrase recreates the root seed, so keeping it in the app's own secure
// storage (software on Windows, plugin-dependent elsewhere) would leave the
// seed's twin unprotected by hardware. The app puts it here until its owner has
// confirmed it is written down, reads it back when it needs to derive from it,
// and deletes it on confirmation. A production build refuses to hold it where
// it cannot be wrapped, with the root-seed refusal (secureenclave.StoreRecoveryPhrase).
//
// Owner only, and never a controller: whoever reads the
// phrase becomes the identity. The phrase is never in a log line or a URL.

type recoveryPhraseBody struct {
	Phrase string `json:"phrase"`
}

// aDifferentPhraseIsHeldCode is the code on the 409 for a different phrase
// held, so the app tells it apart from the paired-computer 409.
const aDifferentPhraseIsHeldCode = "a_different_phrase_is_held"

// holdPhraseBody is what PUT takes. Replace says the caller means to replace a
// different phrase already held: the app sets it only when a phrase move
// finishes, and for a deliberate reset. Without it a different phrase held is
// refused (409), as the root-seed route refuses a different seed, so a
// re-onboarding or a migration racing another app process cannot overwrite the
// only copy of an identity.
type holdPhraseBody struct {
	Phrase  string `json:"phrase"`
	Replace bool   `json:"replace,omitempty"`
}

// aPlausiblePhrase is whether s is shaped like a BIP39 phrase: 12 to 24
// lowercase words. It does not check the wordlist or the checksum — the app
// that made it did — only that this is not an arbitrary blob being filed here.
func aPlausiblePhrase(s string) bool {
	words := strings.Split(s, " ")
	if n := len(words); n < 12 || n > 24 {
		return false
	}
	for _, w := range words {
		if len(w) == 0 || len(w) > 12 {
			return false
		}
		for _, c := range w {
			if c < 'a' || c > 'z' {
				return false
			}
		}
	}
	return true
}

// phraseSlotOps are the operations on one place a phrase is held: the phrase
// in force, or the phrase an identity is moving to (ADR-061 section 10). Both
// are held by the same code under the same wrapper, so the second is never the
// weaker of the two.
type phraseSlotOps struct {
	what       string // for messages
	store      func(dataDir string, phrase []byte) error
	replace    func(dataDir string, phrase []byte) error
	load       func(dataDir string) ([]byte, error)
	protection func(dataDir string) (protection, scheme string, ok bool)
	forget     func(dataDir string) error
}

var (
	inForcePhrase = phraseSlotOps{"the recovery phrase", secureenclave.StoreRecoveryPhrase,
		secureenclave.ReplaceRecoveryPhrase, secureenclave.LoadRecoveryPhrase, secureenclave.RecoveryPhraseProtection, secureenclave.ForgetRecoveryPhrase}
	movingToPhrase = phraseSlotOps{"the phrase being moved to", secureenclave.StorePhraseMovingTo,
		secureenclave.ReplacePhraseMovingTo, secureenclave.LoadPhraseMovingTo, secureenclave.PhraseMovingToProtection, secureenclave.ForgetPhraseMovingTo}
)

func (s *CoreServer) handleHoldRecoveryPhrase(w http.ResponseWriter, r *http.Request) {
	s.holdPhrase(w, r, inForcePhrase)
}

func (s *CoreServer) handleHoldPhraseMovingTo(w http.ResponseWriter, r *http.Request) {
	s.holdPhrase(w, r, movingToPhrase)
}

func (s *CoreServer) holdPhrase(w http.ResponseWriter, r *http.Request, op phraseSlotOps) {
	if !s.isOwner(r) {
		jsonError(w, op.what+" is for the owner of this agent", http.StatusForbidden)
		return
	}
	// The phrase recreates the root seed, so a paired computer, which answers to
	// its owner's device, takes it no more than it takes the seed.
	if s.refuseWhenThisComputerAnswersToSomebody(w, op.what) {
		return
	}
	var req holdPhraseBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || !aPlausiblePhrase(req.Phrase) {
		jsonError(w, "body must be {\"phrase\": \"<12 to 24 lowercase words, single-spaced>\"}", http.StatusBadRequest)
		return
	}
	store := op.store
	if req.Replace {
		store = op.replace
	}
	if err := store(s.DataDir, []byte(req.Phrase)); err != nil {
		if secureenclave.IsRootSeedRefusal(err) {
			writeRootSeedRefused(w, err.Error())
			return
		}
		if errors.Is(err, secureenclave.ErrADifferentPhraseIsHeld) {
			log.Printf("[identity-agent-core] refused to replace %s: %v", op.what, err)
			jsonreply.Write(w, http.StatusConflict, ErrorResponse{
				Error:   "a different phrase is already held on this agent (" + op.what + ")",
				Details: "it is replaced only by a caller that says it is replacing it",
				Code:    aDifferentPhraseIsHeldCode})
			return
		}
		log.Printf("[identity-agent-core] could not hold %s: %v", op.what, err)
		jsonError(w, "failed to hold "+op.what, http.StatusInternalServerError)
		return
	}
	jsonreply.Write(w, http.StatusCreated, phraseState(s.DataDir, op))
}

// handleRecoveryPhraseStatus says whether a phrase is held and what protects it,
// never the phrase.
func (s *CoreServer) handleRecoveryPhraseStatus(w http.ResponseWriter, r *http.Request) {
	s.phraseStatus(w, r, inForcePhrase)
}

func (s *CoreServer) handlePhraseMovingToStatus(w http.ResponseWriter, r *http.Request) {
	s.phraseStatus(w, r, movingToPhrase)
}

func (s *CoreServer) phraseStatus(w http.ResponseWriter, r *http.Request, op phraseSlotOps) {
	if !s.isOwner(r) {
		jsonError(w, op.what+" is for the owner of this agent", http.StatusForbidden)
		return
	}
	jsonResponse(w, phraseState(s.DataDir, op))
}

func phraseState(dataDir string, op phraseSlotOps) map[string]any {
	protection, scheme, held := op.protection(dataDir)
	if !held {
		return map[string]any{"held": false}
	}
	return map[string]any{"held": true, "protection": protection, "scheme": scheme}
}

// handleOpenRecoveryPhrase returns the held phrase to the owner. POST, so the
// phrase is never the answer to something a proxy or a log treats as a plain read.
func (s *CoreServer) handleOpenRecoveryPhrase(w http.ResponseWriter, r *http.Request) {
	s.openPhrase(w, r, inForcePhrase)
}

func (s *CoreServer) handleOpenPhraseMovingTo(w http.ResponseWriter, r *http.Request) {
	s.openPhrase(w, r, movingToPhrase)
}

func (s *CoreServer) openPhrase(w http.ResponseWriter, r *http.Request, op phraseSlotOps) {
	if !s.isOwner(r) {
		jsonError(w, op.what+" is for the owner of this agent", http.StatusForbidden)
		return
	}
	phrase, err := op.load(s.DataDir)
	switch {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		jsonResponse(w, recoveryPhraseBody{Phrase: string(phrase)})
	case errors.Is(err, secureenclave.ErrNoRecoveryPhrase):
		jsonError(w, "none is held on this agent: "+op.what, http.StatusNotFound)
	case secureenclave.IsRootSeedRefusal(err):
		writeRootSeedRefused(w, err.Error())
	default:
		log.Printf("[identity-agent-core] the held phrase (%s) could not be opened: %v", op.what, err)
		jsonError(w, "the held phrase could not be opened just now", http.StatusServiceUnavailable)
	}
}

// handleForgetRecoveryPhrase deletes the held phrase, once its owner has
// confirmed it is written down. It answers 200 only when it is gone.
func (s *CoreServer) handleForgetRecoveryPhrase(w http.ResponseWriter, r *http.Request) {
	s.forgetPhrase(w, r, inForcePhrase)
}

func (s *CoreServer) handleForgetPhraseMovingTo(w http.ResponseWriter, r *http.Request) {
	s.forgetPhrase(w, r, movingToPhrase)
}

func (s *CoreServer) forgetPhrase(w http.ResponseWriter, r *http.Request, op phraseSlotOps) {
	if !s.isOwner(r) {
		jsonError(w, op.what+" is for the owner of this agent", http.StatusForbidden)
		return
	}
	if err := op.forget(s.DataDir); err != nil {
		log.Printf("[identity-agent-core] could not forget %s: %v", op.what, err)
		jsonError(w, op.what+" could not be removed", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]any{"held": false})
}
