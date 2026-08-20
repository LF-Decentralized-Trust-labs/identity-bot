package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"identity-agent-core/recovery"

	"github.com/go-chi/chi/v5"
)

func (s *CoreServer) mountRecoveryRoutes(r chi.Router) {
	r.Route("/recovery", func(r chi.Router) {
		r.Post("/verify", s.handleRecoveryVerify)
		r.Post("/start", s.handleRecoveryStart)
		// Every recovery this agent is holding. Without it a session is
		// reachable only from the screen that started it, and the wait is
		// measured in days.
		r.Get("/sessions", s.handleRecoveryListSessions)
		r.Get("/sessions/{id}", s.handleRecoveryGetSession)
		r.Post("/sessions/{id}/rotation", s.handleRecoveryRotation)
		r.Post("/sessions/{id}/activate", s.handleRecoveryActivate)
		r.Post("/sessions/{id}/cancel", s.handleRecoveryCancel)
		// What this identity has chosen about being coerced. Off unless
		// somebody turned it on.
		r.Get("/duress-policy", s.handleGetDuressPolicy)
		r.Put("/duress-policy", s.handlePutDuressPolicy)
		r.Post("/retrieve", s.handleRecoveryRetrieve)
		r.Post("/root-aid-rotation", s.handleRecoveryRootAIDRotation)
		r.Get("/root-aid-rotation/status", s.handleRecoveryRootAIDStatus)
	})
}

// recoveryOnce guards building the recovery service exactly once.
//
// Two requests arriving together both saw a nil field, both built a service
// over the same directory, both loaded the sessions, and the later assignment
// won — so a session written through one service was unreachable through the
// other and reported "not found" while sitting on disk. Handlers run
// concurrently, so this was reachable by two people, or one person and a
// retry.
var recoveryOnce sync.Once

func (s *CoreServer) recoveryService() *recovery.Service {
	recoveryOnce.Do(func() {
		s.RecoveryService = recovery.NewService(s.DataDir, s.DataStore, s.backupService())
		// Sessions that were waiting out their window when this agent last
		// stopped. Loaded here rather than in a startup hook so it happens on
		// the first use of recovery however the agent was started — a session
		// that survives being written down and is not read back is no better
		// than one that was never written.
		if n, err := s.RecoveryService.LoadSessions(); err != nil {
			log.Printf("[recovery] could not read sessions waiting out their window: %v", err)
		} else if n > 0 {
			log.Printf("[recovery] %d recovery session(s) resumed after restart", n)
		}
	})
	return s.RecoveryService
}

func (s *CoreServer) handleRecoveryVerify(w http.ResponseWriter, r *http.Request) {
	var req recovery.VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if req.Mnemonic == "" {
		writeError(w, http.StatusBadRequest, "mnemonic required", "Provide seed phrase to decrypt archive")
		return
	}
	if req.ArchiveB64 == "" {
		writeError(w, http.StatusBadRequest, "archive_b64 required", "Provide encrypted .iab archive")
		return
	}

	result, err := s.recoveryService().Verify(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Verify failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleRecoveryStart(w http.ResponseWriter, r *http.Request) {
	var req recovery.StartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if req.Mnemonic == "" || req.ArchiveB64 == "" {
		writeError(w, http.StatusBadRequest, "Missing fields", "mnemonic and archive_b64 are required")
		return
	}

	sess, err := s.recoveryService().Start(req)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Start failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleRecoveryGetSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sess, err := s.recoveryService().GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "Not found", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleRecoveryRotation(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	var req recovery.RotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if err := recovery.ValidateRotationRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid rotation request", err.Error())
		return
	}

	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Rotate via /api/rotation on desktop, or via the embedded Go core on mobile, then record the result here")
		return
	}

	result, err := s.KeriDriver.RotateAid(req.Name, req.NewPublicKey, req.NewNextPublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Rotation failed", err.Error())
		return
	}

	rotResult := recovery.RotationResult{
		AID:            result.AID,
		NewPublicKey:   result.NewPublicKey,
		SequenceNumber: result.SequenceNumber,
	}
	sess, err := s.recoveryService().RecordRotation(sessionID, rotResult)
	if err != nil {
		writeError(w, http.StatusNotFound, "Session not found", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session":         sess,
		"rotation_result": result,
	})
}

func (s *CoreServer) handleRecoveryActivate(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	// The recovery phrase again. It is not held while the waiting period runs,
	// so the archive is opened here rather than kept open across two days.
	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryBody)
	var req recovery.ActivateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Said plainly rather than swallowed. A malformed body used to fall
		// through to "the recovery phrase is needed again", which sends
		// somebody hunting for their phrase over a broken request.
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	sess, err := s.recoveryService().Activate(sessionID, req)
	if err != nil {
		switch err.(type) {
		case *recovery.ErrCancelWindowActive:
			writeError(w, http.StatusConflict, "Cancel window active", err.Error())
		case *recovery.ErrRotationMandatory:
			writeError(w, http.StatusPreconditionFailed, "Rotation required", err.Error())
		default:
			// A wrong phrase, a missing phrase and an archive that opens a
			// different identity are all the caller's to fix, not this
			// agent's failures. They were reported as 500.
			writeError(w, http.StatusBadRequest, "Could not complete this recovery", err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleRecoveryRetrieve(w http.ResponseWriter, r *http.Request) {
	var req recovery.RetrieveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	resp, err := s.recoveryService().Retrieve(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Retrieve failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *CoreServer) handleRecoveryRootAIDRotation(w http.ResponseWriter, r *http.Request) {
	if !recovery.RootAIDRotationAvailable() {
		writeError(w, http.StatusServiceUnavailable, "Root-AID rotation not available",
			"Break-glass root-AID rotation is gated pending security review of the signed old-root delegation anchor")
		return
	}
	var req recovery.RootAIDRotationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "KERI driver not available",
			"Root-AID rotation requires the KERI driver on desktop, or the embedded Go core on mobile")
		return
	}
	if s.DataStore == nil {
		writeError(w, http.StatusServiceUnavailable, "Store not available", "identity store is required")
		return
	}

	var watcherHints []string
	if s.WatcherService != nil {
		watcherHints = s.WatcherService.WatcherHints()
	}

	adapter := &recovery.KeriDriverAdapter{Driver: s.KeriDriver}
	result, err := recovery.RotateRootAID(req, adapter, s.DataStore, s.DataDir, watcherHints)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "Root-AID rotation failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *CoreServer) handleRecoveryRootAIDStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"available": recovery.RootAIDRotationAvailable(),
		"message":   "break-glass root-AID rotation requires an old-root signed rot event sealing the new inception SAID; gated pending security review",
	}
	if s.DataDir != "" {
		if m, err := recovery.LoadRootAIDMap(s.DataDir); err == nil && len(m.Entries) > 0 {
			resp["rotation_count"] = len(m.Entries)
			last := m.Entries[len(m.Entries)-1]
			resp["last_rotation_at"] = last.RotatedAt
			resp["current_root_aid"] = last.NewRootAID
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// maxRecoveryBody bounds what a recovery request can make this agent hold.
//
// The archive routes are the large ones; a phrase and a passphrase are not. The
// backup side limits its upload and these did not, which is the same omission
// in the same package.
const maxRecoveryBody = 512 << 20 // 512 MiB, enough for an archive body

// handleRecoveryCancel stops a recovery during its window.
//
// No recovery phrase is asked for, deliberately. The window exists so somebody
// who did NOT start the recovery can stop it, and requiring the phrase would
// mean only the person who started it could.
func (s *CoreServer) handleRecoveryCancel(w http.ResponseWriter, r *http.Request) {
	sess, err := s.recoveryService().Cancel(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Could not cancel this recovery", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}

func (s *CoreServer) handleGetDuressPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.recoveryService().LoadDuressPolicy())
}

// handlePutDuressPolicy records what an identity wants to happen when somebody
// may be being forced.
//
// A policy that cannot be satisfied is refused here rather than stored, so the
// moment somebody discovers they locked themselves out is not their recovery.
func (s *CoreServer) handlePutDuressPolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryBody)
	var p recovery.DuressPolicy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if err := s.recoveryService().SaveDuressPolicy(p); err != nil {
		writeError(w, http.StatusBadRequest, "That setting would not work", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.recoveryService().LoadDuressPolicy())
}

// handleRecoveryListSessions answers what recoveries are in progress.
//
// So an app can offer to resume one. A recovery that survives the agent
// restarting but not the screen closing is not something anybody can actually
// wait out.
func (s *CoreServer) handleRecoveryListSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": s.recoveryService().InProgress(),
	})
}
