package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"identity-agent-core/backup"
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

		// Holding a share for somebody else's identity. Small on purpose: a
		// machine that agrees to help stores one key and one promise, and
		// learns nothing about the person it is helping.
		r.Post("/holdings", s.handleAgreeToHold)
		r.Get("/holdings", s.handleWhatThisMachineHolds)
		r.Post("/holdings/approve", s.handleApproveShare)
		r.Post("/holdings/stop", s.handleStopHolding)
		r.Post("/share-requests", s.handleReleaseShare)
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

// Built per server rather than once per process.
//
// A package-level sync.Once binds whichever CoreServer ran first to the whole
// program: a second instance then serves the first one's holdings and writes
// its waiting clock into the first one's data directory. That is wrong in
// tests and worse in anything running two agents, and it is reached through an
// unauthenticated route.
var holderState sync.Map // *CoreServer -> *holderPair

type holderPair struct {
	once     sync.Once
	holdings *recovery.Holdings
	holder   *recovery.Holder
}

func (s *CoreServer) holderPairFor() *holderPair {
	v, _ := holderState.LoadOrStore(s, &holderPair{})
	pair := v.(*holderPair)
	pair.once.Do(func() {
		pair.holdings = &recovery.Holdings{DataDir: s.DataDir}
		pair.holder = &recovery.Holder{
			DataDir: s.DataDir,
			Notify: func(identityAID string, first bool) {
				// Somebody is recovering an identity this machine helps
				// protect. Logged for now: the owner-facing notification is
				// the point of it, and there is nowhere yet to send one.
				log.Printf("[recovery] a share was asked for: identity=%s first=%v",
					identityAID, first)
			},
		}
	})
	return pair
}

// holdings is what this machine has agreed to hold for other identities.
func (s *CoreServer) holdings() *recovery.Holdings { return s.holderPairFor().holdings }

// shareHolder decides whether to release a share, and is the clock while it
// does.
func (s *CoreServer) shareHolder() *recovery.Holder { return s.holderPairFor().holder }

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
		case *recovery.ErrHeldForDuress:
			// Its own status, because a client has to be able to tell this from
			// a mistyped phrase. Falling to the default made a duress hold a
			// bad request, which threw away the "until" and "how many more
			// approvals" this type carries precisely so a screen can say them.
			writeError(w, http.StatusConflict, "Held", err.Error())
		case *recovery.ErrNotAuthenticated:
			writeError(w, http.StatusForbidden, "Not authenticated", err.Error())
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

// statusForActivateError says which refusal this is.
//
// Lifted out of the handler so it can be tested, and so the two cannot drift.
// None of these is a server fault: each is a true statement about the request
// or about where the recovery has got to, and somebody reading it should be
// able to act on it.
func statusForActivateError(err error) int {
	// Needing shares is not a bad request. It is the archive working as
	// designed, and a client has to be able to tell it from a mistyped phrase
	// — which is what 400 already means here.
	var needs *backup.ErrNeedsShares
	if errors.As(err, &needs) {
		return http.StatusConflict
	}
	switch err.(type) {
	case *recovery.ErrCancelWindowActive:
		return http.StatusConflict
	case *recovery.ErrRotationMandatory:
		return http.StatusPreconditionFailed
	case *recovery.ErrHeldForDuress:
		return http.StatusConflict
	case *recovery.ErrNotAuthenticated:
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

// --- holding a share for somebody else's identity -------------------------

// handleAgreeToHold takes on a share for another identity and answers with the
// public key to seal it to.
//
// The keypair is made here, by the machine that will have to use it, and only
// the public half goes back. If the asking agent generated it instead, the
// machine that wrote the backup would once have held every key needed to open
// it.
func (s *CoreServer) handleAgreeToHold(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryBody)
	var req recovery.AgreeToHold
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	agreed, err := s.holdings().Agree(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "This machine cannot hold that", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agreed)
}

// handleWhatThisMachineHolds lists what somebody has taken on, without keys.
func (s *CoreServer) handleWhatThisMachineHolds(w http.ResponseWriter, r *http.Request) {
	held, err := s.holdings().All()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read what this machine holds", err.Error())
		return
	}
	asked, err := s.shareHolder().WhatHasBeenAsked()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read what has been asked", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"holding": held,
		"asked":   asked,
	})
}

// handleReleaseShare is a recovering machine asking for a share back.
//
// Unauthenticated by design, and the reason is the sealed share it carries:
// opening that needs a private key only this machine has, and holding it at
// all means the caller opened a bootstrap envelope, which needed the recovery
// words. So the request authenticates itself with something no stranger can
// forge, and everything that cannot be opened gets one answer.
func (s *CoreServer) handleReleaseShare(w http.ResponseWriter, r *http.Request) {
	// Kilobytes, not the half a gigabyte the rest of recovery allows. This
	// route is unauthenticated, so anybody at all can post to it, and a share
	// request is an identifier, a name and a sealed 32-byte secret. Reading
	// megabytes from a stranger before deciding anything is work they get for
	// free.
	r.Body = http.MaxBytesReader(w, r.Body, maxShareRequestBody)
	var req struct {
		IdentityAID string             `json:"identity_aid"`
		HolderID    string             `json:"holder_id"`
		Sealed      backup.SealedShare `json:"sealed_share"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	holding, err := s.holdings().Find(req.IdentityAID, req.HolderID)
	if err != nil || holding == nil {
		// Byte-for-byte the answer a share sealed to somebody else gets.
		// Anything that distinguishes them turns this route into a way for a
		// stranger to enumerate whose backups this machine helps protect.
		writeError(w, http.StatusForbidden, "This share was not released",
			notSealedToThisHolder)
		return
	}

	share, err := s.shareHolder().Release(*holding, req.Sealed, time.Now())
	if err != nil {
		writeShareRefusal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"share_b64": backup.EncodeB64(share)})
}

// handleStopHolding is somebody deciding they no longer want to hold a share.
//
// Agreeing to hold part of a recovery is a commitment, and a commitment with
// no way out is not one somebody can make freely. Every share sealed to this
// key stops being openable, so whoever was being helped needs a fresh backup —
// which the answer says, because a holder quietly disappearing is the failure
// nobody finds out about until a recovery.
func (s *CoreServer) handleStopHolding(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxShareRequestBody)
	var req struct {
		IdentityAID string `json:"identity_aid"`
		HolderID    string `json:"holder_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if err := s.holdings().Forget(req.IdentityAID, req.HolderID); err != nil {
		writeError(w, http.StatusInternalServerError, "That could not be given up", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"stopped_holding": req.HolderID,
		"tell_them": "Every backup already sealed to this machine can no longer be opened " +
			"by it. Whoever this was helping needs to take a fresh backup.",
	})
}

// notSealedToThisHolder is the one answer every unopenable request gets.
//
// One string, used from both places, because two messages that mean "no" and
// differ by a word are a way to tell what a machine holds.
const notSealedToThisHolder = "this share was not sealed to this holder"

// maxShareRequestBody bounds what an unauthenticated caller may send.
const maxShareRequestBody = 64 << 10

// handleApproveShare records that a person said yes to a recovery.
func (s *CoreServer) handleApproveShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRecoveryBody)
	var req struct {
		IdentityAID string `json:"identity_aid"`
		HolderID    string `json:"holder_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if err := s.shareHolder().Approve(req.IdentityAID, req.HolderID, time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, "That could not be approved", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeShareRefusal answers a refusal in a way a screen can act on.
//
// Being held and being refused are different things and must not arrive as the
// same status, or no client can tell "come back on Tuesday" from "this will
// never work".
func writeShareRefusal(w http.ResponseWriter, err error) {
	var held *recovery.ErrHeldForWait
	if errors.As(err, &held) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "This share is being held",
			"detail":        err.Error(),
			"release_after": held.Until.UTC().Format(time.RFC3339),
		})
		return
	}
	var approval *recovery.ErrNeedsApproval
	if errors.As(err, &approval) {
		writeError(w, http.StatusConflict, "This share is waiting to be approved", err.Error())
		return
	}
	writeError(w, http.StatusForbidden, "This share was not released", err.Error())
}
