package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *CoreServer) mountBackupRoutes(r chi.Router) {
	r.Route("/backup", func(r chi.Router) {
		r.Post("/export", s.handleBackupExport)
		r.Get("/status", s.handleBackupStatus)
		r.Get("/config", s.handleBackupGetConfig)
		r.Put("/config", s.handleBackupPutConfig)
		r.Post("/destinations", s.handleBackupUpsertDestination)
		r.Delete("/destinations/{id}", s.handleBackupDeleteDestination)
		r.Post("/receive", s.handleBackupReceive)
		// What this machine holds for other people, and the offer that decides
		// whether it holds anything at all. See B5 and B6.
		r.Get("/held", s.handleBackupHeld)
		r.Get("/offer", s.handleBackupGetOffer)
		r.Put("/offer", s.handleBackupPutOffer)
		r.Delete("/held/{identityAID}", s.handleBackupStopHolding)
		r.Get("/receive/{identityAID}", s.handleBackupListReceived)
		r.Get("/receive/{identityAID}/download/{name}", s.handleBackupDownload)
		r.Post("/trigger", s.handleBackupTrigger)
		r.Post("/credentials", s.handleBackupSaveCredentials)
		r.Post("/pull/{destID}", s.handleBackupPull)
	})
}

type backupExportRequest struct {
	Mnemonic     string   `json:"mnemonic"`
	Passphrase   string   `json:"passphrase,omitempty"`
	DestPath     string   `json:"dest_path,omitempty"`
	Tiers        []string `json:"tiers,omitempty"`
	BIP39SeedB64 string   `json:"bip39_seed_b64,omitempty"`
}

func (s *CoreServer) backupService() *backup.Service {
	if s.BackupService == nil {
		s.BackupService = backup.NewService(s.DataDir, s.DataStore)
	}
	return s.BackupService
}

func (s *CoreServer) notifyBackupEvent(reason backup.EventReason) {
	s.backupService().NotifyEvent(reason)
}

// hasSealRecipients reports whether this agent has been given anyone to seal
// backup keys to.
func (s *CoreServer) hasSealRecipients() bool {
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		return false
	}
	return len(cfg.SealToPublicKeysB64) > 0
}

func (s *CoreServer) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	var req backupExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	// Nobody has to send a phrase over the wire to take a backup.
	//
	// There are two ways an archive can end up openable, and the caller supplying
	// a secret is neither of them. A delegated device seals to recovery public
	// keys it was given at pairing. A ROOT device already holds its own seed —
	// wrapped, on disk, put there at onboarding — so asking its owner to type the
	// words again only creates a second copy in flight to protect. The seed it
	// would derive from is the same seed either way.
	//
	// A mnemonic in the request is still honoured, because recovery flows pass
	// one deliberately. It is simply no longer the price of a backup.
	seed := req.BIP39SeedB64
	if req.Mnemonic == "" && seed == "" && !s.hasSealRecipients() {
		local, err := secureenclave.LoadRootSeed(s.DataDir)
		if err != nil {
			writeError(w, http.StatusBadRequest, "no way to unlock the archive",
				"this agent holds no root seed and has no recovery keys, so an archive it wrote could never be opened — "+
					"pair it with an owner, or supply a mnemonic: "+err.Error())
			return
		}
		seed = base64.StdEncoding.EncodeToString(local)
	}
	if req.DestPath == "" {
		req.DestPath = filepath.Join(s.DataDir, "exports", "manual-"+time.Now().UTC().Format("20060102-150405")+".iab")
	}
	result, err := s.backupService().ExportWithSeed(req.Mnemonic, seed, req.Passphrase, req.DestPath, req.Tiers)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Export failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"path":           req.DestPath,
		"size_bytes":     result.Size,
		"tiers":          result.Tiers,
		"snapshot_type":  result.SnapshotType,
		"format_version": result.Manifest.FormatVersion,
	})
}

func (s *CoreServer) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.backupService().Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Status failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *CoreServer) handleBackupGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (s *CoreServer) handleBackupPutConfig(w http.ResponseWriter, r *http.Request) {
	var cfg backup.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid config", err.Error())
		return
	}
	if err := s.backupService().SaveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "Save config failed", err.Error())
		return
	}
	if cfg.Enabled {
		s.backupService().Scheduler.StartDaily()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

type backupDestinationRequest struct {
	Destination backup.Destination `json:"destination"`
}

func (s *CoreServer) handleBackupUpsertDestination(w http.ResponseWriter, r *http.Request) {
	var req backupDestinationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if req.Destination.ID == "" {
		req.Destination.ID = uuid.New().String()
	}
	if err := backup.ValidateDestination(req.Destination); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid destination", err.Error())
		return
	}
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", err.Error())
		return
	}
	backup.UpsertDestination(&cfg, req.Destination)
	if err := s.backupService().SaveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "Save failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req.Destination)
}

func (s *CoreServer) handleBackupDeleteDestination(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", err.Error())
		return
	}
	filtered := []backup.Destination{}
	for _, d := range cfg.Destinations {
		if d.ID != id {
			filtered = append(filtered, d)
		}
	}
	cfg.Destinations = filtered
	if err := s.backupService().SaveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "Save failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type backupReceiveRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	IdentityAID     string `json:"identity_aid"`
	ArchiveB64      string `json:"archive_b64"`
}

func (s *CoreServer) handleBackupReceive(w http.ResponseWriter, r *http.Request) {
	var req backupReceiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	raw, err := backup.DecodeB64(req.ArchiveB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid archive", err.Error())
		return
	}
	// Backup-only device stores opaque ciphertext — never unwraps BEK.
	path, err := s.backupService().ReceiveArchive(req.IdentityAID, raw)
	if err != nil {
		// A refusal is not a failure, and the difference has to survive the
		// trip. The pushing agent shows this to somebody, and "this machine is
		// full" or "we are not taking on new identities" are things they can
		// act on, where a 500 is not. 409 because retrying changes nothing
		// until a person changes something.
		var refused *backup.RefusedToHold
		if errors.As(err, &refused) {
			writeError(w, http.StatusConflict, "This machine will not hold that",
				refused.Reason)
			return
		}
		writeError(w, http.StatusInternalServerError, "Store failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(backup.PushResponse{
		Received:   true,
		StoredPath: path,
		Message:    "opaque archive stored",
	})
}

func (s *CoreServer) handleBackupListReceived(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "identityAID")
	paths, err := s.backupService().ListReceived(aid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "List failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"archives": paths})
}

func (s *CoreServer) handleBackupTrigger(w http.ResponseWriter, r *http.Request) {
	// Say whether it can actually happen, rather than reporting success for
	// something that will skip quietly minutes later. That is how backups went
	// un-taken for as long as they did: this route always answered
	// "scheduled", and the only trace of the truth was a log line.
	if sch := s.backupService().Scheduler; sch != nil {
		if err := sch.CanRun(); err != nil {
			writeError(w, http.StatusConflict, "This agent cannot take a backup", err.Error())
			return
		}
	}
	s.notifyBackupEvent(backup.EventManual)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "scheduled"})
}

type backupCredentialsRequest struct {
	Credentials backup.RemoteCredentialSecrets `json:"credentials"`
}

func (s *CoreServer) handleBackupSaveCredentials(w http.ResponseWriter, r *http.Request) {
	var req backupCredentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	id, err := s.backupService().SaveDestinationCredentials(req.Credentials)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Save credentials failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"credential_id": id})
}

func (s *CoreServer) handleBackupPull(w http.ResponseWriter, r *http.Request) {
	destID := chi.URLParam(r, "destID")
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", err.Error())
		return
	}
	var dest *backup.Destination
	for i := range cfg.Destinations {
		if cfg.Destinations[i].ID == destID {
			dest = &cfg.Destinations[i]
			break
		}
	}
	if dest == nil {
		writeError(w, http.StatusNotFound, "Destination not found", destID)
		return
	}
	data, key, err := s.backupService().PullLatestArchive(*dest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Pull failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"object_key":  key,
		"size_bytes":  len(data),
		"archive_b64": backup.EncodeB64(data),
	})
}

// handleBackupDownload serves a received opaque archive for recovery retrieval (C7).
func (s *CoreServer) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	identityAID := chi.URLParam(r, "identityAID")
	name := chi.URLParam(r, "name")
	path := filepath.Join(s.DataDir, "backup_receive", identityAID, name)
	f, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "Not found", err.Error())
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

// handleBackupHeld answers "what is this machine holding, and for whom".
//
// Metadata only — identifier, how many archives, how much disk, when the last
// one arrived. Never contents, and there is no route that would return them:
// the archives are sealed to keys this machine does not have, so the honest
// screen is one that shows a person enough to manage disk and notice a backup
// that stopped arriving, and nothing more.
func (s *CoreServer) handleBackupHeld(w http.ResponseWriter, r *http.Request) {
	held, err := s.backupService().Held()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read what this machine holds", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"held": held})
}

func (s *CoreServer) handleBackupGetOffer(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", err.Error())
		return
	}
	offer := cfg.Offer
	if offer.ReserveBytes == 0 {
		// A config written before this existed decodes to a zero reserve, which
		// would mean "fill the disk completely". Reported as the default rather
		// than as zero, because this value is shown to somebody.
		offer.ReserveBytes = backup.DefaultOffer().ReserveBytes
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(offer)
}

// handleBackupPutOffer is where a machine volunteers, and stops volunteering.
func (s *CoreServer) handleBackupPutOffer(w http.ResponseWriter, r *http.Request) {
	var offer backup.Offer
	if err := json.NewDecoder(r.Body).Decode(&offer); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid offer", err.Error())
		return
	}
	if offer.ReserveBytes <= 0 {
		offer.ReserveBytes = backup.DefaultOffer().ReserveBytes
	}
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", err.Error())
		return
	}
	cfg.Offer = offer
	if err := s.backupService().SaveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "Save config failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(offer)
}

// handleBackupStopHolding removes what this machine holds for one identity.
//
// Whoever owns the hardware is entitled to their disk back. What they are not
// entitled to is doing it silently: the identity has to be told, or it goes on
// believing it has an off-site copy it does not have, which is the worst of the
// three states in B6. Telling it is the caller's job and is not yet built —
// tracked rather than pretended.
func (s *CoreServer) handleBackupStopHolding(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "identityAID")
	if err := s.backupService().StopHoldingFor(aid); err != nil {
		var refused *backup.RefusedToHold
		if errors.As(err, &refused) {
			writeError(w, http.StatusBadRequest, "Not something this machine holds", refused.Reason)
			return
		}
		writeError(w, http.StatusInternalServerError, "Could not remove", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
