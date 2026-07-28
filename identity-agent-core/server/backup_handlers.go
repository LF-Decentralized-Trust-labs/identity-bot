package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"identity-agent-core/backup"

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

func (s *CoreServer) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	var req backupExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	if req.Mnemonic == "" && req.BIP39SeedB64 == "" {
		writeError(w, http.StatusBadRequest, "mnemonic required", "Provide mnemonic for envelope encryption")
		return
	}
	if req.DestPath == "" {
		req.DestPath = filepath.Join(s.DataDir, "exports", "manual-"+time.Now().UTC().Format("20060102-150405")+".iab")
	}
	result, err := s.backupService().Export(req.Mnemonic, req.Passphrase, req.DestPath, req.Tiers)
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
