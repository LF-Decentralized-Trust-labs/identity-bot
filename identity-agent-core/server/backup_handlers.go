package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
		// whether it holds anything at all.
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
	// Where the archive is written is this agent's decision, not the caller's.
	//
	// dest_path was taken as given and passed to MkdirAll and WriteFile, so a
	// caller chose any path on the machine and the archive replaced whatever
	// was there — the identity store included. It also pointed the other way:
	// an archive written to a synced folder is this identity's sealed backup
	// leaving the machine on somebody else's instruction. That is the same hole
	// as reading an arbitrary file, with the arrow reversed.
	//
	// A caller may still choose the NAME, which is all any caller needed.
	name := "manual-" + time.Now().UTC().Format("20060102-150405") + ".iab"
	if req.DestPath != "" {
		chosen := filepath.Base(filepath.Clean(req.DestPath))
		if err := backup.AcceptableExportName(chosen); err != nil {
			writeError(w, http.StatusBadRequest, "Not a name for an archive", err.Error())
			return
		}
		name = chosen
	}
	req.DestPath = filepath.Join(s.DataDir, "exports", name)
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
	// Decoded ONTO what is stored, not into a blank config.
	//
	// This decoded a whole Config and saved it verbatim, so every field the
	// sender left out was silently reset. The client does exactly that: it
	// sends six fields and omits the rest, so saving any backup setting from a
	// screen wiped the recipients able to open this identity's archives, and
	// wiped whether this machine had volunteered to hold archives for other
	// identities — turning a working destination somebody else relies on into
	// one that refuses everything, with nothing said.
	//
	// Decoding onto the stored value means an absent field keeps what it had,
	// and only what was actually sent can change. Guarding one field at a time
	// would leave the next one to be found the same way.
	body, rerr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRecoveryBody))
	if rerr != nil {
		writeError(w, http.StatusBadRequest, "Invalid config", rerr.Error())
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	cfg, lerr := s.backupService().LoadConfig()
	if lerr != nil {
		writeError(w, http.StatusInternalServerError, "Load config failed", lerr.Error())
		return
	}
	// CLONED, not aliased. A slice header copy shares its backing array, and
	// json.Unmarshal decodes into that same array whenever the incoming list
	// fits the existing capacity — so "before" became the new value too, and
	// the comparison below was a slice against itself. The guard passed for
	// every agent that already had a recipient, which is every paired agent.
	before := slices.Clone(cfg.SealToPublicKeysB64)

	// The same aliasing problem, one field deeper.
	//
	// Go decodes a JSON array onto an existing slice POSITIONALLY, reusing
	// each element in place, so a field the client omits keeps whatever the
	// destination at that INDEX had. Send a shorter or reordered list — which
	// is what removing a destination does — and the answer belonging to one
	// destination silently attaches to another.
	//
	// That is tolerable for a label. It is not tolerable for Elsewhere, which
	// is the owner's own statement that a destination is not in the same
	// building, and which decides whether the agent says a fire would take
	// everything. So the answers are taken from what was stored, by ID, after
	// the decode.
	elsewhereWas := map[string]bool{}
	for _, d := range cfg.Destinations {
		elsewhereWas[d.ID] = d.Elsewhere
	}

	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid config", err.Error())
		return
	}

	// Put each destination's own answer back, by identity rather than by
	// position. A client that genuinely means to change one sends it, and this
	// keeps the sent value; a client that omits it keeps what that destination
	// had rather than inheriting a neighbour's.
	var sent struct {
		Destinations []struct {
			ID        string `json:"id"`
			Elsewhere *bool  `json:"elsewhere"`
		} `json:"destinations"`
	}
	saidElsewhere := map[string]bool{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &sent); err == nil {
			for _, d := range sent.Destinations {
				if d.Elsewhere != nil {
					saidElsewhere[d.ID] = *d.Elsewhere
				}
			}
		}
	}
	for i := range cfg.Destinations {
		id := cfg.Destinations[i].ID
		if answer, ok := saidElsewhere[id]; ok {
			cfg.Destinations[i].Elsewhere = answer
			continue
		}
		cfg.Destinations[i].Elsewhere = elsewhereWas[id]
	}

	// Recipients are not settable here.
	//
	// A seal recipient is a standing key to every archive this agent writes
	// from now on, openable by that recipient alone and by nobody else's
	// inspection: the archive deliberately carries no recipient names, so a
	// planted slot looks exactly like a legitimate one. There is already a path
	// that does this properly — it validates each key and runs only after the
	// claimant has proved control of the identity.
	if !slices.Equal(cfg.SealToPublicKeysB64, before) {
		writeError(w, http.StatusConflict, "Recipients are not set here",
			"who can open this identity's archives is decided when a machine is paired, "+
				"not by writing configuration")
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

// maxArchiveUpload bounds what an unauthenticated caller can make this agent
// hold in memory.
//
// The offer decides whether an archive is KEPT, and it is consulted far too
// late to decide whether one is READ: by then the body has been decoded into a
// string and base64-decoded into bytes, so a machine accepting nothing for
// nobody was as exposed as one that had volunteered. Every other route in this
// package that takes a JSON body already limits it.
const maxArchiveUpload = 2 << 30 // 2 GiB of base64, ~1.5 GiB of archive

func (s *CoreServer) handleBackupReceive(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxArchiveUpload)
	var req backupReceiveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	// Consent before allocation, as far as it can be taken.
	//
	// The size limit above bounds the damage; it does not stop a machine that
	// holds nothing for nobody from being made to allocate up to that limit.
	// The identifier is small and arrives in the same body, so the offer can be
	// consulted before the archive is decoded into a second copy. The
	// authoritative check still runs inside ReceiveArchive — this one exists to
	// refuse earlier, not instead.
	if refusal := s.mayHold(req.IdentityAID); refusal != nil {
		writeError(w, http.StatusConflict, "This machine will not hold that", refusal.Error())
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
	// See handleBackupDownload. "GET /api/backup/receive/.." listed this
	// agent's whole data directory to anybody who asked.
	if err := backup.AcceptableAID(aid); err != nil {
		writeError(w, http.StatusBadRequest, "Not an identifier", err.Error())
		return
	}
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

// handleBackupDownload serves a received opaque archive back to its owner.
//
// PUBLIC and unauthenticated, like the two routes beside it: an identity
// recovering has no credential to present yet, which is the whole situation.
// That makes both parameters attacker-controlled, and both used to be joined
// straight onto a filesystem path.
//
//	GET /api/backup/receive/../download/backup_config.json
//
// returned the file. filepath.Join collapses the "..", so any host that could
// open a connection could list this agent's data directory and read the files
// sitting in it — contacts, profile, the backup configuration. The write side
// of this same surface was given an identifier check; these two read routes
// were not, and they are the half that hands data out.
func (s *CoreServer) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	identityAID := chi.URLParam(r, "identityAID")
	if err := backup.AcceptableAID(identityAID); err != nil {
		writeError(w, http.StatusBadRequest, "Not an identifier", err.Error())
		return
	}
	name := chi.URLParam(r, "name")
	if err := backup.AcceptableArchiveName(name); err != nil {
		writeError(w, http.StatusBadRequest, "Not an archive", err.Error())
		return
	}
	root := filepath.Join(s.DataDir, "backup_receive")
	path := filepath.Join(root, identityAID, name)
	// Confirmed to be inside the receive directory before it is opened, the
	// same second lock StopHoldingFor puts on its delete. The allowlists above
	// already make traversal impossible; this survives one of them being
	// loosened later by somebody who does not know that is what is holding the
	// door shut.
	if rel, rerr := filepath.Rel(root, path); rerr != nil ||
		rel != filepath.Join(identityAID, name) {
		writeError(w, http.StatusBadRequest, "Not an archive",
			"that is not somewhere this machine keeps archives")
		return
	}
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
	// Archives stored before a push had to name its sender sit loose in the
	// receive directory and are reachable by nothing. Gathered here, on the
	// screen that reports them, rather than in a startup path where a failure
	// would be invisible.
	if _, merr := s.backupService().AdoptArchivesFiledUnderNoIdentity(); merr != nil {
		log.Printf("[backup] could not tidy archives that name no identity: %v", merr)
	}
	held, err := s.backupService().Held()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read what this machine holds", err.Error())
		return
	}
	// Reported beside the identities and never as one. Gathering them somewhere
	// tidy is not the same as making them visible: Held skips any directory
	// that is not a well-formed identifier, so a screen that only moved them
	// would leave them exactly where they started, which is unseen — the state
	// this whole screen exists to end.
	body := map[string]interface{}{"held": held}
	if u, uerr := s.backupService().UnattributedArchives(); uerr != nil {
		log.Printf("[backup] could not read archives that name no identity: %v", uerr)
	} else if u != nil {
		body["unattributed"] = u
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
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
// believing it has an off-site copy it does not have, which is the worst state
// of the three. Telling it is the caller's job and is not yet built —
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

// mayHold answers whether this machine would hold an archive for this identity,
// without needing the archive.
//
// A cheap pre-check so a refusal costs a caller nothing and this machine no
// memory. It deliberately mirrors rather than replaces the check inside
// ReceiveArchive: that one is the gate, and it runs whether or not this one
// did.
func (s *CoreServer) mayHold(aid string) error {
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		// Cannot tell. Fall through and let the real check answer.
		return nil
	}
	held, _ := s.backupService().ListReceived(aid)
	return cfg.Offer.MayAccept(aid, len(held) > 0)
}
