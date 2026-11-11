package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/drivers"
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/watcher"
)

// The owner's side of the watcher: what it found about the identities this
// agent has met, and what the owner may do about it.
//
//	GET  /api/watcher/status                     is it on, and whom does it believe
//	GET  /api/watcher/alerts                     duplicity alerts (?aid=, ?open=true)
//	POST /api/watcher/alerts/{id}/acknowledge    the owner has seen it (owner-only)
//	POST /api/watcher/alerts/{id}/resolve        the owner closes it with a note (owner-only)
//	GET  /api/watcher/checks                     the newest check of every identity
//	GET  /api/watcher/checks/{aid}               the newest check of one
//	GET  /api/watcher/trusted, PUT               the watchers whose answers are believed (PUT owner-only)
//	GET  /api/watcher/hints, PUT                 the watchers this identity names to contacts in its own introduction (PUT owner-only)
//
// Every read of an alert or a check goes through the opt-out check in the
// watcher package, so an identity the owner opted out answers as one never seen.
// The opt-out route itself is in watcher_handlers.go.

const (
	maxTrustedWatchers = 32
	maxWatcherHints    = 16
	maxHintBytes       = 2048
	maxAlertNoteBytes  = 2000
)

func (s *CoreServer) mountWatcherOwnerRoutes(r chi.Router) {
	r.Get("/watcher/status", s.handleWatcherStatus)
	r.Get("/watcher/alerts", s.handleWatcherAlertsList)
	r.Post("/watcher/alerts/{id}/acknowledge", s.handleWatcherAlertAcknowledge)
	r.Post("/watcher/alerts/{id}/resolve", s.handleWatcherAlertResolve)
	r.Get("/watcher/checks", s.handleWatcherChecksList)
	r.Get("/watcher/checks/{aid}", s.handleWatcherCheckGet)
	r.Get("/watcher/trusted", s.handleWatcherTrustedGet)
	r.Put("/watcher/trusted", s.handleWatcherTrustedSet)
	r.Get("/watcher/hints", s.handleWatcherHintsGet)
	r.Put("/watcher/hints", s.handleWatcherHintsSet)
}

// watcherAlertJSON is an alert as the owner is shown it. It carries no digest:
// a screen has no use for one, and what is not sent cannot be mishandled.
type watcherAlertJSON struct {
	ID             int64  `json:"id"`
	AID            string `json:"aid"`
	SequenceNum    int    `json:"sequence_num"`
	DetectedAt     string `json:"detected_at"`
	SourceURL      string `json:"source_url,omitempty"`
	Acknowledged   bool   `json:"acknowledged"`
	AcknowledgedAt string `json:"acknowledged_at,omitempty"`
	Kind           string `json:"kind"`
	Resolved       bool   `json:"resolved"`
	ResolutionNote string `json:"resolution_note,omitempty"`
}

// kindOf names the kind an alert has; one stored before kinds existed is a duplicity.
func kindOf(a watcher.DuplicityAlert) string {
	if a.Kind == "" {
		return watcher.AlertKindDuplicity
	}
	return a.Kind
}

func alertJSON(a watcher.DuplicityAlert) watcherAlertJSON {
	out := watcherAlertJSON{
		ID: a.ID, AID: a.AID, SequenceNum: a.SequenceNum,
		DetectedAt: a.DetectedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		SourceURL:  a.SourceURL, Kind: kindOf(a), Resolved: a.Resolved, ResolutionNote: a.ResolutionNote,
	}
	if !a.AcknowledgedAt.IsZero() {
		out.Acknowledged = true
		out.AcknowledgedAt = a.AcknowledgedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	}
	return out
}

// watcherOff answers a request to a route that needs the watcher when there is
// none. It is not "no alerts": the caller has to be able to tell the two apart.
func (s *CoreServer) watcherOff(w http.ResponseWriter) bool {
	if s.WatcherService == nil {
		jsonreply.Write(w, http.StatusNotFound, ErrorResponse{Error: "watcher not running", Code: "watcher_off"})
		return true
	}
	return false
}

// handleWatcherStatus says honestly what the watcher is doing. "off" is its own
// answer, and so is "own_record_only": with no trusted watcher, what another
// watcher says is not believed, so only this agent's own memory can raise an alert.
func (s *CoreServer) handleWatcherStatus(w http.ResponseWriter, r *http.Request) {
	if s.WatcherService == nil {
		jsonreply.Write(w, http.StatusOK, map[string]interface{}{
			"running": false, "state": "off",
			"shipped_trusted": []string{}, "added_trusted": []string{},
			"hints": []string{}, "open_alerts": 0, "open_escalations": 0,
		})
		return
	}
	svc := s.WatcherService
	added := svc.OwnerTrustedL2Signers()
	shipped := append([]string{}, watcher.DefaultL2SignerAIDs...)
	state := "checking"
	if len(added)+len(shipped) == 0 {
		state = "own_record_only"
	}
	open, openEscalations := 0, 0 // counted apart: only a duplicity alert blocks
	alerts, err := svc.DisclosableAllAlerts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	for _, a := range alerts {
		if a.Resolved {
			continue
		}
		if kindOf(a) == watcher.AlertKindEscalation {
			openEscalations++
		} else {
			open++
		}
	}
	hints := svc.WatcherHints()
	if hints == nil {
		hints = []string{}
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"running": true, "state": state,
		"standing_url":    svc.DefaultL2URL(),
		"shipped_trusted": shipped, "added_trusted": added,
		"hints": hints, "open_alerts": open, "open_escalations": openEscalations,
	})
}

func (s *CoreServer) handleWatcherAlertsList(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	var (
		alerts []watcher.DuplicityAlert
		err    error
	)
	aid := r.URL.Query().Get("aid")
	if aid != "" {
		alerts, err = s.WatcherService.DisclosableAlerts(aid)
	} else {
		alerts, err = s.WatcherService.DisclosableAllAlerts()
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	onlyOpen := r.URL.Query().Get("open") == "true"
	out := []watcherAlertJSON{}
	for _, a := range alerts {
		if onlyOpen && a.Resolved {
			continue
		}
		out = append(out, alertJSON(a))
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"alerts": out})
}

func (s *CoreServer) alertID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid alert id", "")
		return 0, false
	}
	return id, true
}

func (s *CoreServer) alertActionError(w http.ResponseWriter, err error) {
	if errors.Is(err, watcher.ErrNoSuchAlert) {
		writeError(w, http.StatusNotFound, "no such alert", "")
		return
	}
	if errors.Is(err, watcher.ErrAlertAlreadyResolved) {
		jsonreply.Write(w, http.StatusConflict, ErrorResponse{
			Error: "alert already resolved", Details: "an alert is an audit record, its first note stands", Code: "already_resolved"})
		return
	}
	writeError(w, http.StatusInternalServerError, "could not save", err.Error())
}

func (s *CoreServer) handleWatcherAlertAcknowledge(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	id, ok := s.alertID(w, r)
	if !ok {
		return
	}
	if err := s.WatcherService.AcknowledgeAlert(id); err != nil {
		s.alertActionError(w, err)
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"id": id, "acknowledged": true})
}

func (s *CoreServer) handleWatcherAlertResolve(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	id, ok := s.alertID(w, r)
	if !ok {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	note := strings.TrimSpace(req.Note)
	if note == "" || len(note) > maxAlertNoteBytes {
		writeError(w, http.StatusBadRequest, "a note is required",
			"say in a few words why this alert is being closed (up to 2000 characters)")
		return
	}
	if err := s.WatcherService.ResolveAlert(id, note); err != nil {
		s.alertActionError(w, err)
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"id": id, "resolved": true})
}

func (s *CoreServer) handleWatcherChecksList(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	checks, err := s.WatcherService.DisclosableChecks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"checks": checks})
}

// handleWatcherCheckGet answers 404 for an identity never checked, and for one
// opted out: the two are not told apart. A contact never checked is
// "unchecked", which is not the same as one checked and found sound.
func (s *CoreServer) handleWatcherCheckGet(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	c, err := s.WatcherService.DisclosableCheck(chi.URLParam(r, "aid"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	if c == nil {
		jsonreply.Write(w, http.StatusNotFound, ErrorResponse{Error: "not checked", Code: "never_checked"})
		return
	}
	jsonreply.Write(w, http.StatusOK, c)
}

func (s *CoreServer) handleWatcherTrustedGet(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"shipped": append([]string{}, watcher.DefaultL2SignerAIDs...),
		"added":   s.WatcherService.OwnerTrustedL2Signers(),
	})
}

func (s *CoreServer) handleWatcherTrustedSet(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	var req struct {
		AIDs []string `json:"aids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AIDs == nil {
		writeError(w, http.StatusBadRequest, "aids required", "send the whole list, which may be empty")
		return
	}
	if len(req.AIDs) > maxTrustedWatchers {
		writeError(w, http.StatusBadRequest, "too many watchers", "at most "+strconv.Itoa(maxTrustedWatchers))
		return
	}
	seen := map[string]bool{}
	clean := []string{}
	for _, a := range req.AIDs {
		a = strings.TrimSpace(a)
		if _, ok := drivers.WitnessKey(a); !ok {
			writeError(w, http.StatusBadRequest, "not a watcher identifier",
				"a watcher is named by its non-transferable identifier: "+a)
			return
		}
		if !seen[a] {
			seen[a] = true
			clean = append(clean, a)
		}
	}
	if err := s.WatcherService.SetTrustedL2Signers(clean); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"shipped": append([]string{}, watcher.DefaultL2SignerAIDs...), "added": clean,
	})
}

func (s *CoreServer) handleWatcherHintsGet(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	hints := s.WatcherService.WatcherHints()
	if hints == nil {
		hints = []string{}
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"hints": hints})
}

// isHTTPSWatcherAddress is the one rule for a watcher address that is queried:
// https, a host, no credentials, bounded length. The owner's own hints and the
// ones a contact names in its introduction both pass through it.
func isHTTPSWatcherAddress(h string) bool {
	u, err := url.Parse(h)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(h) <= maxHintBytes
}

func (s *CoreServer) handleWatcherHintsSet(w http.ResponseWriter, r *http.Request) {
	if s.watcherOff(w) {
		return
	}
	var req struct {
		URLs []string `json:"urls"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URLs == nil {
		writeError(w, http.StatusBadRequest, "urls required", "send the whole list, which may be empty")
		return
	}
	if len(req.URLs) > maxWatcherHints {
		writeError(w, http.StatusBadRequest, "too many hints", "at most "+strconv.Itoa(maxWatcherHints))
		return
	}
	clean := []string{}
	seen := map[string]bool{}
	for _, h := range req.URLs {
		h = strings.TrimSpace(h)
		if !isHTTPSWatcherAddress(h) {
			writeError(w, http.StatusBadRequest, "a hint must be an https address of at most 2048 characters", h)
			return
		}
		if !seen[h] {
			seen[h] = true
			clean = append(clean, h)
		}
	}
	if err := s.WatcherService.SetWatcherHints(clean); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"hints": clean})
}
