package server

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"identity-agent-core/watcher"

	"github.com/go-chi/chi/v5"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	hits    map[string][]time.Time
	limit   int
	window  time.Duration
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{hits: make(map[string][]time.Time), limit: limit, window: window}
}

func (r *ipRateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	prev := r.hits[ip]
	filtered := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) >= r.limit {
		r.hits[ip] = filtered
		return false
	}
	r.hits[ip] = append(filtered, now)
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *CoreServer) mountWatcherPublicRoutes(r chi.Router) {
	if s.WatcherService == nil {
		return
	}
	lim := newIPRateLimiter(60, time.Minute)
	r.Get("/public/kel-digest", func(w http.ResponseWriter, r *http.Request) {
		if !lim.allow(clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "Rate limited", "")
			return
		}
		aid := r.URL.Query().Get("aid")
		seqStr := r.URL.Query().Get("seq")
		if aid == "" || seqStr == "" {
			writeError(w, http.StatusBadRequest, "aid and seq required", "")
			return
		}
		seq, err := strconv.Atoi(seqStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid seq", err.Error())
			return
		}
		resp, err := s.WatcherService.GetPublicDigest(aid, seq)
		if err != nil {
			if err.Error() == "opted_out" {
				writeError(w, http.StatusNotFound, "Not found", "")
				return
			}
			writeError(w, http.StatusInternalServerError, "digest lookup failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	r.Post("/public/kel-check", func(w http.ResponseWriter, r *http.Request) {
		if !lim.allow(clientIP(r)) {
			writeError(w, http.StatusTooManyRequests, "Rate limited", "")
			return
		}
		var req watcher.KelCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body", err.Error())
			return
		}
		resp, err := s.WatcherService.KelCheck(req)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "kel-check failed", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	if os.Getenv("WATCHER_DEBUG") == "true" {
		r.Get("/debug/watcher/first-seen", s.handleDebugWatcherFirstSeen)
		r.Get("/debug/watcher/coverage", s.handleDebugWatcherCoverage)
	}
}

func (s *CoreServer) handleDebugWatcherFirstSeen(w http.ResponseWriter, r *http.Request) {
	if !isLocalhost(r) {
		writeError(w, http.StatusForbidden, "localhost only", "")
		return
	}
	aid := r.URL.Query().Get("aid")
	if aid == "" {
		writeError(w, http.StatusBadRequest, "aid required", "")
		return
	}
	rows, err := s.WatcherService.Store.ListFirstSeen(aid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"aid": aid, "records": rows})
}

func (s *CoreServer) handleDebugWatcherCoverage(w http.ResponseWriter, r *http.Request) {
	if !isLocalhost(r) {
		writeError(w, http.StatusForbidden, "localhost only", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"note":   "coverage summary — extend with aggregate queries as needed",
	})
}

func isLocalhost(r *http.Request) bool {
	ip := clientIP(r)
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

func (s *CoreServer) runWatcherOnKel(ctx context.Context, aid string, kel []map[string]interface{}, source watcher.SourceType, sourceURL string, bootstrap []string) *watcher.VerifyKelResult {
	if s.WatcherService == nil || aid == "" || len(kel) == 0 {
		return nil
	}
	res, err := s.WatcherService.VerifyKel(ctx, watcher.VerifyKelInput{
		AID: aid, KEL: kel, SourceType: source, SourceURL: sourceURL, BootstrapL2: bootstrap,
	})
	if err != nil {
		log.Printf("[watcher] VerifyKel %s: %v", aid, err)
		return nil
	}
	if res.Blocked {
		log.Printf("[watcher] DUPLICITY blocked aid=%s seq=%d reason=%s", aid, res.SequenceNum, res.Reason)
	}
	return res
}