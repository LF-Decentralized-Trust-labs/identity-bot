package server

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"identity-agent-core/watcher"

	"github.com/go-chi/chi/v5"
)

// maxRateLimitedClients bounds the limiter's memory. Each key is a caller
// address, which a caller choosing its own addresses could otherwise multiply
// without limit.
const maxRateLimitedClients = 10000

// maxPublicBodyBytes caps a request body on the unauthenticated peer routes.
// Every legitimate body on them is a few hundred bytes.
const maxPublicBodyBytes = 64 << 10

type ipRateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{hits: make(map[string][]time.Time), limit: limit, window: window}
}

// limiterKey is what a caller is counted as. An IPv6 customer holds a whole /64
// (2^64 addresses), so keying by full address would let one caller fill the
// table with throwaway addresses and lock newcomers out; they are one caller.
func limiterKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// allow records a request from ip and reports whether it is within the limit.
// A nil limiter allows everything, so a server built without one degrades to
// unlimited rather than to unusable.
func (r *ipRateLimiter) allow(ip string) bool {
	if r == nil {
		return true
	}
	ip = limiterKey(ip)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-r.window)
	if !r.roomForLocked(ip, cutoff) {
		return false
	}
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

// wouldAllow reports whether allow(ip) would let a request through, without
// counting it or remembering ip.
func (r *ipRateLimiter) wouldAllow(ip string) bool {
	if r == nil {
		return true
	}
	ip = limiterKey(ip)
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-r.window)
	n := 0
	for _, t := range r.hits[ip] {
		if t.After(cutoff) {
			n++
		}
	}
	if !r.roomForLocked(ip, cutoff) {
		return false
	}
	return n < r.limit
}

// roomForLocked reports whether ip can be counted: it is already known, or the
// table has room, after forgetting callers whose every hit has aged out. If
// that frees nothing, the table is full of live callers: refuse the newcomer
// rather than grow, which is the safe side for an unauthenticated route. allow
// and wouldAllow both ask it, so a table of expired callers never locks a
// newcomer out. The caller holds r.mu.
func (r *ipRateLimiter) roomForLocked(ip string, cutoff time.Time) bool {
	if _, known := r.hits[ip]; known || len(r.hits) < maxRateLimitedClients {
		return true
	}
	for k, ts := range r.hits {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(r.hits, k)
		}
	}
	return len(r.hits) < maxRateLimitedClients
}

// trustedProxies are the addresses of reverse proxies this agent sits behind,
// from TRUSTED_PROXIES (comma-separated IPs or CIDRs). Empty by default: with
// no proxy in front, every forwarding header is written by the caller.
func trustedProxies() []*net.IPNet {
	var out []*net.IPNet
	for _, f := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			if strings.Contains(f, ":") {
				f += "/128"
			} else {
				f += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func isTrustedProxy(ip string, proxies []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range proxies {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// clientIP is the address of the connection, unless that connection is from a
// configured trusted proxy, in which case it is the nearest address in
// X-Forwarded-For that is not itself a trusted proxy. A forwarding header from
// anybody else is ignored: it is whatever the caller chose to write, and
// believing it lets a caller pick a fresh identity for every request.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	proxies := trustedProxies()
	if len(proxies) == 0 || !isTrustedProxy(host, proxies) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if !isTrustedProxy(hop, proxies) {
			return hop
		}
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
		r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
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
	if !s.isOwnerOrItsController(r) {
		writeError(w, http.StatusForbidden, "owner only", "")
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
	if !s.isOwnerOrItsController(r) {
		writeError(w, http.StatusForbidden, "owner only", "")
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
