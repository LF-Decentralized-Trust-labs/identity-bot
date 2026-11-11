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
	"time"

	"identity-agent-core/watcher"

	"github.com/go-chi/chi/v5"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/ratewindow"
)

// maxRateLimitedClients bounds the limiter's memory. Each key is a caller
// address, which a caller choosing its own addresses could otherwise multiply
// without limit.
const maxRateLimitedClients = 10000

// maxPublicBodyBytes caps a request body on the unauthenticated peer routes.
// Every legitimate body on them is a few hundred bytes.
const maxPublicBodyBytes = 64 << 10

type ipRateLimiter struct{ w *ratewindow.Window }

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return newIPRateLimiterAt(limit, window, nil)
}

// newIPRateLimiterAt is newIPRateLimiter on a given clock (nil is time.Now).
func newIPRateLimiterAt(limit int, window time.Duration, now func() time.Time) *ipRateLimiter {
	return &ipRateLimiter{w: ratewindow.New(limit, window, maxRateLimitedClients, now)}
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
	return r.w.Allow(limiterKey(ip))
}

// wouldAllow reports whether allow(ip) would let a request through, without
// counting it or remembering ip.
func (r *ipRateLimiter) wouldAllow(ip string) bool {
	if r == nil {
		return true
	}
	return r.w.Would(limiterKey(ip))
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

// callerKey is who a public watcher request is counted as. A relayed request
// reaches this agent from the relay's own address, so counting that would make
// every caller through the relay one caller; it is counted as the visitor address
// the relay passed on (the /64 for IPv6), or, from a relay that names none, as one
// shared caller. A direct request is counted by clientIP, which believes a
// forwarding header only from a trusted proxy.
func callerKey(r *http.Request) string {
	if p, relayed := relayproto.PreambleFrom(r.Context()); relayed {
		if v := visitorShare(p.Visitor); v != "" {
			return "relayed " + v
		}
		return "relayed, address unknown"
	}
	return clientIP(r)
}

func (s *CoreServer) mountWatcherPublicRoutes(r chi.Router) {
	if s.WatcherService == nil {
		return
	}
	lim := newIPRateLimiter(60, time.Minute)
	// A cross-check is a yes/no on a digest, so guessing one is the only way to
	// probe it: a tighter limit per caller, and a cap across all callers so
	// many addresses cannot add up to a search.
	checkLim := newIPRateLimiter(20, time.Minute)
	checkAll := newIPRateLimiter(600, time.Minute)
	contactLim := newIPRateLimiter(120, time.Minute)
	// Before any signature is checked, which is the costly part: a caller that
	// sends more than a contact ever would is turned away unchecked. Set above
	// the strangers' own limit so a contact reaching this agent through the same
	// relay as strangers is not turned away by them.
	preLim := newIPRateLimiter(60, time.Minute)
	r.Get("/public/kel-digest", func(w http.ResponseWriter, r *http.Request) {
		if !lim.allow(callerKey(r)) {
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
			writeError(w, http.StatusInternalServerError, "digest lookup failed", err.Error())
			return
		}
		jsonreply.Write(w, http.StatusOK, resp)
	})

	// A cross-check is a yes/no on a digest, so guessing one is the only way to
	// probe it. It is answered only for a contact who signed the request, so the
	// limits below bind strangers, who get "no match" whatever they send: a
	// tighter limit per caller, and a cap across all strangers so many addresses
	// cannot add up to a search. A contact has its own, larger, limit and does not
	// draw on the strangers' cap, so a crowd of strangers cannot lock out peers.
	r.Post("/public/kel-check", func(w http.ResponseWriter, r *http.Request) {
		var req watcher.KelCheckRequest
		r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body", err.Error())
			return
		}
		if !preLim.allow(callerKey(r)) {
			writeError(w, http.StatusTooManyRequests, "Rate limited", "")
			return
		}
		resp, fromContact, err := s.WatcherService.KelCheck(req, s.ownPublicURL(r), func(aid string) ([]map[string]interface{}, bool) { return s.servedLog(aid, r) })
		if fromContact {
			if !contactLim.allow(req.Requester) {
				writeError(w, http.StatusTooManyRequests, "Rate limited", "")
				return
			}
		} else if !checkLim.allow(callerKey(r)) || !checkAll.allow("all strangers") {
			writeError(w, http.StatusTooManyRequests, "Rate limited", "")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "kel-check failed", err.Error())
			return
		}
		jsonreply.Write(w, http.StatusOK, resp)
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
	rows, err := s.WatcherService.DisclosableAll(aid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"aid": aid, "records": rows})
}

func (s *CoreServer) handleDebugWatcherCoverage(w http.ResponseWriter, r *http.Request) {
	if !s.isOwnerOrItsController(r) {
		writeError(w, http.StatusForbidden, "owner only", "")
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"note":   "coverage summary — extend with aggregate queries as needed",
	})
}

func isLocalhost(r *http.Request) bool {
	ip := clientIP(r)
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

// maxContactNamedWatchers caps the watcher addresses a contact names in its own
// introduction that are queried. They are advisory and the contact chose them.
const maxContactNamedWatchers = 3

// cappedWatcherHints drops any address that is not https (the same rule as the
// owner's own hints, so a contact cannot make this agent send a query in the
// clear that the owner could not), removes repeats and keeps the first
// maxContactNamedWatchers.
func cappedWatcherHints(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, h := range in {
		if !isHTTPSWatcherAddress(h) || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) == maxContactNamedWatchers {
			break
		}
	}
	return out
}

func (s *CoreServer) runWatcherOnKel(ctx context.Context, aid string, kel []map[string]interface{}, source watcher.SourceType, sourceURL string, bootstrap []string) *watcher.VerifyKelResult {
	if s.WatcherService == nil || aid == "" || len(kel) == 0 {
		return nil
	}
	res, err := s.WatcherService.VerifyKel(ctx, watcher.VerifyKelInput{
		AID: aid, KEL: kel, SourceType: source, SourceURL: sourceURL, BootstrapL2: cappedWatcherHints(bootstrap),
	})
	if err != nil {
		log.Printf("[watcher] VerifyKel %s: %v", aid, err)
		return nil
	}
	// Kept so a screen can say what was found and when. A failure to keep it
	// is logged and does not change the verdict the caller acts on.
	if err := s.WatcherService.RecordCheck(res); err != nil {
		log.Printf("[watcher] could not keep the check of %s: %v", aid, err)
	}
	if res.Blocked {
		log.Printf("[watcher] DUPLICITY blocked aid=%s seq=%d reason=%s", aid, res.SequenceNum, res.Reason)
	}
	return res
}

// handleWatcherOptOutGet says whether this agent's watcher is silent about an
// identity. Under /api, so a stranger is refused; a paired controller may read it.
func (s *CoreServer) handleWatcherOptOutGet(w http.ResponseWriter, r *http.Request) {
	if s.WatcherService == nil {
		jsonreply.Write(w, http.StatusNotFound, ErrorResponse{Error: "watcher not running", Code: "watcher_off"})
		return
	}
	aid := r.URL.Query().Get("aid")
	if aid == "" {
		writeError(w, http.StatusBadRequest, "aid required", "")
		return
	}
	opted, err := s.WatcherService.Store.IsOptedOut(aid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"aid": aid, "opted_out": opted})
}

// handleWatcherOptOutSet opts an identity out of, or back into, being discussed
// by this agent's watcher. From then on /public/kel-digest, /public/kel-check and
// the owner listing all answer as for an identity never seen. Owner-only: it is
// on controllerOwnerOnly, so a paired controller is refused at any score.
//
// This only hides what the watcher says. VerifyKel still records first-seen for
// an opted-out identity, because duplicity detection needs it: stopping would
// let a forked key log pass unnoticed.
func (s *CoreServer) handleWatcherOptOutSet(w http.ResponseWriter, r *http.Request) {
	if s.WatcherService == nil {
		jsonreply.Write(w, http.StatusNotFound, ErrorResponse{Error: "watcher not running", Code: "watcher_off"})
		return
	}
	var req struct {
		AID      string `json:"aid"`
		OptedOut *bool  `json:"opted_out"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AID == "" || req.OptedOut == nil {
		writeError(w, http.StatusBadRequest, "aid and opted_out required", "")
		return
	}
	if err := s.WatcherService.Store.SetOptOut(req.AID, *req.OptedOut); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"aid": req.AID, "opted_out": *req.OptedOut})
}

// writeDuplicity refuses a contact whose key history the watcher found forked.
// The code and aid are for the app, which words the refusal itself; error and
// details are for a log or a developer, and "details" is the technical reason.
func writeDuplicity(w http.ResponseWriter, aid, reason string) {
	jsonreply.Write(w, http.StatusConflict, map[string]interface{}{
		"error": "KEL duplicity detected", "details": reason,
		"code": "duplicity", "aid": aid,
	})
}
