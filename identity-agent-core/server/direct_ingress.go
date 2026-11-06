package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"identity-agent-core/internal/atomicfile"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"identity-agent-core/endpoint"
	"identity-agent-core/iacrypto"
)

// The direct listener — the second listener of ADR-042 §2.
//
// A Direct-mode agent has no relay or tunnel to carry a counterparty in, so it
// must answer off-box itself. It does that here, on a socket of its own, and
// never on the root listener: the root/management surface stays on loopback in
// every mode (rootListenAddr). Three things keep this listener from being the
// root surface by another name:
//
//  1. It serves a fixed list of routes (directIngressRoutes), each a GET under
//     /{aid}/ that publicRoutes already names as public by design. The router
//     is built from that list and nothing else; every other path, method or
//     route is a 404 from a router that has no other route to fall to.
//  2. It answers for an identifier only when the URL manager has allowlisted
//     that identifier (directAllowlist), so learning this address teaches a
//     stranger nothing about identifiers it was not given. An identifier off
//     the list and one the agent has never heard of get the same bare 404.
//  3. It answers only while the resolved ingress mode is Direct
//     (resolveIngressMode), so changing the mode away from Direct silences it
//     without a restart.
//
// Binding is the operator's explicit act: AGENT_DIRECT_LISTEN_ADDR, host:port.
// The retired AGENT_DIRECT_INGRESS_ADDR, which put the whole surface on a
// reachable address, stops the agent starting while it is set.
//
// Direct mode is lookup only: LAN phone pairing (/api) and DIDComm are not
// served here (ADR-042, still partial).

// directIngressRoutes are the routes the direct listener serves, all GET.
// Each is a key of publicRoutes, which is where it says why it is public.
var directIngressRoutes = []struct {
	pattern string
	handler func(*CoreServer) http.HandlerFunc
}{
	{"/{aid}/oobi", func(s *CoreServer) http.HandlerFunc { return s.handleAidOobi }},
	{"/{aid}/did.json", func(s *CoreServer) http.HandlerFunc { return s.handleDidJSON }},
	{"/{aid}/kel", func(s *CoreServer) http.HandlerFunc { return s.handleKEL }},
	{"/{aid}/keri.cesr", func(s *CoreServer) http.HandlerFunc { return s.handleKeriCesr }},
}

// arrivedDirect marks a request that came in on the direct listener, so a
// handler shared with the root router can write the links that listener serves
// (/{aid}/oobi) and not the root's (/public/oobi/{aid}), and publish the port
// the request came to. Set by the direct router only, never read off a request.
type directCtxKey struct{}

func arrivedDirect(r *http.Request) bool {
	v, _ := r.Context().Value(directCtxKey{}).(bool)
	return v
}

// oobiLink is the address of aid's OOBI under base, in the form the listener the
// request arrived on serves.
func oobiLink(r *http.Request, base, aid string) string {
	if arrivedDirect(r) {
		return fmt.Sprintf("%s/%s/oobi", base, aid)
	}
	return fmt.Sprintf("%s/public/oobi/%s", base, aid)
}

// directAllowlistFileName holds the identifiers the direct listener answers
// for, in the data directory.
const directAllowlistFileName = "direct-ingress-aids.json"

// directAllowlist is the set of identifiers the URL manager lets the direct
// listener answer for. It is kept on disk, so a restart does not silence or
// widen it.
type directAllowlist struct {
	mu   sync.RWMutex
	path string
	aids map[string]struct{}
}

func loadDirectAllowlist(dataDir string) (*directAllowlist, error) {
	l := &directAllowlist{path: filepath.Join(dataDir, directAllowlistFileName), aids: map[string]struct{}{}}
	raw, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return l, err
	}
	var aids []string
	if err := json.Unmarshal(raw, &aids); err != nil {
		return l, fmt.Errorf("%s is not a list of identifiers: %w", directAllowlistFileName, err)
	}
	for _, a := range aids {
		if iacrypto.IsIdentifierQB64(a) {
			l.aids[a] = struct{}{}
		}
	}
	return l, nil
}

func (l *directAllowlist) Has(aid string) bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.aids[aid]
	return ok
}

func (l *directAllowlist) List() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]string, 0, len(l.aids))
	for a := range l.aids {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// save writes the list whole, to a temporary file renamed over the old one.
// Callers hold mu.
func (l *directAllowlist) save(aids []string) error {
	raw, err := json.Marshal(aids)
	if err != nil {
		return err
	}
	return atomicfile.Write(l.path, raw, 0o600)
}

// sortedWithLocked is the sorted list as it would be with aid added (add) or
// removed, without touching the set: memory changes only once it is on disk.
func (l *directAllowlist) sortedWithLocked(aid string, add bool) []string {
	out := make([]string, 0, len(l.aids)+1)
	for a := range l.aids {
		if a != aid {
			out = append(out, a)
		}
	}
	if add {
		out = append(out, aid)
	}
	sort.Strings(out)
	return out
}

// Allow adds aid. Something that is not an identifier is refused.
func (l *directAllowlist) Allow(aid string) error {
	if !iacrypto.IsIdentifierQB64(aid) {
		return errors.New("not an identifier")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.aids[aid]; ok {
		return nil
	}
	if err := l.save(l.sortedWithLocked(aid, true)); err != nil {
		return err
	}
	l.aids[aid] = struct{}{}
	return nil
}

func (l *directAllowlist) Remove(aid string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.aids[aid]; !ok {
		return nil
	}
	if err := l.save(l.sortedWithLocked(aid, false)); err != nil {
		return err
	}
	delete(l.aids, aid)
	return nil
}

// directListenAddr is where the direct listener binds, and false when the
// operator has not asked for one.
func directListenAddr() (string, bool) {
	host, port, ok := endpoint.DirectListenAddr()
	if !ok {
		return "", false
	}
	return net.JoinHostPort(host, fmt.Sprint(port)), true
}

// directRouter is the direct listener's router: the routes above behind the
// allowlist and the mode check, and nothing else. It does not carry the
// root router's authorisation layer because it carries none of the routes that
// layer guards; a route added here is a route this list names.
func (s *CoreServer) directRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(context.WithValue(req.Context(), directCtxKey{}, true)))
		})
	})
	// A wrong method on a served path is the same bare 404 as no path.
	r.MethodNotAllowed(http.NotFound)
	r.NotFound(http.NotFound)
	for _, rt := range directIngressRoutes {
		r.Get(rt.pattern, s.onlyForAllowlisted(rt.handler(s)))
	}
	return r
}

// onlyForAllowlisted answers next only for an allowlisted identifier while the
// mode is Direct, and otherwise with the bare 404 of an unknown path.
func (s *CoreServer) onlyForAllowlisted(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.resolveIngressMode() != IngressModeDirect || !s.directAIDs.Has(chi.URLParam(r, "aid")) {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// bindDirectListener binds the direct listener when one is configured. A
// configured bind that fails is an error: the operator asked for reach and
// would otherwise be told nothing.
func (s *CoreServer) bindDirectListener() error {
	// A deployment still setting the retired variable asked for the whole surface
	// on a LAN or mapped-port address. Starting with everything on loopback
	// instead would lose that reach without a word, so it does not start.
	if v := os.Getenv("AGENT_DIRECT_INGRESS_ADDR"); v != "" {
		return errors.New("AGENT_DIRECT_INGRESS_ADDR is no longer supported and the agent will not start " +
			"while it is set: the management surface now stays on loopback in every mode. Unset it, and to be " +
			"reached off this machine set AGENT_DIRECT_LISTEN_ADDR=host:port and use Direct mode, which serves " +
			"identifier documents only (ADR-042 §2)")
	}
	addr, ok := directListenAddr()
	if !ok {
		if v := os.Getenv("AGENT_DIRECT_LISTEN_ADDR"); v != "" {
			return fmt.Errorf("AGENT_DIRECT_LISTEN_ADDR=%q is not host:port with a port from 1 to 65535", v)
		}
		return nil
	}
	if al, err := loadDirectAllowlist(s.DataDir); err != nil {
		// A list that cannot be read is an empty one: nothing is served.
		log.Printf("[identity-agent-core] direct-ingress allowlist unreadable, serving nothing: %v", err)
		s.directAIDs = al
	} else {
		s.directAIDs = al
	}
	// "tcp", not "tcp4": a LAN is often IPv6 as well, and a wildcard host binds
	// both families (a specific address binds its own family).
	if host, port, ok := endpoint.DirectListenAddr(); ok {
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			addr = fmt.Sprintf(":%d", port)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("the direct listener cannot bind %s: %w", addr, err)
	}
	s.directLn = ln
	srv := s.httpServer()
	srv.Handler = s.directRouter()
	s.directSrv = srv
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[identity-agent-core] direct listener stopped: %v", err)
		}
	}()
	log.Printf("[identity-agent-core] Direct listener on %s: path-scoped identifier documents only, "+
		"for allowlisted identifiers, while the mode is Direct", ln.Addr())
	return nil
}

// The owner's view of the allowlist. These are under /api and named in neither
// publicRoutes nor the scoped list, so they are owner-only, and they are on the
// root listener, which the direct listener never serves.
func (s *CoreServer) allowlistOrNone() *directAllowlist {
	if s.directAIDs != nil {
		return s.directAIDs
	}
	al, _ := loadDirectAllowlist(s.DataDir)
	s.directAIDs = al
	return al
}

func (s *CoreServer) handleListDirectAIDs(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	al := s.allowlistOrNone()
	s.mu.Unlock()
	_, bound := directListenAddr()
	writeJSONStatus(w, http.StatusOK, map[string]interface{}{
		"aids": al.List(), "listening": bound && s.directSrv != nil,
		"serving": s.resolveIngressMode() == IngressModeDirect,
	})
}

func (s *CoreServer) handleAllowDirectAID(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	al := s.allowlistOrNone()
	s.mu.Unlock()
	if err := al.Allow(chi.URLParam(r, "aid")); err != nil {
		writeError(w, http.StatusBadRequest, "Cannot allow that identifier", err.Error())
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"aids": al.List()})
}

func (s *CoreServer) handleRemoveDirectAID(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	al := s.allowlistOrNone()
	s.mu.Unlock()
	if err := al.Remove(chi.URLParam(r, "aid")); err != nil {
		writeError(w, http.StatusInternalServerError, "Cannot remove that identifier", err.Error())
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]interface{}{"aids": al.List()})
}
