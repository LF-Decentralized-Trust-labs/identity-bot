package server

import (
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// logRequests writes one line per request, naming the route that served it
// ("/api/invites/{token}"), not the path it was asked for.
//
// A path can carry a secret: whoever holds an invite code presents it as
// /api/invites/<code>, and /i/<token> is a one-time pointer. The default
// request logger writes the path, which would put every such secret in the log
// beside the request. The route pattern says what was called without saying
// who held what.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		route := "(unmatched)"
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		log.Printf("%s %s from %s - %d %dB in %s", r.Method, route, r.RemoteAddr, status, ww.BytesWritten(), time.Since(start))
	})
}
