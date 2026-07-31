package server

import (
	"net/http"
	"time"
)

// Timeouts on the listening server.
//
// Both listeners were started with http.Serve, which uses a zero-value
// http.Server: no read timeout, no write timeout, no idle timeout, no header
// deadline. A connection that opened and then sent one byte a minute held a file
// descriptor and a goroutine for as long as it liked, and enough of them exhaust
// the agent without a single valid request being made.
//
// That was survivable while the agent answered only on loopback. It stops being
// survivable the moment a tunnel is up or a peer-facing route is reachable,
// which is now — and the tunnel listener has always been exactly as exposed.
func (s *CoreServer) httpServer() *http.Server {
	return &http.Server{
		Handler: s.router,
		// The header deadline is the one that stops a connection held open
		// having sent nothing. It is separate from ReadTimeout because a large
		// legitimate body may take a while, while headers never should.
		ReadHeaderTimeout: 10 * time.Second,
		// Generous, because an encrypted archive is a legitimate upload here.
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		// A kept-alive connection nobody is using should be given up.
		IdleTimeout: 2 * time.Minute,
	}
}
