package relay

import (
	"bufio"
	"net"
	"net/http"
	"strconv"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// protocolOnly holds this Identity Agent's own answer through a relay to the
// rule a relay applies (relayproto.CheckProtocolResponse), so a relay that
// does not apply it still never carries a page, a redirect or a header the
// protocol does not use (ADR-048, "An address carries only the protocol").
//
// The answer's headers are checked once, before any of them is sent: when the
// handler first writes body, flushes, or returns. Until then nothing reaches
// the relay, so a refused answer is replaced whole by a refusal.
type protocolOnly struct {
	w    http.ResponseWriter
	r    *http.Request
	mode relayproto.Mode

	status    int
	committed bool
	refused   bool
	// flushed is set when the headers go out before any body: a body may
	// follow, of a length nobody knows yet.
	flushed bool
}

func newProtocolOnly(w http.ResponseWriter, r *http.Request, mode relayproto.Mode) *protocolOnly {
	return &protocolOnly{w: w, r: r, mode: mode}
}

func (p *protocolOnly) Header() http.Header { return p.w.Header() }

func (p *protocolOnly) WriteHeader(code int) {
	if p.committed || p.status != 0 {
		return
	}
	// An informational answer would reach the caller before the final one is
	// checked, so none passes but a protocol switch.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		return
	}
	p.status = code
	if code == http.StatusSwitchingProtocols {
		p.commit(nil)
	}
}

func (p *protocolOnly) Write(b []byte) (int, error) {
	if !p.committed {
		p.commit(b)
	}
	if p.refused {
		return len(b), nil
	}
	return p.w.Write(b)
}

// Flush sends what is checked so far.
func (p *protocolOnly) Flush() {
	if !p.committed {
		p.flushed = true
		p.commit(nil)
	}
	if !p.refused {
		_ = http.NewResponseController(p.w).Flush()
	}
}

// Unwrap lets a handler reach the connection underneath, for a websocket.
func (p *protocolOnly) Unwrap() http.ResponseWriter { return p.w }

// Hijack hands a handler the connection, for a websocket. What it writes then
// is checked only by the relay, which reads the protocol switch it answers.
func (p *protocolOnly) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	p.committed = true
	return http.NewResponseController(p.w).Hijack()
}

// finish checks an answer whose handler wrote no body.
func (p *protocolOnly) finish() {
	if !p.committed {
		p.commit(nil)
	}
}

// commit checks the answer's headers. first is the first body written, if
// any. With no type named, it takes the type net/http would detect from that
// body, which is what the relay will see.
func (p *protocolOnly) commit(first []byte) {
	p.committed = true
	if p.status == 0 {
		p.status = http.StatusOK
	}
	if len(first) > 0 && len(p.w.Header().Values("Content-Type")) == 0 && p.w.Header().Get("Transfer-Encoding") == "" {
		p.w.Header().Set("Content-Type", http.DetectContentType(first))
	}
	resp := &http.Response{StatusCode: p.status, Header: p.w.Header().Clone(), Request: p.r, ContentLength: 0}
	if len(first) > 0 || p.flushed {
		resp.ContentLength = -1
		if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
			resp.ContentLength = n
		}
	}
	h := p.w.Header()
	if err := relayproto.CheckProtocolResponse(resp, p.mode); err != nil {
		p.refused = true
		clear(h)
		http.Error(p.w, "an Identity Agent address answers only with protocol data", http.StatusInternalServerError)
		return
	}
	clear(h)
	for k, v := range resp.Header {
		h[k] = v
	}
	p.w.WriteHeader(p.status)
}
