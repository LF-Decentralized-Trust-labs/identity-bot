package relayproto

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Mode is what kind of address an allocation is. Which one an identity uses is
// its own choice; the protocol does not tie either to a kind of identity.
type Mode string

const (
	// ModePublic is one stable address anybody may find.
	ModePublic Mode = "public"
	// ModePrivate is one unlinkable address per relationship.
	ModePrivate Mode = "private"
	// modeRenew marks the relay's control stream, which renews the lease and
	// never carries a request.
	modeRenew Mode = "renew"
)

// Preamble is what the relay says about a stream before any HTTP crosses it:
// which allocation the request arrived on, in which mode, at which host, and
// from which address.
//
// It is written by the relay and read by the Identity Agent before the HTTP
// bytes, so nothing a caller puts in a request can change it. A header naming an
// allocation would be a header a caller could set.
type Preamble struct {
	Allocation string `json:"allocation"`
	Mode       Mode   `json:"mode"`
	Host       string `json:"host"`
	// Visitor is the network address the relay saw the request arrive from, as a
	// bare IP. Every relayed request reaches the Identity Agent from the relay's
	// own address, so this is the only way it can tell callers apart. It is empty
	// from a relay that does not send it, and then callers cannot be told apart.
	Visitor string `json:"visitor,omitempty"`
}

// VisitorAddr is the bare IP in a network address such as a request's
// RemoteAddr, or "" if it holds none. The relay uses it to fill [Preamble]'s
// Visitor from the connection it accepted, and the Identity Agent uses it to
// read the field back, so a malformed or oversized value is never used as a key.
func VisitorAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	return ip.Unmap().WithZone("").String()
}

func (p Preamble) valid() error {
	switch p.Mode {
	case ModePublic, ModePrivate:
		if p.Allocation == "" {
			return fmt.Errorf("a request stream must name its allocation")
		}
	case modeRenew:
	default:
		return fmt.Errorf("unknown stream mode %q", p.Mode)
	}
	return nil
}

// writePreamble frames a preamble as a two-byte length and its JSON.
func writePreamble(w io.Writer, p Preamble) error {
	if err := p.valid(); err != nil {
		return err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(body) > MaxPreambleBytes {
		return fmt.Errorf("preamble is %d bytes; the limit is %d", len(body), MaxPreambleBytes)
	}
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame, uint16(len(body)))
	copy(frame[2:], body)
	_, err = w.Write(frame)
	return err
}

func readPreamble(r io.Reader) (Preamble, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return Preamble{}, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > MaxPreambleBytes {
		return Preamble{}, fmt.Errorf("preamble length %d is outside 1..%d", n, MaxPreambleBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Preamble{}, err
	}
	var p Preamble
	if err := json.Unmarshal(body, &p); err != nil {
		return Preamble{}, fmt.Errorf("preamble is not readable: %w", err)
	}
	return p, p.valid()
}

type preambleKey struct{}

// PreambleFrom returns the preamble of the relay stream a request arrived on.
// It reports false for a request that did not come through a relay.
func PreambleFrom(ctx context.Context) (Preamble, bool) {
	p, ok := ctx.Value(preambleKey{}).(Preamble)
	return p, ok
}

// ContextWithPreamble is ctx carrying p, as a request that arrived on a relay
// stream does. It lets an Identity Agent exercise its own rules for relayed
// requests (in its tests, say) without a relay that applies the same rules
// first. It grants nothing: only code in the same process can call it.
func ContextWithPreamble(ctx context.Context, p Preamble) context.Context {
	return context.WithValue(ctx, preambleKey{}, p)
}

// streamConn is a relay stream whose preamble has been read.
//
// It ends itself once nothing has moved on it, in either direction, for
// streamIdle: a body trickled in slowly, or a response that never comes,
// cannot hold a stream for ever. It watches rather than setting deadlines,
// because net/http sets its own deadlines on the connection it serves (to
// hijack one for a websocket, for instance) and must not have them moved.
type streamConn struct {
	net.Conn
	preamble Preamble
	once     sync.Once
	release  func()
	last     atomic.Int64 // unix nanoseconds of the last bytes moved
	done     chan struct{}
}

func newStreamConn(c net.Conn, p Preamble, release func()) *streamConn {
	sc := &streamConn{Conn: c, preamble: p, release: release, done: make(chan struct{})}
	sc.last.Store(time.Now().UnixNano())
	go sc.watch()
	return sc
}

func (c *streamConn) watch() {
	idle := streamIdle()
	tick := time.NewTicker(idle / 4)
	defer tick.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-tick.C:
			if now.Sub(time.Unix(0, c.last.Load())) >= idle {
				c.Close()
				return
			}
		}
	}
}

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *streamConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		close(c.done)
		if c.release != nil {
			c.release()
		}
	})
	return err
}
