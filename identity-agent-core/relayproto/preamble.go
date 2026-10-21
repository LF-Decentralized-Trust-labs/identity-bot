package relayproto

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
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
// which allocation the request arrived on, in which mode, and at which host.
//
// It is written by the relay and read by the Identity Agent before the HTTP
// bytes, so nothing a caller puts in a request can change it. A header naming an
// allocation would be a header a caller could set.
type Preamble struct {
	Allocation string `json:"allocation"`
	Mode       Mode   `json:"mode"`
	Host       string `json:"host"`
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

// streamConn is a relay stream whose preamble has been read.
type streamConn struct {
	net.Conn
	preamble Preamble
	once     sync.Once
	release  func()
}

func (c *streamConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
	return err
}
