// Package boundedread is the one way the core reads a body somebody else
// controls: a counterparty's reply, or a request a counterparty can send.
//
// A bare io.ReadAll on such a body lets the other side choose how much memory
// the core spends. Every function here has a stated limit and REFUSES a body
// over it with ErrTooLarge. None of them truncates silently, because a body cut
// short at the limit can still parse as a different, shorter document.
package boundedread

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Limits the core uses; a caller with a reason to differ states its own.
const (
	// Document is a signed Ask, an OOBI answer, a schema, a login bundle.
	Document int64 = 1 << 20
	// Request is a JSON request body sent to the core's own API.
	Request int64 = 1 << 20
	// Archive is a whole backup archive fetched from a paired agent.
	Archive int64 = 512 << 20
	// Diagnostic is how much of an error body is quoted back in an error message.
	Diagnostic int64 = 512
)

// ErrTooLarge is returned when a body is larger than the limit it was read under.
var ErrTooLarge = errors.New("body exceeds the size limit")

// All reads r to the end and returns it, or ErrTooLarge if it holds more than limit bytes.
// A read error is returned, never ignored.
func All(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrTooLarge, limit)
	}
	return b, nil
}

// Reader wraps r so a stream consumer (a json.Decoder) fails with ErrTooLarge
// rather than reading past limit bytes.
func Reader(r io.Reader, limit int64) io.Reader {
	return &limited{r: r, left: limit}
}

type limited struct {
	r    io.Reader
	left int64
}

func (l *limited) Read(p []byte) (int, error) {
	if l.left < 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		return n - int(-l.left), ErrTooLarge
	}
	return n, err
}

// Snippet returns at most Diagnostic bytes of an error body for quoting in a
// message. It is the one deliberate truncation here: the text is for a person,
// is never parsed, and is never passed on as data.
func Snippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, Diagnostic))
	return string(b)
}

// LimitRequest bounds an incoming request body; reading past limit fails and the
// server closes the connection. Pair it with Status to answer the right code.
func LimitRequest(w http.ResponseWriter, r *http.Request, limit int64) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

// Status is the HTTP status for an error from reading a request body:
// 413 for one over the limit, 400 for anything else.
func Status(err error) int {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) || errors.Is(err, ErrTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
