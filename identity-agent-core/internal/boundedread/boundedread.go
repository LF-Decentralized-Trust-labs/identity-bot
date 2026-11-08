// Package boundedread is the one way the core reads a body somebody else
// controls: a counterparty's reply, or a request a counterparty can send.
//
// A bare io.ReadAll on such a body lets the other side choose how much memory
// the core spends. Every function here has a stated limit and REFUSES a body
// over it with ErrTooLarge. None of them truncates silently, because a body cut
// short at the limit can still parse as a different, shorter document.
package boundedread

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Limits the core uses; a caller with a reason to differ states its own.
const (
	// Document is a signed Ask, an OOBI answer, a schema, a login bundle.
	Document int64 = 1 << 20
	// OOBI is an OOBI answer: a key log and what is needed to check it. The
	// one limit for it, whoever reads it, so no reader refuses what another
	// accepts.
	OOBI int64 = 8 << 20
	// Request is a JSON request body sent to the core's own API.
	Request int64 = 1 << 20
	// ArchiveUploadBase64 is the most base64 text the core accepts for one
	// backup archive sent to it.
	ArchiveUploadBase64 int64 = 2 << 30
	// Archive is the most a whole backup archive can be, fetched from a paired
	// agent or a remote store: what the core accepts to store (that much base64
	// is this much archive), so what can be stored can be fetched back.
	Archive int64 = ArchiveUploadBase64 / 4 * 3
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

// Decode reads r under limit and unmarshals it into v. A body over the limit is
// ErrTooLarge, and one with anything after the JSON value is an error too.
func Decode(r io.Reader, limit int64, v any) error {
	b, err := All(r, limit)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
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
