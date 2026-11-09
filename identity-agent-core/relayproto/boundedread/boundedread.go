// Package boundedread is the refusing reader the relay protocol reads its
// streams through, and the one the Identity Agent core's own boundedread
// package delegates its stream reader to, so there is a single implementation.
//
// A bare io.LimitReader ends a stream at the limit as though it had ended, and
// a document cut short there can still parse as a different, shorter one. This
// reader fails with ErrTooLarge instead.
package boundedread

import (
	"errors"
	"io"
)

// ErrTooLarge is returned when a stream holds more than the limit it was read under.
var ErrTooLarge = errors.New("body exceeds the size limit")

// Reader wraps r so a stream consumer (a json.Decoder) fails with ErrTooLarge
// rather than reading past limit bytes, or seeing the stream end there.
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
