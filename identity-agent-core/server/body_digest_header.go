package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"identity-agent-core/iacrypto"
)

// The signature is checked before the body is read.
//
// An owner's (or a controller's) signature covers a digest of the body. To
// check it the agent used to read the body first, so a caller holding no key
// could still make it read up to a route's bound -- 512 MiB on the recovery
// routes -- before the signature failed.
//
// The client now sends that same digest in X-IA-Body-Digest. The signed string
// is unchanged: it already contained the digest, and it is built from the
// header instead of from the bytes. The signature is verified first, having read
// nothing. Only then is the body read, hashing as it is read, and a body whose
// digest is not the one signed is refused with a 400 before any handler sees it.
//
// WITHOUT THE HEADER (older clients) the agent reads the body to digest it, as
// before, but only up to maxSignedBodyBytes: the larger per-route bounds in
// signedBodyBounds apply only to a request that sends the header. THE HEADER
// BECOMES REQUIRED IN A LATER VERSION, and the no-header path is then removed.
const headerBodyDigest = "X-IA-Body-Digest"

// bodyDoesNotMatchItsDigest is the refusal for a body whose Blake3 digest is not
// the one the request declared and signed. A type of its own so the gate answers
// 400 and says so, where any other failure to verify is a 403.
type bodyDoesNotMatchItsDigest struct{}

func (bodyDoesNotMatchItsDigest) Error() string {
	return headerBodyDigest + " does not match the body that was sent: the request was signed over a different body"
}

// theDigestTheRequestDeclares is the digest in X-IA-Body-Digest, and whether the
// request carries the header at all. A header that is present but is not one
// Blake3 qb64 digest is an error, never "absent": treating a malformed header
// as no header would let the sender choose the older, weaker path.
func theDigestTheRequestDeclares(r *http.Request) (string, bool, error) {
	values := r.Header.Values(headerBodyDigest)
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) > 1 {
		return "", true, fmt.Errorf("%s must be sent once", headerBodyDigest)
	}
	digest := strings.TrimSpace(values[0])
	if !looksLikeABlake3Digest(digest) {
		return "", true, fmt.Errorf("%s must be a Blake3 digest in qb64 (E followed by 43 characters)", headerBodyDigest)
	}
	return digest, true, nil
}

// looksLikeABlake3Digest: code E, then 43 base64url characters -- 44 in all. It
// is compared with the digest computed from the body as a string, so this need
// only keep junk out of the signed string.
func looksLikeABlake3Digest(s string) bool {
	if len(s) != 44 || s[0] != 'E' {
		return false
	}
	for _, c := range s[1:] {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// aBodyThatWasChecked is a request body that has been read, bounded and matched
// to the digest the request signed. It is what r.Body becomes afterwards, so
// that a later reader (readSignedBody, or the handler) takes the checked bytes
// rather than reading again.
type aBodyThatWasChecked struct {
	*bytes.Reader
	bytes  []byte
	digest string
}

func (aBodyThatWasChecked) Close() error { return nil }

// readTheBodyAgainst reads r's body -- bounded by its route (signedBodyBoundFor),
// hashing as it reads -- and refuses one whose digest is not declared. Called
// only AFTER the signature over declared has verified, which is what makes the
// route's larger bound safe to apply: the caller is the key holder by then.
//
// Over the bound is requestTooLarge, a mismatch is bodyDoesNotMatchItsDigest, and
// on either r.Body is left erroring rather than holding what was read, so no
// handler can serve a cut-off or substituted body.
func readTheBodyAgainst(r *http.Request, declared string) error {
	if done, ok := r.Body.(*aBodyThatWasChecked); ok && done.digest == declared {
		_, _ = done.Seek(0, io.SeekStart)
		return nil
	}
	limit := signedBodyBoundFor(r)
	refuse := func(err error) error {
		r.Body = refusedBody{err}
		return err
	}
	if r.ContentLength > limit {
		return refuse(requestTooLarge{limit})
	}

	var body []byte
	digest := iacrypto.NewBlake3Digest()
	if r.Body != nil {
		var buf bytes.Buffer
		if _, err := io.Copy(io.MultiWriter(&buf, digest), io.LimitReader(r.Body, limit+1)); err != nil {
			return refuse(fmt.Errorf("read body: %w", err))
		}
		if int64(buf.Len()) > limit {
			return refuse(requestTooLarge{limit})
		}
		body = buf.Bytes()
	}
	got, err := digest.QB64()
	if err != nil {
		return refuse(err)
	}
	if got != declared {
		return refuse(bodyDoesNotMatchItsDigest{})
	}
	r.Body = &aBodyThatWasChecked{Reader: bytes.NewReader(body), bytes: body, digest: declared}
	return nil
}
