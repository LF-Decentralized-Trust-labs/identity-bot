package witness

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Who may read a key log from a witness.
//
// A witness holds the key logs of the identities it witnesses, and for a root
// identity that set is the owner's contact graph (a root identifier is witnessed
// by the owner's contacts). Answering "do you hold X?" to anybody, with a 404
// against a log or a tip of -1 against a real one, tells a stranger who
// witnesses whom. So a read is answered from what is held only to the
// identity itself, or to the identity it is delegated from, proving it with a
// signature by its current key. Anybody else is answered exactly as if nothing
// were held for the identifier.
const (
	// HeaderReader, HeaderReadStamp and HeaderReadSignature carry the proof.
	HeaderReader        = "X-Reader-AID"
	HeaderReadStamp     = "X-Read-Stamp"
	HeaderReadSignature = "X-Read-Signature"

	readFreshness = 2 * time.Minute
	readMarker    = "/witness/kel/"
)

// ReadTarget is the part of a read's address that is signed: from
// "/witness/kel/" on, query included. What comes before it differs by how the
// witness is reached (a service provider is mounted without "/api").
func ReadTarget(requestURI string) string {
	i := strings.Index(requestURI, readMarker)
	if i < 0 {
		return requestURI
	}
	return requestURI[i:]
}

// ReadStatement is what a reader signs: who it is, what it asks for, and when.
func ReadStatement(reader, target, stamp string) string {
	return fmt.Sprintf("witness-kel-read/v1\n%s\n%s\n%s", reader, target, stamp)
}

// SignRead adds the proof of who is reading to a request for a key log.
// Without a signer, or without a known identity, the request goes unsigned and
// is answered as a stranger's.
func (s *Service) SignRead(req *http.Request) {
	reader := s.ourAID()
	if s.SignAsRequester == nil || reader == "" {
		return
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	sig, err := s.SignAsRequester(ReadStatement(reader, ReadTarget(req.URL.RequestURI()), stamp))
	if err != nil {
		return
	}
	req.Header.Set(HeaderReader, reader)
	req.Header.Set(HeaderReadStamp, stamp)
	req.Header.Set(HeaderReadSignature, sig)
}

// MayRead reports whether req is a read of aid's key log by aid itself, or by
// the identity aid is witnessed as a delegate of, signed freshly by that
// reader's current key.
func (s *Service) MayRead(aid string, req *http.Request) bool {
	reader := req.Header.Get(HeaderReader)
	stamp := req.Header.Get(HeaderReadStamp)
	sig := req.Header.Get(HeaderReadSignature)
	if aid == "" || reader == "" || stamp == "" || sig == "" {
		return false
	}
	if reader != aid && s.delegateOf(aid) != reader {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || time.Since(at) > readFreshness || time.Until(at) > readFreshness {
		return false
	}
	return s.signedBy(reader, ReadStatement(reader, ReadTarget(req.URL.RequestURI()), stamp), sig)
}
