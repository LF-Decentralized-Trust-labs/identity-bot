package witness

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"identity-agent-core/drivers"
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

	// HeaderInception carries, base64url, the inception event of the log asked
	// for. It is how a verifier that is neither the identity nor its delegator
	// reads a log it was shown: see MayRead.
	HeaderInception = "X-Inception-Event"

	// maxInceptionHeader bounds what is parsed from HeaderInception.
	maxInceptionHeader = 8 << 10

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

// ReadStatement is what a reader signs: who it is, which witness it asks (by
// host, so a read signed for one witness cannot be replayed to another), what it
// asks for, and when.
func ReadStatement(reader, host, target, stamp string) string {
	return fmt.Sprintf("witness-kel-read/v2\n%s\n%s\n%s\n%s", reader, boundHost(host), target, stamp)
}

// boundHost is the host as signed: lower case, and without a default port, so
// a proxy that adds or strips ":443" (or ":80") between reader and witness does
// not change what was signed.
func boundHost(host string) string {
	host = strings.ToLower(host)
	if h, port, err := net.SplitHostPort(host); err == nil && (port == "443" || port == "80") {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return host
}

// InceptionOf finds the inception (icp or dip) in a presented key log and
// returns it parsed, with the exact bytes the controller published when the
// record carries them.
//
// The bytes are what a claim is verified by (drivers.ValidateKELInputFromRecords
// checks raw_bytes_b64 and nothing else), so they are the only part of a record
// that can be believed. event_json is text the claimant wrote beside them: it is
// read only for a record that has no bytes at all, and never when it has them,
// so changing a field there changes nothing that is acted on.
func InceptionOf(kel []map[string]interface{}) (ev map[string]interface{}, raw []byte, ok bool) {
	for _, entry := range kel {
		if b64, has := entry["raw_bytes_b64"].(string); has && b64 != "" {
			r, err := drivers.DecodeRawBytes(b64)
			if err != nil {
				continue
			}
			var parsed map[string]interface{}
			if json.Unmarshal(r, &parsed) != nil {
				continue
			}
			if t, _ := parsed["t"].(string); t == "icp" || t == "dip" {
				return parsed, r, true
			}
			continue
		}
		parsed := entry
		if _, has := entry["t"].(string); !has {
			body, _ := entry["event_json"].(string)
			parsed = nil
			if body != "" {
				_ = json.Unmarshal([]byte(body), &parsed)
			}
		}
		if parsed == nil {
			continue
		}
		if t, _ := parsed["t"].(string); t == "icp" || t == "dip" {
			return parsed, nil, true
		}
	}
	return nil, nil, false
}

// InceptionProof is the header value that lets a verifier holding a log read it
// from a witness: the log's inception event, exactly as published, which only a
// party the controller gave the log to has. ok is false when the log has no
// readable inception.
func InceptionProof(kel []map[string]interface{}) (string, bool) {
	ev, raw, ok := InceptionOf(kel)
	if !ok {
		return "", false
	}
	if raw == nil { // a record with no bytes: the best that can be offered
		var err error
		if raw, err = json.Marshal(ev); err != nil {
			return "", false
		}
	}
	if len(raw) > maxInceptionHeader*3/4 {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(raw), true
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
	sig, err := s.SignAsRequester(ReadStatement(reader, req.URL.Host, ReadTarget(req.URL.RequestURI()), stamp))
	if err != nil {
		return
	}
	req.Header.Set(HeaderReader, reader)
	req.Header.Set(HeaderReadStamp, stamp)
	req.Header.Set(HeaderReadSignature, sig)
}

// MayRead reports whether req is a read of aid's key log by a party entitled to
// it: aid itself, or the identity aid is witnessed as a delegate of, signed
// freshly by that reader's current key; or a verifier that presents the log's
// inception event, which this witness holds and only somebody the controller
// gave the log to can reproduce (the withheld-rotation cross-check, see
// server/corroborate_the_claim.go). The verifier thereby learns only that this
// witness holds a log it already holds the start of.
//
// Both proofs are always evaluated, so that what a caller sends does not change
// how much work a held and a not-held log cost.
func (s *Service) MayRead(aid string, req *http.Request) bool {
	signed := s.mayReadSigned(aid, req)
	incepted := s.mayReadByInception(aid, req)
	return signed || incepted
}

func (s *Service) mayReadSigned(aid string, req *http.Request) bool {
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
	return s.signedBy(reader, ReadStatement(reader, req.Host, ReadTarget(req.URL.RequestURI()), stamp), sig)
}

func (s *Service) mayReadByInception(aid string, req *http.Request) bool {
	h := req.Header.Get(HeaderInception)
	if aid == "" || h == "" || len(h) > maxInceptionHeader {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return false
	}
	var presented map[string]interface{}
	if json.Unmarshal(raw, &presented) != nil {
		return false
	}
	t, _ := presented["t"].(string)
	if t != "icp" && t != "dip" {
		return false
	}
	kel, err := s.Store.GetKelEvents(aid)
	if err != nil || len(kel) == 0 {
		return false
	}
	// Compare bytes with the bytes the controller published, which is what the
	// verifier's claim was checked by. Only an event stored before witnesses
	// kept bytes is compared by its parsed fields.
	if kel[0].RawBytesB64 != "" {
		held, err := drivers.DecodeRawBytes(kel[0].RawBytesB64)
		return err == nil && bytes.Equal(raw, held)
	}
	var held map[string]interface{}
	_ = json.Unmarshal([]byte(kel[0].EventJSON), &held)
	return held != nil && reflect.DeepEqual(presented, held)
}

// MayReadFromAPage is whether req is a read that a browser page may be handed
// the answer to: one that presents the log's inception (mayReadByInception).
// A signed read is never a page's, so it is not widened. Only this decides
// whether the answer carries the headers that let a page read it; a stranger's
// read is answered exactly as before, and a page cannot see it.
func (s *Service) MayReadFromAPage(aid string, req *http.Request) bool {
	return s.mayReadByInception(aid, req)
}
