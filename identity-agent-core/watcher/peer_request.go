package watcher

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

var errTooManyPeers = fmt.Errorf("at most %d peers can be chosen to cross-check with", MaxChosenPeers)

// KelCheckRequestTag opens every signed cross-check request, so a signature
// over one cannot be a valid signature over anything else the watcher key signs.
const KelCheckRequestTag = "kel-check-request/v1"

// KelCheckRequestStatement is the text a cross-check request is signed over. It
// names the peer it is for and the time, so a captured request cannot be
// replayed to a different peer or later.
func KelCheckRequestStatement(aid string, seq int, digest, to string, at int64) string {
	var b strings.Builder
	b.WriteString(KelCheckRequestTag + "\n")
	for _, f := range [][2]string{{"aid", aid}, {"seq", strconv.Itoa(seq)}, {"digest", digest}, {"to", to}, {"at", strconv.FormatInt(at, 10)}} {
		b.WriteString(f[0] + "=" + strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, f[1]) + "\n")
	}
	return b.String()
}

// signedRequest builds a request to one peer and signs it as the identifier that
// peer knows this agent by (SignRequest). With no signer, or if signing fails, it returns an error and the
// peer is not asked: an unsigned question is what this replaces.
func (s *Service) signedRequest(peerAID, peerURL, aid string, seq int, digest string) (KelCheckRequest, error) {
	req := KelCheckRequest{AID: aid, Seq: seq, Digest: digest, At: time.Now().Unix()}
	if s.SignRequest == nil {
		return req, fmt.Errorf("no key to sign a cross-check request with")
	}
	by, sig, err := s.SignRequest(peerAID, KelCheckRequestStatement(aid, seq, digest, strings.TrimRight(peerURL, "/"), req.At))
	if err != nil {
		return req, err
	}
	req.Requester, req.Signature = by, sig
	return req, nil
}
