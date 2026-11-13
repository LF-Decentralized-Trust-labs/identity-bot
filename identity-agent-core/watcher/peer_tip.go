package watcher

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A peer is asked how much of one identity's key history it holds, the
// identifier being one every build pins (the software publisher): a second
// source of "what is the latest state", beside the identity's own witnesses.
// The witnesses a history names are the only ones its reader can ask, so a
// reader whose copy predates a rotation that replaced every witness could be
// shown a stale history by witnesses whose keys are retired. A contact that
// holds more of the history shows it (ADR-078).
//
// What it asks is public and the same for every identity everybody pins, so
// unlike a cross-check it tells the peer nothing about whom this agent deals
// with: it is asked about nobody else.

// KelTipRequestTag opens every signed tip request, so a signature over one
// cannot be a valid signature over a cross-check request or anything else.
const KelTipRequestTag = "kel-tip-request/v1"

// KelTipRequest is the /public/kel-tip contract: which identity, and who asked
// and when, signed as for a cross-check (see KelTipRequestStatement).
type KelTipRequest struct {
	AID       string `json:"aid"`
	Requester string `json:"requester,omitempty"`
	At        int64  `json:"at,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// KelTipResponse is the newest place of the identity's key history the peer
// holds and that event's SAID. A peer that holds none, does not know the
// identity, or does not answer this requester says -1: all the same answer.
type KelTipResponse struct {
	SN   int    `json:"sn"`
	SAID string `json:"said,omitempty"`
}

// KelTipRequestStatement is the text a tip request is signed over. It names the
// peer it is for and the time, so a captured request cannot be replayed to
// another peer or later.
func KelTipRequestStatement(aid, to string, at int64) string {
	var b strings.Builder
	b.WriteString(KelTipRequestTag + "\n")
	for _, f := range [][2]string{{"aid", aid}, {"to", to}, {"at", strconv.FormatInt(at, 10)}} {
		b.WriteString(f[0] + "=" + strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, f[1]) + "\n")
	}
	return b.String()
}

var noTip = &KelTipResponse{SN: -1}

// KelTip answers POST /public/kel-tip. Only a contact who signed the request,
// inside the window and not seen before, is told anything; everybody else, and
// every identity held cannot tell, gets the same "holds nothing". held is what
// this agent has itself verified of aid's history, if it holds any. The second
// result says the request was from a contact, so the caller can hold only
// strangers to the shared limit.
func (s *Service) KelTip(req KelTipRequest, to string, held func(aid string) (sn int, said string, ok bool)) (*KelTipResponse, bool, error) {
	if s.VerifyRequester == nil || to == "" || req.Requester == "" || req.Signature == "" || req.At == 0 || req.AID == "" {
		return noTip, false, nil
	}
	now := s.now()
	if d := now.Unix() - req.At; d > int64(kelCheckWindow/time.Second) || d < -int64(kelCheckWindow/time.Second) {
		return noTip, false, nil
	}
	if !s.VerifyRequester(req.Requester, KelTipRequestStatement(req.AID, strings.TrimRight(to, "/"), req.At), req.Signature) {
		return noTip, false, nil
	}
	if !s.replays.first(fmt.Sprintf("tip\n%s\n%d\n%s", req.Requester, req.At, req.AID), now) {
		return noTip, false, nil
	}
	if held == nil {
		return noTip, true, nil
	}
	sn, said, ok := held(req.AID)
	if !ok || sn < 0 || said == "" {
		return noTip, true, nil
	}
	return &KelTipResponse{SN: sn, SAID: said}, true, nil
}

// PeerTipAnswer is what one peer said.
type PeerTipAnswer struct {
	Peer string
	SN   int
	SAID string
}

// AskPeerTips asks each peer the owner chose (and may ask: the peer boundary)
// how much of aid's key history it holds, and returns what came back. It is for
// an identity that is public and pinned, so it does not narrow the peers to
// those that plausibly know aid, as a cross-check does. A peer it cannot ask or
// that does not answer is left out; silence is not agreement and nothing here
// counts it as any.
func (s *Service) AskPeerTips(ctx context.Context, aid string) []PeerTipAnswer {
	if s.PeerWatchers == nil || !s.PeerWatchEnabled() || s.L3 == nil {
		return nil
	}
	var out []PeerTipAnswer
	var mu sync.Mutex
	var wg sync.WaitGroup
	asked := 0
	for _, p := range s.PeerWatchers() {
		if p.URL == "" || (p.AID != "" && p.AID == aid) || s.checkPeerAllowed(p.URL) != nil || asked >= MaxChosenPeers {
			continue
		}
		asked++
		req := KelTipRequest{AID: aid, At: s.now().Unix()}
		if s.SignRequest == nil {
			continue
		}
		by, sig, err := s.SignRequest(p.AID, KelTipRequestStatement(aid, strings.TrimRight(p.URL, "/"), req.At))
		if err != nil {
			continue
		}
		req.Requester, req.Signature = by, sig
		wg.Add(1)
		go func(p PeerWatcher, req KelTipRequest) {
			defer wg.Done()
			resp, err := s.L3.Tip(ctx, p.URL, req)
			if err != nil || resp == nil {
				return
			}
			mu.Lock()
			out = append(out, PeerTipAnswer{Peer: p.AID, SN: resp.SN, SAID: resp.SAID})
			mu.Unlock()
		}(p, req)
	}
	wg.Wait()
	return out
}
