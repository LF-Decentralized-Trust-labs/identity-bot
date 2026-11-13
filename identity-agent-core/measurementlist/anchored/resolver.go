package anchored

import (
	"context"
	"time"

	"identity-agent-core/witness"
)

// TipAsker is what asks witnesses for their signed tip of an identity's key
// history: witness.Service. Each question carries a nonce that is made for it.
type TipAsker interface {
	AskTips(ctx context.Context, aid string, designated []string) []witness.AskedTip
}

// Resolver is the network half of the freshness check: it asks the publisher's
// designated witnesses for their tip with a new random nonce each, and hands the
// answers to AgreedTip, which decides. It keeps no nonce: one is made for each
// witness for each question, so an answer cannot be replayed into a later one.
type Resolver struct {
	Witnesses TipAsker
	// Timeout bounds the whole question; zero is ten seconds.
	Timeout time.Duration
}

// Asker is the Asker for VerifyAsking and Checker.CheckAsking, bound to ctx.
func (r Resolver) Asker(ctx context.Context) Asker {
	return func(aid string, designated []string, _ int) ([]TipReply, error) {
		if r.Witnesses == nil {
			return nil, ErrNotFresh
		}
		to := r.Timeout
		if to <= 0 {
			to = 10 * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, to)
		defer cancel()
		var out []TipReply
		for _, a := range r.Witnesses.AskTips(cctx, aid, designated) {
			out = append(out, TipReply{Nonce: a.Nonce, Answer: a.Answer})
		}
		return out, nil
	}
}

// PeerTipAsker is what asks the person's peer watchers for the publisher's tip:
// watcher.Service, through an adapter in the server.
type PeerTipAsker interface {
	AskPeerTips(ctx context.Context, aid string) []PeerTip
}

// PeersOf is the PeerAsker for Checker.Peers, bound to ctx. A nil asker asks
// nobody.
func PeersOf(ctx context.Context, a PeerTipAsker) PeerAsker {
	if a == nil {
		return nil
	}
	return func(aid string) []PeerTip { return a.AskPeerTips(ctx, aid) }
}
