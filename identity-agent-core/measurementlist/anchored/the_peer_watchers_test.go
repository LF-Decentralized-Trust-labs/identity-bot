package anchored

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// The witnesses the bundle's own history names are the only ones the checker can
// ask. A device whose floor predates a rotation that replaced every witness can
// be served a stale bundle, and have it vouched for by witnesses whose keys are
// retired. These tests show that limit, and that asking the person's peer
// watchers too closes it whenever a peer holds more of the history.

// aStaleBundleAnsweredByRetiredWitnesses: the publisher issued list 7, then list
// 8 and the withdrawal of list 7. The bundle shown is from before; the answers
// are what witnesses whose keys have since been retired would still sign.
func aStaleBundleAnsweredByRetiredWitnesses(t *testing.T) (p *publisher, stale *Bundle, retired []TipReply, current Tip) {
	t.Helper()
	p = onekey(t)
	c7, _ := published(p, 7)
	stale = p.bundle()
	retired = p.answers(p.tip(), 2)
	published(p, 8)
	p.revoke(c7)
	return p, stale, retired, p.tip()
}

func peersSaying(tips ...PeerTip) PeerAsker { return func(string) []PeerTip { return tips } }

func TestAStaleBundleVouchedForByRetiredWitnessesIsSeenByAPeer(t *testing.T) {
	p, stale, retired, current := aStaleBundleAnsweredByRetiredWitnesses(t)
	ask := func(string, []string, int) ([]TipReply, error) { return retired, nil }

	t.Run("without a peer the limit is real: the withdrawn list is accepted", func(t *testing.T) {
		res, err := VerifyAskingAlso(stale, p.pin(), ask, nil, Floors{}, now)
		if err != nil || res.List.Sequence != 7 {
			t.Fatalf("expected the limit to show (list 7 taken), got %v %v", res, err)
		}
	})
	t.Run("a peer that holds more of the history refuses it", func(t *testing.T) {
		_, err := VerifyAskingAlso(stale, p.pin(), ask, peersSaying(PeerTip{Peer: "EPeer", SN: current.SN, SAID: current.SAID}), Floors{}, now)
		if !errors.Is(err, ErrBehind) {
			t.Fatalf("a stale bundle against a peer that holds the newer history: %v", err)
		}
	})
	t.Run("one peer ahead among peers that know nothing is enough", func(t *testing.T) {
		_, err := VerifyAskingAlso(stale, p.pin(), ask, peersSaying(PeerTip{Peer: "E1", SN: -1}, PeerTip{Peer: "E2", SN: current.SN, SAID: current.SAID}, PeerTip{Peer: "E3", SN: -1}), Floors{}, now)
		if !errors.Is(err, ErrBehind) {
			t.Fatal(err)
		}
	})
}

func TestPeersThatAgreeOrKnowNothingChangeNothing(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	tip := p.tip()
	ask := func(string, []string, int) ([]TipReply, error) { return p.answers(tip, 2), nil }
	for name, peers := range map[string]PeerAsker{
		"no peers asked":                             nil,
		"nobody answered":                            peersSaying(),
		"a peer holding nothing":                     peersSaying(PeerTip{Peer: "E1", SN: -1}),
		"a peer at the same tip":                     peersSaying(PeerTip{Peer: "E1", SN: tip.SN, SAID: tip.SAID}),
		"a peer that is behind, on the same history": peersSaying(PeerTip{Peer: "E1", SN: 1, SAID: tipAt(p, 1).SAID}),
		"a peer that names a place and no event":     peersSaying(PeerTip{Peer: "E1", SN: 3}),
	} {
		if _, err := VerifyAskingAlso(p.bundle(), p.pin(), ask, peers, Floors{}, now); err != nil {
			t.Errorf("%s: a good bundle was refused: %v", name, err)
		}
	}
}

func TestAPeerHoldingAnotherEventAtAPlaceTheBundleHoldsIsDuplicity(t *testing.T) {
	p := onekey(t)
	published(p, 7)
	tip := p.tip()
	ask := func(string, []string, int) ([]TipReply, error) { return p.answers(tip, 2), nil }
	for name, at := range map[string]int{"at the tip": tip.SN, "earlier in the history": 1} {
		other := "EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		_, err := VerifyAskingAlso(p.bundle(), p.pin(), ask, peersSaying(PeerTip{Peer: "E1", SN: at, SAID: other}), Floors{}, now)
		var d *Duplicity
		if !errors.As(err, &d) || d.SN != at || d.Held != other || d.Offered != tipAt(p, at).SAID || len(d.Message) == 0 {
			t.Errorf("%s: %+v (%v)", name, d, err)
		}
	}
}

func TestTheCheckerAsksItsPeersAndRecordsNothingWhenOneRefuses(t *testing.T) {
	p, stale, retired, current := aStaleBundleAnsweredByRetiredWitnesses(t)
	store := FileFloors{Path: filepath.Join(t.TempDir(), "f.json")}
	c := &Checker{Pin: p.pin(), Store: store,
		Peers: peersSaying(PeerTip{Peer: "EPeer", SN: current.SN, SAID: current.SAID})}
	if _, err := c.Check(stale, retired, now); !errors.Is(err, ErrBehind) {
		t.Fatalf("%v", err)
	}
	if fl, _ := store.Load(); fl != (Floors{}) {
		t.Fatalf("a refused bundle left floors: %+v", fl)
	}
	// and the same device with no peers takes it, as the limit says
	c.Peers = nil
	if _, err := c.Check(stale, retired, now); err != nil {
		t.Fatal(err)
	}
}

type recordingPeers struct{ asked []string }

func (r *recordingPeers) AskPeerTips(_ context.Context, aid string) []PeerTip {
	r.asked = append(r.asked, aid)
	return nil
}

func TestPeersOfIsBoundToTheContextAndAsksAboutThePublisher(t *testing.T) {
	if PeersOf(context.Background(), nil) != nil {
		t.Fatal("no asker is a function that asks")
	}
	r := &recordingPeers{}
	PeersOf(context.Background(), r)("EPub")
	if len(r.asked) != 1 || r.asked[0] != "EPub" {
		t.Fatal(r.asked)
	}
	p := onekey(t)
	published(p, 7)
	rr := &recordingPeers{}
	c := &Checker{Pin: p.pin(), Store: FileFloors{Path: filepath.Join(t.TempDir(), "f")}, Peers: PeersOf(context.Background(), rr)}
	if _, err := c.Check(p.bundle(), p.answers(p.tip(), 2), now); err != nil {
		t.Fatal(err)
	}
	if len(rr.asked) != 1 || rr.asked[0] != p.aid {
		t.Fatalf("the peers were asked about %v, not the pinned publisher", rr.asked)
	}
}
