package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/endpoint"
	"identity-agent-core/login"
	"identity-agent-core/measurementlist/anchored"
	"identity-agent-core/watcher"
)

// A contact that asks how much of the software publisher's key history this
// core holds is told the place and event of the newest history it has itself
// checked, and nothing about anything else.
func TestAContactIsToldTheNewestPublisherHistoryThisCoreHasChecked(t *testing.T) {
	f := newListFixture(t)
	seed := make([]byte, 32)
	seed[0] = 11
	s := contactAndAgent(t, "accepted", seed)
	s.EndpointService = endpoint.New(nil, 0)
	s.EndpointService.SetOverrideURL("https://us.example")
	s.measurementLists = f.lists
	router := s.buildRouter()

	var stamp int64
	ask := func(aid string, signWith []byte) watcher.KelTipResponse {
		t.Helper()
		stamp++
		at := time.Now().Unix() + stamp
		sig, err := login.SignString(watcher.KelTipRequestStatement(aid, "https://us.example", at), signWith)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(watcher.KelTipRequest{AID: aid, Requester: "EContact", At: at, Signature: sig})
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, remote("POST", "/public/kel-tip", string(body)))
		var out watcher.KelTipResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		return out
	}

	// nothing accepted yet: nothing held
	if got := ask(f.v.Publisher, seed); got.SN != -1 {
		t.Fatalf("told of a history never checked: %+v", got)
	}
	if err := f.submit("seq7"); err != nil {
		t.Fatal(err)
	}
	fl, err := f.lists.floors().Load()
	if err != nil || !fl.HasKeyHistory {
		t.Fatalf("%+v %v", fl, err)
	}
	got := ask(f.v.Publisher, seed)
	if got.SN != fl.KeyHistorySN || got.SAID != fl.KeyHistorySAID || got.SAID == "" {
		t.Fatalf("told %+v, this core holds %d %s", got, fl.KeyHistorySN, fl.KeyHistorySAID)
	}
	// any other identity: the same as one not held
	if other := ask("EAnybodyElse", seed); other.SN != -1 || other.SAID != "" {
		t.Fatalf("told something of another identity: %+v", other)
	}
	// somebody who is not the contact it claims to be
	wrong := make([]byte, 32)
	wrong[0] = 12
	if stranger := ask(f.v.Publisher, wrong); stranger.SN != -1 {
		t.Fatalf("a request signed by the wrong key was answered: %+v", stranger)
	}
	// and a build that pins no publisher holds none
	s.measurementLists = &measurementLists{dataDir: f.dir}
	if got := ask(f.v.Publisher, seed); got.SN != -1 {
		t.Fatalf("a build with no pin told a tip: %+v", got)
	}
}

// stubPeers are the peers a core asks, saying what they hold.
type stubPeers struct{ tips []anchored.PeerTip }

func (p stubPeers) AskPeerTips(context.Context, string) []anchored.PeerTip { return p.tips }

// What a core asks its peers is what the checker acts on: a contact that holds
// more of the publisher's history than the bundle shown refuses it.
func TestAPeerHoldingMoreOfThePublishersHistoryRefusesTheBundle(t *testing.T) {
	f := newListFixture(t)
	b8, err := anchored.ParseBundle([]byte(f.v.Bundles["seq8"]))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := keri.EventOfMessage(b8.KEL[len(b8.KEL)-1])
	ev, _ := keri.ParseEvent(raw)

	// the older bundle, with the witnesses (the retired ones, say) still
	// answering for its tip, and a contact that has seen the newer history
	f.lists.peers = func() anchored.PeerTipAsker {
		return stubPeers{tips: []anchored.PeerTip{{Peer: "EContact", SN: int(ev.SN), SAID: ev.SAID}}}
	}
	if err := f.submit("seq7"); !errors.Is(err, anchored.ErrBehind) {
		t.Fatalf("the older bundle was taken though a contact holds the newer history: %v", err)
	}
	if fl, _ := f.lists.floors().Load(); fl.ListSequence != 0 {
		t.Fatalf("a refused bundle left floors: %+v", fl)
	}
	f.lists.peers = nil
	if err := f.submit("seq7"); err != nil {
		t.Fatalf("control, with no peers: %v", err)
	}
}
