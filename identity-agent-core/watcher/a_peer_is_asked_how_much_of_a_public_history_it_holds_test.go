package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A peer that answers a tip request as a given tip, recording what it was sent.
func tipPeer(t *testing.T, sn int, said string, got *KelTipRequest, asked *int32) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/kel-tip" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(asked, 1)
		_ = json.NewDecoder(r.Body).Decode(got)
		_ = json.NewEncoder(w).Encode(KelTipResponse{SN: sn, SAID: said})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAPeerIsAskedForTheTipWithASignedRequestBoundToIt(t *testing.T) {
	var asked int32
	var got KelTipRequest
	p := tipPeer(t, 4, "Esaid", &got, &asked)
	s := contactService(t, p.URL)
	var signed string
	s.SignRequest = func(peer, statement string) (string, string, error) {
		signed = peer + "|" + statement
		return "Ewatcher", "sig", nil
	}

	// the peer is not one that has met the publisher: it is asked all the same
	out := s.AskPeerTips(context.Background(), "EPublisher")
	if len(out) != 1 || out[0] != (PeerTipAnswer{Peer: "EContact", SN: 4, SAID: "Esaid"}) {
		t.Fatalf("%+v", out)
	}
	if got.AID != "EPublisher" || got.Requester != "Ewatcher" || got.Signature != "sig" || got.At == 0 {
		t.Fatalf("the request: %+v", got)
	}
	if !strings.HasPrefix(signed, "EContact|"+KelTipRequestTag+"\n") ||
		!strings.Contains(signed, "to="+p.URL+"\n") || !strings.Contains(signed, "aid=EPublisher\n") {
		t.Fatalf("what was signed does not name the peer and the identity: %q", signed)
	}
}

func TestPeersAreNotAskedWhenTheOwnerHasNotSaidSoOrCannotSign(t *testing.T) {
	var asked int32
	var got KelTipRequest
	p := tipPeer(t, 4, "Esaid", &got, &asked)

	s := contactService(t, p.URL)
	if err := s.SetPeerWatchEnabled(false); err != nil {
		t.Fatal(err)
	}
	if out := s.AskPeerTips(context.Background(), "EPublisher"); len(out) != 0 || asked != 0 {
		t.Fatalf("a peer was asked with peer checks off: %v", out)
	}
	s = contactService(t, p.URL)
	s.SignRequest = nil
	if out := s.AskPeerTips(context.Background(), "EPublisher"); len(out) != 0 || asked != 0 {
		t.Fatalf("a peer was asked with nothing to sign with: %v", out)
	}
	s = contactService(t, p.URL)
	if out := s.AskPeerTips(context.Background(), "EContact"); len(out) != 0 || asked != 0 {
		t.Fatalf("a peer was asked about itself: %v", out)
	}
	s = contactService(t, p.URL)
	s.PeerAllowed = func(string) bool { return false }
	if out := s.AskPeerTips(context.Background(), "EPublisher"); len(out) != 0 || asked != 0 {
		t.Fatalf("a peer outside the boundary was asked: %v", out)
	}
}

func TestAPeerThatDoesNotAnswerIsLeftOut(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	t.Cleanup(down.Close)
	s := contactService(t, down.URL)
	if out := s.AskPeerTips(context.Background(), "EPublisher"); len(out) != 0 {
		t.Fatalf("an error was an answer: %v", out)
	}
}

func tipRequest(s *Service, at int64, aid string) KelTipRequest {
	return KelTipRequest{AID: aid, Requester: "EContact", At: at, Signature: "sig"}
}

func TestATipIsGivenOnlyToAContactWhoSignedAFreshRequestOnce(t *testing.T) {
	s := storedService(t)
	now := time.Unix(1_800_000_000, 0)
	s.Now = func() time.Time { return now }
	var verified []string
	s.VerifyRequester = func(requester, statement, sig string) bool {
		verified = append(verified, statement)
		return requester == "EContact" && sig == "sig"
	}
	held := func(aid string) (int, string, bool) {
		if aid == "EPublisher" {
			return 5, "Etip", true
		}
		return 0, "", false
	}
	ask := func(req KelTipRequest) (*KelTipResponse, bool) {
		r, c, err := s.KelTip(req, "https://us.example/", held)
		if err != nil {
			t.Fatal(err)
		}
		return r, c
	}

	if r, c := ask(tipRequest(s, now.Unix(), "EPublisher")); !c || r.SN != 5 || r.SAID != "Etip" {
		t.Fatalf("a contact was not told: %+v %v", r, c)
	}
	if want := KelTipRequestStatement("EPublisher", "https://us.example", now.Unix()); verified[0] != want {
		t.Fatalf("verified %q, not the statement bound to this agent's address and the time", verified[0])
	}
	// the same request again is a replay
	if r, _ := ask(tipRequest(s, now.Unix(), "EPublisher")); r.SN != -1 {
		t.Fatalf("a replayed request was answered: %+v", r)
	}
	// stale and future
	for _, at := range []int64{now.Unix() - 3600, now.Unix() + 3600} {
		if r, c := ask(tipRequest(s, at, "EPublisher")); r.SN != -1 || c {
			t.Fatalf("a request at %d was answered: %+v", at, r)
		}
	}
	// a stranger, and a bad signature
	bad := tipRequest(s, now.Unix()+1, "EPublisher")
	bad.Requester = "EStranger"
	if r, c := ask(bad); r.SN != -1 || c {
		t.Fatalf("a stranger was told: %+v", r)
	}
	bad = tipRequest(s, now.Unix()+2, "EPublisher")
	bad.Signature = "forged"
	if r, c := ask(bad); r.SN != -1 || c {
		t.Fatalf("a request with a bad signature was answered: %+v", r)
	}
	// an identity not held, and no source of what is held, answer as a contact would be answered for nothing
	if r, c := ask(tipRequest(s, now.Unix()+3, "ESomeoneElse")); !c || r.SN != -1 || r.SAID != "" {
		t.Fatalf("an identity not held: %+v", r)
	}
	if r, _, _ := s.KelTip(tipRequest(s, now.Unix()+4, "EPublisher"), "https://us.example", nil); r.SN != -1 {
		t.Fatalf("with nothing held: %+v", r)
	}
	// no address of its own: nobody can have signed for it
	if r, _, _ := s.KelTip(tipRequest(s, now.Unix()+5, "EPublisher"), "", held); r.SN != -1 {
		t.Fatalf("answered with no address: %+v", r)
	}
	// a tip request's signature is not a cross-check's, nor the reverse
	if KelTipRequestStatement("A", "B", 1) == KelCheckRequestStatement("A", 1, "", "B", 1) {
		t.Fatal("one statement serves both routes")
	}
}
