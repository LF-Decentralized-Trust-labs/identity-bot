package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// peer stands up an agent that answers a cross-check the way a real one does.
//
// digest nil means it has never seen the identity, which is the case that must
// not be confused with agreement.
func peer(t *testing.T, digest *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req KelCheckRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := KelCheckResponse{OurDigest: digest}
		if digest != nil {
			resp.Match = *digest == req.Digest
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func peerService(t *testing.T, peers ...*httptest.Server) *Service {
	t.Helper()
	s := &Service{L3: NewL3Client()}
	s.PeerWatchers = func() []PeerWatcher {
		var out []PeerWatcher
		for _, p := range peers {
			out = append(out, PeerWatcher{URL: p.URL})
		}
		return out
	}
	return s
}

// Peers holding the same history agree, and that is recorded as agreement.
func TestPeersHoldingTheSameHistoryAgree(t *testing.T) {
	d := "EdigestAtSeqZero"
	s := peerService(t, peer(t, &d), peer(t, &d))

	outcomes, agreed, disagreed := s.crossCheckPeers(context.Background(), "EAlice", 0, d)
	if agreed != 2 || disagreed != 0 {
		t.Fatalf("agreed=%d disagreed=%d, expected both peers to agree", agreed, disagreed)
	}
	for _, o := range outcomes {
		if o.Outcome != "match" {
			t.Errorf("peer %s reported %q", o.URL, o.Outcome)
		}
	}
}

// A peer holding a different history at the same sequence is duplicity — the
// signal the whole layer exists to surface.
func TestAPeerHoldingADifferentHistoryDisagrees(t *testing.T) {
	ours, theirs := "EourDigest", "EtheirDigest"
	s := peerService(t, peer(t, &theirs))

	_, agreed, disagreed := s.crossCheckPeers(context.Background(), "EAlice", 0, ours)
	if agreed != 0 || disagreed != 1 {
		t.Fatalf("agreed=%d disagreed=%d, expected the peer to disagree", agreed, disagreed)
	}
}

// The case that matters most. A peer that has never seen this identity has not
// agreed with anybody, and counting its silence as agreement is how a verifier
// convinces itself it has corroboration it does not have.
func TestAPeerThatHasNeverSeenTheIdentityIsNotAgreement(t *testing.T) {
	s := peerService(t, peer(t, nil))

	outcomes, agreed, disagreed := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest")
	if agreed != 0 {
		t.Fatal("a peer that holds no opinion was counted as agreeing")
	}
	if disagreed != 0 {
		t.Fatal("a peer that holds no opinion was counted as disagreeing")
	}
	if len(outcomes) != 1 || outcomes[0].Outcome != "unknown" {
		t.Fatalf("expected the silence recorded as unknown, got %+v", outcomes)
	}
}

// An unreachable peer is likewise not agreement. It is recorded so a caller can
// see how thin its corroboration actually was.
func TestAnUnreachablePeerIsRecordedRatherThanIgnored(t *testing.T) {
	s := &Service{L3: NewL3Client()}
	s.PeerWatchers = func() []PeerWatcher {
		return []PeerWatcher{{URL: "http://127.0.0.1:1"}} // nothing listening
	}
	outcomes, agreed, _ := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest")
	if agreed != 0 {
		t.Fatal("an unreachable peer was counted as agreeing")
	}
	if len(outcomes) != 1 || outcomes[0].Outcome != "unavailable" {
		t.Fatalf("expected the failure recorded, got %+v", outcomes)
	}
}

// The entity boundary is applied at selection too, so a source that has not
// applied it cannot widen who gets asked — and a refused peer is never
// contacted, so it never learns which identity was being asked about.
func TestTheBoundaryIsAppliedWhenChoosingPeersAsWell(t *testing.T) {
	d := "Edigest"
	p := peer(t, &d)
	s := peerService(t, p)
	s.PeerAllowed = func(string) bool { return false }

	outcomes, agreed, disagreed := s.crossCheckPeers(context.Background(), "EAlice", 0, d)
	if len(outcomes) != 0 || agreed != 0 || disagreed != 0 {
		t.Fatalf("a peer the boundary refuses was queried anyway: %+v", outcomes)
	}
}

// No peers configured means no L3, reported as nothing rather than as agreement.
func TestNoPeersMeansNoCorroboration(t *testing.T) {
	s := &Service{L3: NewL3Client()}
	outcomes, agreed, disagreed := s.crossCheckPeers(context.Background(), "EAlice", 0, "Edigest")
	if len(outcomes) != 0 || agreed != 0 || disagreed != 0 {
		t.Fatalf("peers appeared from nowhere: %+v", outcomes)
	}
}
