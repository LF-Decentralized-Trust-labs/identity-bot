package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBuildAskContextPreservesPath verifies the scan gate recovers the asker base by stripping
// only the trailing /i/{token} and PRESERVING any path prefix (path-based relay tunnels), and
// reads the action `t` from the fetched Ask.
func TestBuildAskContextPreservesPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/green-oak-87/i/tok123" {
			_, _ = w.Write([]byte(`{"v":"ASK1","t":1,"site_oobi":"https://x/oobi/E1"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := &CoreServer{}
	ctx, err := s.buildAskContext(srv.URL + "/green-oak-87/i/tok123")
	if err != nil {
		t.Fatalf("buildAskContext: %v", err)
	}
	if ctx.Token != "tok123" {
		t.Fatalf("token = %q, want tok123", ctx.Token)
	}
	if want := srv.URL + "/green-oak-87"; ctx.Base != want {
		t.Fatalf("base = %q, want %q (path prefix must be preserved)", ctx.Base, want)
	}
	if ctx.T != 1 {
		t.Fatalf("t = %d, want 1", ctx.T)
	}

	// Apex/subdomain form: no path prefix → base is just the origin.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"v":"ASK1","t":2}`))
	}))
	defer srv2.Close()
	ctx2, err := s.buildAskContext(srv2.URL + "/i/abc")
	if err != nil {
		t.Fatalf("buildAskContext apex: %v", err)
	}
	if ctx2.Base != srv2.URL || ctx2.Token != "abc" || ctx2.T != 2 {
		t.Fatalf("apex: base=%q token=%q t=%d", ctx2.Base, ctx2.Token, ctx2.T)
	}
}

func TestTierRankNeverDowngrades(t *testing.T) {
	if tierRank("trusted") <= tierRank("general") || tierRank("general") <= tierRank("transactional") {
		t.Fatal("tier ordering wrong: transactional < general < professional < trusted")
	}
}
