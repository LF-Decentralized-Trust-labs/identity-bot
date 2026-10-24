package server

import (
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

// A production build takes nothing as measured that was not measured, so an
// unvouched controller stays out of every raised action exactly as before.
func TestAProductionBuildTakesNothingAsMeasured(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, false, false, now)
	if got.Measured {
		t.Fatalf("a production build treated an unmeasured controller as measured: %+v", got)
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/mcp/agents", got, now); ok {
		t.Fatal("a production build let an unmeasured controller create an AI agent")
	}
}

// The stand-in opens the verified actions — creating an AI agent among them —
// and nothing raised to high.
func TestADevelopmentBuildOpensVerifiedButNotHigh(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, true, false, now)
	if got.Provider != developmentBuildProvider {
		t.Fatalf("the stand-in is not labelled as one: %q", got.Provider)
	}
	for _, route := range []string{"/api/mcp/agents", "/api/mcp/tokens"} {
		if ok, why := mayThisControllerDoThis("POST", route, got, now); !ok {
			t.Fatalf("a development build refused POST %s: %s", route, why)
		}
	}
	if ok, _ := mayThisControllerDoThis(
		"PUT", "/api/mcp/agents/{id}/capabilities", got, now); !ok {
		t.Fatal("a development build refused re-issuing an AI agent's grant")
	}
	for _, route := range []string{"/api/rotation", "/api/backup/export", "/api/keystore/root-seed"} {
		if ok, _ := mayThisControllerDoThis("POST", route, got, now); ok {
			t.Fatalf("a development build opened POST %s, which is raised to high", route)
		}
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/controllers", got, now); ok {
		t.Fatal("a development build opened enrolling a controller, which no level opens")
	}
}

// A person who was checked and fell short was not checked "by default": the
// real, lower answer stands.
func TestADevelopmentBuildKeepsAMeasuredLowerLevel(t *testing.T) {
	now := time.Now().UTC()
	measured := authprovider.Result{
		Level: authprovider.LevelBasic, Measured: true, At: now, Provider: "root-identity-device",
	}
	got := whatThisBuildTakesAsMeasured(measured, true, true, false, now)
	if got != measured {
		t.Fatalf("a development build replaced a real measurement: %+v", got)
	}
	if ok, _ := mayThisControllerDoThis("POST", "/api/mcp/agents", got, now); ok {
		t.Fatal("a measured basic level created an AI agent")
	}
}

// A statement that was offered and did not hold up — unvouched, or forged — is
// not raised by the stand-in: it was an attempt, not an absence.
func TestADevelopmentBuildDoesNotRaiseARefusedStatement(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("not vouched for by the device that holds the key"), true, true, false, now)
	if got.Measured {
		t.Fatalf("a refused statement was taken as verified: %+v", got)
	}
}

// A development build that anything outside this computer can reach takes
// nothing as measured: every machine holding a grant there would otherwise be
// able to issue credentials, mint tokens and create AI agents for the identity.
func TestADevelopmentBuildReachableFromOutsideTakesNothingAsMeasured(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, true, true, now)
	if got.Measured {
		t.Fatalf("a reachable development build vouched for a controller: %+v", got)
	}
	for _, route := range []string{"/api/mcp/agents", "/api/mcp/tokens"} {
		if ok, _ := mayThisControllerDoThis("POST", route, got, now); ok {
			t.Fatalf("a reachable development build let an unmeasured controller POST %s", route)
		}
	}
}

// Every way this Identity Agent can be reached from elsewhere counts, including the
// ones that are only intended so far — a relay configured but not connected,
// a tunnel still starting — and only loopback with nothing published does not.
func TestWhatCountsAsReachableFromOutside(t *testing.T) {
	cases := []struct {
		name string
		h    howThisIdentityAgentIsReached
		want bool
	}{
		{"loopback only, nothing published", howThisIdentityAgentIsReached{PublishedSource: "localhost", ThisRequestIsLocal: true}, false},
		{"not yet started", howThisIdentityAgentIsReached{ThisRequestIsLocal: true}, false},
		{"listening on loopback explicitly", howThisIdentityAgentIsReached{ListensOn: "127.0.0.1", ThisRequestIsLocal: true}, false},
		{"a request from elsewhere, nothing else telling", howThisIdentityAgentIsReached{}, true},
		{"behind a proxy it was told about", howThisIdentityAgentIsReached{ThisRequestIsLocal: true, BehindAProxy: true}, true},
		{"in tunnel mode with no tunnel up yet", howThisIdentityAgentIsReached{ThisRequestIsLocal: true, TunnelMode: true}, true},
		{"a sealed instance", howThisIdentityAgentIsReached{SealedInstance: true}, true},
		{"listening on every interface", howThisIdentityAgentIsReached{ListensOn: "0.0.0.0"}, true},
		{"listening on a LAN address", howThisIdentityAgentIsReached{ListensOn: "192.168.0.10"}, true},
		{"holding a relay address while disconnected", howThisIdentityAgentIsReached{HoldsRelay: true}, true},
		{"a relay configured, not yet up", howThisIdentityAgentIsReached{RelayConfigured: true}, true},
		{"a tunnel", howThisIdentityAgentIsReached{Tunnel: true}, true},
		{"PUBLIC_URL set", howThisIdentityAgentIsReached{PublicURL: "https://identity-agent.example"}, true},
		{"an override address", howThisIdentityAgentIsReached{PublishedSource: "override"}, true},
		{"an address a proxy reported", howThisIdentityAgentIsReached{PublishedSource: "observed:proxy"}, true},
		{"a relay address published", howThisIdentityAgentIsReached{PublishedSource: "relay:example"}, true},
	}
	for _, c := range cases {
		got, why := whoCanReachThisIdentityAgent(c.h)
		if got != c.want {
			t.Errorf("%s: reachable = %v, want %v", c.name, got, c.want)
		}
		if got && why == "" {
			t.Errorf("%s: reachable with no reason given", c.name)
		}
	}
}

// The facts are read from the running Identity Agent and the request, not
// assumed: a PUBLIC_URL, or a request arriving from elsewhere or through a
// proxy, makes it reachable.
func TestTheRunningIdentityAgentReportsHowItIsReached(t *testing.T) {
	s := &CoreServer{}
	t.Setenv("RELAY_BASE_URL", "")
	t.Setenv("PUBLIC_RELAY_BASE_URL", "")
	here := httptest.NewRequest("GET", "/api/profile", nil)
	here.RemoteAddr = "127.0.0.1:50000"
	if got, why := whoCanReachThisIdentityAgent(s.howThisIdentityAgentIsReachedNow(here)); got {
		t.Fatalf("an Identity Agent with nothing configured, asked from this computer, was taken as reachable: %s", why)
	}
	far := httptest.NewRequest("GET", "/api/profile", nil)
	far.RemoteAddr = "203.0.113.9:50000"
	if got, _ := whoCanReachThisIdentityAgent(s.howThisIdentityAgentIsReachedNow(far)); !got {
		t.Fatal("a request from another machine was taken as local")
	}
	proxied := httptest.NewRequest("GET", "/api/profile", nil)
	proxied.RemoteAddr = "127.0.0.1:50000"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got, _ := whoCanReachThisIdentityAgent(s.howThisIdentityAgentIsReachedNow(proxied)); !got {
		t.Fatal("a request a proxy forwarded over loopback was taken as local")
	}
	t.Setenv("PUBLIC_URL", "https://identity-agent.example")
	if got, _ := whoCanReachThisIdentityAgent(s.howThisIdentityAgentIsReachedNow(here)); !got {
		t.Fatal("an Identity Agent publishing PUBLIC_URL was taken as reachable only from this computer")
	}
}

// The decision as the controller path makes it, from a real request: on a
// development build, a controller asking from this computer of an Identity
// Agent nothing else can reach is stood in for, and one asking from anywhere
// else is not.
func TestTheStandInIsDecidedFromTheRequestItself(t *testing.T) {
	s := &CoreServer{}
	t.Setenv("RELAY_BASE_URL", "")
	t.Setenv("PUBLIC_RELAY_BASE_URL", "")
	now := time.Now().UTC()
	nothing := authprovider.Unmeasured("nothing vouched")

	here := httptest.NewRequest("POST", "/api/mcp/agents", nil)
	here.RemoteAddr = "127.0.0.1:50000"
	if got := s.whatThisRequestTakesAsMeasured(here, nothing, false, true, now); !got.Measured {
		t.Fatal("a development build did not stand in for a controller on this computer")
	}
	far := httptest.NewRequest("POST", "/api/mcp/agents", nil)
	far.RemoteAddr = "203.0.113.9:50000"
	if got := s.whatThisRequestTakesAsMeasured(far, nothing, false, true, now); got.Measured {
		t.Fatalf("a development build stood in for a controller asking from elsewhere: %+v", got)
	}
	t.Setenv("RELAY_BASE_URL", "https://relay.example")
	if got := s.whatThisRequestTakesAsMeasured(here, nothing, false, true, now); got.Measured {
		t.Fatalf("a development build set to be reached through a relay stood in for a controller: %+v", got)
	}
}
