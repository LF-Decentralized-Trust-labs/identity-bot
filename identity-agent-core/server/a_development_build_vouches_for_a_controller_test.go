package server

import (
	"testing"
	"time"

	"identity-agent-core/authprovider"
)

// A production build takes nothing as measured that was not measured, so an
// unvouched controller stays out of every raised action exactly as before.
func TestAProductionBuildTakesNothingAsMeasured(t *testing.T) {
	now := time.Now().UTC()
	got := whatThisBuildTakesAsMeasured(
		authprovider.Unmeasured("nothing vouched"), false, false, now)
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
		authprovider.Unmeasured("nothing vouched"), false, true, now)
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
	got := whatThisBuildTakesAsMeasured(measured, true, true, now)
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
		authprovider.Unmeasured("not vouched for by the device that holds the key"), true, true, now)
	if got.Measured {
		t.Fatalf("a refused statement was taken as verified: %+v", got)
	}
}
