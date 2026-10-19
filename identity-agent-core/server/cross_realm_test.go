package server

import (
	"encoding/json"
	"testing"

	"identity-agent-core/buildmode"
)

// A cross-realm contact is refused in both directions, a same-realm contact is
// allowed, and an absent realm is read as production. The decision is tested
// directly because the build mode is fixed per test binary, so the handler path
// (ensureKeriContactIs) exercises only one realm at a time.
func TestPeerRealmRefused(t *testing.T) {
	cases := []struct {
		name      string
		ourRealm  string
		peerRealm string
		refused   bool
	}{
		{"prod meets prod", buildmode.Prod, buildmode.Prod, false},
		{"dev meets dev", buildmode.Dev, buildmode.Dev, false},
		{"prod meets dev", buildmode.Prod, buildmode.Dev, true},
		{"dev meets prod", buildmode.Dev, buildmode.Prod, true},
		{"prod meets an untagged peer is prod", buildmode.Prod, "", false},
		{"dev meets an untagged peer is prod, so refused", buildmode.Dev, "", true},
		{"two untagged peers are both prod", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := peerRealmRefused(c.ourRealm, c.peerRealm); got != c.refused {
				t.Fatalf("peerRealmRefused(%q, %q) = %v, want %v",
					c.ourRealm, c.peerRealm, got, c.refused)
			}
		})
	}
}

// A connect-request body is stamped with this agent's realm while its other
// fields are preserved, an empty object gains the realm, and a body that is not
// an object is returned untouched rather than dropped. (The test binary is a
// production build, so the stamped value is prod.)
func TestWithRealm(t *testing.T) {
	stamped := withRealm([]byte(`{"alias":"a stranger"}`))
	var got map[string]interface{}
	if err := json.Unmarshal(stamped, &got); err != nil {
		t.Fatalf("stamped body did not parse: %v", err)
	}
	if got["realm"] != buildmode.Mode() {
		t.Fatalf("realm = %v, want %q", got["realm"], buildmode.Mode())
	}
	if got["alias"] != "a stranger" {
		t.Fatalf("stamping dropped an existing field: alias = %v", got["alias"])
	}

	empty := withRealm([]byte(`{}`))
	if err := json.Unmarshal(empty, &got); err != nil || got["realm"] != buildmode.Mode() {
		t.Fatalf("an empty object was not stamped: %s (err %v)", empty, err)
	}

	notObject := []byte(`"not an object"`)
	if out := withRealm(notObject); string(out) != string(notObject) {
		t.Fatalf("a non-object body was altered: %s", out)
	}
}

// An absent realm normalises to production, which is what keeps every peer that
// predates the tag reachable from a production agent.
func TestRealmOfTreatsAbsentAsProd(t *testing.T) {
	if realmOf("") != buildmode.Prod {
		t.Fatalf("realmOf(\"\") = %q, want %q", realmOf(""), buildmode.Prod)
	}
	if realmOf(buildmode.Dev) != buildmode.Dev {
		t.Fatalf("realmOf(%q) = %q, want it unchanged", buildmode.Dev, realmOf(buildmode.Dev))
	}
}
