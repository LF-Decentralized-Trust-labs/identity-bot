package server

import (
	"strings"
	"testing"

	"identity-agent-core/login"
)

const aRelayID = "EPK79TkurF8S2rezG3Z8dUiUYkEuYy_9_kZOSBi5HSqI"

// Fails without the relay identifier in the signed challenge: a front end
// handed a link naming another relay identifier or back end could not tell the
// challenge is not for it. What the owner's Identity Agent recorded for the app is
// what the challenge is signed for, in the text the signature covers.
func TestTheChallengeIsSignedForTheRelayIdentifierRecordedForTheApp(t *testing.T) {
	w := anAppOffering(t, []string{"browser"}, nil)
	a, _, _ := w.org.assetHandler.Store.GetAsset("the-website")
	a.RelayID = aRelayID
	if err := w.org.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, aBrowserKey, "browser", w.srv.URL, false)
	if code != 0 {
		t.Fatalf("no challenge: %d %s", code, msg)
	}
	bundle := w.org.challenges[token]
	if bundle.RelayID != aRelayID {
		t.Fatalf("the challenge is for relay identifier %q", bundle.RelayID)
	}
	if body := login.CanonicalChallengeBody(bundle); !strings.Contains(body, `"rid":"`+aRelayID+`"`) {
		t.Fatalf("the relay identifier is not in the signed text: %s", body)
	}
}

// A utility app whose relay identifier is not recorded signs people in as before, with a
// challenge that names none.
func TestAnAppWithNoRecordedRelayIdentifierKeepsItsChallenge(t *testing.T) {
	w := anAppOffering(t, []string{"browser"}, nil)
	token, _, code, msg := w.org.createSignedAssetChallenge("the-website", "https://portal.example", "", nil, aBrowserKey, "browser", w.srv.URL, false)
	if code != 0 {
		t.Fatalf("no challenge: %d %s", code, msg)
	}
	if rid := w.org.challenges[token].RelayID; rid != "" {
		t.Fatalf("a relay identifier nobody recorded was signed: %q", rid)
	}
}
