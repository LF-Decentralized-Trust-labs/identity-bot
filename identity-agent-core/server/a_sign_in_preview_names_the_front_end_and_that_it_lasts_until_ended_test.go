package server

import (
	"testing"

	"identity-agent-core/login"
)

// The details a screen lists for a sign-in say which kind of front end asks and,
// for an installed app, that approving lasts until it is ended. Fails when an
// installed app's sign-in lists neither row, or a browser's claims to last.
func TestASignInPreviewNamesTheFrontEndAndThatItLastsUntilEnded(t *testing.T) {
	got := frontEndDetails(login.FrontEndInstalledApp, true)
	if len(got) != 2 || got[0] != (PreviewDetail{Label: "Front end", Value: "an installed app"}) ||
		got[1].Label != "Lasts" || got[1].Value != "until you end it, in My apps" {
		t.Fatalf("an installed app's sign-in lists %+v", got)
	}
	got = frontEndDetails(login.FrontEndBrowser, false)
	if len(got) != 1 || got[0].Value != "a web browser" {
		t.Fatalf("a browser's sign-in lists %+v", got)
	}
	if got := frontEndDetails("", false); len(got) != 0 {
		t.Fatalf("a sign-in naming no kind lists %+v", got)
	}
}
