package login

import (
	"os"
	"strings"
	"testing"
)

const aGoodRelayID = "Eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// A person's Identity Agent keeps the relay identifier and back-end address a
// sign-in names, to know where to send the end of a session. A site cannot make
// it keep one that aims the request at this machine or a private network, or
// one that is not shaped as an identifier or an address.
func TestAChallengeNamesOnlyAnAddressThisAgentWillKeep(t *testing.T) {
	was := inDev
	t.Cleanup(func() { inDev = was })
	inDev = func() bool { return false }

	good := &ChallengeBundle{RelayID: aGoodRelayID, BackEnd: "https://tasks.example.com/api"}
	if err := CheckUtilityAppAddress(good); err != nil {
		t.Fatalf("a good pair was refused: %v", err)
	}
	if err := CheckUtilityAppAddress(&ChallengeBundle{}); err != nil {
		t.Fatalf("a challenge that names neither, which is not a utility app's, was refused: %v", err)
	}
	for name, b := range map[string]*ChallengeBundle{
		"a private address":               {BackEnd: "https://10.0.0.5"},
		"where a cloud keeps secrets":     {BackEnd: "https://169.254.169.254/latest"},
		"this machine":                    {BackEnd: "http://127.0.0.1:5050"},
		"this machine by name":            {BackEnd: "http://localhost"},
		"a private suffix":                {BackEnd: "https://db.internal"},
		"a name with no dot":              {BackEnd: "https://intranet"},
		"a user name":                     {BackEnd: "https://user@tasks.example.com"},
		"a trailing slash":                {BackEnd: "https://tasks.example.com/"},
		"a capital":                       {BackEnd: "https://Tasks.example.com"},
		"a relay identifier too short":    {RelayID: "Erelay"},
		"a relay identifier with a slash": {RelayID: aGoodRelayID[:43] + "/"},
	} {
		if err := CheckUtilityAppAddress(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// A development build may name this machine.
	inDev = func() bool { return true }
	if err := CheckUtilityAppAddress(&ChallengeBundle{BackEnd: "http://localhost:3000"}); err != nil {
		t.Errorf("a development build refused this machine: %v", err)
	}
}

// The place a sign-in is kept refuses what the check refuses, and keeps nothing.
func TestABrowserSignInThatNamesABadAddressIsNotKept(t *testing.T) {
	h := aBrowserRecordHandler(t)
	for _, b := range []*ChallengeBundle{
		{SiteAID: "Dsite", BrowserKey: aTestKey, FrontEnd: FrontEndBrowser, RelayID: aGoodRelayID, BackEnd: "https://10.0.0.5"},
		{SiteAID: "Dsite", BrowserKey: aTestKey, FrontEnd: FrontEndBrowser, RelayID: "Erelay", BackEnd: "https://tasks.example.com"},
	} {
		if _, err := h.recordBrowserSignIn(&SiteRelationship{PairwiseAID: "Dp"}, b); err == nil {
			t.Fatalf("a sign-in naming %q and %q was kept", b.BackEnd, b.RelayID)
		}
	}
	if n := len(h.BrowserSignIns.List()); n != 0 {
		t.Fatalf("%d sign-ins were kept", n)
	}
}

// The person is asked nothing for a challenge that names an address this agent
// would not keep: prepareLogin runs the check before the consent is shown.
func TestTheCheckRunsBeforeAPersonIsAsked(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func (h *Handler) prepareLogin(")
	if i < 0 {
		t.Fatal("prepareLogin is not where this test looks")
	}
	body := s[i:]
	check, preview := strings.Index(body, "CheckUtilityAppAddress(bundle)"), strings.Index(body, "previewRequestedCredentials(")
	if check < 0 || preview < 0 || check > preview {
		t.Fatal("prepareLogin does not check the challenge's address before it builds the consent")
	}
}
