package login

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func aSignedInstalledAppChallenge(t *testing.T, platform, name string) (ChallengeBundle, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	b := ChallengeBundle{V: "ASK1", T: 1, SiteAID: "ESite", SiteOOBI: "https://x/oobi", Audience: "Portal",
		Nonce: "n", Dt: "2026-11-15T00:00:00Z", Expiry: "2026-11-15T00:10:00Z",
		RequestedDisclosures: []string{}, RequestedCredentials: []RequestedCredential{},
		CallbackURL: "https://x/cb", SessionToken: "s", BrowserKey: "k", FrontEnd: FrontEndInstalledApp,
		DevicePlatform: platform, DeviceName: name}
	if err := SignChallengeForAsset(&b, seed); err != nil {
		t.Fatal(err)
	}
	return b, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

// The device is inside the signed body: a relay that renames the device, swaps
// its platform, adds one, or drops it breaks the signature. Fails if either
// field is left out of canonicalChallengeBody.
func TestTheDeviceIsSignedInTheChallenge(t *testing.T) {
	b, pub := aSignedInstalledAppChallenge(t, DeviceAndroid, "Ann's Pixel")
	if ok, _ := verifyUTF8(canonicalChallengeBody(b), b.Sig, pub); !ok {
		t.Fatal("the signed challenge does not verify")
	}
	for name, tamper := range map[string]func(*ChallengeBundle){
		"platform swapped": func(c *ChallengeBundle) { c.DevicePlatform = DeviceApple },
		"name changed":     func(c *ChallengeBundle) { c.DeviceName = "Bob's Pixel" },
		"name dropped":     func(c *ChallengeBundle) { c.DeviceName = "" },
		"device dropped":   func(c *ChallengeBundle) { c.DevicePlatform, c.DeviceName = "", "" },
	} {
		c := b
		tamper(&c)
		if ok, _ := verifyUTF8(canonicalChallengeBody(c), c.Sig, pub); ok {
			t.Fatalf("%s: the signature still verified", name)
		}
	}
	// A challenge that names no device keeps its form.
	plain := b
	plain.DevicePlatform, plain.DeviceName = "", ""
	if strings.Contains(canonicalChallengeBody(plain), "device") {
		t.Fatal("a challenge naming no device carries device fields")
	}
}

func TestCheckDevice(t *testing.T) {
	for _, c := range []struct {
		why                   string
		front, platform, name string
		ok                    bool
	}{
		{"no device", FrontEndBrowser, "", "", true},
		{"installed app, platform only", FrontEndInstalledApp, DeviceTPM, "", true},
		{"installed app, platform and name", FrontEndInstalledApp, DeviceApple, "Ann's iPhone", true},
		{"a browser names a device", FrontEndBrowser, DeviceAndroid, "", false},
		{"no kind names a device", "", DeviceAndroid, "", false},
		{"a virtual TPM", FrontEndInstalledApp, DeviceVirtualTPM, "", true},
		{"unknown platform", FrontEndInstalledApp, "windows", "", false},
		{"a name with no platform", FrontEndInstalledApp, "", "Ann's Pixel", false},
		{"a name not fit to show", FrontEndInstalledApp, DeviceAndroid, "a‮b", false},
		{"a name too long", FrontEndInstalledApp, DeviceAndroid, strings.Repeat("x", MaxDeviceNameRunes+1), false},
	} {
		if (CheckDevice(c.front, c.platform, c.name) == nil) != c.ok {
			t.Errorf("%s: CheckDevice = %v", c.why, CheckDevice(c.front, c.platform, c.name))
		}
	}
}

func TestCleanDeviceName(t *testing.T) {
	for in, want := range map[string]string{
		"  Ann's   Pixel \n":                "Ann's Pixel",
		"a‮b⁦c\x00d":                        "abcd",
		"line\nbreak here":                  "line break here",
		"“”":                                "“”",
		"":                                  "",
		" \t ":                              "",
		strings.Repeat("é", 100):            strings.Repeat("é", MaxDeviceNameRunes),
		strings.Repeat("a ", 100):           strings.TrimSpace(strings.Repeat("a ", MaxDeviceNameRunes/2)),
		"a\u034F\u17B4b":                    "ab",
		"\u3164\u115F\u2800":                "",
		"\uF8FF Ann's iPhone":               "Ann's iPhone",
		"A" + strings.Repeat("\u0336", 47):  "A\u0336\u0336",
		"\u0301start":                       "start",
		"\U0001F469\u200D\U0001F4BB laptop": "\U0001F469\u200D\U0001F4BB laptop",
		"\u200Dlead trail\u200D":            "lead trail",
		"\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645": "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645",
		"Ann\u00A0\u2003Pixel":                             "Ann Pixel",
	} {
		if got := CleanDeviceName(in); got != want {
			t.Errorf("CleanDeviceName(%q) = %q, want %q", in, got, want)
		}
		if CleanDeviceName(CleanDeviceName(in)) != CleanDeviceName(in) {
			t.Errorf("CleanDeviceName is not stable for %q", in)
		}
	}
}

// A sign-in waiting in the person's list names its device, as the preview does.
func TestAWaitingSignInNamesItsDevice(t *testing.T) {
	h := &Handler{Pending: NewPendingStore()}
	b, _ := aSignedInstalledAppChallenge(t, DeviceApple, "Ann's iPhone")
	h.Pending.Put("k", &pendingLogin{SessionToken: "s", Bundle: &b, Relationship: &SiteRelationship{}})
	w := httptest.NewRecorder()
	h.HandlePendingList(w, httptest.NewRequest("GET", "/pending", nil))
	var out struct {
		Pending []LoginPreviewResponse `json:"pending"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Pending) != 1 {
		t.Fatalf("%v %s", err, w.Body.String())
	}
	if p := out.Pending[0]; p.DevicePlatform != DeviceApple || p.DeviceName != "Ann's iPhone" {
		t.Fatalf("the waiting sign-in does not name its device: %+v", p)
	}
}
