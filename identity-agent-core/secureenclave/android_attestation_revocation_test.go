package secureenclave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testAppPackage = "org.example.agent"

// testAppDigest is the SHA-256 of the app's signing certificate, as declared.
var testAppDigest = bytes.Repeat([]byte{0xA7}, 32)

// The serial numbers of the certificates builtChain makes: the root is 1, the
// intermediate 2 and the leaf 3.
const (
	serialRoot, serialIntermediate, serialLeaf = "1", "2", "3"
)

// statusListJSON is Google's list: the entries of the real list read on
// 2026-11-06 (testdata/android_attestation/status_list_2026-11-06.json, the
// first twenty of 1771) plus any added here as serial -> status.
func statusListJSON(extra ...string) []byte {
	raw, err := os.ReadFile(filepath.Join("testdata", "android_attestation", "status_list_2026-11-06.json"))
	if err != nil {
		panic(err)
	}
	var l struct {
		Entries map[string]map[string]string `json:"entries"`
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		panic(err)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		l.Entries[extra[i]] = map[string]string{"status": extra[i+1], "reason": "KEY_COMPROMISE"}
	}
	out, _ := json.MarshalIndent(l, "", "  ")
	return out
}

// googleStatusListIs makes Google's server answer with body, on a data
// directory of its own, and returns the number of fetches made so far.
func googleStatusListIs(t *testing.T, body []byte) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	return serverAnswers(t, func(context.Context) ([]byte, error) { n.Add(1); return body, nil }, &n)
}

// googleIsUnreachable: every fetch fails, as with no network.
func googleIsUnreachable(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	return serverAnswers(t, func(context.Context) ([]byte, error) {
		n.Add(1)
		return nil, errors.New("dial tcp: network is unreachable")
	}, &n)
}

func serverAnswers(t *testing.T, f func(context.Context) ([]byte, error), n *atomic.Int32) *atomic.Int32 {
	t.Helper()
	prevFetch := fetchStatusList
	statusMu.Lock()
	statusMem, statusMemDir, statusLastTry, statusLastErr = nil, "", time.Time{}, nil
	statusMu.Unlock()
	prevDir := attestationStatusDir()
	DeclareAttestationStatusDir(t.TempDir())
	fetchStatusList = f
	t.Cleanup(func() {
		fetchStatusList = prevFetch
		DeclareAttestationStatusDir(prevDir)
		statusMu.Lock()
		statusMem, statusMemDir, statusLastTry, statusLastErr = nil, "", time.Time{}, nil
		statusMu.Unlock()
	})
	return n
}

// aCopyKeptFor puts a copy of the list on disk as if it were fetched age ago,
// and forgets the one in memory (a core that has just started).
func aCopyKeptFor(t *testing.T, age time.Duration, body []byte) {
	t.Helper()
	l, err := parseStatusList(body, time.Now().Add(-age))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStatusCache(attestationStatusDir(), l); err != nil {
		t.Fatal(err)
	}
	statusMu.Lock()
	statusMem, statusLastTry, statusLastErr = nil, time.Time{}, nil
	statusMu.Unlock()
}

func aProductionPhone(t *testing.T, dev bool) {
	t.Helper()
	usablePhone(t, Capability{Status: Usable, Kind: "android_strongbox"})
	prev := isDevBuild
	isDevBuild = func() bool { return dev }
	t.Cleanup(func() { isDevBuild = prev })
}

func whyRefused(t *testing.T) string {
	t.Helper()
	w := declaredHostSeedWrapper().(hostedSeedWrapper)
	if w.Available() {
		t.Fatal("the key was accepted")
	}
	return w.whyNotAttested()
}

func TestAChainOfCleanCertificatesIsAccepted(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	if !declaredHostSeedWrapper().Available() {
		t.Fatal(whyRefused(t))
	}
}

func TestARevokedLeafIsRefused(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleStatusListIs(t, statusListJSON(serialLeaf, "REVOKED"))
	why := whyRefused(t)
	if !errors.Is(mustErr(t), ErrAttestationRevoked) || !strings.Contains(why, "REVOKED") || !strings.Contains(why, "certificate 0") {
		t.Fatalf("unhelpful or wrong refusal: %s", why)
	}
	dir := t.TempDir()
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err == nil {
		t.Fatal("a seed was stored under a revoked key")
	}
	if _, err := os.Stat(rootSeedPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("a seed file exists: %v", err)
	}
}

func mustErr(t *testing.T) error {
	t.Helper()
	_, err := declaredHostSeedWrapper().(hostedSeedWrapper).attested()
	if err == nil {
		t.Fatal("accepted")
	}
	return err
}

func TestASuspendedIntermediateIsRefused(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestTrustedEnvironment), true)
	googleStatusListIs(t, statusListJSON(serialIntermediate, "SUSPENDED"))
	why := whyRefused(t)
	if !errors.Is(mustErr(t), ErrAttestationRevoked) || !strings.Contains(why, "SUSPENDED") || !strings.Contains(why, "certificate 1") {
		t.Fatalf("unhelpful or wrong refusal: %s", why)
	}
}

// A revoked certificate is refused in a development build too: Google saying a
// key cannot be trusted is not a question of whether a list was reachable.
func TestARevokedCertificateIsRefusedInADevelopmentBuildToo(t *testing.T) {
	aProductionPhone(t, true)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleStatusListIs(t, statusListJSON(serialRoot, "REVOKED"))
	if !errors.Is(mustErr(t), ErrAttestationRevoked) {
		t.Fatal("not refused as revoked")
	}
}

// The list spells serial numbers in lower-case hex with no leading zeros; a
// list that spells one otherwise must not hide a revocation.
func TestSerialNumbersAreMatchedWhateverTheirSpelling(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleStatusListIs(t, statusListJSON("0003", "REVOKED"))
	if !errors.Is(mustErr(t), ErrAttestationRevoked) {
		t.Fatal("a zero-padded serial hid a revocation")
	}
}

func TestStaleCopyInProductionIsRefusedWithAClearReason(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleIsUnreachable(t)
	aCopyKeptFor(t, 8*24*time.Hour, statusListJSON())
	why := whyRefused(t)
	for _, want := range []string{"revocation list", "could not be fetched", "older than 7 days", "production build"} {
		if !strings.Contains(why, want) {
			t.Fatalf("the reason does not say %q: %s", want, why)
		}
	}
	if !errors.Is(mustErr(t), ErrNoStatusList) {
		t.Fatal("not the no-list refusal")
	}
	if ok, refusal := RootKeyPermittedHere(t.TempDir()); ok || refusal == "" {
		t.Fatalf("the phone may hold a root key: %v %q", ok, refusal)
	}
}

func TestOfflineWithAFreshCopyIsAccepted(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleIsUnreachable(t)
	aCopyKeptFor(t, 6*24*time.Hour, statusListJSON())
	if !declaredHostSeedWrapper().Available() {
		t.Fatal(whyRefused(t))
	}
}

func TestOfflineACopyThatNamesTheCertificateStillRefuses(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleIsUnreachable(t)
	aCopyKeptFor(t, 24*time.Hour, statusListJSON(serialLeaf, "REVOKED"))
	if !errors.Is(mustErr(t), ErrAttestationRevoked) {
		t.Fatal("the kept copy was not applied")
	}
}

func TestNoCopyAtAllInProductionIsRefused(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleIsUnreachable(t)
	why := whyRefused(t)
	if !strings.Contains(why, "no copy has been kept") || !strings.Contains(why, "unreachable") {
		t.Fatalf("reason: %s", why)
	}
}

// A development build may found with no list, and the seed file says it was not checked.
func TestNoListInDevelopmentIsAllowedAndFlagged(t *testing.T) {
	aProductionPhone(t, true)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleIsUnreachable(t)
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	p, _, why, err := RootSeedProtection(dir)
	if err != nil || p != ProtectionHardwareWrapped || !strings.Contains(why, "NOT checked against Google's revocation list") {
		t.Fatalf("protection %q, flag %q (%v)", p, why, err)
	}
	f, err := declaredHostSeedWrapper().(hostedSeedWrapper).attested()
	if err != nil || f.RevocationNote == "" {
		t.Fatalf("the facts do not carry the flag: %v", err)
	}
}

// A checked chain carries no flag.
func TestACheckedChainCarriesNoFlag(t *testing.T) {
	aProductionPhone(t, true)
	theApp(t, aKeyIn(attestStrongBox), true)
	r := UseSeedWrapper(declaredHostSeedWrapper())
	defer r()
	dir := t.TempDir()
	if err := StoreDeviceLocalSeed(dir, theSeed()); err != nil {
		t.Fatal(err)
	}
	if _, _, why, _ := RootSeedProtection(dir); why != "" {
		t.Fatalf("flag on a checked chain: %q", why)
	}
}

// The list is not fetched for each question: many checks, one fetch. A failed
// fetch is not repeated at once either.
func TestTheListIsFetchedOnceNotPerCheck(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	fetches := googleStatusListIs(t, statusListJSON())
	for i := 0; i < 20; i++ {
		if !declaredHostSeedWrapper().Available() {
			t.Fatal(whyRefused(t))
		}
	}
	if n := fetches.Load(); n != 1 {
		t.Fatalf("%d fetches for 20 checks", n)
	}

	fails := googleIsUnreachable(t)
	for i := 0; i < 20; i++ {
		declaredHostSeedWrapper().Available()
	}
	if n := fails.Load(); n != 1 {
		t.Fatalf("%d fetches of an unreachable server for 20 checks", n)
	}
}

// A day on, an online core refreshes; the copy on disk records when.
func TestTheCopyIsKeptWithItsFetchTimeAndRefreshedAfterADay(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	fetches := googleStatusListIs(t, statusListJSON())
	if !declaredHostSeedWrapper().Available() {
		t.Fatal(whyRefused(t))
	}
	p := statusCachePath(attestationStatusDir())
	st, err := os.Stat(p)
	if err != nil || (!isWindowsLike() && st.Mode().Perm() != 0o600) {
		t.Fatalf("copy on disk: %v %v", st, err)
	}
	l := readStatusCache(attestationStatusDir())
	if l == nil || time.Since(l.Fetched) > time.Minute || len(l.Entries) < 20 {
		t.Fatalf("copy: %+v", l)
	}
	real := attestationClock
	attestationClock = func() time.Time { return time.Now().Add(25 * time.Hour) }
	t.Cleanup(func() { attestationClock = real })
	if !declaredHostSeedWrapper().Available() {
		t.Fatal(whyRefused(t))
	}
	if fetches.Load() != 2 {
		t.Fatalf("%d fetches after a day", fetches.Load())
	}
}

func isWindowsLike() bool { return os.PathSeparator == '\\' }

// Whatever is not Google's list is no list: an error page is not "nothing revoked".
func TestSomethingThatIsNotTheListIsNotTakenForIt(t *testing.T) {
	for name, body := range map[string]string{
		"html":            "<html>Sign in to the network</html>",
		"empty":           "",
		"no entries":      `{"other": {}}`,
		"bad serial":      `{"entries": {"not hex": {"status": "REVOKED"}}}`,
		"entry no status": `{"entries": {"abc": {}}}`,
		"truncated":       `{"entries": {"abc": {"status": "REVO`,
	} {
		if _, err := parseStatusList([]byte(body), time.Now()); err == nil {
			t.Errorf("%s was accepted as the list", name)
		}
	}
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleStatusListIs(t, []byte("<html>captive portal</html>"))
	if !errors.Is(mustErr(t), ErrNoStatusList) {
		t.Fatal("a captive portal's page counted as a list")
	}
	if _, err := os.Stat(statusCachePath(attestationStatusDir())); !os.IsNotExist(err) {
		t.Fatal("a bad page was kept as the list")
	}
}

func TestACorruptOrFutureCopyOnDiskIsNotUsed(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	googleIsUnreachable(t)
	p := statusCachePath(attestationStatusDir())
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte(`{"fetched":"2026-11-06T00:00:00Z","entries":{"zz":{"status":"x"}}}`), 0o600)
	if declaredHostSeedWrapper().Available() {
		t.Fatal("a corrupt copy was used")
	}
	aCopyKeptFor(t, -48*time.Hour, statusListJSON()) // "fetched" two days from now
	if declaredHostSeedWrapper().Available() {
		t.Fatal("a copy from the future was used")
	}
}

// What is sent: one GET of the whole list, nothing that identifies the phone.
func TestTheRequestCarriesNothingAboutThePhone(t *testing.T) {
	var got *http.Request
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Write(statusListJSON())
	}))
	defer srv.Close()
	c := srv.Client()
	c.CheckRedirect = statusHTTPClient.CheckRedirect
	body, err := fetchStatusListFrom(context.Background(), c, srv.URL+"/attestation/status")
	if err != nil || !bytes.Contains(body, []byte("entries")) {
		t.Fatalf("fetch: %v", err)
	}
	if got.Method != http.MethodGet || got.URL.RawQuery != "" || got.ContentLength > 0 {
		t.Fatalf("request: %s %s", got.Method, got.URL)
	}
	for k := range got.Header {
		switch k {
		case "Accept-Encoding":
		default:
			t.Errorf("header %s was sent: %v", k, got.Header[k])
		}
	}
	if got.Header.Get("User-Agent") != "" || got.Header.Get("Cookie") != "" || got.Header.Get("Authorization") != "" {
		t.Fatal("identifying headers sent")
	}
}

func TestARedirectOrErrorAnswerIsNotAList(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := srv.Client()
	c.CheckRedirect = statusHTTPClient.CheckRedirect
	for _, p := range []string{"/moved", "/broken"} {
		if _, err := fetchStatusListFrom(context.Background(), c, srv.URL+p); err == nil {
			t.Errorf("%s answered as a list", p)
		}
	}
}

// ---- the app the key was made for

func TestAKeyMadeForAnotherAppIsRefused(t *testing.T) {
	aProductionPhone(t, false)
	other := bytes.Repeat([]byte{0x11}, 32)
	for name, c := range map[string]struct {
		mod  func(*chainSpec)
		want string
	}{
		"another package":          {func(s *chainSpec) { s.appPackage = "org.evil.agent" }, "org.evil.agent"},
		"another signing key":      {func(s *chainSpec) { s.appDigests = [][]byte{other} }, "does not declare"},
		"one of two signers wrong": {func(s *chainSpec) { s.appDigests = [][]byte{testAppDigest, other} }, "does not declare"},
		"no application id":        {func(s *chainSpec) { s.appPackage = "" }, "does not say which app"},
		"no signer at all":         {func(s *chainSpec) { s.appDigests = nil }, "no signing certificate"},
	} {
		t.Run(name, func(t *testing.T) {
			s := aKeyIn(attestStrongBox)
			c.mod(&s)
			theApp(t, s, true)
			if why := whyRefused(t); !strings.Contains(why, c.want) {
				t.Fatalf("reason: %s", why)
			}
		})
	}
}

func TestAnAppThatDeclaredNothingIsRefused(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	ClearAppIdentity()
	if why := whyRefused(t); !strings.Contains(why, "has not declared") {
		t.Fatalf("reason: %s", why)
	}
}

// An app may list its old and new signing certificates; the key's must be among them.
func TestAnAppMayDeclareSeveralSigningCertificates(t *testing.T) {
	aProductionPhone(t, false)
	theApp(t, aKeyIn(attestStrongBox), true)
	other := bytes.Repeat([]byte{0x22}, 32)
	if err := DeclareAppIdentity(testAppPackage, [][]byte{other, testAppDigest}); err != nil {
		t.Fatal(err)
	}
	if !declaredHostSeedWrapper().Available() {
		t.Fatal(whyRefused(t))
	}
	if err := DeclareAppIdentity(testAppPackage, [][]byte{other}); err != nil {
		t.Fatal(err)
	}
	if declaredHostSeedWrapper().Available() {
		t.Fatal("accepted with a certificate that is not the app's")
	}
}

func TestAnAppIdentityMustBeCompleteAndWellFormed(t *testing.T) {
	defer ClearAppIdentity()
	for name, f := range map[string]func() error{
		"no package":   func() error { return DeclareAppIdentity("", [][]byte{testAppDigest}) },
		"no digests":   func() error { return DeclareAppIdentity("a.b", nil) },
		"short digest": func() error { return DeclareAppIdentity("a.b", [][]byte{{1, 2}}) },
	} {
		if f() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	d, err := ParseSignerDigests("A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7:A7, " +
		strings.Repeat("a7", 32))
	if err != nil || len(d) != 2 || !bytes.Equal(d[0], testAppDigest) || !bytes.Equal(d[1], testAppDigest) {
		t.Fatalf("%v %v", d, err)
	}
	if _, err := ParseSignerDigests("xyz"); err == nil {
		t.Fatal("non-hex accepted")
	}
}
