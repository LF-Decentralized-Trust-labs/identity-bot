package secureenclave

import (
	"crypto/x509"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/fstest"
)

const askWhetherInitReadTheTPMPins = "SECUREENCLAVE_TEST_REPORT_TPM_PINS_AT_START"

// reportWhetherInitReadTheTPMPins, in the copy of this test binary the test below starts,
// says whether anything had read the pinned TPM package before main ran, and ends it.
func reportWhetherInitReadTheTPMPins() {
	if os.Getenv(askWhetherInitReadTheTPMPins) != "1" {
		return
	}
	n := len(tpmManufacturerRoots) + len(tpmManufacturerIssuers) + len(tpmVirtualIssuers) + len(tpmLenientIssuers)
	fmt.Printf("pinned TPM certificates read at start: %d\n", n)
	if n != 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// The core binary is started for far more than checking a TPM: a client of the core runs it
// once for each key operation. Parsing the pinned package (some two and a half thousand
// certificates) at start made every one of those runs pay for it, which slowed every key
// operation and the tests that make them. It is read when a TPM's evidence is first checked
// instead.
func TestTheTPMPinsAreNotReadAsTheProgramStarts(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), askWhetherInitReadTheTPMPins+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the pinned TPM package was read before any TPM was checked: %s(%v)", out, err)
	}
	// The run must have answered, not merely run no tests.
	if !strings.Contains(string(out), "pinned TPM certificates read at start: 0\n") {
		t.Fatalf("the test binary did not say what it read at start: %q", out)
	}
}

// A package with a file that does not read sets none of the four sets: a full root set beside an
// empty issuer set would weaken the checks.
func TestABadPinnedFileSetsNoneOfThePins(t *testing.T) {
	good, err := fs.ReadFile(tpmRootFiles, "tpmroots/"+firstPEM(t, "tpmroots"))
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"tpmroots/a.pem":         {Data: good},
		"tpmintermediates/b.pem": {Data: []byte("not a certificate")},
	}
	var roots []*x509.Certificate
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("a file that is not a certificate was read as one")
			}
		}()
		_, _, roots, _ = readTPMPins(fsys)
	}()
	if roots != nil {
		t.Fatal("the roots were set though an issuer file did not read")
	}
}

func firstPEM(t *testing.T, dir string) string {
	entries, err := fs.ReadDir(tpmRootFiles, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".pem") {
			return e.Name()
		}
	}
	t.Fatalf("no PEM file in %s", dir)
	return ""
}

// What is read on first use is the whole package: the check above must not pass by reading
// nothing at all.
func TestTheTPMPinsAreReadWhenATPMIsChecked(t *testing.T) {
	loadTPMPins()
	if len(tpmManufacturerRoots) == 0 || len(tpmManufacturerIssuers) == 0 || len(tpmVirtualIssuers) == 0 || len(tpmLenientIssuers) == 0 {
		t.Fatalf("pins read: %d roots, %d issuers, %d virtual, %d lenient",
			len(tpmManufacturerRoots), len(tpmManufacturerIssuers), len(tpmVirtualIssuers), len(tpmLenientIssuers))
	}
}
