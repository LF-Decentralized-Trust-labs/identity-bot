package secureenclave

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"identity-agent-core/tpmcert"
	"io/fs"
	"strings"
	"sync"
)

// The roots are the PEM files committed in tpmroots: Microsoft's trusted TPM root list,
// of which tools/tpmroots keeps only what it can classify as a physical TPM chip's
// (tpmroots/README.md). The list is read once, when a TPM's evidence is first checked
// (loadTPMPins), never as the program starts.
//
//go:embed tpmroots tpmintermediates tpmvirtual tpmlenient
var tpmRootFiles embed.FS

// tpmManufacturerIssuers are the issuers of the same package: certificates a chain
// may pass through on its way to a pinned root, so a front end need not send them.
// They are never trust anchors.
var tpmManufacturerIssuers []*x509.Certificate

// tpmVirtualIssuers are issuers of the same package that stand for Microsoft's own software
// TPM (Hyper-V, Azure). They are trusted only for an owner who opted in to virtual TPMs (virtual_tpm_keys), and the proof then says its class is virtual.
var tpmVirtualIssuers []*x509.Certificate

// tpmLenientIssuers are issuers of the same package, physical ones, that crypto/x509 refuses to
// read (a serial number with redundant leading zeros), kept as bytes and read by tpmcert. They
// are never trust anchors, and are used only where tpm_lenient.go says.
var tpmLenientIssuers []*tpmcert.Certificate

// tpmPinsRead makes loadTPMPins read the package once, however many sign-ins ask at once.
var tpmPinsRead sync.Once

// tpmPinsLoaded is whether that read succeeded.
var tpmPinsLoaded bool

// loadTPMPins reads the pinned package into the variables above, the first time it is called.
// Every path that reads them passes through a function that calls it first: the exported
// checks, and verifyEKCertificateClass, which every chain check goes through.
//
// The four sets are assigned together, only once all of them are read, so a file that does not
// read leaves none of them set rather than some: an empty issuer set beside a full root set
// would weaken the checks. Such a file panics here, on the first check and on every one after,
// as it would have stopped the program had it been read at start.
//
// Reading it parses some two and a half thousand certificates, tens of milliseconds and 28 MB
// of allocation. Done in init, every start of the binary paid that, and the binary is started
// for far more than checking a TPM: a client of the core runs it once for each key operation
// (keymath), most of them in a row while a person waits, and none of those reads a TPM pin.
// Read here, the package is also linked only into a binary that can check a TPM, rather than
// adding its 7 MB to every build of the core.
func loadTPMPins() {
	tpmPinsRead.Do(func() {
		lenient, virtual, roots, issuers := readTPMPins(tpmRootFiles)
		tpmLenientIssuers, tpmVirtualIssuers, tpmManufacturerRoots, tpmManufacturerIssuers = lenient, virtual, roots, issuers
		tpmPinsLoaded = true
	})
	if !tpmPinsLoaded {
		panic("the pinned TPM package could not be read")
	}
}

// readTPMPins reads the four sets of the pinned package in fsys, or panics naming the file
// that does not read.
func readTPMPins(fsys fs.FS) (lenient []*tpmcert.Certificate, virtual, roots, issuers []*x509.Certificate) {
	return pinnedLenientTPMCerts(fsys, "tpmlenient"), pinnedTPMCerts(fsys, "tpmvirtual"),
		pinnedTPMCerts(fsys, "tpmroots"), pinnedTPMCerts(fsys, "tpmintermediates")
}

func pinnedTPMRoots(fsys fs.FS) []*x509.Certificate { return pinnedTPMCerts(fsys, "tpmroots") }

func pinnedTPMCerts(fsys fs.FS, dir string) []*x509.Certificate {
	var roots []*x509.Certificate
	entries, _ := fs.ReadDir(fsys, dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			panic(dir + "/" + e.Name() + ": " + err.Error())
		}
		b, _ := pem.Decode(raw)
		if b == nil {
			panic(dir + "/" + e.Name() + " is not PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			panic(dir + "/" + e.Name() + ": " + err.Error())
		}
		roots = append(roots, c)
	}
	return roots
}

func pinnedLenientTPMCerts(fsys fs.FS, dir string) []*tpmcert.Certificate {
	var out []*tpmcert.Certificate
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		panic(dir + ": " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			panic(dir + "/" + e.Name() + ": " + err.Error())
		}
		b, _ := pem.Decode(raw)
		if b == nil {
			panic(dir + "/" + e.Name() + " is not PEM")
		}
		// A lenient issuer is pinned by the SHA-256 of its bytes, which names its file.
		if h := sha256.Sum256(b.Bytes); hex.EncodeToString(h[:])+".pem" != e.Name() {
			panic(dir + "/" + e.Name() + " is not the certificate it is named for")
		}
		c, err := tpmcert.Parse(b.Bytes)
		if err != nil {
			panic(dir + "/" + e.Name() + ": " + err.Error())
		}
		out = append(out, c)
	}
	return out
}
