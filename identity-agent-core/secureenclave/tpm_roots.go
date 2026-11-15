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
)

// The roots are the PEM files committed in tpmroots: Microsoft's trusted TPM root list,
// of which tools/tpmroots keeps only what it can classify as a physical TPM chip's
// (tpmroots/README.md). The list is read once.
//
//go:embed tpmroots tpmintermediates tpmvirtual tpmlenient
var tpmRootFiles embed.FS

// tpmManufacturerIssuers are the issuers of the same package: certificates a chain
// may pass through on its way to a pinned root, so a front end need not send them.
// They are never trust anchors.
var tpmManufacturerIssuers []*x509.Certificate

// tpmVirtualIssuers are issuers of the same package that stand for Microsoft's own software
// TPM (Hyper-V, Azure). They are never trusted: a chain through one is refused by name.
var tpmVirtualIssuers []*x509.Certificate

// tpmLenientIssuers are issuers of the same package, physical ones, that crypto/x509 refuses to
// read (a serial number with redundant leading zeros), kept as bytes and read by tpmcert. They
// are never trust anchors, and are used only where tpm_lenient.go says.
var tpmLenientIssuers []*tpmcert.Certificate

func init() {
	tpmLenientIssuers = pinnedLenientTPMCerts(tpmRootFiles, "tpmlenient")
	tpmVirtualIssuers = pinnedTPMCerts(tpmRootFiles, "tpmvirtual")
	tpmManufacturerRoots = pinnedTPMCerts(tpmRootFiles, "tpmroots")
	tpmManufacturerIssuers = pinnedTPMCerts(tpmRootFiles, "tpmintermediates")
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
