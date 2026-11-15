package secureenclave

import (
	"crypto/x509"
	"embed"
	"encoding/pem"
	"io/fs"
	"strings"
)

// The roots are the PEM files committed in tpmroots, and none is pinned until the
// owner says whom to trust (tpmroots/README.md). The list is read once.
//
//go:embed tpmroots tpmintermediates
var tpmRootFiles embed.FS

// tpmManufacturerIssuers are the issuers of the same package: certificates a chain
// may pass through on its way to a pinned root, so a front end need not send them.
// They are never trust anchors.
var tpmManufacturerIssuers []*x509.Certificate

func init() {
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
