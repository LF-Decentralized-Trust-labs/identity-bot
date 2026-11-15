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
//go:embed tpmroots
var tpmRootFiles embed.FS

func init() { tpmManufacturerRoots = pinnedTPMRoots(tpmRootFiles) }

func pinnedTPMRoots(fsys fs.FS) []*x509.Certificate {
	var roots []*x509.Certificate
	entries, _ := fs.ReadDir(fsys, "tpmroots")
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		raw, err := fs.ReadFile(fsys, "tpmroots/"+e.Name())
		if err != nil {
			panic("tpmroots/" + e.Name() + ": " + err.Error())
		}
		b, _ := pem.Decode(raw)
		if b == nil {
			panic("tpmroots/" + e.Name() + " is not PEM")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			panic("tpmroots/" + e.Name() + ": " + err.Error())
		}
		roots = append(roots, c)
	}
	return roots
}
