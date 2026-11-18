package secureenclave

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"time"

	"identity-agent-core/tpmcert"
)

// lenientIssuer finds, among the pinned issuers crypto/x509 cannot read (tpmLenientIssuers),
// the one that issued leaf, and says who it is. Nil when none did.
//
// crypto/x509 cannot build a chain through a certificate it will not parse, so this does what
// its verifier would, directly: the leaf names the issuer and the issuer's key made its
// signature, the issuer is a CA, and the issuer in turn was signed by a pinned root. Both are
// valid now. The issuer is trusted because its bytes are pinned, as every other pinned issuer
// is, and the signature under a root is checked as well so a pinned file that was not that
// maker's would not pass. These issuers are all physical chips' (the package's maker folders).
func lenientIssuer(leaf *x509.Certificate, roots []*x509.Certificate, now time.Time) *EKIssuer {
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil
	}
	for _, li := range tpmLenientIssuers {
		if !li.IsCA || now.Before(li.NotBefore) || now.After(li.NotAfter) || !bytes.Equal(li.RawSubject, leaf.RawIssuer) {
			continue
		}
		if tpmcert.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature, li.PublicKey) != nil {
			continue
		}
		if !underPinnedRoot(li, roots, now) {
			continue
		}
		h := sha256.Sum256(li.Raw)
		return &EKIssuer{Subject: li.Subject.String(), SHA256: hex.EncodeToString(h[:]), Class: TPMClassPhysical}
	}
	return nil
}

func underPinnedRoot(c *tpmcert.Certificate, roots []*x509.Certificate, now time.Time) bool {
	for _, r := range roots {
		if r.IsCA && !now.Before(r.NotBefore) && !now.After(r.NotAfter) && bytes.Equal(r.RawSubject, c.RawIssuer) &&
			c.CheckSignatureFrom(r.PublicKey) == nil {
			return true
		}
	}
	return false
}
