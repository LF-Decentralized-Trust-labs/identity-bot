package secureenclave

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// The TCG EK Credential Profile names a TPM in its endorsement key certificate's subject
// alternative name, not its subject: the subject is empty, so the SAN is critical (RFC 5280
// §4.2.1.6), and it holds one directoryName whose attributes are the TPM's manufacturer,
// model and version. crypto/x509 reads only DNS, email, IP and URI names, so it leaves such a
// SAN among the leaf's unhandled critical extensions and its verifier refuses every real
// endorsement key certificate. go-attestation accepts the extension for the same reason.
var (
	oidSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTPMModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTPMVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	// The otherNames RFC 4043 and RFC 4108 define for a device's identity, which the TCG
	// profile allows beside the directoryName.
	oidPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}
	oidHardwareModuleName  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}
)

// isTPMOtherName says whether body, the inside of an otherName, is a permanentIdentifier or
// a hardwareModuleName: its type and an explicitly tagged value, and nothing else.
func isTPMOtherName(body []byte) bool {
	var id asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(body, &id)
	if err != nil || !(id.Equal(oidPermanentIdentifier) || id.Equal(oidHardwareModuleName)) {
		return false
	}
	var v asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &v)
	return err == nil && len(rest) == 0 && v.Class == asn1.ClassContextSpecific && v.Tag == 0 && v.IsCompound
}

// acceptTCGSubjectAltName marks the leaf's critical subject alternative name as handled when,
// and only when, it is the TCG form: one directoryName that says the TPM's manufacturer,
// model and version, each once, as a string, with at most a device-identity otherName beside
// it (isTCGDirectoryNameSAN). A critical SAN
// in any other form is refused here, even one crypto/x509 could read (a DNS name beside the
// TPM's name, say), since an endorsement key certificate's critical SAN has no other use.
// Any other critical extension stays unhandled, so the verifier still refuses it.
func acceptTCGSubjectAltName(leaf *x509.Certificate) error {
	var san []byte
	critical, n := false, 0
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSubjectAltName) {
			san, critical = e.Value, e.Critical
			n++
		}
	}
	if n == 0 || !critical {
		return nil
	}
	// crypto/x509 refuses a certificate with a repeated extension, so n > 1 does not reach
	// here; it is checked anyway so the rule does not rest on that.
	if n != 1 || !isTCGDirectoryNameSAN(san) {
		return errTPM("its critical subject alternative name is not the TPM's manufacturer, model and version")
	}
	kept := leaf.UnhandledCriticalExtensions[:0:0]
	for _, o := range leaf.UnhandledCriticalExtensions {
		if !o.Equal(oidSubjectAltName) {
			kept = append(kept, o)
		}
	}
	leaf.UnhandledCriticalExtensions = kept
	return nil
}

// isTCGDirectoryNameSAN says whether value, a GeneralNames, is one directoryName holding
// exactly the TPM manufacturer, model and version attributes, with nothing beside it but the
// otherNames go-attestation also takes there (permanentIdentifier, hardwareModuleName).
func isTCGDirectoryNameSAN(value []byte) bool {
	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(value, &names)
	if err != nil || len(rest) != 0 {
		return false
	}
	var dn *asn1.RawValue
	for i := range names {
		n := &names[i]
		if n.Class != asn1.ClassContextSpecific || !n.IsCompound {
			return false
		}
		switch n.Tag {
		case 4: // directoryName, explicitly tagged because Name is a CHOICE
			if dn != nil {
				return false
			}
			dn = n
		case 0: // otherName
			if !isTPMOtherName(n.Bytes) {
				return false
			}
		default:
			return false
		}
	}
	if dn == nil {
		return false
	}
	var rdns pkix.RDNSequence
	rest, err = asn1.Unmarshal(dn.Bytes, &rdns)
	if err != nil || len(rest) != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, set := range rdns {
		for _, a := range set {
			switch {
			case a.Type.Equal(oidTPMManufacturer), a.Type.Equal(oidTPMModel), a.Type.Equal(oidTPMVersion):
			default:
				return false
			}
			s, ok := a.Value.(string)
			if !ok || s == "" || seen[a.Type.String()] {
				return false
			}
			seen[a.Type.String()] = true
		}
	}
	return len(seen) == 3
}
