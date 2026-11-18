// Command tpmroots makes the set of pinned TPM manufacturer roots
// (secureenclave/tpmroots) from the files of Microsoft's TrustedTpm package
// (https://go.microsoft.com/fwlink/?linkid=2097925, a .cab that holds, for each
// maker, a RootCA and an IntermediateCA folder), extracted into one directory.
//
//	go run ./tools/tpmroots -in <extracted dir> -out secureenclave/tpmroots -source <url> -sha256 <of the .cab>
//
// It takes the certificates in each maker's RootCA folder only, drops any that is
// unreadable, and writes one PEM per certificate named by the SHA-256 of its DER,
// with SOURCE.txt saying where they came from. It prints each one's subject and
// expiry so the set can be read before it is committed.
//
// It also classifies every certificate: physical (a chip maker's, or Microsoft's issuers
// of a chip maker's endorsement keys), virtual (an issuer of Microsoft's own TPM, the
// software TPM of a hypervisor), or unclassified. Only physical ones are written to the
// trusted directories; virtual ones go to -virtual so a chain through one is refused by
// name; an unclassified one is written nowhere, because trust is given only to what is
// positively known to be a physical chip's (see classify and SOURCE.txt).
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"identity-agent-core/tpmcert"
)

func main() {
	in := flag.String("in", "", "the extracted TrustedTpm package")
	out := flag.String("out", "", "where to write the roots' PEM files")
	inter := flag.String("intermediates", "", "where to write the issuers' PEM files (each maker's IntermediateCA folder)")
	lenient := flag.String("lenient", "", "where to write the issuers crypto/x509 refuses to read but tpmcert reads (physical ones only; each is pinned by its bytes)")
	virt := flag.String("virtual", "", "where to write the virtual and cloud TPM issuers' PEM files (never trusted; kept so a chain through one is refused by name)")
	source := flag.String("source", "https://go.microsoft.com/fwlink/?linkid=2097925", "where the package was fetched")
	sum := flag.String("sha256", "", "the SHA-256 of the package file, as fetched")
	flag.Parse()
	if *in == "" || *out == "" || *sum == "" {
		fmt.Fprintln(os.Stderr, "usage: tpmroots -in DIR -out DIR -sha256 HEX [-source URL]")
		os.Exit(2)
	}
	var lines []string
	dirs := dirsFor{physical: *out, virtual: *virt, lenient: *lenient}
	lines = append(lines, write(*in, "RootCA", dirs)...)
	if *inter != "" {
		dirs.physical = *inter
		lines = append(lines, write(*in, "IntermediateCA", dirs)...)
	}
	note := fmt.Sprintf("Made by tools/tpmroots on %s from %s\nSHA-256 of the package as fetched: %s\nRoots (trust anchors) and issuers (certificates a chain may pass through) are listed with their maker and class; version.txt of the package said: %s\n\n%s\n", time.Now().UTC().Format("2006-01-02"), *source, *sum, packageDate(*in), classNote)
	for _, l := range lines {
		note += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(*out, "SOURCE.txt"), []byte(note), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%d certificates written; see %s/SOURCE.txt\n", len(lines), *out)
}

func packageDate(in string) string {
	b, err := os.ReadFile(filepath.Join(in, "version.txt"))
	if err != nil {
		return "(no version.txt)"
	}
	for _, l := range strings.Split(string(b), "\n")[1:] {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return "(unreadable)"
}

// The classes. Only classPhysical is trusted.
const (
	classPhysical     = "physical"     // a chip maker's own certificate, or Microsoft's issuer of a chip maker's endorsement keys
	classVirtual      = "virtual"      // an issuer of Microsoft's own TPM: the software TPM of Hyper-V and Azure
	classUnclassified = "unclassified" // nothing shows which; not trusted
)

// classNote is written into SOURCE.txt, with the evidence for the classes.
const classNote = `Classes (what tpm_keys trusts is class physical only):
  physical      Every certificate in a chip maker's own folder (AMD incl. Pluton, Atmel, Infineon,
                Intel, NationZ, Nuvoton, QC, STMicro), and the Microsoft-run issuers under the
                Microsoft root whose name carries a chip maker's TCG vendor id (<region>-<ID>-KEYID-...,
                ID one of AMD ATML IFX INTC INTL NSG NTC NTZ QCOM STM): these re-issue a chip maker's
                endorsement keys for firmware TPMs.
  virtual       Issuers named MSFT-KEYID-...: MSFT is Microsoft's own TPM vendor id, and Microsoft's
                own TPM is the software TPM of Hyper-V and Azure (NIST CMVP certificate 4537 validates
                it as the software library TPMEngUM.dll; Microsoft Q&A, "Root CA for Hyper-V virtual TPM
                Endorsement Key", says this trusted-TPM package covers physical TPMs, not Hyper-V VMs).
                Written to tpmvirtual: never trusted, a chain through one is refused by name.
  unclassified  Anything else (for example the WEC-NameId issuers, a vendor id this tool does not
                know). Written nowhere: a certificate that cannot be classified is not trusted.
  The Microsoft TPM Root Certificate Authority 2014 is a trust anchor shared by both kinds of issuer, so a
  chain is accepted only through a pinned physical issuer under it (secureenclave verifyEKCertificate).
  The package itself names no certificate as virtual or cloud; the virtual class rests on the vendor id
  and the sources above, and is a deliberately narrow reading: when unsure, a certificate is unclassified.

`

// vendorToken reads the vendor id from an issuer's name: an optional region (EUS-, WUS-,
// NCU- today; any word, so a region Microsoft adds later still classifies), the vendor id,
// then KEYID or NAMEID. The class rests on the vendor id, never on the region.
var vendorToken = regexp.MustCompile(`(?i)^(?:([A-Z]+)-)?([A-Z]+)-(?:KEYID|NAMEID)-`)

// physicalVendorIDs are the TCG vendor ids of chip makers whose endorsement keys Microsoft's
// issuers re-issue.
var physicalVendorIDs = map[string]bool{"AMD": true, "ATML": true, "IFX": true, "INTC": true, "INTL": true, "NSG": true, "NTC": true, "NTZ": true, "QCOM": true, "STM": true}

// classify says which kind of TPM a certificate stands for. maker is the package folder it was in.
func classify(maker, subjectCN string, isRoot bool) string {
	if maker != "Microsoft" {
		return classPhysical // the folders of chip makers hold only that maker's certificates
	}
	if isRoot {
		return classPhysical // the anchor; see classNote on how a chain is accepted through it
	}
	m := vendorToken.FindStringSubmatch(subjectCN)
	if m == nil {
		return classUnclassified
	}
	region, id := strings.ToUpper(m[1]), strings.ToUpper(m[2])
	if region == "MSFT" || physicalVendorIDs[region] {
		return classUnclassified // two vendor ids in one name: not a form Microsoft uses, so not read
	}
	switch {
	case id == "MSFT":
		return classVirtual
	case physicalVendorIDs[id]:
		return classPhysical
	}
	return classUnclassified
}

type dirsFor struct{ physical, virtual, lenient string }

// write writes the PEM of every certificate in each maker's folder of this name, to the
// directory of its class.
func write(in, folder string, dirs dirsFor) []string {
	files, _ := filepath.Glob(filepath.Join(in, "*", folder, "*"))
	sort.Strings(files)
	seen := map[string]bool{}
	var lines []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		raw = derOf(raw)
		c, lenientRead, err := readCertificate(raw, folder)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipped %s: %v\n", f, err)
			// A file that is no certificate, or one neither reader accepts, cannot be pinned;
			// it is listed so what is missing is known.
			lines = append(lines, fmt.Sprintf("%s  SKIPPED %s (%v)", folder, filepath.Base(f), err))
			continue
		}
		h := sha256.Sum256(c.Raw)
		id := hex.EncodeToString(h[:])
		if seen[id] {
			continue
		}
		seen[id] = true
		maker := filepath.Base(filepath.Dir(filepath.Dir(f)))
		class := classify(maker, c.CN, folder == "RootCA")
		dir := ""
		switch class {
		case classPhysical:
			dir = dirs.physical
			if lenientRead {
				dir = dirs.lenient
			}
		case classVirtual:
			dir = dirs.virtual
		}
		if dir != "" {
			if err := os.WriteFile(filepath.Join(dir, id+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		note := ""
		if lenientRead {
			note = "  (read by tpmcert: crypto/x509 refuses it)"
		}
		lines = append(lines, fmt.Sprintf("%s  %s  class=%s  %s  expires %s  (%s)%s", folder, id, class, c.Subject, c.NotAfter.Format("2006-01-02"), maker, note))
	}
	return lines
}

// certificate is what write needs of either reader's result.
type certificate struct {
	Raw      []byte
	Subject  fmt.Stringer
	CN       string
	NotAfter time.Time
}

// derOf returns the DER of a certificate file that is DER or PEM. A PEM file whose lines end
// in a bare carriage return (one in the package does) is read as PEM too.
func derOf(raw []byte) []byte {
	if b, _ := pem.Decode(raw); b != nil {
		return b.Bytes
	}
	if bytes.Contains(raw, []byte("-----BEGIN")) {
		if b, _ := pem.Decode(bytes.ReplaceAll(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), []byte("\r"), []byte("\n"))); b != nil {
			return b.Bytes
		}
	}
	return raw
}

// readCertificate reads a certificate with crypto/x509, and failing that, in an
// IntermediateCA folder, with tpmcert (whose reading is the same but for the serial number).
// The second result says which read it. A root is always read strictly: a trust anchor
// is a pinned crypto/x509 certificate.
func readCertificate(der []byte, folder string) (*certificate, bool, error) {
	c, err := x509.ParseCertificate(der)
	if err == nil {
		return &certificate{c.Raw, c.Subject, c.Subject.CommonName, c.NotAfter}, false, nil
	}
	if folder == "RootCA" {
		return nil, false, err
	}
	lc, lerr := tpmcert.Parse(der)
	if lerr != nil {
		return nil, false, err
	}
	return &certificate{lc.Raw, lc.Subject, lc.Subject.CommonName, lc.NotAfter}, true, nil
}
