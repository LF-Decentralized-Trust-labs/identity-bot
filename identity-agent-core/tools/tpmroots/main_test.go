package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		maker, cn string
		root      bool
		want      string
	}{
		{"Infineon", "IFX-KeyId-1", false, classPhysical},
		{"AMD", "Microsoft Pluton Root CA 2021", true, classPhysical},
		{"Microsoft", "Microsoft TPM Root Certificate Authority 2014", true, classPhysical},
		{"Microsoft", "WUS-IFX-KEYID-DA20", false, classPhysical},
		{"Microsoft", "NCU-ntc-keyid-e151", false, classPhysical},
		{"Microsoft", "MSFT-KEYID-1565", false, classVirtual},
		{"Microsoft", "EUS-msft-keyid-1565", false, classVirtual},
		{"Microsoft", "MSFT-KEYID-1565-V2", false, classVirtual},
		{"Microsoft", "WUS-WEC-NAMEID-19BC", false, classUnclassified}, // a vendor id not known: not trusted
		{"Microsoft", "SEA-IFX-KEYID-1", false, classPhysical},         // a region not seen yet still reads its vendor id
		{"Microsoft", "SEA-MSFT-KEYID-1", false, classVirtual},
		{"Microsoft", "MSFT-IFX-KEYID-1", false, classUnclassified}, // two vendor ids: not a name Microsoft uses
		{"Microsoft", "Something Else CA", false, classUnclassified},
		{"Microsoft", "", false, classUnclassified},
	} {
		if got := classify(c.maker, c.cn, c.root); got != c.want {
			t.Errorf("classify(%s, %q) = %s, want %s", c.maker, c.cn, got, c.want)
		}
	}
}

// A PEM file whose lines end in a bare carriage return (the Qualcomm provisioning issuer of the
// Glymur family is one) is a certificate, not a skipped file.
func TestDerOfReadsPEMWithBareCarriageReturns(t *testing.T) {
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for name, in := range map[string]string{
		"lf":   p,
		"crlf": strings.ReplaceAll(p, "\n", "\r\n"),
		"cr":   strings.ReplaceAll(p, "\n", "\r"),
	} {
		if got := derOf([]byte(in)); !bytes.Equal(got, der) {
			t.Errorf("%s: got %x", name, got)
		}
	}
	if got := derOf(der); !bytes.Equal(got, der) {
		t.Errorf("DER passed through as %x", got)
	}
}

// An issuer whose serial number crypto/x509 refuses is read by tpmcert, in an IntermediateCA
// folder only: a trust anchor is always read strictly.
func TestAnIssuerGoRefusesIsReadLeniently(t *testing.T) {
	files, _ := filepath.Glob("../../secureenclave/tpmlenient/*.pem")
	if len(files) == 0 {
		t.Fatal("no pinned lenient issuers to try")
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		der := derOf(raw)
		if _, err := x509.ParseCertificate(der); err == nil {
			t.Fatalf("%s is readable by crypto/x509", f)
		}
		c, lenient, err := readCertificate(der, "IntermediateCA")
		if err != nil || !lenient || !strings.HasPrefix(c.CN, "STM ") {
			t.Errorf("%s: %v %v %+v", f, err, lenient, c)
		}
		if _, _, err := readCertificate(der, "RootCA"); err == nil {
			t.Errorf("%s was read as a root", f)
		}
	}
}
