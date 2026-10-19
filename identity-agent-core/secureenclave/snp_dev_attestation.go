package secureenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
)

// A development attestation root, for a dev box that has no sealed hardware.
//
// A production black box is a sealed VM that proves itself with a real SEV-SNP
// report, and a verifier trusts it only after chaining the report's signature to
// AMD's root (see amd_chain.go). A software-only development machine cannot
// produce one, so it could never be adopted through that flow at all — which is
// exactly the machine developer mode has to run on.
//
// The answer is the same shape as every other dev/prod split in this system: a
// SEPARATE TRUST ROOT. A development build signs its report with a development
// attestation key and a development verifier trusts THAT key; a production build
// trusts only AMD and so rejects a development report outright. The adopt path is
// otherwise unchanged — parse, check the binding, refuse a debug report unless
// this is a dev build, check the measurement, then verify. Only what "verify"
// trusts differs, which is the one thing that has to.
//
// TWO THINGS KEEP A DEVELOPMENT REPORT OUT OF PRODUCTION, either sufficient:
//   - It carries the POLICY debug bit, which a production verifier refuses before
//     it ever looks at a signature (DebugReportRefused).
//   - Its signature chains to the development key, not to AMD, so a production
//     verifier — which fetches the per-chip certificate from AMD's service and
//     has never heard of this key — cannot verify it.
//
// The development key is derived from a compiled-in constant rather than stored,
// so no private-key material lives in the repository and every development build
// derives the same key (the box that signs and the agent that verifies agree
// without exchanging anything). It is worthless in production: nothing there
// trusts it, and a report it signs announces itself as debug.

// devAttestationSeed is the one constant the development attestation key derives
// from. Changing it rotates the development root; it has no meaning in
// production, where this key is never trusted.
const devAttestationSeed = "IA-DEV-ATTESTATION-ROOT-V1"

// devChipIDMarker fills CHIP_ID on a development report. It must be non-zero
// (ParseSNPReport refuses an all-zero chip id) and is deliberately legible, so a
// development report is recognisable as one on sight.
var devChipIDMarker = []byte("GRAPE-DEVELOPMENT-ATTESTATION-NOT-REAL-HARDWARE-DO-NOT-TRUST-0000")

// devAttestationKey derives the development attestation signing key.
//
// The scalar is reduced from a hash directly rather than by rejection sampling,
// so the key is identical across Go toolchains and therefore identical in every
// development build — the property the box signing a report and the agent
// verifying it both rely on.
func devAttestationKey() *ecdsa.PrivateKey {
	curve := elliptic.P384()
	h := sha512.Sum512([]byte(devAttestationSeed))
	n := curve.Params().N
	d := new(big.Int).SetBytes(h[:48]) // 384 bits of the hash
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1)) // d in [1, n-1]
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return priv
}

// devMeasurement is the fixed launch measurement a development report carries,
// and the one a development build adds to its accepted-measurements allowlist, so
// the two always agree. Derived from a constant for the same reason the key is:
// no fixture to keep in sync.
var devMeasurement = func() []byte {
	h := sha512.Sum512([]byte("IA-DEV-LAUNCH-MEASUREMENT-V1"))
	out := make([]byte, MeasurementSize)
	copy(out, h[:MeasurementSize])
	return out
}()

// DevMeasurement returns the development launch measurement (a fresh copy). A
// development build adds it to what it will adopt; production never carries it.
func DevMeasurement() []byte { return append([]byte(nil), devMeasurement...) }

// DevAttestationReport is a development report bound to value, launched at the
// development measurement. A development build offers this where real hardware
// would offer a genuine report.
func DevAttestationReport(value string) ([]byte, error) {
	return GenerateDevSNPReport(value, devMeasurement)
}

// GenerateDevSNPReport builds a development attestation report bound to value and
// launched at measurement, signed by the development attestation key.
//
// The report is the real 1184-byte SEV-SNP layout — a production verifier can
// parse and inspect it exactly as it would a genuine one — but it carries the
// debug bit and the development chip-id marker and is signed by the development
// key, so production refuses it. Only a development build calls this.
func GenerateDevSNPReport(value string, measurement []byte) ([]byte, error) {
	if len(measurement) != MeasurementSize {
		return nil, fmt.Errorf("measurement is %d bytes, want %d", len(measurement), MeasurementSize)
	}
	reportData := BindReportData(value)

	report := make([]byte, ReportSize)
	// POLICY with the debug bit set, so a production verifier refuses it up front.
	binary.LittleEndian.PutUint64(report[offPolicy:offPolicy+8], policyDebugBit)
	// SIGNER_INFO 0 is a VCEK-signed report; it must not read as signerNone (7),
	// or ParseSNPReport rejects it as unsigned before anything else runs.
	binary.LittleEndian.PutUint32(report[offSignerInfo:offSignerInfo+4], 0)
	copy(report[offReportData:offReportData+ReportDataSize], reportData)
	copy(report[offMeasurement:offMeasurement+MeasurementSize], measurement)
	copy(report[offChipID:offChipID+ChipIDSize], devChipIDMarker)
	// A plausible REPORTED_TCB; unused by the development verifier, present so the
	// report is well-formed.
	binary.LittleEndian.PutUint64(report[offReportedTCB:offReportedTCB+8], 0x0900000000001515)

	digest := sha512.Sum384(report[:reportSignedLength])
	r, s, err := ecdsa.Sign(rand.Reader, devAttestationKey(), digest[:])
	if err != nil {
		return nil, fmt.Errorf("could not sign the development attestation report: %w", err)
	}
	// r then s, each a fixed 72-byte LITTLE-endian field — the layout
	// reportSignature reads back. Big-endian here would verify against nothing.
	putReportComponentLE(report[reportSignatureOffset:reportSignatureOffset+ecdsaComponentLength], r)
	putReportComponentLE(report[reportSignatureOffset+ecdsaComponentLength:reportSignatureOffset+2*ecdsaComponentLength], s)
	return report, nil
}

// VerifyDevSNPReport reports nil when report was signed by the development
// attestation key. It is the development build's stand-in for the AMD chain
// check: the only step whose trust root differs between dev and prod.
//
// It intentionally does NOT accept a report unless the signature is the
// development key's — a report signed by anything else (a real AMD part, a
// stranger's key) does not verify here, exactly as a development report does not
// verify against AMD in production.
func VerifyDevSNPReport(report []byte) error {
	if len(report) < ReportSize {
		return fmt.Errorf("report is %d bytes, an SNP report is %d", len(report), ReportSize)
	}
	r, s := reportSignature(report)
	digest := sha512.Sum384(report[:reportSignedLength])
	if !ecdsa.Verify(&devAttestationKey().PublicKey, digest[:], r, s) {
		return fmt.Errorf("this report was not signed by the development attestation key, " +
			"so a development build will not accept it as a development box")
	}
	return nil
}

// putReportComponentLE writes a signature component into a fixed field as
// little-endian, zero-padded — the inverse of beFromLE in amd_chain.go.
func putReportComponentLE(dst []byte, v *big.Int) {
	be := v.Bytes() // big-endian, minimal length
	for i := 0; i < len(be) && i < len(dst); i++ {
		dst[i] = be[len(be)-1-i]
	}
}
