package secureenclave

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Android key attestation: where does this key live?
//
// The Keystore is a Java API, so the app creates the key and the core cannot
// look at it. Left alone, the app would simply say "StrongBox" and the core
// would believe it. Android lets a key prove where it lives: when a key is
// generated with an attestation challenge, the hardware that holds it signs a
// certificate for the key's public half, and the certificate carries a
// KeyDescription extension that says which hardware (software, TEE or
// StrongBox) made and holds it. The chain above that certificate ends at a
// Google root. This file checks that chain and reads that extension; nothing
// the app says is believed beyond it.
//
// Facts established against Google's published samples (android/keyattestation
// testdata, Apache-2.0; the real chains are in testdata/android_attestation/)
// rather than against the documentation:
//
//   - Only asymmetric keys can be attested, which is why the seed is wrapped
//     under an RSA key and not an AES key (see seedwrap_host.go).
//   - The roots are pinned by their PUBLIC KEY, not by certificate. Google has
//     reissued the RSA root's certificate three times (2016, 2019 and 2022)
//     with the same key and the same serial number, and devices in the field
//     chain to each of them.
//   - The certificates in a chain are short lived (a Pixel's StrongBox chain
//     was valid for about a month), so checking them against today's date
//     would refuse a perfectly good key a month after it was made. They are
//     checked at the moment the key was created, which the leaf records.
//   - A bootloader-unlocked phone attests honestly, with an unverified boot
//     state. Hardware holds the key all the same, so the boot state is
//     reported and does not refuse.

// Security levels in a KeyDescription.
const (
	attestSoftware           = 0
	attestTrustedEnvironment = 1
	attestStrongBox          = 2
)

// Keymaster tags used here (the Android key attestation schema).
const (
	kmTagPurpose        = 1
	kmTagAlgorithm      = 2
	kmTagKeySize        = 3
	kmTagDigest         = 5
	kmTagPadding        = 6
	kmTagNoAuthRequired = 503
	kmTagUnlockedDevice = 509
	kmTagUserAuthType   = 504
	kmTagCreationTime   = 701
	kmTagOrigin         = 702
	kmTagRootOfTrust    = 704
)

const (
	kmPurposeDecrypt = 1
	kmDigestSHA256   = 4
	kmPaddingOAEP    = 2
	kmAlgorithmRSA   = 1
	kmOriginGen      = 0
)

var oidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// googleAttestationRoots are SHA-256 hashes of the DER SubjectPublicKeyInfo of
// the roots Google publishes at https://android.googleapis.com/attestation/root
// (read 2026-11-06): the RSA root and the ECDSA P-384 root ("Key Attestation
// CA1", 2025). A hash of the key is pinned, not a certificate, for the reason
// above.
var googleAttestationRoots = [][sha256.Size]byte{
	mustHash32("feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae"),
	mustHash32("3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"),
}

func mustHash32(s string) (h [sha256.Size]byte) {
	if len(s) != 2*sha256.Size {
		panic("bad pinned root")
	}
	for i := 0; i < sha256.Size; i++ {
		var b byte
		if _, err := fmt.Sscanf(s[2*i:2*i+2], "%02x", &b); err != nil {
			panic(err)
		}
		h[i] = b
	}
	return h
}

// AndroidKeyFacts is what a verified attestation chain says about a key.
type AndroidKeyFacts struct {
	// Level is where the key was generated and is held: attestStrongBox or
	// attestTrustedEnvironment. A key in software is refused before this exists.
	Level int
	// Challenge is the challenge the app put in the key request.
	Challenge []byte
	// Created is when the key was made, from the leaf (zero if it did not say).
	Created time.Time
	// PublicKey is the attested key's public half.
	PublicKey *rsa.PublicKey
	// Purposes are the key's purposes, as hardware enforces them.
	Purposes []int
	// Digests and Paddings are the values hardware enforces on the key.
	Digests, Paddings []int
	// NeedsUnlockedDevice is true when the key works only while the phone is unlocked.
	NeedsUnlockedDevice bool
	// NoAuthRequired is true when use needs no person's authentication.
	NoAuthRequired bool
	// Generated is true when the hardware generated the key (it was not imported).
	Generated bool
	// BootState is "verified", "self_signed", "unverified", "failed" or "" when
	// the chain carried no root of trust. DeviceLocked is the bootloader state.
	BootState    string
	DeviceLocked bool
}

// LevelName is "strongbox" or "tee".
func (f AndroidKeyFacts) LevelName() string {
	if f.Level == attestStrongBox {
		return "strongbox"
	}
	return "tee"
}

// ErrNotAttested is every reason a chain does not prove where a key lives. It
// is wrapped, so callers can match it and the message still says which.
var ErrNotAttested = errors.New("the key's attestation does not prove where it lives")

func notAttested(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrNotAttested, fmt.Sprintf(format, a...))
}

// splitChain reads the chain the app hands over: each certificate DER, leaf
// first, each preceded by its length as 4 bytes big-endian. gomobile can pass
// a []byte and not a [][]byte, which is why it is one blob.
func splitChain(blob []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(blob) > 0 {
		if len(blob) < 4 {
			return nil, notAttested("the chain is cut off")
		}
		n := binary.BigEndian.Uint32(blob)
		blob = blob[4:]
		if n == 0 || uint64(n) > uint64(len(blob)) {
			return nil, notAttested("a certificate's length runs past the chain")
		}
		c, err := x509.ParseCertificate(blob[:n])
		if err != nil {
			return nil, notAttested("a certificate does not parse: %v", err)
		}
		out = append(out, c)
		blob = blob[n:]
		if len(out) > 8 {
			return nil, notAttested("the chain is too long")
		}
	}
	if len(out) == 0 {
		return nil, notAttested("no certificates")
	}
	return out, nil
}

// JoinAttestationChain is splitChain's inverse: the form the app sends. Kept
// here so the app and the tests build it one way.
func JoinAttestationChain(ders ...[]byte) []byte {
	var b bytes.Buffer
	for _, d := range ders {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(d)))
		b.Write(l[:])
		b.Write(d)
	}
	return b.Bytes()
}

// VerifyAndroidKeyAttestation checks that blob (see splitChain) is a chain from
// Google's attestation root down to a key, that the key was generated in a TEE
// or StrongBox, and that it was asked for with wantChallenge. It says nothing
// about whether that key suits the seed; seedWrapKeyPolicy does.
func VerifyAndroidKeyAttestation(blob, wantChallenge []byte, now time.Time) (*AndroidKeyFacts, error) {
	return verifyAndroidKeyAttestation(blob, wantChallenge, now, googleAttestationRoots)
}

func verifyAndroidKeyAttestation(blob, wantChallenge []byte, now time.Time, roots [][sha256.Size]byte) (*AndroidKeyFacts, error) {
	chain, err := splitChain(blob)
	if err != nil {
		return nil, err
	}
	if len(chain) < 2 {
		// A key the Keystore made in software has a one-certificate chain, signed
		// by itself. That proves nothing.
		return nil, notAttested("a single certificate is not a chain to a root")
	}
	leaf := chain[0]
	facts, err := readKeyDescription(leaf)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(facts.Challenge, wantChallenge) {
		return nil, notAttested("the challenge is not the one this key was asked for")
	}

	// Each certificate must be signed by the next, and each (but the leaf, whose
	// dates the app sets, and the pinned root, which is trusted by its key) must
	// have been valid when the key was made.
	at := facts.Created
	if at.IsZero() || at.After(now) {
		at = now
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, notAttested("certificate %d is not signed by certificate %d: %v", i, i+1, err)
		}
		if i > 0 && (at.Before(chain[i].NotBefore) || at.After(chain[i].NotAfter)) {
			return nil, notAttested("certificate %d was not valid when the key was made", i)
		}
	}
	root := chain[len(chain)-1]
	h := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	pinned := false
	for _, r := range roots {
		if r == h {
			pinned = true
			break
		}
	}
	if !pinned {
		return nil, notAttested("the chain does not end at a Google attestation root")
	}
	// A root signs itself. Anything else at the end is a chain that was cut short.
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, notAttested("the last certificate is not a self-signed root: %v", err)
	}
	return facts, nil
}

// readKeyDescription reads the attestation extension of a leaf. It does not
// trust the leaf; the caller has the chain checked.
func readKeyDescription(leaf *x509.Certificate) (*AndroidKeyFacts, error) {
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidKeyDescription) {
			ext = e.Value
			break
		}
	}
	if ext == nil {
		return nil, notAttested("the key's certificate has no attestation extension")
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, notAttested("the attested key is not an RSA key")
	}

	var kd struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		TeeEnforced              asn1.RawValue
	}
	rest, err := asn1.Unmarshal(ext, &kd)
	if err != nil || len(rest) != 0 {
		return nil, notAttested("the attestation extension does not parse")
	}
	// Both the attesting hardware and the key's hardware must be the same
	// secure element. An attestation made in software about a hardware key, or
	// the other way, is not the claim this check exists to verify.
	if int(kd.AttestationSecurityLevel) != int(kd.KeymasterSecurityLevel) {
		return nil, notAttested("the attestation and the key are held at different security levels")
	}
	level := int(kd.KeymasterSecurityLevel)
	if level != attestTrustedEnvironment && level != attestStrongBox {
		return nil, notAttested("the key is held in software (level %d)", level)
	}

	hw, err := authList(kd.TeeEnforced)
	if err != nil {
		return nil, err
	}
	sw, err := authList(kd.SoftwareEnforced)
	if err != nil {
		return nil, err
	}

	f := &AndroidKeyFacts{
		Level:     level,
		Challenge: kd.AttestationChallenge,
		PublicKey: pub,
	}
	// The key's properties count only where hardware enforces them. A purpose
	// listed in the software-enforced list is something Android's framework
	// promises and the hardware does not.
	if v, ok := hw[kmTagPurpose]; ok {
		f.Purposes, err = intSet(v)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := hw[kmTagDigest]; ok {
		if f.Digests, err = intSet(v); err != nil {
			return nil, err
		}
	}
	if v, ok := hw[kmTagPadding]; ok {
		if f.Paddings, err = intSet(v); err != nil {
			return nil, err
		}
	}
	_, f.NeedsUnlockedDevice = hw[kmTagUnlockedDevice]
	if v, ok := hw[kmTagAlgorithm]; ok {
		if n, e := intOf(v); e != nil || n != kmAlgorithmRSA {
			return nil, notAttested("the key's algorithm is not RSA")
		}
	} else {
		return nil, notAttested("the hardware did not state the key's algorithm")
	}
	_, f.NoAuthRequired = hw[kmTagNoAuthRequired]
	if _, authTyped := hw[kmTagUserAuthType]; authTyped {
		f.NoAuthRequired = false
	}
	if v, ok := hw[kmTagOrigin]; ok {
		n, e := intOf(v)
		f.Generated = e == nil && n == kmOriginGen
	}
	if v, ok := sw[kmTagCreationTime]; ok {
		if ms, e := intOf(v); e == nil && ms > 0 {
			f.Created = time.UnixMilli(int64(ms))
		}
	} else if v, ok := hw[kmTagCreationTime]; ok {
		if ms, e := intOf(v); e == nil && ms > 0 {
			f.Created = time.UnixMilli(int64(ms))
		}
	}
	if v, ok := hw[kmTagRootOfTrust]; ok {
		f.BootState, f.DeviceLocked = readRootOfTrust(v)
	}
	return f, nil
}

// authList reads an AuthorizationList into tag -> the value inside its
// explicit tag. Tags above 30 use the long form, which encoding/asn1 reads.
func authList(rv asn1.RawValue) (map[int][]byte, error) {
	out := map[int][]byte{}
	if rv.Tag != asn1.TagSequence || rv.Class != asn1.ClassUniversal {
		return nil, notAttested("an authorization list is not a sequence")
	}
	rest := rv.Bytes
	for len(rest) > 0 {
		var item asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &item)
		if err != nil || item.Class != asn1.ClassContextSpecific || !item.IsCompound {
			return nil, notAttested("an authorization list entry does not parse")
		}
		if _, dup := out[item.Tag]; dup {
			// Which of two statements about one property is true? Neither is
			// believed: Keystore never writes the same tag twice.
			return nil, notAttested("an authorization list states tag %d twice", item.Tag)
		}
		out[item.Tag] = item.Bytes
	}
	return out, nil
}

func intOf(b []byte) (int, error) {
	var n int
	rest, err := asn1.Unmarshal(b, &n)
	if err != nil || len(rest) != 0 {
		return 0, errors.New("not an integer")
	}
	return n, nil
}

func intSet(b []byte) ([]int, error) {
	var rv asn1.RawValue
	if rest, err := asn1.Unmarshal(b, &rv); err != nil || len(rest) != 0 || rv.Tag != asn1.TagSet {
		return nil, notAttested("a purpose list is not a set")
	}
	var out []int
	rest := rv.Bytes
	for len(rest) > 0 {
		var n int
		var err error
		rest, err = asn1.Unmarshal(rest, &n)
		if err != nil {
			return nil, notAttested("a purpose list holds a non-integer")
		}
		out = append(out, n)
	}
	return out, nil
}

// readRootOfTrust: RootOfTrust is SEQUENCE { verifiedBootKey OCTET STRING,
// deviceLocked BOOLEAN, verifiedBootState ENUMERATED, ... }.
func readRootOfTrust(b []byte) (state string, locked bool) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(b, &seq); err != nil || seq.Tag != asn1.TagSequence {
		return "", false
	}
	var key asn1.RawValue
	var st asn1.Enumerated
	rest, err := asn1.Unmarshal(seq.Bytes, &key)
	if err == nil {
		rest, err = asn1.Unmarshal(rest, &locked)
	}
	if err == nil {
		_, err = asn1.Unmarshal(rest, &st)
	}
	if err != nil {
		return "", false
	}
	switch int(st) {
	case 0:
		state = "verified"
	case 1:
		state = "self_signed"
	case 2:
		state = "unverified"
	case 3:
		state = "failed"
	}
	return state, locked
}

// seedWrapKeyPolicy is what a key must be, beyond being in hardware, to be the
// key a root seed is wrapped under: made by the hardware (not imported, so no
// one else holds a copy), able to decrypt, usable with nobody present, and big
// enough.
func seedWrapKeyPolicy(f *AndroidKeyFacts) error {
	if !f.Generated {
		return notAttested("the key was imported, not generated in the hardware, so someone else may hold a copy")
	}
	if !hasInt(f.Purposes, kmPurposeDecrypt) {
		return notAttested("the key is not one that decrypts")
	}
	if !hasInt(f.Digests, kmDigestSHA256) || !hasInt(f.Paddings, kmPaddingOAEP) {
		return notAttested("the key is not limited to RSA-OAEP with SHA-256 in the hardware, " +
			"so it may not open what the core seals to it")
	}
	if f.NeedsUnlockedDevice {
		return notAttested("the key works only while the phone is unlocked, and the agent runs with nobody present")
	}
	if !f.NoAuthRequired {
		return notAttested("the key needs a person to authenticate, and the agent runs with nobody present")
	}
	if f.PublicKey.N.BitLen() < 2048 {
		return notAttested("the key is under 2048 bits")
	}
	return nil
}

func hasInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
