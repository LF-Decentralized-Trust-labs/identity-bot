package secureenclave

// TPM 2.0 key attestation for an installed app's own signing key.
//
// VerifyTPMKeyCertify checks that a P-256 signing key lives inside a real TPM,
// was generated there, and cannot leave it. It is the TPM counterpart of
// VerifyInstalledAppKeyAttestation (Android) and returns the same facts.
//
// WHAT A TPM DOES NOT PROVE. A TPM vouches for a key and for the TPM; it says
// nothing about which program asked for the key. The result therefore leaves
// AppIDPresent false and fills no AppPackages, AppSigners or AppleAppID. A
// caller that needs to know WHICH app holds the key must get that elsewhere
// (for example an OS-level binding) and must not read the TPM proof as one.
//
// EVIDENCE FORMAT (version 1). One JSON object; every []byte is standard
// base64; every TPM structure is in its TCG wire form (big-endian):
//
//	{
//	  "key_public":         TPM2B_PUBLIC of the app key (size-prefixed TPMT_PUBLIC)
//	  "certify_info":       the TPMS_ATTEST the AK signed (no size prefix), as
//	                        returned by TPM2_Certify in TPM2B_ATTEST.attestationData
//	  "certify_signature":  TPMT_SIGNATURE over certify_info, made by the AK
//	  "ak_public":          TPM2B_PUBLIC of the attestation key (AK)
//	  "ek_cert":            DER of the endorsement key (EK) certificate
//	  "ek_chain":           [DER, ...] issuer certificates of ek_cert, any order
//	  "credential_secret":  the secret the TPM released by TPM2_ActivateCredential
//	}
//
// CHALLENGE AND CREDENTIAL KEY. For each attestation the core picks two random
// values and no other party may choose or know the second:
//
//	challenge     given to the app; it is not a secret.
//	credentialKey kept by the core, NEVER given to the app, the app's back end
//	              or anyone else, and used once.
//
// The credential is what proves the AK shares a TPM with the EK, and that holds
// only while the app cannot compute it. Were it keyed by the challenge (which
// the app holds), or by anything derived from public facts, software could
// make a credential for a genuine EK certificate and an AK of its own, and the
// check would pass the moment a root is pinned. So the credential's key is the
// core's alone and the app learns the credential only from the TPM, by
// TPM2_ActivateCredential on a blob the core made with TPM2_MakeCredential
// (the core's side of that exchange is not built yet, and until it is no
// TPM key can be proved). verifyTPMKeyCertify refuses, in code, a
// credentialKey that is short or is the challenge. Two values derive:
//
//	extraData  = SHA-256("grape-tpm-key-certify-v1" 0x00 || challenge)
//	             the qualifying data the app passes to TPM2_Certify.
//	credential = HMAC-SHA-256(key = credentialKey,
//	                          "grape-tpm-credential-v1" 0x00 ||
//	                          uint16(len(akName)) || akName || ekPublicDER)
//	             where akName is the AK's TPM name (nameAlg || H(TPMT_PUBLIC))
//	             and ekPublicDER is the PKIX encoding of the EK certificate's
//	             public key. The core runs
//	             TPM2_MakeCredential(EK public, akName, credential); the TPM can
//	             only return it from TPM2_ActivateCredential if the AK named is
//	             loaded in the same TPM as the EK. The app puts the result in
//	             credential_secret.
//
// WHY EACH CHECK EXISTS (the list in tpmEndorsementID's comment, made real):
//   - The EK certificate must chain to a manufacturer root we pin. Without it
//     the EK is only "a key some software generated".
//   - The credential check ties the AK to that EK. Without it an attacker
//     presents a genuine EK certificate and signs with an AK from elsewhere.
//   - The AK must be restricted, sign, fixedTPM, fixedParent. A NON-restricted
//     signing key signs attacker-chosen bytes shaped like a certify structure.
//   - The certify structure must carry TPM_GENERATED_VALUE and type CERTIFY
//     (a restricted key will only sign structures the TPM itself generated),
//     our extraData, and the name of exactly the key's public area.
//   - The app key must be fixedTPM and fixedParent (cannot be duplicated or
//     moved), sensitiveDataOrigin (the TPM generated the secret; it was not
//     imported, so nobody else holds a copy), and sign. It must NOT be
//     decrypt (one purpose per key, matching the Android check that limits a
//     key to signing) and NOT restricted: a restricted signing key signs only
//     TPM-produced digests, so it could never sign the sign-in challenge the
//     caller needs, and accepting one would be accepting a key that cannot be
//     the app's signing key.
//
// PINNED ROOTS. tpmManufacturerRoots is EMPTY in this file and verification
// FAILS CLOSED while it is. The real roots (Infineon, STMicroelectronics,
// Nuvoton, Intel PTT, AMD fTPM, Microsoft's virtual-TPM root, ...) must be
// supplied by the vendor-roots process from the manufacturers' published
// certificates; none are invented here.
//
// NOT PROVEN WITHOUT A REAL TPM: see tpm_key_certify_test.go. The structures
// are parsed from the TCG spec, and the tests use synthetic structures built
// by the same layout; no TPM has produced a vector for this code.

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"time"
)

// tpmManufacturerRoots are the TPM manufacturer root certificates an EK
// certificate must chain to. Empty on purpose: verification fails closed until
// the vendor roots are supplied.
var tpmManufacturerRoots []*x509.Certificate

const (
	tpmGeneratedValue  = 0xFF544347
	tpmSTAttestCertify = 0x8017

	tpmAlgRSA    = 0x0001
	tpmAlgSHA256 = 0x000B
	tpmAlgSHA384 = 0x000C
	tpmAlgSHA512 = 0x000D
	tpmAlgNull   = 0x0010
	tpmAlgRSASSA = 0x0014
	tpmAlgRSAPSS = 0x0016
	tpmAlgECDSA  = 0x0018
	tpmAlgECC    = 0x0023
	tpmCurveP256 = 0x0003

	tpmAttrFixedTPM          = 1 << 1
	tpmAttrFixedParent       = 1 << 4
	tpmAttrSensitiveDataOrig = 1 << 5
	tpmAttrRestricted        = 1 << 16
	tpmAttrDecrypt           = 1 << 17
	tpmAttrSign              = 1 << 18

	tpmMaxEvidence = 64 << 10
)

type tpmKeyCertifyEvidence struct {
	KeyPublic        []byte   `json:"key_public"`
	CertifyInfo      []byte   `json:"certify_info"`
	CertifySignature []byte   `json:"certify_signature"`
	AKPublic         []byte   `json:"ak_public"`
	EKCert           []byte   `json:"ek_cert"`
	EKChain          [][]byte `json:"ek_chain"`
	CredentialSecret []byte   `json:"credential_secret"`
}

// tpmCertifyExtraData is the qualifying data TPM2_Certify must have been given.
func tpmCertifyExtraData(challenge []byte) []byte {
	h := sha256.New()
	h.Write([]byte("grape-tpm-key-certify-v1\x00"))
	h.Write(challenge)
	return h.Sum(nil)
}

// tpmCredentialSecret is what the verifier seals to the EK with
// TPM2_MakeCredential; only the TPM holding both EK and the named AK can
// return it.
func tpmCredentialSecret(credentialKey, akName, ekPublicDER []byte) []byte {
	m := hmac.New(sha256.New, credentialKey)
	m.Write([]byte("grape-tpm-credential-v1\x00"))
	m.Write([]byte{byte(len(akName) >> 8), byte(len(akName))})
	m.Write(akName)
	m.Write(ekPublicDER)
	return m.Sum(nil)
}

// VerifyTPMKeyCertify checks TPM evidence (format in the file header) for an
// app key asked for with challenge, against the pinned manufacturer roots.
// It proves the key is a non-exportable signing key generated inside a genuine
// TPM. It does NOT prove which app holds it: AppIDPresent is always false.
func VerifyTPMKeyCertify(evidence, challenge, credentialKey []byte, now time.Time) (*InstalledAppKeyFacts, error) {
	return verifyTPMKeyCertify(evidence, challenge, credentialKey, now, tpmManufacturerRoots)
}

// TPMCredentialKeyLen is the least length of the secret the core keeps for one attestation.
const TPMCredentialKeyLen = 32

func verifyTPMKeyCertify(evidence, challenge, credentialKey []byte, now time.Time, roots []*x509.Certificate) (*InstalledAppKeyFacts, error) {
	if len(roots) == 0 {
		return nil, notAttested("no TPM manufacturer roots are pinned in this build, so no TPM can be trusted")
	}
	if len(challenge) == 0 {
		return nil, notAttested("no challenge to bind the attestation to")
	}
	// The credential's key is the core's secret for this one attestation. A key
	// the app could know (the challenge, or anything derived from public facts)
	// would let software make the credential, so it is refused here, whatever
	// roots are pinned.
	if len(credentialKey) < TPMCredentialKeyLen || bytes.Equal(credentialKey, challenge) {
		return nil, notAttested("the attestation was not issued a secret credential key by the core")
	}
	if len(evidence) == 0 || len(evidence) > tpmMaxEvidence {
		return nil, notAttested("the TPM evidence is empty or too large")
	}
	var ev tpmKeyCertifyEvidence
	dec := json.NewDecoder(bytes.NewReader(evidence))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, notAttested("the TPM evidence is not the expected document: %v", err)
	}
	if dec.More() {
		return nil, notAttested("the TPM evidence has trailing data")
	}

	key, err := parseTPM2BPublic(ev.KeyPublic)
	if err != nil {
		return nil, notAttested("the key's public area: %v", err)
	}
	ak, err := parseTPM2BPublic(ev.AKPublic)
	if err != nil {
		return nil, notAttested("the attestation key's public area: %v", err)
	}

	// The app key.
	if key.typ != tpmAlgECC || key.curve != tpmCurveP256 {
		return nil, notAttested("the key is not a P-256 key")
	}
	if key.attrs&tpmAttrFixedTPM == 0 || key.attrs&tpmAttrFixedParent == 0 {
		return nil, notAttested("the key can be duplicated out of the TPM (not fixedTPM and fixedParent)")
	}
	if key.attrs&tpmAttrSensitiveDataOrig == 0 {
		return nil, notAttested("the key was imported into the TPM, not generated in it, so someone else may hold a copy")
	}
	if key.attrs&tpmAttrSign == 0 || key.attrs&tpmAttrDecrypt != 0 {
		return nil, notAttested("the key is not limited to signing")
	}
	if key.attrs&tpmAttrRestricted != 0 {
		return nil, notAttested("the key is restricted, so it cannot sign the app's own challenges")
	}
	if key.scheme != tpmAlgNull && key.scheme != tpmAlgECDSA {
		return nil, notAttested("the key's signing scheme is not ECDSA")
	}
	keyName, err := key.name()
	if err != nil {
		return nil, notAttested("the key's name: %v", err)
	}
	pub, err := key.ecdsaPublic()
	if err != nil {
		return nil, notAttested("the key: %v", err)
	}

	// The attestation key.
	const akNeeds = tpmAttrRestricted | tpmAttrSign | tpmAttrFixedTPM | tpmAttrFixedParent
	if ak.attrs&akNeeds != akNeeds || ak.attrs&tpmAttrDecrypt != 0 {
		return nil, notAttested("the attestation key is not a restricted, fixedTPM, fixedParent signing key")
	}
	akName, err := ak.name()
	if err != nil {
		return nil, notAttested("the attestation key's name: %v", err)
	}
	if bytes.Equal(akName, keyName) {
		return nil, notAttested("the attestation key and the attested key are the same key")
	}

	// The certify structure and the AK's signature over it.
	att, err := parseTPMSAttestCertify(ev.CertifyInfo)
	if err != nil {
		return nil, notAttested("the certify structure: %v", err)
	}
	if subtle.ConstantTimeCompare(att.extraData, tpmCertifyExtraData(challenge)) != 1 {
		return nil, notAttested("the certify structure was not made for this challenge")
	}
	if !bytes.Equal(att.name, keyName) {
		return nil, notAttested("the certify structure names a different key than the one presented")
	}
	if err := verifyTPMSignature(ak, ev.CertifyInfo, ev.CertifySignature); err != nil {
		return nil, notAttested("the attestation key's signature does not verify: %v", err)
	}

	// The EK certificate, and the AK's binding to that EK.
	ekCert, err := verifyEKCertificate(ev.EKCert, ev.EKChain, roots, now)
	if err != nil {
		return nil, err
	}
	ekDER, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
	if err != nil {
		return nil, notAttested("the EK certificate's key: %v", err)
	}
	want := tpmCredentialSecret(credentialKey, akName, ekDER)
	if subtle.ConstantTimeCompare(ev.CredentialSecret, want) != 1 {
		return nil, notAttested("the attestation key is not shown to share a TPM with the endorsement key")
	}

	// AppIDPresent stays false: a TPM does not say which app asked for a key.
	return &InstalledAppKeyFacts{Public: pub, Platform: "tpm", Level: "tpm"}, nil
}

func verifyEKCertificate(der []byte, chain [][]byte, roots []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if len(der) == 0 {
		return nil, notAttested("no endorsement key certificate")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, notAttested("the endorsement key certificate: %v", err)
	}
	if len(chain) > 8 {
		return nil, notAttested("the endorsement key certificate chain is too long")
	}
	inter := x509.NewCertPool()
	for _, c := range chain {
		ic, err := x509.ParseCertificate(c)
		if err != nil {
			return nil, notAttested("an issuer certificate: %v", err)
		}
		inter.AddCert(ic)
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		pool.AddCert(r)
	}
	// EK certificates carry the TCG EK-certificate extended key usage, not
	// server or client auth, so any usage is accepted; the chain to a pinned
	// root is the claim being checked.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, notAttested("the endorsement key certificate does not chain to a pinned TPM manufacturer root: %v", err)
	}
	return leaf, nil
}

// ---- TPM structure parsing (TCG TPM 2.0 Part 2, big-endian) ----

type tpmReader struct {
	b   []byte
	err bool
}

func (r *tpmReader) take(n int) []byte {
	if r.err || n < 0 || n > len(r.b) {
		r.err = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}
func (r *tpmReader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}
func (r *tpmReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func (r *tpmReader) sized() []byte { return r.take(r.u16()) }

type tpmPublic struct {
	raw     []byte // the TPMT_PUBLIC bytes a name is computed over
	typ     int
	nameAlg int
	attrs   uint32
	scheme  int
	hash    int
	curve   int
	x, y    []byte
	mod     []byte
	exp     uint32
}

func parseTPM2BPublic(b []byte) (*tpmPublic, error) {
	r := &tpmReader{b: b}
	area := r.sized()
	if r.err || len(r.b) != 0 {
		return nil, errTPM("not a TPM2B_PUBLIC")
	}
	p := &tpmPublic{raw: area}
	a := &tpmReader{b: area}
	p.typ = a.u16()
	p.nameAlg = a.u16()
	p.attrs = a.u32()
	a.sized() // authPolicy
	skipSym := func() {
		if alg := a.u16(); alg != tpmAlgNull {
			a.u16() // keyBits
			a.u16() // mode
		}
	}
	readScheme := func() {
		p.scheme = a.u16()
		if p.scheme != tpmAlgNull {
			p.hash = a.u16()
		}
	}
	switch p.typ {
	case tpmAlgECC:
		skipSym()
		readScheme()
		p.curve = a.u16()
		if a.u16() != tpmAlgNull { // KDF
			a.u16()
		}
		p.x, p.y = a.sized(), a.sized()
	case tpmAlgRSA:
		skipSym()
		readScheme()
		a.u16() // keyBits
		p.exp = a.u32()
		p.mod = a.sized()
	default:
		return nil, errTPM("unsupported public area type")
	}
	if a.err || len(a.b) != 0 {
		return nil, errTPM("malformed public area")
	}
	return p, nil
}

type tpmError string

func (e tpmError) Error() string { return string(e) }
func errTPM(s string) error      { return tpmError(s) }

func tpmHashByAlg(alg int) (crypto.Hash, bool) {
	switch alg {
	case tpmAlgSHA256:
		return crypto.SHA256, true
	case tpmAlgSHA384:
		return crypto.SHA384, true
	case tpmAlgSHA512:
		return crypto.SHA512, true
	}
	return 0, false // SHA-1 and anything unknown are refused
}

func tpmDigest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	s := sha256.Sum256(data)
	return s[:]
}

// name is the TPM name: nameAlg || H_nameAlg(TPMT_PUBLIC).
func (p *tpmPublic) name() ([]byte, error) {
	h, ok := tpmHashByAlg(p.nameAlg)
	if !ok {
		return nil, errTPM("unsupported name algorithm")
	}
	return append([]byte{byte(p.nameAlg >> 8), byte(p.nameAlg)}, tpmDigest(h, p.raw)...), nil
}

func (p *tpmPublic) ecdsaPublic() (*ecdsa.PublicKey, error) {
	if p.typ != tpmAlgECC || p.curve != tpmCurveP256 || len(p.x) > 32 || len(p.y) > 32 {
		return nil, errTPM("not a P-256 key")
	}
	pt := make([]byte, 65)
	pt[0] = 4
	copy(pt[1+32-len(p.x):33], p.x)
	copy(pt[33+32-len(p.y):], p.y)
	if _, err := ecdh.P256().NewPublicKey(pt); err != nil { // rejects points off the curve
		return nil, errTPM("the point is not on the P-256 curve")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(p.x), Y: new(big.Int).SetBytes(p.y)}, nil
}

type tpmAttest struct{ extraData, name []byte }

func parseTPMSAttestCertify(b []byte) (*tpmAttest, error) {
	r := &tpmReader{b: b}
	if r.u32() != tpmGeneratedValue {
		return nil, errTPM("magic is not TPM_GENERATED_VALUE")
	}
	if r.u16() != tpmSTAttestCertify {
		return nil, errTPM("type is not ATTEST_CERTIFY")
	}
	r.sized() // qualifiedSigner
	extra := r.sized()
	r.take(8 + 4 + 4 + 1) // clockInfo
	r.take(8)             // firmwareVersion
	name := r.sized()
	r.sized() // qualifiedName
	if r.err || len(r.b) != 0 {
		return nil, errTPM("malformed")
	}
	return &tpmAttest{extraData: extra, name: name}, nil
}

// verifyTPMSignature checks a TPMT_SIGNATURE over msg with the AK.
func verifyTPMSignature(ak *tpmPublic, msg, sig []byte) error {
	r := &tpmReader{b: sig}
	sigAlg := r.u16()
	h, ok := tpmHashByAlg(r.u16())
	if r.err || !ok {
		return errTPM("unsupported or malformed signature")
	}
	if ak.scheme != tpmAlgNull && ak.scheme != sigAlg {
		return errTPM("signature scheme differs from the key's scheme")
	}
	digest := tpmDigest(h, msg)
	switch {
	case ak.typ == tpmAlgRSA && (sigAlg == tpmAlgRSASSA || sigAlg == tpmAlgRSAPSS):
		s := r.sized()
		if r.err || len(r.b) != 0 || len(ak.mod) < 128 {
			return errTPM("malformed RSA signature")
		}
		e := int(ak.exp)
		if e == 0 {
			e = 65537
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(ak.mod), E: e}
		if sigAlg == tpmAlgRSASSA {
			return rsa.VerifyPKCS1v15(pk, h, digest, s)
		}
		return rsa.VerifyPSS(pk, h, digest, s, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case ak.typ == tpmAlgECC && sigAlg == tpmAlgECDSA:
		rb, sb := r.sized(), r.sized()
		if r.err || len(r.b) != 0 {
			return errTPM("malformed ECDSA signature")
		}
		if ak.curve != tpmCurveP256 {
			return errTPM("unsupported attestation key curve")
		}
		pk, err := ak.ecdsaPublic()
		if err != nil {
			return err
		}
		if !ecdsa.Verify(pk, digest, new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb)) {
			return errTPM("ECDSA signature invalid")
		}
		return nil
	}
	return errTPM("signature algorithm does not match the attestation key")
}
