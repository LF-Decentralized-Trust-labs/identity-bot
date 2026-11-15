package secureenclave

// The core's half of the TPM credential exchange (ADR-072 Amendment 3, and the
// header of tpm_key_certify.go): TPM2_MakeCredential, done in software by the
// party that wants to know an attestation key (AK) shares a TPM with an
// endorsement key (EK) whose certificate chains to a manufacturer.
//
// The core makes a credential only the TPM holding that EK AND the named AK can
// open (TPM2_ActivateCredential), and what is inside is keyed by a secret the
// core keeps for this one ask (tpmCredentialSecret). The app learns it only from
// its TPM, so software that has a genuine EK certificate and an AK of its own
// cannot produce it.
//
// Layout and derivations are TPM 2.0 Library Part 1, section 24 (credential
// protection) and annex B.10.4 (RSA OAEP), C.6 (ECDH, KDFe). They are held to the
// reference TPM implementation's own ActivateCredential (a software TPM): see
// testdata/tpm_credential_exchange_rsa.json and _ecc.json and tpm_make_credential_test.go.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"time"
)

// TPMCredential is what the core hands the app to open in its TPM with
// TPM2_ActivateCredential (credential_blob and secret, in the TCG wire form
// ActivateCredential takes them: each a size-prefixed TPM2B).
type TPMCredential struct {
	// CredentialBlob is a TPM2B_ID_OBJECT.
	CredentialBlob []byte `json:"credential_blob"`
	// Secret is a TPM2B_ENCRYPTED_SECRET.
	Secret []byte `json:"secret"`
}

// MakeTPMCredential makes the credential for an EK and an AK. ekPublic and
// akPublic are TPM2B_PUBLIC; ekCert and ekChain are the EK's certificate and its
// issuers. It refuses unless the EK certificate chains to a pinned manufacturer
// root, the EK public area is the certificate's key, and the EK is a decrypt key
// of the standard kind, so the core never makes a credential for a key that is
// not a TPM's. credentialKey is the core's secret for this ask.
func MakeTPMCredential(ekPublic, ekCert []byte, ekChain [][]byte, akPublic, credentialKey []byte, now time.Time) (*TPMCredential, error) {
	return makeTPMCredential(ekPublic, ekCert, ekChain, akPublic, credentialKey, now, tpmManufacturerRoots, rand.Reader)
}

// MakeTPMCredentialAgainstRoots is MakeTPMCredential for roots the caller names,
// for the tool that checks this code against a software TPM
// (testdata/tpmsim). The server never calls it: it takes the pinned roots.
func MakeTPMCredentialAgainstRoots(ekPublic, ekCert []byte, ekChain [][]byte, akPublic, credentialKey []byte, now time.Time, roots []*x509.Certificate) (*TPMCredential, error) {
	return makeTPMCredential(ekPublic, ekCert, ekChain, akPublic, credentialKey, now, roots, rand.Reader)
}

func makeTPMCredential(ekPublic, ekCert []byte, ekChain [][]byte, akPublic, credentialKey []byte, now time.Time, roots []*x509.Certificate, rnd io.Reader) (*TPMCredential, error) {
	if len(roots) == 0 {
		return nil, notAttested("no TPM manufacturer roots are pinned in this build, so no TPM can be trusted")
	}
	if len(credentialKey) < TPMCredentialKeyLen {
		return nil, notAttested("the attestation was not issued a secret credential key by the core")
	}
	if len(ekPublic) > tpmMaxEvidence || len(akPublic) > tpmMaxEvidence || len(ekCert) > tpmMaxEvidence || len(ekChain) > 8 {
		return nil, notAttested("a public area is too large")
	}
	cert, err := verifyEKCertificate(ekCert, ekChain, roots, now)
	if err != nil {
		return nil, err
	}
	ek, err := parseTPM2BPublic(ekPublic)
	if err != nil {
		return nil, notAttested("the endorsement key's public area: %v", err)
	}
	ak, err := parseTPM2BPublic(akPublic)
	if err != nil {
		return nil, notAttested("the attestation key's public area: %v", err)
	}
	// The EK is a restricted decrypt key, fixed in its TPM, and not a signing key.
	const ekNeeds = tpmAttrFixedTPM | tpmAttrFixedParent | tpmAttrRestricted | tpmAttrDecrypt
	if ek.attrs&ekNeeds != ekNeeds || ek.attrs&tpmAttrSign != 0 {
		return nil, notAttested("the endorsement key is not a restricted decrypt key fixed in its TPM")
	}
	if ek.nameAlg != tpmAlgSHA256 || ak.nameAlg != tpmAlgSHA256 {
		return nil, notAttested("only SHA-256 named keys take part in the credential exchange")
	}
	// The public area the app sent is the certificate's key, and no other.
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		exp := int(ek.exp)
		if exp == 0 {
			exp = 65537 // a TPM public area writes the default exponent as zero
		}
		if ek.typ != tpmAlgRSA || pub.N.Cmp(new(big.Int).SetBytes(ek.mod)) != 0 || exp != pub.E {
			return nil, notAttested("the endorsement key's public area is not the certificate's key")
		}
		if pub.N.BitLen() < 2048 {
			return nil, notAttested("the endorsement key is shorter than 2048 bits")
		}
	default:
		ekEC, err := ek.ecdhPublic()
		if err != nil {
			return nil, notAttested("the endorsement key: %v", err)
		}
		want, err := ecdhOfCertificate(cert)
		if err != nil || !ekEC.Equal(want) {
			return nil, notAttested("the endorsement key's public area is not the certificate's key")
		}
	}
	akName, err := ak.name()
	if err != nil {
		return nil, notAttested("the attestation key's name: %v", err)
	}
	ekDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, notAttested("the endorsement key certificate's key: %v", err)
	}
	// The AES key size the EK says it decrypts credentials with (the standard
	// EK profile is AES-128 CFB).
	if ek.symAlg != 0x0006 /*AES*/ || ek.symMode != 0x0043 /*CFB*/ || (ek.symBits != 128 && ek.symBits != 256) {
		return nil, notAttested("the endorsement key's symmetric algorithm is not AES in CFB mode")
	}

	var seed, encSeed []byte
	switch ek.typ {
	case tpmAlgRSA:
		pub := cert.PublicKey.(*rsa.PublicKey)
		seed = make([]byte, sha256.Size)
		if _, err := io.ReadFull(rnd, seed); err != nil {
			return nil, err
		}
		ct, err := rsa.EncryptOAEP(sha256.New(), rnd, pub, seed, append([]byte("IDENTITY"), 0))
		if err != nil {
			return nil, notAttested("sealing the credential's seed to the endorsement key: %v", err)
		}
		encSeed = sized(ct)
	case tpmAlgECC:
		ekEC, _ := ek.ecdhPublic()
		eph, err := ecdh.P256().GenerateKey(rnd)
		if err != nil {
			return nil, err
		}
		z, err := eph.ECDH(ekEC)
		if err != nil {
			return nil, notAttested("sealing the credential's seed to the endorsement key: %v", err)
		}
		ex, ey := ecdhXY(eph.PublicKey())
		kx, _ := ecdhXY(ekEC)
		seed = tpmKDFe(z, "IDENTITY", ex, kx, sha256.Size*8)
		encSeed = sized(append(sized(ex), sized(ey)...))
	default:
		return nil, notAttested("unsupported endorsement key type")
	}

	secret := tpmCredentialSecret(credentialKey, akName, ekDER)
	symKey := tpmKDFa(seed, "STORAGE", akName, nil, ek.symBits)
	blk, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, err
	}
	enc := sized(secret) // TPM2B_DIGEST
	cipher.NewCFBEncrypter(blk, make([]byte, aes.BlockSize)).XORKeyStream(enc, enc)
	macKey := tpmKDFa(seed, "INTEGRITY", nil, nil, sha256.Size*8)
	m := hmac.New(sha256.New, macKey)
	m.Write(enc)
	m.Write(akName)
	// TPM2B_ID_OBJECT: size, then TPM2B_DIGEST integrityHMAC and encIdentity.
	id := append(sized(m.Sum(nil)), enc...)
	return &TPMCredential{CredentialBlob: sized(id), Secret: encSeed}, nil
}

func sized(b []byte) []byte {
	return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
}

// tpmKDFa is the counter-mode KDF of TPM 2.0 Part 1 section 11.4.10.2 with
// HMAC-SHA-256: HMAC(key, counter || label 0x00 || contextU || contextV || bits).
func tpmKDFa(key []byte, label string, contextU, contextV []byte, bits int) []byte {
	out := make([]byte, 0, (bits+7)/8)
	for ctr := uint32(1); len(out)*8 < bits; ctr++ {
		m := hmac.New(sha256.New, key)
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		m.Write(c[:])
		m.Write([]byte(label))
		m.Write([]byte{0})
		m.Write(contextU)
		m.Write(contextV)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(bits))
		m.Write(b[:])
		out = m.Sum(out)
	}
	out = out[:(bits+7)/8]
	if bits%8 != 0 {
		out[0] &= 0xff >> (8 - bits%8)
	}
	return out
}

// tpmKDFe is the concatenation KDF of Part 1 section 11.4.10.3 (SP 800-56A):
// SHA-256(counter || Z || label 0x00 || partyU || partyV).
func tpmKDFe(z []byte, label string, partyU, partyV []byte, bits int) []byte {
	out := make([]byte, 0, (bits+7)/8)
	for ctr := uint32(1); len(out)*8 < bits; ctr++ {
		h := sha256.New()
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		h.Write(c[:])
		h.Write(z)
		h.Write([]byte(label))
		h.Write([]byte{0})
		h.Write(partyU)
		h.Write(partyV)
		out = h.Sum(out)
	}
	return out[:(bits+7)/8]
}

func ecdhXY(k *ecdh.PublicKey) (x, y []byte) {
	b := k.Bytes()[1:]
	return b[:len(b)/2], b[len(b)/2:]
}

func (p *tpmPublic) ecdhPublic() (*ecdh.PublicKey, error) {
	if p.typ != tpmAlgECC || p.curve != tpmCurveP256 || len(p.x) > 32 || len(p.y) > 32 {
		return nil, errTPM("not a P-256 key")
	}
	pt := make([]byte, 65)
	pt[0] = 4
	copy(pt[1+32-len(p.x):33], p.x)
	copy(pt[33+32-len(p.y):], p.y)
	return ecdh.P256().NewPublicKey(pt)
}

func ecdhOfCertificate(c *x509.Certificate) (*ecdh.PublicKey, error) {
	switch k := c.PublicKey.(type) {
	case interface {
		ECDH() (*ecdh.PublicKey, error)
	}:
		return k.ECDH()
	}
	return nil, errTPM("the certificate's key is not an RSA or elliptic curve key")
}
