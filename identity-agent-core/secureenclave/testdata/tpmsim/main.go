// Command tpmsim makes the test vector for the TPM credential exchange
// (../tpm_credential_exchange_rsa.json and _ecc.json) from a software TPM: the reference
// implementation of the TPM 2.0 library (ms-tpm-20-ref, through
// go-tpm-tools/simulator), not code written here.
//
// It makes an endorsement key (EK) and an attestation key (AK) in the simulator,
// has the core make a credential for them (secureenclave.MakeTPMCredentialAgainstRoots),
// has the simulator OPEN it with TPM2_ActivateCredential (which checks the
// credential's integrity HMAC and decrypts it, so a wrong layout or key
// derivation fails here), makes an app key, certifies it with the AK, and
// writes the evidence the core verifies. The EK certificate is made here, signed
// by a root made here, because a simulator has no manufacturer: the vector
// proves the exchange and not any manufacturer's chain.
//
// It needs cgo and OpenSSL headers (the simulator is C). Run, from this folder:
//
//	go run . > ../tpm_credential_exchange_rsa.json
//	ECC=1 go run . > ../tpm_credential_exchange_ecc.json
//
// (ECC=1 makes the endorsement key the ECC P-256 one.)
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"identity-agent-core/secureenclave"
)

func must(err error, what string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, what+":", err)
		os.Exit(1)
	}
}

func main() {
	sim, err := simulator.Get()
	must(err, "simulator")
	defer sim.Close()

	// A root, and an EK certificate it signs for the simulator's EK.
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tpmsim test root (not a manufacturer)"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * 365 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	must(err, "root")
	root, _ := x509.ParseCertificate(rootDER)

	var ek *client.Key
	if os.Getenv("ECC") == "1" {
		ek, err = client.EndorsementKeyECC(sim)
	} else {
		ek, err = client.EndorsementKeyRSA(sim)
	}
	must(err, "EK")
	defer ek.Close()
	ak, err := client.AttestationKeyRSA(sim)
	must(err, "AK")
	defer ak.Close()
	ekCertTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tpmsim endorsement key"}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * 365 * time.Hour)}
	ekDER, err := x509.CreateCertificate(rand.Reader, ekCertTmpl, root, ek.PublicKey(), rootKey)
	must(err, "EK certificate")

	ekPub, err := ek.PublicArea().Encode()
	must(err, "EK public")
	akPub, err := ak.PublicArea().Encode()
	must(err, "AK public")
	sized := func(b []byte) []byte { return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...) }

	challenge := make([]byte, 32)
	credKey := make([]byte, 32)
	rand.Read(challenge)
	rand.Read(credKey)

	cred, err := secureenclave.MakeTPMCredentialAgainstRoots(sized(ekPub), ekDER, nil, sized(akPub), credKey, now, []*x509.Certificate{root})
	must(err, "make credential")

	// The simulator opens it: the EK needs a PolicySecret(endorsement) session.
	sess, _, err := tpm2.StartAuthSession(sim, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16), nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	must(err, "session")
	_, _, err = tpm2.PolicySecret(sim, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sess, nil, nil, nil, 0)
	must(err, "policy secret")
	secret, err := tpm2.ActivateCredentialUsingAuth(sim, []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		{Session: sess, Attributes: tpm2.AttrContinueSession},
	}, ak.Handle(), ek.Handle(), cred.CredentialBlob[2:], cred.Secret[2:])
	must(err, "TPM2_ActivateCredential refused the core's credential")

	// The app key: ECC P-256, signing only, generated in the TPM, certified by the AK.
	tmpl := tpm2.Public{Type: tpm2.AlgECC, NameAlg: tpm2.AlgSHA256,
		Attributes:    tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{Sign: &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256}, CurveID: tpm2.CurveNISTP256}}
	srk, err := client.StorageRootKeyRSA(sim)
	must(err, "SRK")
	defer srk.Close()
	priv, pubBlob, _, _, _, err := tpm2.CreateKey(sim, srk.Handle(), tpm2.PCRSelection{}, "", "", tmpl)
	must(err, "app key")
	h, _, err := tpm2.Load(sim, srk.Handle(), "", pubBlob, priv)
	must(err, "load app key")
	defer tpm2.FlushContext(sim, h)
	pubArea, _, _, err := tpm2.ReadPublic(sim, h)
	must(err, "read app key")
	appPubBytes, err := pubArea.Encode()
	must(err, "encode app key")
	extra := secureenclaveExtra(challenge)
	attest, sig, err := tpm2.CertifyEx(sim, "", "", h, ak.Handle(), extra, tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256})
	must(err, "certify")

	evidence, _ := json.Marshal(map[string]any{
		"key_public": sized(appPubBytes), "certify_info": attest, "certify_signature": sig,
		"ak_public": sized(akPub), "ek_cert": ekDER, "ek_chain": [][]byte{}, "credential_secret": secret,
	})
	// Only the evidence is a vector the app made; the rest is what the core held.
	out, _ := json.MarshalIndent(map[string]any{
		"about":          "Made by testdata/tpmsim from a software TPM (ms-tpm-20-ref). The root stands in for a manufacturer's.",
		"ek_type":        map[bool]string{true: "ecc", false: "rsa"}[os.Getenv("ECC") == "1"],
		"root":           rootDER,
		"challenge":      challenge,
		"credential_key": credKey,
		"now":            now.Format(time.RFC3339),
		"ek_public":      sized(ekPub),
		"credential":     cred,
		"evidence":       json.RawMessage(evidence),
	}, "", " ")
	fmt.Println(string(out))
}

var _ crypto.Hash
var _ = tpmutil.Handle(0)

// secureenclaveExtra is the qualifying data the core expects (the core's own function is unexported).
func secureenclaveExtra(challenge []byte) []byte {
	return secureenclave.TPMCertifyExtraData(challenge)
}
