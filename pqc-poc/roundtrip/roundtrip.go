package roundtrip

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	SigAlg = "ML-DSA-65"
	KemAlg = "ML-KEM-768"
)

type Result struct {
	LiboqsVersion string
	SigAlg        string
	KemAlg        string
	SigVerifyOK   bool
	KemSecretOK   bool
}

func Run() (Result, error) {
	res := Result{
		LiboqsVersion: oqs.LiboqsVersion(),
		SigAlg:        SigAlg,
		KemAlg:        KemAlg,
	}

	if err := runSig(&res); err != nil {
		return res, fmt.Errorf("signature round-trip: %w", err)
	}
	if err := runKem(&res); err != nil {
		return res, fmt.Errorf("kem round-trip: %w", err)
	}
	return res, nil
}

func (r Result) String() string {
	return fmt.Sprintf(
		"liboqs=%s sig=%s verify=%t kem=%s secret_match=%t",
		r.LiboqsVersion, r.SigAlg, r.SigVerifyOK, r.KemAlg, r.KemSecretOK,
	)
}

func runSig(res *Result) error {
	signer := oqs.Signature{}
	defer signer.Clean()

	if err := signer.Init(SigAlg, nil); err != nil {
		return fmt.Errorf("init signer: %w", err)
	}
	if !slices.Contains(oqs.EnabledSigs(), SigAlg) {
		return fmt.Errorf("%s not in enabled signatures: %v", SigAlg, oqs.EnabledSigs())
	}

	msg := []byte("m63-c4-poc-signature-roundtrip")
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	verifier := oqs.Signature{}
	defer verifier.Clean()
	if err := verifier.Init(SigAlg, nil); err != nil {
		return fmt.Errorf("init verifier: %w", err)
	}
	ok, err := verifier.Verify(msg, sig, pubKey)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	res.SigVerifyOK = ok
	return nil
}

func runKem(res *Result) error {
	client := oqs.KeyEncapsulation{}
	defer client.Clean()

	if err := client.Init(KemAlg, nil); err != nil {
		return fmt.Errorf("init client: %w", err)
	}
	if !slices.Contains(oqs.EnabledKEMs(), KemAlg) {
		return fmt.Errorf("%s not in enabled KEMs: %v", KemAlg, oqs.EnabledKEMs())
	}

	pubKey, err := client.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	server := oqs.KeyEncapsulation{}
	defer server.Clean()
	if err := server.Init(KemAlg, nil); err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	ct, serverSecret, err := server.EncapSecret(pubKey)
	if err != nil {
		return fmt.Errorf("encap: %w", err)
	}
	clientSecret, err := client.DecapSecret(ct)
	if err != nil {
		return fmt.Errorf("decap: %w", err)
	}
	res.KemSecretOK = bytes.Equal(clientSecret, serverSecret)
	return nil
}

