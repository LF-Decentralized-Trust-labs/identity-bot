package iacrypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	keri "github.com/grapeid/keri-go"
)

// HybridKeyMaterial holds raw key bytes for hybrid inception (synthetic or caller-supplied).
type HybridKeyMaterial struct {
	Ed25519SigningRaw     []byte
	MLDSA65SigningRaw     []byte
	X25519AgreementRaw    []byte
	MLKEM768EncapRaw      []byte
	NextEd25519SigningRaw []byte
	NextMLDSA65SigningRaw []byte
}

// SyntheticHybridKeyMaterial returns deterministic synthetic bytes for harness vectors.
func SyntheticHybridKeyMaterial(seed int) HybridKeyMaterial {
	fill := func(n, tag int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = byte((seed + tag + i) % 256)
		}
		return out
	}
	return HybridKeyMaterial{
		Ed25519SigningRaw:     fill(Ed25519PubkeyBytes, 0x01),
		MLDSA65SigningRaw:     fill(MLDSA65VerkeyBytes, 0x02),
		X25519AgreementRaw:    fill(X25519PubkeyBytes, 0x03),
		MLKEM768EncapRaw:      fill(MLKEM768EncapBytes, 0x04),
		NextEd25519SigningRaw: fill(Ed25519PubkeyBytes, 0x11),
		NextMLDSA65SigningRaw: fill(MLDSA65VerkeyBytes, 0x12),
	}
}

type cesrKeys struct {
	Ed25519Signing    string `json:"ed25519_signing"`
	MLDSA65Signing    string `json:"mldsa65_signing"`
	X25519Agreement   string `json:"x25519_agreement"`
	MLKEM768Encap     string `json:"mlkem768_encap"`
	NextEd25519Digest string `json:"next_ed25519_digest"`
	NextMLDSA65Digest string `json:"next_mldsa65_digest"`
}

// HybridInceptionResult mirrors the keripy driver response shape.
type HybridInceptionResult struct {
	AID            string                 `json:"aid"`
	SAID           string                 `json:"said"`
	InceptionEvent map[string]interface{} `json:"inception_event"`
	RawBytesB64    string                 `json:"raw_bytes_b64"`
	CipherSuite    string                 `json:"cipher_suite"`
	CESR           cesrKeys               `json:"cesr"`
	// Delegator is the identity this one acts under, empty when it acts alone.
	Delegator     string `json:"delegator,omitempty"`
	PublicKey     string `json:"public_key"`
	NextKeyDigest string `json:"next_key_digest"`
}

func ed25519VerferQB64(raw32 []byte) (string, error) {
	if len(raw32) != Ed25519PubkeyBytes {
		return "", fmt.Errorf("Ed25519 public key must be 32 bytes")
	}
	_ = ed25519.PublicKey(raw32)
	return MatterFixedQB64("D", raw32)
}

func materialToCESR(m HybridKeyMaterial) (cesrKeys, error) {
	ed, err := ed25519VerferQB64(m.Ed25519SigningRaw)
	if err != nil {
		return cesrKeys{}, err
	}
	mldsa, err := EncodeLargeFixed(CESRMLDSA65Verkey, m.MLDSA65SigningRaw, MLDSA65VerkeyBytes)
	if err != nil {
		return cesrKeys{}, err
	}
	x, err := EncodeLargeFixed(CESRX25519Pubkey, m.X25519AgreementRaw, X25519PubkeyBytes)
	if err != nil {
		return cesrKeys{}, err
	}
	kem, err := EncodeLargeFixed(CESRMLKEM768Encap, m.MLKEM768EncapRaw, MLKEM768EncapBytes)
	if err != nil {
		return cesrKeys{}, err
	}
	nEd, err := Blake3QB64(m.NextEd25519SigningRaw)
	if err != nil {
		return cesrKeys{}, err
	}
	nMldsa, err := Blake3QB64(m.NextMLDSA65SigningRaw)
	if err != nil {
		return cesrKeys{}, err
	}
	return cesrKeys{
		Ed25519Signing:    ed,
		MLDSA65Signing:    mldsa,
		X25519Agreement:   x,
		MLKEM768Encap:     kem,
		NextEd25519Digest: nEd,
		NextMLDSA65Digest: nMldsa,
	}, nil
}

// BuildHybridInception constructs keri 1.1.17 conformant hybrid icp (SerderKERI makify).
func BuildHybridInception(m HybridKeyMaterial) (*HybridInceptionResult, error) {
	return buildHybrid(m, "")
}

// BuildHybridDelegatedInception is the same event for an identity that acts
// under another one's authority, naming its delegator.
//
// This is what a sealed machine gets. It generates these keys inside the
// enclave and they never leave it, so it holds the private half it needs in
// order to decrypt — while the owner's root seed stays where it is and never
// reaches the hardware. The owner's authority arrives as a signature over this
// event rather than as key material, which is the whole reason the machine can
// have an identity at all without being given the owner's.
//
// The encryption keys are anchored in THIS event, so the machine's own
// identifier commits to them: substituting them means substituting the
// identifier, which the delegation no longer covers.
func BuildHybridDelegatedInception(m HybridKeyMaterial, delegatorAID string) (*HybridInceptionResult, error) {
	if delegatorAID == "" {
		return nil, fmt.Errorf("a delegated inception must name its delegator, or nothing establishes who this identity acts for")
	}
	return buildHybrid(m, delegatorAID)
}

func buildHybrid(m HybridKeyMaterial, delegatorAID string) (*HybridInceptionResult, error) {
	cesr, err := materialToCESR(m)
	if err != nil {
		return nil, err
	}

	// Built with keri-go rather than this package's own serialiser, so there is
	// one KERI implementation in this codebase instead of two. The two were
	// compared byte-for-byte on this exact event before the swap — see
	// kerigo_agreement_test.go, which stays as the guard against them drifting
	// apart again.
	anchor, err := json.Marshal(map[string]any{
		"ia": CipherSuiteIAHybrid1,
		"ka": []string{cesr.X25519Agreement, cesr.MLKEM768Encap},
	})
	if err != nil {
		return nil, err
	}
	// A delegated inception is a different event type carrying the delegator,
	// not an ordinary one with a field added — the identifier derives from the
	// whole event, so the two are different identities.
	var raw []byte
	if delegatorAID != "" {
		raw, err = keri.BuildDelegatedInception(keri.DelegationInput{
			Keys:        []string{cesr.Ed25519Signing, cesr.MLDSA65Signing},
			Isith:       json.RawMessage(`"1"`),
			NextDigests: []string{cesr.NextEd25519Digest, cesr.NextMLDSA65Digest},
			Nsith:       json.RawMessage(`"1"`),
			Data:        []json.RawMessage{anchor},
			Delegator:   delegatorAID,
		})
	} else {
		raw, err = keri.BuildInception(keri.InceptionInput{
			Keys:        []string{cesr.Ed25519Signing, cesr.MLDSA65Signing},
			Isith:       json.RawMessage(`"1"`),
			NextDigests: []string{cesr.NextEd25519Digest, cesr.NextMLDSA65Digest},
			Nsith:       json.RawMessage(`"1"`),
			Data:        []json.RawMessage{anchor},
		})
	}
	if err != nil {
		return nil, err
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	var event map[string]interface{}
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, err
	}

	return &HybridInceptionResult{
		AID:            ev.Identifier,
		SAID:           ev.SAID,
		InceptionEvent: event,
		Delegator:      delegatorAID,
		RawBytesB64:    base64.StdEncoding.EncodeToString(raw),
		CipherSuite:    CipherSuiteIAHybrid1,
		CESR:           cesr,
		PublicKey:      cesr.Ed25519Signing,
		NextKeyDigest:  cesr.NextEd25519Digest,
	}, nil
}
