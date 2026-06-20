package m63

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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
	PublicKey      string                 `json:"public_key"`
	NextKeyDigest  string                 `json:"next_key_digest"`
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

func hybridAnchor(cesr cesrKeys) []anchorSeal {
	return []anchorSeal{{
		Ia: CipherSuiteIAHybrid1,
		Ka: []string{cesr.X25519Agreement, cesr.MLKEM768Encap},
	}}
}

func wireFromCESR(cesr cesrKeys) icpWire {
	return icpWire{
		T:  "icp",
		S:  "0",
		Kt: "1",
		K:  []string{cesr.Ed25519Signing, cesr.MLDSA65Signing},
		Nt: "1",
		N:  []string{cesr.NextEd25519Digest, cesr.NextMLDSA65Digest},
		Bt: "0",
		B:  []interface{}{},
		C:  []interface{}{},
		A:  hybridAnchor(cesr),
	}
}

func wireToInceptionMap(w icpWire) map[string]interface{} {
	return map[string]interface{}{
		"v": w.V, "t": w.T, "d": w.D, "i": w.I, "s": w.S, "kt": w.Kt,
		"k": w.K, "nt": w.Nt, "n": w.N, "bt": w.Bt,
		"b": w.B, "c": w.C, "a": []map[string]interface{}{{
			"ia": w.A[0].Ia,
			"ka": w.A[0].Ka,
		}},
	}
}

// BuildHybridInception constructs keri 1.1.17 conformant hybrid icp (SerderKERI makify).
func BuildHybridInception(m HybridKeyMaterial) (*HybridInceptionResult, error) {
	cesr, err := materialToCESR(m)
	if err != nil {
		return nil, err
	}

	final, raw, err := makifyICPWire(wireFromCESR(cesr))
	if err != nil {
		return nil, err
	}

	return &HybridInceptionResult{
		AID:            final.I,
		SAID:           final.D,
		InceptionEvent: wireToInceptionMap(final),
		RawBytesB64:    base64.StdEncoding.EncodeToString(raw),
		CipherSuite:    CipherSuiteIAHybrid1,
		CESR:           cesr,
		PublicKey:      cesr.Ed25519Signing,
		NextKeyDigest:  cesr.NextEd25519Digest,
	}, nil
}