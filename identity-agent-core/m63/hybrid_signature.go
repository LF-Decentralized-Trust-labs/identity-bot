package m63

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func composeHybridSignature(ed25519SigerQB64, mldsaSigQB64 string) string {
	return CtrControllerIdxSigs + intToB64(2, 2) + ed25519SigerQB64 + mldsaSigQB64
}

// MatterIndexedSigQB64 encodes a keri 1.1.17 indexed signature (Indexer._infil).
func MatterIndexedSigQB64(code string, index int, raw []byte, fs int) (string, error) {
	hs := len(code)
	if hs < 1 {
		return "", fmt.Errorf("code required")
	}
	ss := 1
	os := 0
	ls := 0
	cs := hs + ss
	ms := ss - os
	if fs <= cs {
		return "", fmt.Errorf("invalid fs %d for code %q", fs, code)
	}
	ps := (3 - (len(raw) % 3)) % 3
	both := code + intToB64(index, ms)
	padded := make([]byte, ps+len(raw))
	copy(padded[ps:], raw)
	b64 := base64.RawURLEncoding.EncodeToString(padded)
	skip := ps - ls
	if skip > len(b64) {
		return "", fmt.Errorf("invalid indexed sig encoding")
	}
	out := both + b64[skip:]
	if len(out) != fs {
		return "", fmt.Errorf("indexed sig len %d != fs %d", len(out), fs)
	}
	return out, nil
}

// EncodeIndexedMLDSASig encodes ML-DSA-65 signature with provisional 1PDS code + index char.
func EncodeIndexedMLDSASig(index int, raw []byte) (string, error) {
	if len(raw) != MLDSA65SigBytes {
		return "", fmt.Errorf("ML-DSA-65 sig must be %d bytes, got %d", MLDSA65SigBytes, len(raw))
	}
	if index < 0 || index > 63 {
		return "", fmt.Errorf("index out of range: %d", index)
	}
	return CESRMLDSA65Sig + intToB64(index, 1) + base64.RawURLEncoding.EncodeToString(raw), nil
}

// ParseCompositeSignature splits -A counter group into Ed25519 + ML-DSA halves.
func ParseCompositeSignature(wire string) (ed25519Siger string, mldsaSig string, err error) {
	if len(wire) < 4 || wire[:2] != CtrControllerIdxSigs {
		return "", "", fmt.Errorf("composite signature must start with %s counter", CtrControllerIdxSigs)
	}
	count := b64ToInt(wire[2:4])
	if count != 2 {
		return "", "", fmt.Errorf("expected 2 indexed sigs, counter=%d", count)
	}
	rest := wire[4:]
	if len(rest) < 88 {
		return "", "", fmt.Errorf("truncated composite signature")
	}
	ed := rest[:88]
	mldsa := rest[88:]
	if len(mldsa) < 5 || mldsa[:4] != CESRMLDSA65Sig {
		return "", "", fmt.Errorf("ML-DSA half missing %s prefix", CESRMLDSA65Sig)
	}
	return ed, mldsa, nil
}

// DecodeIndexedMLDSASig extracts index + raw signature bytes from 1PDS wire.
func DecodeIndexedMLDSASig(wire string) (int, []byte, error) {
	if len(wire) < 5 || wire[:4] != CESRMLDSA65Sig {
		return 0, nil, fmt.Errorf("expected %s indexed sig", CESRMLDSA65Sig)
	}
	index := b64ToInt(string(wire[4]))
	raw, err := base64.RawURLEncoding.DecodeString(wire[5:])
	if err != nil {
		return 0, nil, err
	}
	if len(raw) != MLDSA65SigBytes {
		return 0, nil, fmt.Errorf("decoded sig len %d != %d", len(raw), MLDSA65SigBytes)
	}
	return index, raw, nil
}

// IsHybridIdentity returns true when a[0].ia == IA-HYBRID-1.
func IsHybridIdentity(inception map[string]interface{}) bool {
	raw, ok := inception["a"]
	if !ok {
		return false
	}
	var seal map[string]interface{}
	switch anchors := raw.(type) {
	case []interface{}:
		if len(anchors) == 0 {
			return false
		}
		seal, ok = anchors[0].(map[string]interface{})
	case []map[string]interface{}:
		if len(anchors) == 0 {
			return false
		}
		seal = anchors[0]
	default:
		return false
	}
	if !ok && seal == nil {
		return false
	}
	return seal["ia"] == CipherSuiteIAHybrid1
}

// SigningKeyCount returns len(k) for hybrid inception validation.
func SigningKeyCount(inception map[string]interface{}) int {
	k, ok := inception["k"].([]interface{})
	if !ok {
		if ks, ok := inception["k"].([]string); ok {
			return len(ks)
		}
		return 0
	}
	return len(k)
}

// HybridSignatureResult mirrors keripy driver output.
type HybridSignatureResult struct {
	MessageB64       string `json:"message_b64"`
	Ed25519Siger     string `json:"ed25519_siger"`
	MLDSA65Sig       string `json:"mldsa65_sig"`
	CompositeWire    string `json:"composite_wire"`
	CompositeWireLen int    `json:"composite_wire_len"`
}

// SignHybridMessage produces deterministic C2 golden-vector composite signature.
func SignHybridMessage() (HybridSignatureResult, error) {
	msg := []byte(C2Message)
	edPriv := ed25519.NewKeyFromSeed(C2Ed25519Seed)
	edSig := ed25519.Sign(edPriv, msg)
	edWire, err := MatterIndexedSigQB64("B", 0, edSig, 88)
	if err != nil {
		return HybridSignatureResult{}, err
	}

	var mldsaSeed [mldsa65.SeedSize]byte
	copy(mldsaSeed[:], C2MLDSASeed)
	_, sk := mldsa65.NewKeyFromSeed(&mldsaSeed)
	mldsaRaw := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, false, mldsaRaw); err != nil {
		return HybridSignatureResult{}, err
	}
	mldsaWire, err := EncodeIndexedMLDSASig(1, mldsaRaw)
	if err != nil {
		return HybridSignatureResult{}, err
	}
	composite := composeHybridSignature(edWire, mldsaWire)
	return HybridSignatureResult{
		MessageB64:       fmt.Sprintf("%x", msg),
		Ed25519Siger:     edWire,
		MLDSA65Sig:       mldsaWire,
		CompositeWire:    composite,
		CompositeWireLen: len(composite),
	}, nil
}

// VerifyHybridSignature enforces both-must-verify for IA-HYBRID-1 identities.
func VerifyHybridSignature(
	msg []byte,
	compositeWire string,
	ed25519Verkey []byte,
	mldsaVerkey []byte,
	inception map[string]interface{},
) bool {
	if inception != nil {
		if !IsHybridIdentity(inception) {
			return false
		}
		if SigningKeyCount(inception) != 2 {
			return false
		}
	}
	edWire, mldsaWire, err := ParseCompositeSignature(compositeWire)
	if err != nil {
		return false
	}
	if len(ed25519Verkey) != Ed25519PubkeyBytes {
		return false
	}
	edSigBytes, err := decodeEd25519SigerRaw(edWire)
	if err != nil {
		return false
	}
	if !ed25519.Verify(ed25519.PublicKey(ed25519Verkey), msg, edSigBytes) {
		return false
	}
	_, mldsaRaw, err := DecodeIndexedMLDSASig(mldsaWire)
	if err != nil {
		return false
	}
	if len(mldsaVerkey) != MLDSA65VerkeyBytes {
		return false
	}
	var pk mldsa65.PublicKey
	var pkBuf [mldsa65.PublicKeySize]byte
	copy(pkBuf[:], mldsaVerkey)
	pk.Unpack(&pkBuf)
	return mldsa65.Verify(&pk, msg, nil, mldsaRaw)
}

func decodeEd25519SigerRaw(sigerQB64 string) ([]byte, error) {
	if len(sigerQB64) != 88 || sigerQB64[0] != 'B' {
		return nil, fmt.Errorf("invalid Ed25519 indexed sig")
	}
	ps := (3 - (Ed25519SigBytes % 3)) % 3
	prefix := intToB64(0, ps)
	padded, err := base64.RawURLEncoding.DecodeString(prefix + sigerQB64[2:])
	if err != nil {
		return nil, err
	}
	if len(padded) < Ed25519SigBytes {
		return nil, fmt.Errorf("ed25519 sig len %d", len(padded))
	}
	return padded[len(padded)-Ed25519SigBytes:], nil
}

// C2SigningVerkeys returns deterministic Ed25519 + ML-DSA-65 verification key bytes.
func C2SigningVerkeys() (ed25519Pub []byte, mldsaPub []byte, err error) {
	edPriv := ed25519.NewKeyFromSeed(C2Ed25519Seed)
	ed25519Pub = edPriv.Public().(ed25519.PublicKey)

	var mldsaSeed [mldsa65.SeedSize]byte
	copy(mldsaSeed[:], C2MLDSASeed)
	pk, _ := mldsa65.NewKeyFromSeed(&mldsaSeed)
	var buf [mldsa65.PublicKeySize]byte
	pk.Pack(&buf)
	return ed25519Pub, buf[:], nil
}