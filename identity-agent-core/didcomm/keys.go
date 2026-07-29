// Package didcomm implements the DIDComm IA-to-IA envelope — the encrypted,
// mutually-authenticated message format every Identity-Agent-to-Identity-Agent exchange
// rides inside (credential exchange, KERI events, direct messages, AI-agent traffic).
//
// Three modes (authcrypt default / signed / anoncrypt), a JWM body with type routing,
// replay protection, a signed ACK, and direct-HTTPS transport. Crypto is hybrid:
// X25519+ML-KEM-768 key agreement (HKDF-combined) and Ed25519+ML-DSA-65 dual
// signatures — both halves must verify, no classical-only fallback.
//
// The canonical CESR byte serialization of the post-quantum material is pending a
// shared cipher-suite spec; this version uses a functional internal JSON/base64url
// encoding (IA-to-IA only, no external interop) that a canonical format later replaces.
// The envelope interface (modes, routing, replay, packing) is stable.
//
// Key custody note: when the KERI layer is classical Ed25519-only, DIDComm keys are
// managed here as an associated hybrid keyset per AID. The eventual model commits all
// four keys at inception; the envelope layer is identical either way — only where the
// keys come from changes.
package didcomm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/curve25519"
)

// KeySet is one identity's full hybrid DIDComm keyset — the private halves. It is
// generated per pairwise AID and persisted (owner-only) alongside the AID.
type KeySet struct {
	AID string

	EdPub  ed25519.PublicKey
	EdPriv ed25519.PrivateKey

	DsaPub  *mldsa65.PublicKey
	DsaPriv *mldsa65.PrivateKey

	XPub  [32]byte // X25519 public
	XPriv [32]byte // X25519 private

	KemPub  *mlkem768.PublicKey
	KemPriv *mlkem768.PrivateKey
}

// DID is the PUBLIC half of a KeySet — the four public keys a peer needs to authcrypt
// to (and verify signatures from) this AID. Exchanged between IAs via /api/didcomm/did
// (and, in the full model, published in the AID's KERI/OOBI key state).
type DID struct {
	AID    string `json:"aid"`
	Ed     string `json:"ed25519"`      // base64url
	Dsa    string `json:"mldsa65"`      // base64url
	X25519 string `json:"x25519"`       // base64url
	MlKem  string `json:"mlkem768"`     // base64url
	Suite  string `json:"cipher_suite"` // IA-HYBRID-1 (informational; canonical byte-freeze pending)
}

const CipherSuite = "IA-HYBRID-1"

var b64 = base64.RawURLEncoding

// GenerateKeySet mints a fresh hybrid keyset for an AID.
func GenerateKeySet(aid string) (*KeySet, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	dsaPub, dsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mldsa65 keygen: %w", err)
	}
	kemPub, kemPriv, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mlkem768 keygen: %w", err)
	}
	ks := &KeySet{AID: aid, EdPub: edPub, EdPriv: edPriv, DsaPub: dsaPub, DsaPriv: dsaPriv, KemPub: kemPub, KemPriv: kemPriv}
	if _, err := rand.Read(ks.XPriv[:]); err != nil {
		return nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	pub, err := curve25519.X25519(ks.XPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("x25519 derive: %w", err)
	}
	copy(ks.XPub[:], pub)
	return ks, nil
}

// DID returns the public DID for this keyset.
func (k *KeySet) DID() (*DID, error) {
	dsaB, err := k.DsaPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kemB, err := k.KemPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &DID{
		AID:    k.AID,
		Ed:     b64.EncodeToString(k.EdPub),
		Dsa:    b64.EncodeToString(dsaB),
		X25519: b64.EncodeToString(k.XPub[:]),
		MlKem:  b64.EncodeToString(kemB),
		Suite:  CipherSuite,
	}, nil
}

// parsedDID holds a peer's public keys decoded from a DID.
type parsedDID struct {
	aid    string
	ed     ed25519.PublicKey
	dsa    *mldsa65.PublicKey
	x25519 [32]byte
	kem    *mlkem768.PublicKey
}

func (d *DID) parse() (*parsedDID, error) {
	edB, err := b64.DecodeString(d.Ed)
	if err != nil || len(edB) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad ed25519 key")
	}
	dsaB, err := b64.DecodeString(d.Dsa)
	if err != nil {
		return nil, fmt.Errorf("bad mldsa key: %w", err)
	}
	dsaPub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(dsaB)
	if err != nil {
		return nil, fmt.Errorf("parse mldsa key: %w", err)
	}
	xB, err := b64.DecodeString(d.X25519)
	if err != nil || len(xB) != 32 {
		return nil, fmt.Errorf("bad x25519 key")
	}
	kemB, err := b64.DecodeString(d.MlKem)
	if err != nil {
		return nil, fmt.Errorf("bad mlkem key: %w", err)
	}
	kemPub, err := mlkem768.Scheme().UnmarshalBinaryPublicKey(kemB)
	if err != nil {
		return nil, fmt.Errorf("parse mlkem key: %w", err)
	}
	pd := &parsedDID{aid: d.aid(), ed: ed25519.PublicKey(edB), dsa: dsaPub.(*mldsa65.PublicKey), kem: kemPub.(*mlkem768.PublicKey)}
	copy(pd.x25519[:], xB)
	return pd, nil
}

func (d *DID) aid() string { return d.AID }

// --- persistence: a KeySet serializes to/from a portable JSON blob (owner-only). ---

type keySetWire struct {
	AID     string `json:"aid"`
	EdPriv  string `json:"ed_priv"`
	DsaPriv string `json:"dsa_priv"`
	XPriv   string `json:"x_priv"`
	KemPriv string `json:"kem_priv"`
}

// Marshal serializes the private keyset (for encrypted-at-rest storage by the caller).
func (k *KeySet) Marshal() ([]byte, error) {
	dsaB, err := k.DsaPriv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	kemB, err := k.KemPriv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(keySetWire{
		AID:     k.AID,
		EdPriv:  b64.EncodeToString(k.EdPriv),
		DsaPriv: b64.EncodeToString(dsaB),
		XPriv:   b64.EncodeToString(k.XPriv[:]),
		KemPriv: b64.EncodeToString(kemB),
	})
}

// UnmarshalKeySet restores a KeySet from Marshal output.
func UnmarshalKeySet(data []byte) (*KeySet, error) {
	var w keySetWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	edB, err := b64.DecodeString(w.EdPriv)
	if err != nil || len(edB) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad ed priv")
	}
	dsaB, err := b64.DecodeString(w.DsaPriv)
	if err != nil {
		return nil, err
	}
	dsaPriv, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(dsaB)
	if err != nil {
		return nil, err
	}
	kemB, err := b64.DecodeString(w.KemPriv)
	if err != nil {
		return nil, err
	}
	kemPriv, err := mlkem768.Scheme().UnmarshalBinaryPrivateKey(kemB)
	if err != nil {
		return nil, err
	}
	xB, err := b64.DecodeString(w.XPriv)
	if err != nil || len(xB) != 32 {
		return nil, fmt.Errorf("bad x priv")
	}
	ks := &KeySet{
		AID:     w.AID,
		EdPriv:  ed25519.PrivateKey(edB),
		EdPub:   ed25519.PrivateKey(edB).Public().(ed25519.PublicKey),
		DsaPriv: dsaPriv.(*mldsa65.PrivateKey),
		KemPriv: kemPriv.(*mlkem768.PrivateKey),
	}
	copy(ks.XPriv[:], xB)
	pub, err := curve25519.X25519(ks.XPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(ks.XPub[:], pub)
	ks.DsaPub = dsaPriv.(*mldsa65.PrivateKey).Public().(*mldsa65.PublicKey)
	ks.KemPub = kemPriv.(*mlkem768.PrivateKey).Public().(*mlkem768.PublicKey)
	return ks, nil
}
