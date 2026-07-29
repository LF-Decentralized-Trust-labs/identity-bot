package didcomm

import (
	"encoding/json"
	"errors"
	"fmt"
)

// JWM is the cleartext message body. The router dispatches on Type; Body is
// opaque (defined by the consuming feature).
type JWM struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	From        string          `json:"from"` // did:keri:<sender Pairwise AID>
	To          []string        `json:"to"`   // did:keri:<recipient Pairwise AID>
	CreatedTime string          `json:"created_time"`
	ExpiresTime string          `json:"expires_time"`
	Body        json.RawMessage `json:"body"`
}

// signedJWM is the encrypted-side structure: the canonical JWM bytes, the Blake3 body
// hash, and the hybrid signature over (canonical JWM || body hash). Encrypting this
// (not the bare JWM) keeps the signatures inside the ciphertext, carried alongside the
// JWM rather than in the JWE header.
type signedJWM struct {
	JWM      json.RawMessage `json:"jwm"`
	BodyHash string          `json:"body_hash"`
	EdSig    string          `json:"ed_sig"`
	DsaSig   string          `json:"mldsa_sig"`
}

// ProtectedHeader is the JWE protected header. The PQC material's canonical byte
// encoding is pending; the field semantics are stable.
type ProtectedHeader struct {
	Alg  string `json:"alg"`
	Enc  string `json:"enc"`
	Skid string `json:"skid,omitempty"` // sender Pairwise AID (never Root); absent in anoncrypt
	Apu  string `json:"apu,omitempty"`  // sender key-agreement material (epk + ML-KEM ct)
	Apv  string `json:"apv,omitempty"`  // recipient key-agreement reference
}

type recipientHeader struct {
	Kid string `json:"kid"` // recipient Pairwise AID (never Root)
}
type recipient struct {
	Header recipientHeader `json:"header"`
}

// Envelope is the wire JWE.
type Envelope struct {
	Mode       string          `json:"mode"` // authcrypt | anoncrypt | signed
	Ciphertext string          `json:"ciphertext"`
	Protected  ProtectedHeader `json:"protected"`
	Recipients []recipient     `json:"recipients"`
	IV         string          `json:"iv"`
	// Sig* carry the signature for the `signed` (plaintext) mode, where there is no
	// ciphertext to embed it in. Empty for authcrypt/anoncrypt.
	EdSig  string `json:"ed_sig,omitempty"`
	DsaSig string `json:"mldsa_sig,omitempty"`
	Plain  string `json:"plaintext,omitempty"` // base64url canonical JWM (signed mode only)
}

const algAuthcrypt = "ECDH-1PU+X25519-ML-KEM-768"

// signInput binds the signature to the exact transmitted JWM bytes + the body hash.
func signInput(canonicalJWM []byte, bodyHash string) []byte {
	out := make([]byte, 0, len(canonicalJWM)+len(bodyHash))
	out = append(out, canonicalJWM...)
	return append(out, []byte(bodyHash)...)
}

// PackAuthcrypt encrypts+signs a JWM to recipient rcpt, authenticated as sender — the
// default mode for all established IA-to-IA messages.
func PackAuthcrypt(sender *KeySet, rcpt *DID, jwm *JWM) (*Envelope, error) {
	pd, err := rcpt.parse()
	if err != nil {
		return nil, fmt.Errorf("recipient DID: %w", err)
	}
	canonical, err := json.Marshal(jwm)
	if err != nil {
		return nil, err
	}
	bodyHash := blake3Body(jwm.Body)
	edSig, dsaSig := signHybrid(sender, signInput(canonical, bodyHash))
	sjB, err := json.Marshal(signedJWM{
		JWM: canonical, BodyHash: bodyHash,
		EdSig: b64.EncodeToString(edSig), DsaSig: b64.EncodeToString(dsaSig),
	})
	if err != nil {
		return nil, err
	}
	// AAD binds the header identities to the ciphertext.
	aad := []byte(sender.AID + "|" + rcpt.AID)
	apu, nonce, ct, err := authEncrypt(sender, pd, sjB, aad)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Mode:       "authcrypt",
		Ciphertext: b64.EncodeToString(ct),
		Protected:  ProtectedHeader{Alg: algAuthcrypt, Enc: "XC20P", Skid: sender.AID, Apu: apu, Apv: b64.EncodeToString(pd.x25519[:])},
		Recipients: []recipient{{Header: recipientHeader{Kid: rcpt.AID}}},
		IV:         b64.EncodeToString(nonce),
	}, nil
}

// UnpackAuthcrypt decrypts + verifies an authcrypt envelope. senderDID is resolved from
// the envelope's skid by the caller.
func UnpackAuthcrypt(rcpt *KeySet, senderDID *DID, env *Envelope) (*JWM, error) {
	if env.Mode != "authcrypt" {
		return nil, fmt.Errorf("not an authcrypt envelope")
	}
	if env.Protected.Skid == "" || env.Protected.Skid != senderDID.AID {
		return nil, errors.New("skid mismatch")
	}
	if len(env.Recipients) == 0 || env.Recipients[0].Header.Kid != rcpt.AID {
		return nil, errors.New("unknown_recipient_aid")
	}
	pd, err := senderDID.parse()
	if err != nil {
		return nil, fmt.Errorf("sender DID: %w", err)
	}
	ct, err := b64.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, errors.New("bad ciphertext")
	}
	nonce, err := b64.DecodeString(env.IV)
	if err != nil {
		return nil, errors.New("bad iv")
	}
	aad := []byte(env.Protected.Skid + "|" + rcpt.AID)
	sjB, err := authDecrypt(rcpt, pd, env.Protected.Apu, nonce, ct, aad)
	if err != nil {
		return nil, err // key_agreement_failed
	}
	var sj signedJWM
	if err := json.Unmarshal(sjB, &sj); err != nil {
		return nil, errors.New("bad signed jwm")
	}
	edSig, _ := b64.DecodeString(sj.EdSig)
	dsaSig, _ := b64.DecodeString(sj.DsaSig)
	if !verifyHybrid(pd, signInput(sj.JWM, sj.BodyHash), edSig, dsaSig) {
		return nil, errors.New("signature_invalid")
	}
	var jwm JWM
	if err := json.Unmarshal(sj.JWM, &jwm); err != nil {
		return nil, errors.New("bad jwm")
	}
	if blake3Body(jwm.Body) != sj.BodyHash {
		return nil, errors.New("body_hash_mismatch")
	}
	if !KnownType(jwm.Type) {
		return nil, errors.New("unknown_message_type")
	}
	return &jwm, nil
}

// PackSigned produces a signed-plaintext envelope (no encryption) — for public
// announcements / OOBI broadcasts where authenticity, not confidentiality, is needed.
func PackSigned(sender *KeySet, jwm *JWM) (*Envelope, error) {
	canonical, err := json.Marshal(jwm)
	if err != nil {
		return nil, err
	}
	bodyHash := blake3Body(jwm.Body)
	edSig, dsaSig := signHybrid(sender, signInput(canonical, bodyHash))
	return &Envelope{
		Mode:      "signed",
		Protected: ProtectedHeader{Alg: "none", Enc: "none", Skid: sender.AID},
		Plain:     b64.EncodeToString(canonical),
		EdSig:     b64.EncodeToString(edSig),
		DsaSig:    b64.EncodeToString(dsaSig),
	}, nil
}

// UnpackSigned verifies a signed-plaintext envelope.
func UnpackSigned(senderDID *DID, env *Envelope) (*JWM, error) {
	if env.Mode != "signed" {
		return nil, fmt.Errorf("not a signed envelope")
	}
	pd, err := senderDID.parse()
	if err != nil {
		return nil, err
	}
	canonical, err := b64.DecodeString(env.Plain)
	if err != nil {
		return nil, errors.New("bad plaintext")
	}
	var jwm JWM
	if err := json.Unmarshal(canonical, &jwm); err != nil {
		return nil, errors.New("bad jwm")
	}
	edSig, _ := b64.DecodeString(env.EdSig)
	dsaSig, _ := b64.DecodeString(env.DsaSig)
	if !verifyHybrid(pd, signInput(canonical, blake3Body(jwm.Body)), edSig, dsaSig) {
		return nil, errors.New("signature_invalid")
	}
	return &jwm, nil
}
