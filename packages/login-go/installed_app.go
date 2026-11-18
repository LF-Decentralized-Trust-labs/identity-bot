package login

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// An installed front end's sign-in start (ADR-072 section 2 step 4, Amendment 3).
//
// An installed front end holds its key in its device's secure hardware, and the
// person's approval of a sign-in for that key is an app-key grant that lasts until
// it is ended. Naming the kind proves nothing, so the front end starts its sign-in
// with the hardware's own evidence for the key, made for one ask its back end got
// from the owner's Identity Agent. The back end carries the evidence on to the
// Identity Agent unread (StartRequest.InstalledAppKey) and the Identity Agent
// verifies it; this package only fixes the wire shape and the one statement the key
// signs, held to ../login-web/test-vectors/installed-app.json, which the Dart
// port (login-dart) runs too.

// Platforms that can vouch for an installed front end's key.
const (
	PlatformAndroid = "android"
	PlatformApple   = "apple"
	PlatformTPM     = "tpm"
)

// Where an installed front end asks its back end for an ask, and starts its
// sign-in. Both are calls sealed for the back end (seal.go), like every other.
const (
	InstalledAskPath = "/signin/installed-key/ask"
	// InstalledCredentialPath is the extra step a TPM's evidence needs and no other
	// platform's does: the front end sends its endorsement key's public area and
	// certificate and its attestation key (InstalledCredentialRequest), and the
	// back end passes them to the Identity Agent and answers with the credential
	// only that TPM can open (InstalledCredential).
	InstalledCredentialPath = "/signin/installed-key/credential"
	InstalledStartPath      = "/signin/session"
)

// InstalledKeyProof is the evidence for an installed front end's key: the
// platform that vouches, that platform's own evidence, the ask it was made for, and
// the key's own signature over InstalledAppStatement for that ask, and, if the app
// gives one, its own name for its device. On the wire the
// byte fields are standard base64, as the Identity Agent reads them.
type InstalledKeyProof struct {
	Platform     string `json:"platform"`
	Evidence     []byte `json:"evidence"`
	Ask          string `json:"ask"`
	KeySignature []byte `json:"key_signature"`
	// DeviceName is what the installed app calls the device it runs on, for the
	// person's consent. Optional, and nothing proves it: the Identity Agent cleans
	// it and shows it as the app's word, labelled as not checked. The back end
	// passes it on with the rest of the proof.
	DeviceName string `json:"device_name,omitempty"`
}

// InstalledAsk is what the back end hands its installed front end to make the
// evidence for: the ask's name and the challenge the hardware attests.
type InstalledAsk struct {
	Ask string `json:"ask"`
	// AssetID is the utility app's asset, which the key's statement names. Only the
	// back end knows it: the app's identifier a link carries is another name.
	AssetID   string `json:"asset_id"`
	Challenge string `json:"challenge"` // unpadded base64url of the challenge bytes
	Expires   string `json:"expires"`
}

// InstalledAppStatement is what an installed front end's key signs to start a
// sign-in: the app's asset, the ask's challenge and the key's own thumbprint.
// The Identity Agent builds the same text to check it.
func InstalledAppStatement(assetID string, challenge []byte, keyThumbprint string) []byte {
	return []byte("identity-agent installed-app sign-in v1\n" + assetID + "\n" +
		base64.RawURLEncoding.EncodeToString(challenge) + "\n" + keyThumbprint)
}

// InstalledAppStatementDigest is the SHA-256 the key signs (Android and a TPM
// sign it as ECDSA; Apple's App Attest takes it as the client data hash).
func InstalledAppStatementDigest(assetID string, challenge []byte, keyThumbprint string) [32]byte {
	return sha256.Sum256(InstalledAppStatement(assetID, challenge, keyThumbprint))
}

// KeyThumbprint is the RFC 7638 thumbprint of a P-256 public key given as its
// coordinates (unpadded base64url, 32 bytes each): how a front end's key is named.
func KeyThumbprint(x, y string) string {
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// FrontEndStart is a front end's request to start a sign-in, as the back end
// reads it from the sealed call.
type FrontEndStart struct {
	FrontEnd   string             `json:"frontEnd"`
	BrowserKey string             `json:"browserKey"`
	JWK        FrontEndJWK        `json:"jwk"`
	Proof      *InstalledKeyProof `json:"proof,omitempty"`
}

// FrontEndJWK is the public key of a front end.
type FrontEndJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ReadFrontEndStart reads a start request strictly, and refuses what could not
// lead to a sound sign-in: a key whose thumbprint is not the one named, a proof on
// a browser's start, or an installed app's start without its proof. Whether the
// evidence is true is the Identity Agent's to decide, not this reader's.
func ReadFrontEndStart(body []byte) (FrontEndStart, error) {
	var s FrontEndStart
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return FrontEndStart{}, fmt.Errorf("login: the sign-in start is not readable: %w", err)
	}
	if dec.More() {
		return FrontEndStart{}, errors.New("login: the sign-in start has more than one document")
	}
	if s.JWK.Kty != "EC" || s.JWK.Crv != "P-256" || s.JWK.X == "" || s.JWK.Y == "" {
		return FrontEndStart{}, errors.New("login: the sign-in start names no P-256 key")
	}
	if KeyThumbprint(s.JWK.X, s.JWK.Y) != s.BrowserKey {
		return FrontEndStart{}, errors.New("login: the key named is not the key given")
	}
	switch s.FrontEnd {
	case FrontEndBrowser:
		if s.Proof != nil {
			return FrontEndStart{}, errors.New("login: a browser's sign-in carries no hardware proof")
		}
	case FrontEndInstalledApp:
		p := s.Proof
		if p == nil || len(p.Evidence) == 0 || p.Ask == "" || len(p.KeySignature) == 0 {
			return FrontEndStart{}, errors.New("login: an installed app's sign-in needs the hardware's evidence for its key")
		}
		if p.Platform != PlatformAndroid && p.Platform != PlatformApple && p.Platform != PlatformTPM {
			return FrontEndStart{}, errors.New("login: the proof names a platform that cannot vouch for a key")
		}
	default:
		return FrontEndStart{}, errors.New("login: the sign-in does not say which front end it is for, 'browser' or 'installed_app'")
	}
	return s, nil
}

// InstalledCredentialRequest is a TPM front end's request for a credential, for
// the ask the back end gave it. The byte fields are standard base64.
type InstalledCredentialRequest struct {
	Ask      string   `json:"ask"`
	EKPublic []byte   `json:"ek_public"`
	EKCert   []byte   `json:"ek_cert"`
	EKChain  [][]byte `json:"ek_chain"`
	AKPublic []byte   `json:"ak_public"`
}

// InstalledCredential is the Identity Agent's credential, for the TPM to open
// with TPM2_ActivateCredential, in the TCG wire form (each a size-prefixed TPM2B).
type InstalledCredential struct {
	CredentialBlob []byte `json:"credential_blob"`
	Secret         []byte `json:"secret"`
}

// The most a credential request carries. A TPM's public areas and an EK
// certificate with its issuers are a few KiB; anything past this is not one.
const (
	maxCredentialPart  = 8 << 10
	maxCredentialChain = 8
)

// ReadInstalledCredentialRequest reads a credential request strictly and refuses
// one missing a part or carrying more than a TPM's evidence could. Whether the
// keys are a TPM's is the Identity Agent's to decide, not this reader's.
func ReadInstalledCredentialRequest(body []byte) (InstalledCredentialRequest, error) {
	var q InstalledCredentialRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return InstalledCredentialRequest{}, fmt.Errorf("login: the credential request is not readable: %w", err)
	}
	if dec.More() {
		return InstalledCredentialRequest{}, errors.New("login: the credential request has more than one document")
	}
	if q.Ask == "" || len(q.EKPublic) == 0 || len(q.EKCert) == 0 || len(q.AKPublic) == 0 {
		return InstalledCredentialRequest{}, errors.New("login: the credential request names no ask, endorsement key, certificate or attestation key")
	}
	if len(q.EKPublic) > maxCredentialPart || len(q.EKCert) > maxCredentialPart || len(q.AKPublic) > maxCredentialPart || len(q.EKChain) > maxCredentialChain {
		return InstalledCredentialRequest{}, errors.New("login: the credential request is larger than a TPM's evidence")
	}
	for _, c := range q.EKChain {
		if len(c) == 0 || len(c) > maxCredentialPart {
			return InstalledCredentialRequest{}, errors.New("login: the credential request has an unreadable issuer certificate")
		}
	}
	return q, nil
}
