package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// Base-layer signing. Every IA-originated Ask is signed with a PAIRWISE key (HD-derived from
// the root seed, Go-native — the same mechanism the login assertion uses), not the root key.
// The signer's key is published so the scanner can verify; root anchoring, when actually
// needed, is a separate credential concern, not part of every transaction.

// mintPairwise derives a fresh pairwise relationship AID from the root seed, registers its key
// so /public/{aid}/did.json resolves, and returns its AID, OOBI, and signing seed.
func (s *CoreServer) mintPairwise(name string) (aid, oobi string, seed []byte, err error) {
	rootSeed, rerr := secureenclave.LoadRootSeed(s.DataDir)
	if rerr != nil {
		// Bootstrap the root seed if absent (mirrors the login/contact flow).
		rootSeed = make([]byte, 64)
		if _, re := rand.Read(rootSeed); re != nil {
			return "", "", nil, re
		}
		if se := secureenclave.StoreRootSeed(s.DataDir, rootSeed); se != nil {
			return "", "", nil, fmt.Errorf("bootstrap root seed: %w", se)
		}
	}
	idx, aerr := s.DataStore.AllocateNextRelationshipIndex("contacts")
	if aerr != nil {
		return "", "", nil, fmt.Errorf("allocate relationship index: %w", aerr)
	}
	seed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if derr != nil {
		return "", "", nil, fmt.Errorf("derive pairwise seed: %w", derr)
	}
	nextSeed, _ := backup.DerivePairwiseSeed(rootSeed, idx, 1)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
	if s.KeriDriver == nil {
		return "", "", nil, fmt.Errorf("keri driver required to mint pairwise AID")
	}
	// Unique driver name per mint (the index is a never-reused counter) so GetKel resolves
	// this exact pairwise, not a collision on a shared name.
	uniqueName := fmt.Sprintf("%s-%d", name, idx)
	icp, ierr := s.KeriDriver.CreateInceptionNamed(
		iacrypto.VerkeyQB64(pub),
		iacrypto.VerkeyQB64(nextPub),
		uniqueName,
	)
	if ierr != nil || icp.AID == "" {
		return "", "", nil, fmt.Errorf("mint pairwise inception: %w", ierr)
	}
	// Publish the key (did.json, for signature verification) and the KEL (OOBI, so a peer can
	// resolve this pairwise AID when adding us as a contact).
	pairwiseKeys.Lock()
	pairwiseKeys.m[icp.AID] = base64.RawURLEncoding.EncodeToString(pub)
	pairwiseKeys.Unlock()
	if kel, kerr := s.KeriDriver.GetKel(uniqueName); kerr == nil {
		registerPairwiseKEL(icp.AID, kel.KEL)
	}

	publicURL := s.EndpointService.CurrentURL()
	oobi = fmt.Sprintf("%s/public/oobi/%s", publicURL, icp.AID)
	return icp.AID, oobi, seed, nil
}

// injectSig adds a "sig" field to an Ask JSON object.
func injectSig(askBytes []byte, sig string) ([]byte, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(askBytes, &m); err != nil {
		return nil, err
	}
	m["sig"] = sig
	return json.Marshal(m)
}

// verifyAskSignature is the base-layer verification run on every decoded Ask: if the Ask
// carries a `sig` + `signer_oobi`, the signature must verify against the signer's published
// key. Asks without these (e.g. login's t=1 bundle, which self-verifies its own challenge sig)
// are passed through — those are migrated to the base layer separately.
func (s *CoreServer) verifyAskSignature(askBytes []byte) error {
	sig := jsonStringField(askBytes, "sig")
	signerOOBI := jsonStringField(askBytes, "signer_oobi")
	if sig == "" || signerOOBI == "" {
		return nil // not a base-layer-signed Ask; skip
	}
	pub, err := s.resolveSignerKey(signerOOBI)
	if err != nil {
		return fmt.Errorf("resolve signer key: %w", err)
	}
	ok, err := login.VerifyAsk(askBytes, sig, pub)
	if err != nil || !ok {
		return fmt.Errorf("invalid Ask signature")
	}
	return nil
}

// resolveSignerKey fetches the signer's current Ed25519 key from its did.json (resolved from
// the signer OOBI: strip /oobi/{aid}, fetch /{aid}/did.json). Mirrors the login resolver.
func (s *CoreServer) resolveSignerKey(signerOOBI string) ([]byte, error) {
	base := signerOOBI
	if i := strings.Index(base, "/oobi/"); i >= 0 {
		base = base[:i]
	}
	aid := signerOOBI
	if i := strings.LastIndex(aid, "/"); i >= 0 {
		aid = aid[i+1:]
	}
	url := strings.TrimRight(base, "/") + "/" + aid + "/did.json"
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		VerificationMethod []struct {
			PublicKeyJwk struct {
				X string `json:"x"`
			} `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.VerificationMethod) == 0 || doc.VerificationMethod[0].PublicKeyJwk.X == "" {
		return nil, fmt.Errorf("did.json missing key")
	}
	return base64.RawURLEncoding.DecodeString(doc.VerificationMethod[0].PublicKeyJwk.X)
}
