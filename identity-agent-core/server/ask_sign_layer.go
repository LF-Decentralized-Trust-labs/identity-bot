package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
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
	aid, oobi, seed, _, err = s.mintPairwiseIn("contacts", name)
	return aid, oobi, seed, err
}

// mintPairwiseIn is the same, in a named pool, and it hands back the index.
//
// THE POOL MATTERS. Every pairwise key is derived from one root seed and an
// index, so two pools that allocate from the same range hand out the same key
// for unrelated purposes — and two verifiers holding keys derived from one
// secret is exactly the correlation a pairwise identifier exists to prevent.
// A new kind of relationship gets a new pool rather than borrowing one.
//
// THE INDEX MATTERS TOO. It is the only way back to the key: an identity whose
// index was not written down can never sign again and can never be rotated or
// revoked. Callers that intend to use the identity later must store it.
func (s *CoreServer) mintPairwiseIn(pool, name string) (aid, oobi string, seed []byte, idx int, err error) {
	rootSeed, rerr := ensureRootSeed(s.DataDir)
	if rerr != nil {
		return "", "", nil, 0, rerr
	}
	idx, aerr := s.DataStore.AllocateNextRelationshipIndex(pool)
	if aerr != nil {
		return "", "", nil, 0, fmt.Errorf("allocate relationship index: %w", aerr)
	}
	seed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if derr != nil {
		return "", "", nil, 0, fmt.Errorf("derive pairwise seed: %w", derr)
	}
	nextSeed, _ := backup.DerivePairwiseSeed(rootSeed, idx, 1)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
	if s.KeriDriver == nil {
		return "", "", nil, 0, fmt.Errorf("keri driver required to mint pairwise AID")
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
		return "", "", nil, 0, fmt.Errorf("mint pairwise inception: %w", ierr)
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
	return icp.AID, oobi, seed, idx, nil
}

// ensureRootSeed loads this device's root seed, bootstrapping one if there is
// none yet.
//
// A freshly provisioned instance has never been through onboarding, so it has
// no seed at all — and it needs one before it can generate any key, including
// the one it offers for delegation. The canonical path is still the onboarding
// handoff installing the mnemonic-derived seed; a bootstrapped root is
// device-local, recoverable from this instance's own backup archives but never
// from the phrase alone.
func ensureRootSeed(dataDir string) ([]byte, error) {
	if seed, err := secureenclave.LoadRootSeed(dataDir); err == nil {
		return seed, nil
	}
	log.Printf("[keystore] WARNING: bootstrapping a random DEVICE-LOCAL root seed (no onboarding seed handoff yet) — HD-derived keys will not be recoverable from the seed phrase alone")
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := secureenclave.StoreRootSeed(dataDir, seed); err != nil {
		return nil, fmt.Errorf("bootstrap root seed: %w", err)
	}
	return seed, nil
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

// askAuth says how an Ask of a given action establishes who is asking.
type askAuth int

const (
	// authBaseSignature — the Ask carries `sig` + `signer_oobi` and this layer
	// verifies it. The default, deliberately: an action that says nothing about
	// how it is authenticated is required to be signed.
	authBaseSignature askAuth = iota
	// authSelfVerifying — the handler establishes the asker itself, with a
	// stronger check than this one. Login does: it verifies the challenge
	// signature against the key the site's own address publishes, and where an
	// anchor is claimed it requires a delegated inception naming it.
	authSelfVerifying
)

// AskAuthenticator is implemented by handlers that verify the asker themselves.
// Not implementing it means the Ask must be signed.
type AskAuthenticator interface{ AskAuth() askAuth }

// verifyAskSignature establishes who is asking, before anything is shown to a
// person or acted on.
//
// This used to return nil when either `sig` or `signer_oobi` was absent — so an
// Ask carrying neither was accepted unverified, on the strength of the address
// it was fetched from. That is most of the way to no authentication at all: the
// signature is what ties the request to an identity rather than to whoever
// controls a URL, and the actions that skipped it included the invitation that
// decides who owns an organisation.
//
// Now every action declares how it is authenticated and anything that does not
// verify is refused. Adding a new action therefore means signing it, or saying
// in code why it does not need to be — never leaving it out.
func (s *CoreServer) verifyAskSignature(askBytes []byte) error {
	t, terr := askActionType(askBytes)
	if terr != nil {
		return fmt.Errorf("this request does not say what it is asking for")
	}
	h, known := lookupAsk(t)
	if !known {
		// An unknown action cannot state how it authenticates itself, so there
		// is no way to decide whether this one did.
		return fmt.Errorf("this agent does not know action %d, so it cannot tell whether it is genuine", t)
	}
	if a, ok := h.(AskAuthenticator); ok && a.AskAuth() == authSelfVerifying {
		return nil
	}

	sig := jsonStringField(askBytes, "sig")
	signerOOBI := jsonStringField(askBytes, "signer_oobi")
	if sig == "" || signerOOBI == "" {
		return fmt.Errorf("this %s request is not signed, so nothing establishes who is asking", h.Action())
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
