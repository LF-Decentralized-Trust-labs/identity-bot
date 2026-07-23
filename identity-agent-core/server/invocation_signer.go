package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/secureenclave"
)

// invocationSigner signs invocation-log events (sandbox.EventSigner) with a stable
// pairwise identity: an HD-derived key (same derivation the ask-sign layer uses) whose
// AID is minted once via the KERI driver and persisted, so every audit event across
// restarts verifies against one published signer. The signing seed is re-derived from
// the root seed on demand — never stored.
type invocationSigner struct {
	s    *CoreServer
	mu   sync.Mutex
	aid  string
	key  ed25519.PrivateKey
	done bool
}

type invocationSignerRecord struct {
	AID   string `json:"aid"`
	Index int    `json:"index"`
}

func (sg *invocationSigner) recordPath() string {
	return filepath.Join(sg.s.DataDir, "invocation_signer.json")
}

// init derives (or restores) the signer identity lazily, on first sign — server
// dependencies (root seed, KERI driver) are ready by then.
func (sg *invocationSigner) init() error {
	if sg.done {
		return nil
	}
	rootSeed, err := secureenclave.LoadRootSeed(sg.s.DataDir)
	if err != nil {
		return fmt.Errorf("invocation signer: root seed unavailable: %w", err)
	}

	var rec invocationSignerRecord
	if data, rerr := os.ReadFile(sg.recordPath()); rerr == nil && json.Unmarshal(data, &rec) == nil && rec.AID != "" {
		seed, derr := backup.DerivePairwiseSeed(rootSeed, rec.Index, 0)
		if derr != nil {
			return fmt.Errorf("invocation signer: derive seed: %w", derr)
		}
		sg.aid = rec.AID
		sg.key = ed25519.NewKeyFromSeed(seed)
		sg.done = true
		return nil
	}

	if sg.s.KeriDriver == nil {
		return fmt.Errorf("invocation signer: keri driver required to mint the signer AID")
	}
	idx, aerr := sg.s.DataStore.AllocateNextRelationshipIndex("invocation-log")
	if aerr != nil {
		return fmt.Errorf("invocation signer: allocate index: %w", aerr)
	}
	seed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
	if derr != nil {
		return fmt.Errorf("invocation signer: derive seed: %w", derr)
	}
	nextSeed, _ := backup.DerivePairwiseSeed(rootSeed, idx, 1)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	nextPub := ed25519.NewKeyFromSeed(nextSeed).Public().(ed25519.PublicKey)
	icp, ierr := sg.s.KeriDriver.CreateInceptionNamed(
		iacrypto.VerkeyQB64(pub),
		iacrypto.VerkeyQB64(nextPub),
		fmt.Sprintf("invocation-log-%d", idx),
	)
	if ierr != nil || icp.AID == "" {
		return fmt.Errorf("invocation signer: mint inception: %w", ierr)
	}
	data, _ := json.Marshal(invocationSignerRecord{AID: icp.AID, Index: idx})
	if werr := os.WriteFile(sg.recordPath(), data, 0600); werr != nil {
		return fmt.Errorf("invocation signer: persist record: %w", werr)
	}
	sg.aid = icp.AID
	sg.key = ed25519.NewKeyFromSeed(seed)
	sg.done = true
	return nil
}

// SignEvent implements sandbox.EventSigner.
func (sg *invocationSigner) SignEvent(payload []byte) (string, string, error) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if err := sg.init(); err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(sg.key, payload)
	return sg.aid, base64.RawURLEncoding.EncodeToString(sig), nil
}
