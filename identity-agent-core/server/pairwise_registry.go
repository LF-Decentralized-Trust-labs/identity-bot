package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/atomicfile"
)

// What this core publishes about the pairwise identifiers it minted, and the
// contact key checks it has done, belong to this core and to nothing else in
// the process: the embedded core is stopped and started against another
// identity's data, and one identity's identifiers must never be answered by
// another's core. The minted ones are also written beside the profile's data
// (pairwiseFile), so a stop and start of the same profile, which a phone does
// whenever the OS ends the core in the background, keeps what it minted.
type pairwiseRegistry struct {
	sync.Mutex
	keys   map[string]string // aid -> base64url Ed25519 pubkey
	kels   map[string][]map[string]interface{}
	checks map[string]kelCheckResult
}

func newPairwiseRegistry() *pairwiseRegistry {
	return &pairwiseRegistry{
		keys:   map[string]string{},
		kels:   map[string][]map[string]interface{}{},
		checks: map[string]kelCheckResult{},
	}
}

const pairwiseFile = "pairwise-minted.json"

type mintedPairwise struct {
	PublicKey string                   `json:"public_key"`
	KEL       []map[string]interface{} `json:"kel,omitempty"`
}

func (s *CoreServer) pairwise() *pairwiseRegistry {
	s.pairwiseMu.Lock()
	defer s.pairwiseMu.Unlock()
	if s.pairwiseReg == nil {
		s.pairwiseReg = newPairwiseRegistry()
	}
	return s.pairwiseReg
}

func (s *CoreServer) registerPairwiseKey(aid, publicKeyB64 string) {
	r := s.pairwise()
	r.Lock()
	r.keys[aid] = publicKeyB64
	r.Unlock()
}

func (s *CoreServer) getPairwiseKey(aid string) (string, bool) {
	r := s.pairwise()
	r.Lock()
	defer r.Unlock()
	k, ok := r.keys[aid]
	return k, ok
}

func (s *CoreServer) registerPairwiseKEL(aid string, kel []map[string]interface{}) {
	r := s.pairwise()
	r.Lock()
	r.kels[aid] = kel
	r.Unlock()
}

func (s *CoreServer) getPairwiseKEL(aid string) ([]map[string]interface{}, bool) {
	r := s.pairwise()
	r.Lock()
	defer r.Unlock()
	k, ok := r.kels[aid]
	return k, ok
}

func (s *CoreServer) cachedKelCheck(aid string) (kelCheckResult, bool) {
	r := s.pairwise()
	r.Lock()
	defer r.Unlock()
	hit, ok := r.checks[aid]
	return hit, ok
}

func (s *CoreServer) cacheKelCheck(aid string, res kelCheckResult) {
	r := s.pairwise()
	r.Lock()
	r.checks[aid] = res
	r.Unlock()
}

// forgetPublishedPairwise empties what this core published. The file beside
// the profile is left: it is what the next Start of this same profile reads.
func (s *CoreServer) forgetPublishedPairwise() {
	s.pairwiseMu.Lock()
	s.pairwiseReg = newPairwiseRegistry()
	s.pairwiseMu.Unlock()
}

// rememberMintedPairwise publishes a pairwise identifier this core has just
// minted and writes it down with the profile's data.
func (s *CoreServer) rememberMintedPairwise(aid, publicKeyB64 string, kel []map[string]interface{}) {
	s.registerPairwiseKey(aid, publicKeyB64)
	if len(kel) > 0 {
		s.registerPairwiseKEL(aid, kel)
	}
	if s.DataDir == "" {
		return
	}
	s.pairwiseFileMu.Lock()
	defer s.pairwiseFileMu.Unlock()
	all, _ := s.readMintedPairwise()
	all[aid] = mintedPairwise{PublicKey: publicKeyB64, KEL: kel}
	body, err := json.Marshal(all)
	if err == nil {
		err = atomicfile.Write(filepath.Join(s.DataDir, pairwiseFile), body, 0o600)
	}
	if err != nil {
		log.Printf("[pairwise] %s minted, but not written down (%v) — it will not be served again after a restart", aid, err)
	}
}

func (s *CoreServer) readMintedPairwise() (map[string]mintedPairwise, error) {
	all := map[string]mintedPairwise{}
	body, err := os.ReadFile(filepath.Join(s.DataDir, pairwiseFile))
	if errors.Is(err, fs.ErrNotExist) {
		return all, nil
	}
	if err == nil {
		err = json.Unmarshal(body, &all)
	}
	if err != nil {
		return map[string]mintedPairwise{}, err
	}
	return all, nil
}

// restoreMintedPairwise fills this core's registry from its own profile's data
// on Start.
func (s *CoreServer) restoreMintedPairwise() {
	if s.DataDir == "" {
		return
	}
	s.pairwiseFileMu.Lock()
	all, err := s.readMintedPairwise()
	s.pairwiseFileMu.Unlock()
	if err != nil {
		log.Printf("[pairwise] the record of minted identifiers could not be read (%v) — they will not resolve until minted again", err)
	}
	for aid, m := range all {
		s.registerPairwiseKey(aid, m.PublicKey)
		if len(m.KEL) > 0 {
			s.registerPairwiseKEL(aid, m.KEL)
		}
	}
}
