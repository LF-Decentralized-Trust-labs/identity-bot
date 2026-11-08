package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"identity-agent-core/internal/atomicfile"
	"identity-agent-core/login"
)

// The sign-in challenges an agent has issued, whether each is still waiting,
// and the hash of the secret that collects its result, are kept in one file in
// the data directory. Held only in memory, a restart forgot all three: a
// challenge answered before the restart could be answered again, because its
// "settled" mark went with it, and a person partway through signing in found
// the challenge gone.
const challengeStateFile = "login-challenges.json"

type challengeState struct {
	Challenges map[string]login.ChallengeBundle  `json:"challenges"`
	Status     map[string]map[string]interface{} `json:"status"`
	Collector  map[string]string                 `json:"collector"` // base64url SHA-256
}

// loadChallengeState reads the file written by saveChallengeStateLocked. A
// missing file is an agent that has issued nothing; an unreadable one is an
// error, because starting empty would silently unsettle every answered sign-in.
func (s *CoreServer) loadChallengeState(dataDir string) error {
	raw, err := os.ReadFile(filepath.Join(dataDir, challengeStateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st challengeState
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	s.challenges = st.Challenges
	s.challengeStatus = st.Status
	s.challengeCollector = map[string][32]byte{}
	for token, enc := range st.Collector {
		b, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil || len(b) != sha256.Size {
			return errors.New("login challenge state: bad collector hash")
		}
		var h [32]byte
		copy(h[:], b)
		s.challengeCollector[token] = h
	}
	if s.challenges == nil {
		s.challenges = map[string]login.ChallengeBundle{}
	}
	if s.challengeStatus == nil {
		s.challengeStatus = map[string]map[string]interface{}{}
	}
	return nil
}

// saveChallengeStateLocked writes the state; the caller holds challengeMu.
// The write is atomic, so a crash leaves the old state or the new, never part.
func (s *CoreServer) saveChallengeStateLocked() {
	if s.DataDir == "" {
		return
	}
	st := challengeState{
		Challenges: s.challenges,
		Status:     s.challengeStatus,
		Collector:  make(map[string]string, len(s.challengeCollector)),
	}
	for token, h := range s.challengeCollector {
		st.Collector[token] = base64.RawURLEncoding.EncodeToString(h[:])
	}
	raw, err := json.Marshal(st)
	if err == nil {
		err = atomicfile.Write(filepath.Join(s.DataDir, challengeStateFile), raw, 0o600)
	}
	if err != nil {
		// Memory is still right for this run; only a restart would lose it.
		log.Printf("[identity-agent-core] could not save login challenge state: %v", err)
	}
}
