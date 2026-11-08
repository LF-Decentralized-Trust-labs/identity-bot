package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

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
//
// It returns the error rather than logging it. Whoever is about to hand out a
// new sign-in must not do so if it could not be recorded: a restart would
// forget it was ever issued, or ever answered.
func (s *CoreServer) saveChallengeStateLocked() error {
	if s.DataDir == "" {
		return nil
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
		return fmt.Errorf("could not save login challenge state: %w", err)
	}
	return nil
}

// signInResultWindow is how long after a sign-in settles its result can still
// be collected. It matches the life of the challenge itself.
const signInResultWindow = 10 * time.Minute

// settledAt is when a sign-in's status was settled; zero if unknown. It is a
// number in memory and a float64 after a restart, and both are read.
func settledAt(st map[string]interface{}) time.Time {
	switch v := st["settled_at"].(type) {
	case int64:
		return time.Unix(v, 0)
	case float64:
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}

// collectSignIn is how a settled sign-in's result is read by the holder of its
// collector secret. The result is handed over ONCE and then forgotten: the
// identifier, the disclosures, the browser key and the member info are removed
// from what the agent keeps, leaving only that the sign-in ended and how. A
// result not collected within signInResultWindow of settling is forgotten
// unread. Nobody who holds the secret later, however they came by it, gets the
// person's identity.
//
// Anyone else, and anyone reading a sign-in with no collector secret minted,
// gets a copy of the status and takes nothing. If the forgetting cannot be
// recorded the result is not released (fail closed), so it cannot be
// collected again after a restart.
func (s *CoreServer) collectSignIn(token, offered string, now time.Time) (st map[string]interface{}, bound, held bool, err error) {
	s.challengeMu.Lock()
	defer s.challengeMu.Unlock()
	cur := s.challengeStatus[token]
	want, bound := s.challengeCollector[token]
	if bound {
		got := sha256.Sum256([]byte(offered))
		held = subtle.ConstantTimeCompare(got[:], want[:]) == 1
	}
	if cur == nil {
		return nil, bound, held, nil
	}
	st = make(map[string]interface{}, len(cur))
	for k, v := range cur {
		st[k] = v
	}
	if !held || cur["status"] == "pending" || cur["released"] == true {
		return st, bound, held, nil
	}
	forgotten := map[string]interface{}{"status": cur["status"], "released": true}
	if t, ok := cur["settled_at"]; ok {
		forgotten["settled_at"] = t
	}
	if at := settledAt(cur); at.IsZero() || now.Sub(at) > signInResultWindow {
		// Too late: forget it, and release none of it.
		st = forgotten
	}
	s.challengeStatus[token] = forgotten
	if err := s.saveChallengeStateLocked(); err != nil {
		s.challengeStatus[token] = cur
		return nil, bound, held, err
	}
	return st, bound, held, nil
}
