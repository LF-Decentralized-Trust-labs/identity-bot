package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/authorisation"
	"identity-agent-core/internal/atomicfile"
)

// A person's signed statement works once (an_app_speaks_for_a_person_who_signed.go).
// What has been used is kept in a file beside the other records, for as long as
// a statement could still be fresh, so a restart does not make a statement
// that was used usable again: the cache of requests a machine signed
// (rememberSignature) is in memory only, and a statement is fresh for minutes.

// statementsUsedFor is how long a used statement is remembered: from its use,
// past the last moment it could be fresh (signed up to authorisation.Skew in the
// future, accepted until Skew after that), with a margin.
const statementsUsedFor = 3 * authorisation.Skew

var statementsUsedLock sync.Mutex

func (s *CoreServer) statementsUsedPath() string {
	return filepath.Join(s.DataDir, "person_statements_used.json")
}

// rememberPersonStatement records the statement with this signature as used and
// reports whether it already was. An error means it could not be kept, which is
// not an answer: the statement is then refused rather than risked.
func (s *CoreServer) rememberPersonStatement(signature string, now time.Time) (alreadyUsed bool, err error) {
	statementsUsedLock.Lock()
	defer statementsUsedLock.Unlock()
	used := map[string]time.Time{}
	raw, rerr := os.ReadFile(s.statementsUsedPath())
	switch {
	case os.IsNotExist(rerr):
	case rerr != nil:
		return false, fmt.Errorf("the statements already used could not be read: %w", rerr)
	default:
		if err := json.Unmarshal(raw, &used); err != nil {
			return false, fmt.Errorf("the statements already used are not readable: %w", err)
		}
	}
	for sig, at := range used {
		if now.Sub(at) > statementsUsedFor {
			delete(used, sig)
		}
	}
	if _, seen := used[signature]; seen {
		return true, nil
	}
	used[signature] = now
	out, err := json.Marshal(used)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return false, err
	}
	if err := atomicfile.Write(s.statementsUsedPath(), out, 0o600); err != nil {
		return false, fmt.Errorf("the statement could not be marked used: %w", err)
	}
	return false, nil
}
