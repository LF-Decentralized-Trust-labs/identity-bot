package recovery

import (
	"fmt"
	"sync"
	"time"
)

// ErrRotationMandatory is returned when post-restore key rotation has not been completed.
type ErrRotationMandatory struct {
	SessionID string
}

func (e *ErrRotationMandatory) Error() string {
	return fmt.Sprintf("post-restore key rotation is mandatory before recovery session %s can activate", e.SessionID)
}

// RotationRequest captures the client-supplied rotation parameters.
type RotationRequest struct {
	Name             string `json:"name"`
	NewPublicKey     string `json:"new_public_key"`
	NewNextPublicKey string `json:"new_next_public_key"`
	CesrSignature    string `json:"cesr_signature,omitempty"`
}

// RotationResult is the outcome of a mandatory post-restore rotation.
type RotationResult struct {
	AID            string `json:"aid"`
	NewPublicKey   string `json:"new_public_key"`
	SequenceNumber int    `json:"sequence_number"`
	RotatedAt      string `json:"rotated_at"`
}

// KeriRotator performs KERI rotation via the driver (server layer implements this).
type KeriRotator interface {
	RotateAid(name, newPublicKey, newNextPublicKey string) (aid string, newPub string, seq int, err error)
}

// RotationTracker records whether mandatory rotation completed for a recovery
// session.
//
// This is a cache of something the session itself records, and not the record.
// It used to be the only place the fact lived, and it lives in memory — so an
// agent that restarted forgot that the rotation had happened and demanded it
// again, on a session whose whole purpose was to survive being waited out.
// Rebuilt from the sessions on disk at startup.
//
// Guarded, because the rotation route writes it while the activate route reads
// it, and an unsynchronised map in Go is a process-ending fatal error rather
// than a wrong answer.
type RotationTracker struct {
	mu        sync.Mutex
	Completed map[string]RotationResult
}

func NewRotationTracker() *RotationTracker {
	return &RotationTracker{Completed: map[string]RotationResult{}}
}

func (t *RotationTracker) MarkCompleted(sessionID string, result RotationResult) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Completed == nil {
		t.Completed = map[string]RotationResult{}
	}
	if result.RotatedAt == "" {
		result.RotatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	t.Completed[sessionID] = result
}

func (t *RotationTracker) IsCompleted(sessionID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.Completed[sessionID]
	return ok
}

// Forget drops a session's rotation record once the session is over.
func (t *RotationTracker) Forget(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.Completed, sessionID)
}

func (t *RotationTracker) RequireCompleted(sessionID string) error {
	if !t.IsCompleted(sessionID) {
		return &ErrRotationMandatory{SessionID: sessionID}
	}
	return nil
}

// ValidateRotationRequest ensures required rotation fields are present.
func ValidateRotationRequest(req RotationRequest) error {
	if req.Name == "" || req.NewPublicKey == "" || req.NewNextPublicKey == "" {
		return fmt.Errorf("name, new_public_key, and new_next_public_key are required")
	}
	return nil
}
