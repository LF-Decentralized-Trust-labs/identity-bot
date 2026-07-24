package sandbox

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	"github.com/zeebo/blake3"
)

// The signed invocation log is the gateway's answer to "who did what, under whose
// authority". One event per governed invocation — including denials — written at the
// single chokepoint, signed by the agent's event-signer identity so the chain is
// verifiable by a third party.

// InvocationEvent is one audit record. Args are stored as a hash only — no caller
// arguments (and therefore no secrets/PII) at rest.
type InvocationEvent struct {
	ID              int64    `json:"id,omitempty"`
	TS              string   `json:"ts"`
	CallerAID       string   `json:"caller_aid,omitempty"`
	DelegationChain []string `json:"delegation_chain,omitempty"`
	GrantSAID       string   `json:"grant_said,omitempty"`
	CapabilityID    string   `json:"capability_id"`
	ArgsHash        string   `json:"args_hash,omitempty"`
	ResultStatus    string   `json:"result_status"` // ok | denied | error
	DurationMs      int64    `json:"duration_ms"`
	Transport       string   `json:"transport,omitempty"`
	ExecutorType    string   `json:"executor_type,omitempty"`
	CorrelationID   string   `json:"correlation_id,omitempty"`
	ParentEventID   string   `json:"parent_event_id,omitempty"`
	SignerAID       string   `json:"signer_aid,omitempty"`
	Signature       string   `json:"signature,omitempty"`
}

// EventSigner signs an invocation event's canonical JSON. The server layer injects an
// implementation backed by a KERI-anchored pairwise key; nil means events are written
// unsigned (degraded, logged — never silently dropped).
type EventSigner interface {
	SignEvent(payload []byte) (signerAID, signature string, err error)
}

// SetEventSigner injects the event-signing identity (server layer, at startup).
func (m *Manager) SetEventSigner(s EventSigner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventSigner = s
}

func (m *Manager) getEventSigner() EventSigner {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.eventSigner
}

// hashArgs content-addresses the caller's arguments for the audit record.
func hashArgs(args []byte) string {
	if len(args) == 0 {
		return ""
	}
	sum := blake3.Sum256(args)
	return "blake3:" + hex.EncodeToString(sum[:])
}

// recordInvocation writes one signed audit event and returns its row id (0 when the
// write failed or no store is wired). An audit-write failure never fails the
// invocation itself, but is logged loudly — the log is the governance record.
func (m *Manager) recordInvocation(caller CallerContext, capabilityID, executorType string, args []byte, status string, start time.Time) int64 {
	if m.store == nil {
		return 0
	}
	ev := InvocationEvent{
		TS:            start.UTC().Format(time.RFC3339Nano),
		CallerAID:     caller.CallerAID,
		CapabilityID:  capabilityID,
		ArgsHash:      hashArgs(args),
		ResultStatus:  status,
		DurationMs:    time.Since(start).Milliseconds(),
		Transport:     caller.Transport,
		ExecutorType:  executorType,
		CorrelationID: caller.CorrelationID,
	}
	// Sign the canonical event JSON (signature fields empty in the signed payload).
	if signer := m.getEventSigner(); signer != nil {
		payload, err := json.Marshal(ev)
		if err == nil {
			if aid, sig, serr := signer.SignEvent(payload); serr == nil {
				ev.SignerAID = aid
				ev.Signature = sig
			} else {
				log.Printf("[audit] UNSIGNED invocation event for %s: signer error: %v", capabilityID, serr)
			}
		}
	}
	id, err := m.store.InsertInvocationEvent(ev)
	if err != nil {
		log.Printf("[audit] FAILED to write invocation event for %s (caller %s, status %s): %v",
			capabilityID, caller.CallerAID, status, err)
		return 0
	}
	return id
}

// InsertInvocationEvent persists one event; returns its row id.
func (s *SandboxStore) InsertInvocationEvent(ev InvocationEvent) (int64, error) {
	chain, _ := json.Marshal(ev.DelegationChain)
	full, _ := json.Marshal(ev)
	res, err := s.db.Exec(`
		INSERT INTO invocation_log (ts, caller_aid, delegation_chain, grant_said,
			capability_id, args_hash, result_status, duration_ms, transport,
			executor_type, correlation_id, parent_event_id, signer_aid, signature, event_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS, ev.CallerAID, string(chain), ev.GrantSAID,
		ev.CapabilityID, ev.ArgsHash, ev.ResultStatus, ev.DurationMs, ev.Transport,
		ev.ExecutorType, ev.CorrelationID, ev.ParentEventID, ev.SignerAID, ev.Signature, string(full))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// InvocationEventFilter narrows QueryInvocationEvents; zero values mean "any".
type InvocationEventFilter struct {
	CapabilityID  string
	CorrelationID string
	CallerAID     string
	Limit         int
}

// QueryInvocationEvents reads the audit log, newest first (the Activity-view read).
func (s *SandboxStore) QueryInvocationEvents(f InvocationEventFilter) ([]InvocationEvent, error) {
	q := `SELECT id, event_json FROM invocation_log WHERE 1=1`
	var args []any
	if f.CapabilityID != "" {
		q += " AND capability_id = ?"
		args = append(args, f.CapabilityID)
	}
	if f.CorrelationID != "" {
		q += " AND correlation_id = ?"
		args = append(args, f.CorrelationID)
	}
	if f.CallerAID != "" {
		q += " AND caller_aid = ?"
		args = append(args, f.CallerAID)
	}
	q += " ORDER BY id DESC"
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q += " LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InvocationEvent
	for rows.Next() {
		var id int64
		var evJSON string
		if err := rows.Scan(&id, &evJSON); err != nil {
			return nil, err
		}
		var ev InvocationEvent
		if json.Unmarshal([]byte(evJSON), &ev) == nil {
			ev.ID = id
			out = append(out, ev)
		}
	}
	return out, rows.Err()
}
