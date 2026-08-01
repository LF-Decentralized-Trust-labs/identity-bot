package sandbox

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/zeebo/blake3"
)

// The signed invocation log is the gateway's answer to "who did what, under whose
// authority". One event per governed invocation — including denials — written at the
// single chokepoint, signed by the agent's event-signer identity so the chain is
// verifiable by a third party.

// InvocationEvent is one audit record. Arguments are stored as a hash plus a
// key-redacted preview — never the raw arguments, so secrets and PII are not at rest
// in the log while "what was this asked to do" stays answerable from it.
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
	AuthLevel       string   `json:"auth_level,omitempty"`
	ParentEventID   string   `json:"parent_event_id,omitempty"`
	// OrchestratedBy records the master orchestrator that dispatched this step (the
	// "under whose direction" dimension), distinct from CallerAID (the worker that
	// executed under its own authority). Empty for a direct call.
	OrchestratedBy string `json:"orchestrated_by,omitempty"`

	// ── Why this happened ──────────────────────────────────────────────
	// GrantSAID above answers "why was this permitted". These answer the
	// different question "what was it for", which no field previously carried:
	// the log could say an AI agent wrote code but not what it was trying to do.
	// Caller-supplied and never used in authorization — see CallerContext.
	WorkItem string `json:"work_item,omitempty"`
	Reason   string `json:"reason,omitempty"`

	// ── Why it ended the way it did ────────────────────────────────────
	// ResultStatus says denied; StatusReason says denied BY WHAT — the ceiling,
	// a resource constraint, a missing executor. A console that shows a refusal
	// without its cause sends someone hunting through logs to learn what the
	// gateway already knew at the moment it refused.
	StatusReason string `json:"status_reason,omitempty"`

	// ── What it cost ───────────────────────────────────────────────────
	// Optional, because absent and zero are different facts: absent means no cost
	// concept applies to this kind of call, zero means it was measured and free.
	Cost *Cost `json:"cost,omitempty"`

	// ── What it produced ───────────────────────────────────────────────
	// For a mutating capability the outcome IS the artifact — a commit, a PR, a
	// message id. Free-form because what counts as the artifact is the
	// capability's business, not the gateway's.
	Outcome string `json:"outcome,omitempty"`

	// ── What was asked ─────────────────────────────────────────────────
	// ArgsHash commits to the arguments but cannot be read. ArgsPreview is a
	// short redacted rendering so "what was it asked to do" is answerable from
	// the log itself, without weakening the hash beside it.
	ArgsPreview string `json:"args_preview,omitempty"`

	// ── Commitments over the whole interaction ─────────────────────────
	// ArgsHash covers the request; ResultHash covers the response. Together they
	// commit to both halves, so a stored payload can be re-derived and checked
	// against what actually crossed the gateway.
	ResultHash string `json:"result_hash,omitempty"`
	// PrevHash is the hash of the preceding event's signed record, making the log
	// a chain rather than a pile of independently-signed rows. Without it, each
	// row proves only its own contents: deleting a row, or reordering two, leaves
	// every remaining signature valid and the tampering invisible. It is set
	// BEFORE signing, so each signature covers its own link.
	PrevHash string `json:"prev_hash,omitempty"`

	SignerAID string `json:"signer_aid,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// Cost is what an invocation consumed. Deliberately not a currency amount: an LLM
// call costs tokens, a rate-limited API costs requests, a purchase costs money, and
// sending a message may cost nothing at all. Unit carries which of those it is, so
// the log can hold all of them without pretending they are the same quantity.
type Cost struct {
	Amount float64 `json:"amount"`
	// Unit is what Amount counts — "USD", "tokens", "requests", "seconds". Required
	// whenever Amount is set; a bare number is not a cost.
	Unit string `json:"unit"`
	// Basis is what produced the figure — a model name, a rate card, a meter. Lets a
	// reader tell a metered number from an estimated one.
	Basis string `json:"basis,omitempty"`
}

// EventDetail is what the executing layer learned that the caller could not supply:
// why a call was refused, what it cost, what it produced. Separate from CallerContext
// because these are outputs of the invocation, not inputs to it — and separate from a
// widening parameter list because every one of them is optional.
type EventDetail struct {
	StatusReason string
	Cost         *Cost
	Outcome      string
	ResultBody   []byte
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

// SetVaultKeyProvider injects the credential-vault key source (server layer,
// at startup) — the vault stays encrypted at rest and unlocks lazily.
func (m *Manager) SetVaultKeyProvider(p VaultKeyProvider) {
	m.credentials.SetKeyProvider(p)
}

// SetAuthorizer injects the real governance-gateway ingress/egress decision (server
// layer, at startup), replacing the structural default. Nil leaves the structural
// authorizer in place.
func (m *Manager) SetAuthorizer(a Authorizer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authorizer = a
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

// previewKeyBlocked are argument names whose VALUE is never previewed. The list is
// about shape, not about any particular integration: anything named like a secret is
// treated as one. Redaction is by key, so a secret that arrives under an innocuous
// name still reaches the preview — which is why the preview is a convenience for
// reading the log and the hash beside it remains the commitment.
var previewKeyBlocked = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey", "key",
	"credential", "authorization", "auth", "cookie", "session", "private",
	"seed", "mnemonic", "passphrase", "pin", "otp", "signature",
}

const previewMaxValue = 120

// previewArgs renders a short, redacted view of an invocation's arguments so a person
// reading the log can see what was asked. Only top-level scalars are shown: nested
// structures are the most likely place for a secret to hide under a name this function
// has never seen, and a preview is not worth that risk.
func previewArgs(args []byte) string {
	if len(args) == 0 {
		return ""
	}
	var m map[string]interface{}
	if err := json.Unmarshal(args, &m); err != nil {
		return "" // not a JSON object; the hash still commits to it
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // stable output, so two identical calls read identically
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+previewValue(k, m[k]))
	}
	return strings.Join(parts, " ")
}

func previewValue(key string, v interface{}) string {
	lower := strings.ToLower(key)
	for _, blocked := range previewKeyBlocked {
		if strings.Contains(lower, blocked) {
			return "[redacted]"
		}
	}
	switch t := v.(type) {
	case string:
		return truncate(t)
	case bool, float64, nil:
		return truncate(fmt.Sprint(t))
	default:
		// Arrays and objects are summarised, never rendered — see previewArgs.
		return "[object]"
	}
}

func truncate(s string) string {
	s = strings.Join(strings.Fields(s), " ") // collapse newlines; the log is one line per event
	if len(s) <= previewMaxValue {
		return s
	}
	return s[:previewMaxValue] + "…"
}

// recordInvocation writes one signed audit event and returns its row id (0 when the
// write failed or no store is wired). An audit-write failure never fails the
// invocation itself, but is logged loudly — the log is the governance record.
func (m *Manager) recordInvocation(caller CallerContext, capabilityID, executorType string, args []byte, status string, start time.Time) int64 {
	return m.recordInvocationDetail(caller, capabilityID, executorType, args, status, start, EventDetail{})
}

// recordInvocationDetail is recordInvocation plus what the executing layer learned.
//
// Writes serialize on auditMu. That is not incidental: PrevHash is read from the
// last row and must still be the last row when this one lands, or two concurrent
// invocations both chain onto the same predecessor and the chain silently forks.
func (m *Manager) recordInvocationDetail(caller CallerContext, capabilityID, executorType string, args []byte, status string, start time.Time, d EventDetail) int64 {
	if m.store == nil {
		return 0
	}
	m.auditMu.Lock()
	defer m.auditMu.Unlock()

	ev := InvocationEvent{
		TS:              start.UTC().Format(time.RFC3339Nano),
		CallerAID:       caller.CallerAID,
		DelegationChain: caller.DelegationChain,
		GrantSAID:       caller.GrantSAID,
		CapabilityID:    capabilityID,
		ArgsHash:        hashArgs(args),
		ResultStatus:    status,
		DurationMs:      time.Since(start).Milliseconds(),
		Transport:       caller.Transport,
		ExecutorType:    executorType,
		CorrelationID:   caller.CorrelationID,
		AuthLevel:       caller.AuthLevel,
		ParentEventID:   caller.ParentEventID,
		OrchestratedBy:  caller.OrchestratedBy,

		WorkItem:     caller.WorkItem,
		Reason:       caller.Reason,
		StatusReason: d.StatusReason,
		Cost:         d.Cost,
		Outcome:      d.Outcome,
		ArgsPreview:  previewArgs(args),
		ResultHash:   hashArgs(d.ResultBody),
	}
	// Chain to the previous record before signing, so the signature covers the link.
	// A chain-read failure must not drop the event — an unchained record still proves
	// its own contents, and losing the event entirely would prove nothing at all.
	if prev, err := m.store.LastEventHash(); err == nil {
		ev.PrevHash = prev
	} else {
		log.Printf("[audit] UNCHAINED invocation event for %s: could not read previous record: %v",
			capabilityID, err)
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

// RecordGovernedEvent writes one signed governance event for an action that is not a
// plug-in capability invocation — today the master orchestrator's dispatch event
// ("agent.orchestrate"), which anchors the worker steps that follow it (they carry its
// id as ParentEventID). Returns the event's row id (0 if unwritten). Exposed for the
// server layer; the same signing + chokepoint as a capability invocation.
func (m *Manager) RecordGovernedEvent(caller CallerContext, capabilityID, status string) int64 {
	return m.recordInvocation(caller, capabilityID, "orchestrator", nil, status, time.Now())
}

// InsertInvocationEvent persists one event; returns its row id.
func (s *SandboxStore) InsertInvocationEvent(ev InvocationEvent) (int64, error) {
	chain, _ := json.Marshal(ev.DelegationChain)
	full, _ := json.Marshal(ev)
	var costAmount interface{}
	var costUnit, costBasis string
	if ev.Cost != nil {
		costAmount, costUnit, costBasis = ev.Cost.Amount, ev.Cost.Unit, ev.Cost.Basis
	}
	res, err := s.db.Exec(`
		INSERT INTO invocation_log (ts, caller_aid, delegation_chain, grant_said,
			capability_id, args_hash, result_status, duration_ms, transport,
			executor_type, correlation_id, parent_event_id, signer_aid, signature, event_json,
			work_item, reason, status_reason, cost_amount, cost_unit, cost_basis,
			outcome, args_preview, result_hash, prev_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS, ev.CallerAID, string(chain), ev.GrantSAID,
		ev.CapabilityID, ev.ArgsHash, ev.ResultStatus, ev.DurationMs, ev.Transport,
		ev.ExecutorType, ev.CorrelationID, ev.ParentEventID, ev.SignerAID, ev.Signature, string(full),
		ev.WorkItem, ev.Reason, ev.StatusReason, costAmount, costUnit, costBasis,
		ev.Outcome, ev.ArgsPreview, ev.ResultHash, ev.PrevHash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// LastEventHash returns the hash of the most recent event's signed record — the value
// the next event chains onto. Empty (with no error) when the log is empty, which is
// the genesis case, not a failure.
//
// It hashes event_json, the stored record INCLUDING its signature, so the chain commits
// to what was actually written rather than to a re-derivation of it. That matters: a
// verifier walking the log re-hashes the stored bytes, so any edit to a row — including
// swapping in a differently-signed version — breaks the next row's link.
func (s *SandboxStore) LastEventHash() (string, error) {
	var stored string
	err := s.db.QueryRow(`SELECT event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&stored)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hashArgs([]byte(stored)), nil
}

// VerifyChain walks the log oldest-first and reports the id of the first event whose
// PrevHash does not match its predecessor's stored record. Returns 0 when the chain is
// intact. A deleted or reordered row shows up here; nothing else in the system notices.
func (s *SandboxStore) VerifyChain() (brokenAt int64, err error) {
	rows, err := s.db.Query(`SELECT id, event_json FROM invocation_log ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var prevHash string
	first := true
	for rows.Next() {
		var id int64
		var stored string
		if err := rows.Scan(&id, &stored); err != nil {
			return 0, err
		}
		var ev InvocationEvent
		if err := json.Unmarshal([]byte(stored), &ev); err != nil {
			return id, nil // an unreadable record is a broken record
		}
		// Rows written before the chain existed carry no PrevHash. Skip them rather
		// than reporting a break: they were never claimed to be chained, and treating
		// a pre-chain row as tampering would make the check useless on any real log.
		if !first && ev.PrevHash != "" && ev.PrevHash != prevHash {
			return id, nil
		}
		prevHash = hashArgs([]byte(stored))
		first = false
	}
	return 0, rows.Err()
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
