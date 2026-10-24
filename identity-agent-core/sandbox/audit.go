package sandbox

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"reflect"
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
	ResultStatus    string   `json:"result_status"` // ok | denied | error | started (recorded before an action runs)
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

	// Which machine the caller spoke from, when it was one of an AI agent's
	// bodies, and how strongly that machine's key is held. Recorded on every
	// event so nobody reads a weak proof as a strong one.
	BodyHost       string `json:"body_host,omitempty"`
	BodyGrade      string `json:"body_grade,omitempty"`
	BodyCredential string `json:"body_credential,omitempty"`

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

	// SignedPayload is the exact bytes Signature covers, kept beside the record
	// rather than inside it so anybody can check the signature without
	// reproducing how this code encodes an event. Empty on rows written before
	// it was kept.
	SignedPayload string `json:"-"`

	// IntentEventID is the "about to run" row this result follows: a governed
	// action is recorded before it runs, and its result after.
	IntentEventID int64 `json:"intent_event_id,omitempty"`
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
	IntentEventID int64
	StatusReason  string
	Cost          *Cost
	Outcome       string
	ResultBody    []byte
}

// EventSigner signs an invocation event's canonical JSON. The server layer injects an
// implementation backed by a KERI-anchored pairwise key; nil means events are written
// unsigned (degraded, logged — never silently dropped).
type EventSigner interface {
	SignEvent(payload []byte) (signerAID, signature string, err error)
}

// ChainStart is where the log's signed chain begins: the first row id it
// covers, and the hash of that row as stored once it exists. It is kept outside
// the database, so somebody who can rewrite the database cannot move where the
// chain begins and pass the signed rows off as rows from before signing
// existed. A signer stamps it when it is created, before it signs anything, so
// on a fresh installation no row ever goes uncovered; Hash is filled in when
// the first row is written.
type ChainStart struct {
	ID   int64  `json:"id"`
	Hash string `json:"hash,omitempty"`
	// PayloadFrom is the first row that must keep the exact bytes its signature
	// covers. Rows from it on are checked over those bytes only; a row there
	// without them fails. Zero when not known.
	PayloadFrom int64 `json:"payload_from,omitempty"`
	// Linked is true when every row from the start on was written linked to the
	// one before it, which holds for every chain begun by this code. It is false
	// only for a start recorded after an upgrade, on a log signed before links
	// existed; there links are required from the first linked row on.
	Linked bool `json:"linked,omitempty"`
}

// ChainKeeper is an EventSigner that remembers where its chain begins.
// KeepChainStart keeps a start once; after that it only fills in the hash of a
// start stamped before its first row existed.
type ChainKeeper interface {
	ChainStart() (start ChainStart, kept bool, err error)
	KeepChainStart(ChainStart) error
}

// ErrNotRecorded means a governed action was refused because its record could
// not be written first. An action nobody can account for afterwards does not
// run.
var ErrNotRecorded = errors.New("the action was not run because it could not be recorded")

// ErrCannotCheck means the log cannot be checked right now, for example because
// the signer's key cannot be derived. It is never evidence that the log was
// changed, and must not be reported as if it were.
var ErrCannotCheck = errors.New("the log cannot be checked")

// chainBegun reports whether this log's signed chain has begun.
func (m *Manager) chainBegun() bool {
	keeper, ok := m.getEventSigner().(ChainKeeper)
	if !ok {
		return false
	}
	_, kept, err := keeper.ChainStart()
	if err != nil {
		log.Printf("[audit] could not read where the log's chain begins: %v", err)
		return false
	}
	return kept
}

// EnsureChainStart records where the chain begins on a log that was signed
// before the start was kept outside the database: the first signed row. It
// trusts the database once, at the first start after upgrading; from then on
// the start is fixed. Does nothing when the start is already kept or nothing
// has been signed yet.
func (m *Manager) EnsureChainStart() error {
	keeper, ok := m.getEventSigner().(ChainKeeper)
	if !ok || m.store == nil {
		return nil
	}
	if _, kept, err := keeper.ChainStart(); err != nil || kept {
		return err
	}
	var id int64
	var stored sql.NullString
	err := m.store.db.QueryRow(`SELECT id, event_json FROM invocation_log
		WHERE signature IS NOT NULL AND signature != '' ORDER BY id ASC LIMIT 1`).Scan(&id, &stored)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	// Rows written from now on keep their signed bytes; earlier ones never did.
	next, err := m.store.NextEventID()
	if err != nil {
		return err
	}
	return keeper.KeepChainStart(ChainStart{ID: id, Hash: linkTo(stored), PayloadFrom: next})
}

// NextEventID is the id the next row will be given, or one below it: ids are
// never reused, so every row written from now on has at least this id.
func (s *SandboxStore) NextEventID() (int64, error) {
	var next int64
	err := s.db.QueryRow(`SELECT MAX(
		COALESCE((SELECT MAX(id) FROM invocation_log), 0),
		COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'invocation_log'), 0)) + 1`).Scan(&next)
	if err != nil {
		// sqlite_sequence does not exist until the first row is written.
		err = s.db.QueryRow(`SELECT COALESCE(MAX(id), 0) + 1 FROM invocation_log`).Scan(&next)
	}
	return next, err
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

// HashRecord is the link one event's PrevHash names: the hash of the record
// before it, exactly as it was stored. Anything checking the log elsewhere
// computes links with this.
func HashRecord(stored []byte) string { return hashArgs(stored) }

// missingRecordLink is what the row after a missing record links to: a fixed
// value, so a missing row is a fault in the log rather than a stop to it, and
// the rows after it can still be written and checked.
var missingRecordLink = HashRecord([]byte("null"))

// linkTo is the link to a stored record, or missingRecordLink when there is
// none.
func linkTo(stored sql.NullString) string {
	if !stored.Valid || stored.String == "" {
		return missingRecordLink
	}
	return HashRecord([]byte(stored.String))
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
	id, err := m.writeEvent(newEvent(caller, capabilityID, executorType, args, status, start, d), false)
	if err != nil {
		log.Printf("[audit] EVENT NOT WRITTEN for %s (caller %s, status %s): %v",
			capabilityID, caller.CallerAID, status, err)
	}
	return id
}

// recordIntent writes the "about to run" row a governed action needs before it
// runs: who asked, for what, with which arguments. Unlike a result row, it
// fails rather than degrade: when a signer is configured the row must be
// linked and signed, and when it cannot be written the action must not run.
// Recording only afterwards would let an action happen with no record at all
// whenever writing the record failed, and somebody able to break the log
// could then act unrecorded.
func (m *Manager) recordIntent(caller CallerContext, capabilityID, executorType string, args []byte, start time.Time) (int64, error) {
	ev := newEvent(caller, capabilityID, executorType, args, "started", start, EventDetail{StatusReason: "about to run"})
	ev.DurationMs = 0
	return m.writeEvent(ev, true)
}

func newEvent(caller CallerContext, capabilityID, executorType string, args []byte, status string, start time.Time, d EventDetail) InvocationEvent {
	return InvocationEvent{
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
		BodyHost:        caller.BodyHost,
		BodyGrade:       caller.BodyGrade,
		BodyCredential:  caller.BodyCredential,

		WorkItem:      caller.WorkItem,
		Reason:        caller.Reason,
		StatusReason:  d.StatusReason,
		Cost:          d.Cost,
		Outcome:       d.Outcome,
		ArgsPreview:   previewArgs(args),
		ResultHash:    hashArgs(d.ResultBody),
		IntentEventID: d.IntentEventID,
	}
}

// writeEvent links, signs and writes one row, and returns its id. With no
// store wired there is no log, and nothing is written.
//
// Once the signed chain has begun, every row from there on must be linked and
// signed. A row that is not would mark an honest log broken for good, and is
// exactly the shape a rewrite would use to pass a forged row off as an old one,
// so such a row is not written and the reason is returned. strict holds a row
// to that whenever a signer is configured, even before the chain has begun.
func (m *Manager) writeEvent(ev InvocationEvent, strict bool) (int64, error) {
	if m.store == nil {
		return 0, nil
	}
	m.auditMu.Lock()
	defer m.auditMu.Unlock()

	signer := m.getEventSigner()
	begun := m.chainBegun()
	must := begun || (strict && signer != nil)
	// Chain to the previous record before signing, so the signature covers the link.
	if prev, err := m.store.LastEventHash(); err == nil {
		ev.PrevHash = prev
	} else if must {
		return 0, fmt.Errorf("could not read the previous record to link to: %w", err)
	} else {
		log.Printf("[audit] UNCHAINED invocation event for %s: could not read previous record: %v",
			ev.CapabilityID, err)
	}
	// Sign the canonical event JSON (signature fields empty in the signed payload),
	// and keep the signed bytes beside the record.
	switch {
	case signer == nil && begun:
		return 0, fmt.Errorf("no signer")
	case signer != nil:
		payload, err := json.Marshal(ev)
		if err != nil {
			if must {
				return 0, fmt.Errorf("could not encode the event to sign it: %w", err)
			}
			break
		}
		aid, sig, serr := signer.SignEvent(payload)
		if serr != nil {
			if must {
				return 0, fmt.Errorf("could not sign it: %w", serr)
			}
			log.Printf("[audit] UNSIGNED invocation event for %s: signer error: %v", ev.CapabilityID, serr)
			break
		}
		ev.SignerAID, ev.Signature, ev.SignedPayload = aid, sig, string(payload)
	}
	id, err := m.store.InsertInvocationEvent(ev)
	if err != nil {
		return 0, err
	}
	// The first signed row is where the chain begins: keep it, or fill in the
	// hash of a start stamped before the row existed, outside the database so it
	// cannot be moved later.
	if keeper, ok := signer.(ChainKeeper); ok && ev.Signature != "" {
		if kept, has, cerr := keeper.ChainStart(); cerr == nil && (!has || kept.Hash == "") {
			if stored, herr := m.store.eventJSON(id); herr != nil {
				log.Printf("[audit] could not read back the first signed record to keep where the chain begins: %v", herr)
			} else if kerr := keeper.KeepChainStart(ChainStart{ID: id, Hash: HashRecord(stored), Linked: true, PayloadFrom: id}); kerr != nil {
				log.Printf("[audit] could not keep where the log's chain begins: %v", kerr)
			}
		}
	}
	return id, nil
}

// RecordGovernedEvent writes one signed governance event for an action that is not a
// plug-in capability invocation — today the master orchestrator's dispatch event
// ("agent.orchestrate"), which anchors the worker steps that follow it (they carry its
// id as ParentEventID). Returns the event's row id (0 if unwritten). Exposed for the
// server layer; the same signing + chokepoint as a capability invocation.
func (m *Manager) RecordGovernedEvent(caller CallerContext, capabilityID, status string) int64 {
	return m.recordInvocation(caller, capabilityID, "orchestrator", nil, status, time.Now())
}

// RecordGovernanceEvent writes one signed governance event for a decision about
// an AI agent rather than an action it took — a machine asking to become its
// body, approved, rejected, removed. Same signing and chain as an invocation;
// the caller's Reason says why.
func (m *Manager) RecordGovernanceEvent(caller CallerContext, eventID, status string) int64 {
	return m.recordInvocation(caller, eventID, "governance", nil, status, time.Now())
}

// RecordGovernanceEventAbout is RecordGovernanceEvent with what the event is
// about committed in the signed row's argument digest (HashArgs), so anything
// kept elsewhere about it can later be checked against the log: changing it
// after the fact no longer matches the row that was signed when it happened.
func (m *Manager) RecordGovernanceEventAbout(caller CallerContext, eventID, status string, about []byte) int64 {
	return m.recordInvocation(caller, eventID, "governance", about, status, time.Now())
}

// HashArgs is the digest the log keeps of an event's arguments, for a reader
// recomputing it from what the event was about.
func HashArgs(args []byte) string { return hashArgs(args) }

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
			outcome, args_preview, result_hash, prev_hash, signed_payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TS, ev.CallerAID, string(chain), ev.GrantSAID,
		ev.CapabilityID, ev.ArgsHash, ev.ResultStatus, ev.DurationMs, ev.Transport,
		ev.ExecutorType, ev.CorrelationID, ev.ParentEventID, ev.SignerAID, ev.Signature, string(full),
		ev.WorkItem, ev.Reason, ev.StatusReason, costAmount, costUnit, costBasis,
		ev.Outcome, ev.ArgsPreview, ev.ResultHash, ev.PrevHash, ev.SignedPayload)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// eventJSON is one row's record exactly as stored.
func (s *SandboxStore) eventJSON(id int64) ([]byte, error) {
	var stored sql.NullString
	if err := s.db.QueryRow(`SELECT event_json FROM invocation_log WHERE id = ?`, id).Scan(&stored); err != nil {
		return nil, err
	}
	if !stored.Valid {
		return nil, fmt.Errorf("row %d has no record", id)
	}
	return []byte(stored.String), nil
}

// LastEventHash returns the hash of the most recent event's signed record — the value
// the next event chains onto. Empty (with no error) when the log is empty, which is
// the genesis case, not a failure.
//
// It hashes event_json, the stored record INCLUDING its signature, so the chain commits
// to what was actually written rather than to a re-derivation of it. That matters: a
// verifier walking the log re-hashes the stored bytes, so any edit to a row — including
// swapping in a differently-signed version — breaks the next row's link.
//
// A row whose record is missing links on as missingRecordLink: the gap is
// reported by VerifyChain at that row, and the log goes on rather than
// stopping every later event at it.
func (s *SandboxStore) LastEventHash() (string, error) {
	var stored sql.NullString
	err := s.db.QueryRow(`SELECT event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&stored)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return linkTo(stored), nil
}

// EventKeys returns the public key an event signer's identity signs with, or an
// error when the identity is not one this log knows. An error wrapping
// ErrCannotCheck means the key cannot be had right now.
type EventKeys func(signerAID string) (ed25519.PublicKey, error)

// ChainFault is one row of the log that does not hold, and why.
type ChainFault struct {
	ID     int64  `json:"id"`
	Reason string `json:"reason"`
}

// Head is the newest row of the log and the link the next row will name: its
// id, and the hash of it as stored. Zero and empty when the log is empty.
func (s *SandboxStore) Head() (int64, string, error) {
	var id int64
	var stored string
	err := s.db.QueryRow(`SELECT id, event_json FROM invocation_log ORDER BY id DESC LIMIT 1`).Scan(&id, &stored)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	return id, HashRecord([]byte(stored)), nil
}

// RowHash is the hash of one row as stored, and whether the row is there.
func (s *SandboxStore) RowHash(id int64) (string, bool, error) {
	var stored string
	err := s.db.QueryRow(`SELECT event_json FROM invocation_log WHERE id = ?`, id).Scan(&stored)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return HashRecord([]byte(stored)), true, nil
}

// RowsAfter counts the rows written after id.
func (s *SandboxStore) RowsAfter(id int64) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM invocation_log WHERE id > ?`, id).Scan(&n)
	return n, err
}

// VerifyChain walks the log oldest-first and reports every row that does not
// hold, with why. An empty result means every row holds. Every row is
// reported, not only the first, so one damaged row cannot hide a forged one
// after it. An error wrapping ErrCannotCheck means the log could not be
// checked, which says nothing either way about whether it was changed.
//
// start is where the signed chain begins, kept outside the database
// (ChainKeeper); nil when none is kept yet. With it, the row at start must be
// the record kept there, and every row from it on must be signed, so a
// rewrite cannot turn signed rows into rows that look older than signing.
// Without it, the chain is taken to begin at the first row carrying a link or
// a signature, which only somebody without database access can rely on.
//
// Three things are checked, because each catches what the others cannot.
// The signature: a row rewritten together with every link after it still
// fails. The link: each row names the hash of the stored record before it, so
// a deleted, reordered or edited row breaks the next row's link. Links are
// required from the start when it was kept linked (ChainStart.Linked), and
// otherwise from the first linked row on, so rows signed before links existed
// verify on their signatures alone; a signed row cannot drop its link, because
// the link is inside what was signed. The columns a reader filters and totals
// on: they must say what the record says, or a filtered view could be changed
// without touching the record.
func (s *SandboxStore) VerifyChain(keys EventKeys, start *ChainStart) ([]ChainFault, error) {
	rows, err := s.db.Query(`SELECT id, event_json, COALESCE(signed_payload, ''),
		COALESCE(ts, ''), COALESCE(caller_aid, ''), COALESCE(capability_id, ''),
		COALESCE(correlation_id, ''), COALESCE(work_item, ''), COALESCE(result_status, ''),
		COALESCE(executor_type, ''), COALESCE(duration_ms, 0), cost_amount, COALESCE(cost_unit, '')
		FROM invocation_log ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var faults []ChainFault
	fault := func(id int64, why string) { faults = append(faults, ChainFault{ID: id, Reason: why}) }
	var prevHash string
	signedFromHere, linkedFromHere := false, false
	sawStart := false
	for rows.Next() {
		var id, durationMs int64
		var stored sql.NullString
		var payload string
		var cols eventColumns
		var costAmount sql.NullFloat64
		if err := rows.Scan(&id, &stored, &payload, &cols.ts, &cols.callerAID, &cols.capabilityID,
			&cols.correlationID, &cols.workItem, &cols.resultStatus, &cols.executorType,
			&durationMs, &costAmount, &cols.costUnit); err != nil {
			return nil, err
		}
		cols.durationMs = durationMs
		cols.costAmount = costAmount
		storedHash := linkTo(stored)
		if start != nil && id == start.ID {
			sawStart = true
		}
		if !stored.Valid || stored.String == "" {
			// A missing record is a fault at its own row, and the log goes on:
			// the row after it links to missingRecordLink.
			fault(id, "the record is missing")
			prevHash = storedHash
			continue
		}
		ev, rerr := decodeEvent([]byte(stored.String))
		if rerr != nil {
			fault(id, "the record cannot be read: "+rerr.Error())
			prevHash = storedHash
			continue
		}
		if start != nil && id == start.ID && start.Hash != "" {
			if storedHash != start.Hash {
				fault(id, "the record the signed chain begins with is not the one kept when it began")
			}
		}
		if start != nil {
			if id >= start.ID {
				signedFromHere = true
			}
		} else if ev.PrevHash != "" || ev.Signature != "" {
			signedFromHere = true
		}
		if start != nil && start.Hash != "" && id > start.ID && !sawStart {
			fault(start.ID, "the record the signed chain begins with is missing")
			sawStart = true
		}
		if ev.PrevHash != "" || (start != nil && start.Linked && id >= start.ID) {
			linkedFromHere = true
		}
		if linkedFromHere && ev.PrevHash != prevHash {
			fault(id, "the record does not follow from the one before it")
		}
		if signedFromHere || ev.Signature != "" {
			mustKeepPayload := start != nil && start.PayloadFrom > 0 && id >= start.PayloadFrom
			why, cerr := verifyEventSignature(ev, []byte(payload), mustKeepPayload, keys)
			if cerr != nil {
				return nil, cerr
			}
			if why != "" {
				fault(id, why)
			}
		}
		if why := cols.disagreeWith(ev); why != "" {
			fault(id, why)
		}
		prevHash = storedHash
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if start != nil && start.Hash != "" && !sawStart {
		fault(start.ID, "the record the signed chain begins with is missing")
	}
	return faults, nil
}

// decodeEvent reads a stored record, refusing anything this log never writes:
// a field an event does not have, a key spelled in another case, or a key
// given twice. Go's decoder would otherwise take any of those quietly, so two
// different records could read as the same event.
func decodeEvent(stored []byte) (InvocationEvent, error) {
	var ev InvocationEvent
	if err := checkKeys(stored); err != nil {
		return ev, err
	}
	dec := json.NewDecoder(bytes.NewReader(stored))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return ev, err
	}
	if dec.More() {
		return ev, fmt.Errorf("more than one record")
	}
	return ev, nil
}

var (
	eventKeys = jsonKeys(reflect.TypeOf(InvocationEvent{}))
	costKeys  = jsonKeys(reflect.TypeOf(Cost{}))
)

// jsonKeys is the exact set of keys a struct is written with.
func jsonKeys(t reflect.Type) map[string]bool {
	keys := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// checkKeys refuses a record whose keys are not exactly the ones an event is
// written with, once each.
func checkKeys(stored []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(stored, &top); err != nil {
		return err
	}
	if err := exactKeysOnce(stored, eventKeys); err != nil {
		return err
	}
	if c, ok := top["cost"]; ok && string(c) != "null" {
		return exactKeysOnce(c, costKeys)
	}
	return nil
}

// exactKeysOnce reads one JSON object's own keys in order and refuses any not
// in allowed, or any given twice.
func exactKeysOnce(obj []byte, allowed map[string]bool) error {
	dec := json.NewDecoder(bytes.NewReader(obj))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		if !allowed[key] {
			return fmt.Errorf("a key it was not written with: %q", key)
		}
		if seen[key] {
			return fmt.Errorf("the key %q twice", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

// eventColumns are the columns a reader filters and totals on.
type eventColumns struct {
	ts, callerAID, capabilityID, correlationID, workItem, resultStatus, executorType, costUnit string
	durationMs                                                                                 int64
	costAmount                                                                                 sql.NullFloat64
}

// disagreeWith reports how the columns differ from the record, or "".
func (c eventColumns) disagreeWith(ev InvocationEvent) string {
	var wantAmount sql.NullFloat64
	wantUnit := ""
	if ev.Cost != nil {
		wantAmount = sql.NullFloat64{Float64: ev.Cost.Amount, Valid: true}
		wantUnit = ev.Cost.Unit
	}
	for _, f := range []struct {
		name      string
		got, want any
	}{
		{"ts", c.ts, ev.TS},
		{"caller_aid", c.callerAID, ev.CallerAID},
		{"capability_id", c.capabilityID, ev.CapabilityID},
		{"correlation_id", c.correlationID, ev.CorrelationID},
		{"work_item", c.workItem, ev.WorkItem},
		{"result_status", c.resultStatus, ev.ResultStatus},
		{"executor_type", c.executorType, ev.ExecutorType},
		{"duration_ms", c.durationMs, ev.DurationMs},
		{"cost_amount", c.costAmount, wantAmount},
		{"cost_unit", c.costUnit, wantUnit},
	} {
		if f.got != f.want {
			return fmt.Sprintf("the record's %s column says %v, but the record says %v", f.name, f.got, f.want)
		}
	}
	return ""
}

// verifyEventSignature checks an event's signature. Where the signed bytes
// were kept, it checks the signature over exactly those bytes and that they
// say what the record says; otherwise over the event with its signer and
// signature left empty, encoded as recordInvocation encodes it. Returns why
// it fails, or "", or an error wrapping ErrCannotCheck.
//
// mustKeep says the row was written after signed bytes were always kept, so
// re-encoding is no substitute: without them the row fails.
func verifyEventSignature(ev InvocationEvent, kept []byte, mustKeep bool, keys EventKeys) (string, error) {
	if ev.Signature == "" || ev.SignerAID == "" {
		return "the record is not signed", nil
	}
	if mustKeep && len(kept) == 0 {
		return "the bytes its signature covers are missing", nil
	}
	if keys == nil {
		return "", fmt.Errorf("%w: no signer keys were given", ErrCannotCheck)
	}
	pub, err := keys(ev.SignerAID)
	if errors.Is(err, ErrCannotCheck) {
		return "", err
	}
	if err != nil {
		return fmt.Sprintf("the record's signer %s is not this log's: %v", ev.SignerAID, err), nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(ev.Signature)
	if err != nil {
		return "the record's signature is not readable", nil
	}
	signed := ev
	signed.SignerAID, signed.Signature = "", ""
	payload := kept
	if len(payload) > 0 {
		said, derr := decodeEvent(payload)
		if derr != nil || !reflect.DeepEqual(said, signed) {
			return "the record does not say what was signed", nil
		}
	} else if payload, err = json.Marshal(signed); err != nil {
		return "the record cannot be encoded to check its signature", nil
	}
	if !ed25519.Verify(pub, payload, sig) {
		return "the record's signature does not verify", nil
	}
	return "", nil
}

// InvocationEventFilter narrows QueryInvocationEvents; zero values mean "any".
type InvocationEventFilter struct {
	CapabilityID  string
	CorrelationID string
	CallerAID     string
	// WorkItem narrows to one piece of work, which is how a reader asks the question
	// they usually actually have: not "what did this caller do" but "what was done
	// for this task, by whoever did it".
	WorkItem string
	// ResultStatus is ok | denied | error | started. Anything else matches nothing rather than
	// being ignored, so a typo shows up as an empty result instead of silently
	// widening the query back to everything.
	ResultStatus string
	ExecutorType string
	// Since and Until bound the window, RFC3339. Compared as strings because the
	// column stores RFC3339Nano UTC, which sorts lexically in the same order it sorts
	// chronologically — true only because every timestamp is written in that one form.
	Since string
	Until string
	Limit int
}

const (
	defaultEventLimit = 100
	maxEventLimit     = 500
)

// EffectiveLimit is the limit that will actually be applied. Exported so a caller can
// tell whether a full page means "this is everything" or "there is more".
func (f InvocationEventFilter) EffectiveLimit() int {
	if f.Limit <= 0 || f.Limit > maxEventLimit {
		return defaultEventLimit
	}
	return f.Limit
}

// InvocationSummary is the log aggregated into the few numbers a console leads with.
type InvocationSummary struct {
	Total      int64            `json:"total"`
	ByStatus   map[string]int64 `json:"by_status"`
	ByExecutor map[string]int64 `json:"by_executor"`
	// CostByUnit is keyed by unit and never summed across units — adding USD to
	// tokens produces a number that means nothing.
	CostByUnit map[string]float64 `json:"cost_by_unit"`
	// Costed counts how many invocations carried a cost at all. Without it, a total
	// of zero reads as "this was free" when it may mean "nothing reported a cost".
	Costed        int64  `json:"costed"`
	TotalDuration int64  `json:"total_duration_ms"`
	FirstEvent    string `json:"first_event,omitempty"`
	LastEvent     string `json:"last_event,omitempty"`
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
	if f.WorkItem != "" {
		q += " AND work_item = ?"
		args = append(args, f.WorkItem)
	}
	if f.ResultStatus != "" {
		q += " AND result_status = ?"
		args = append(args, f.ResultStatus)
	}
	if f.ExecutorType != "" {
		q += " AND executor_type = ?"
		args = append(args, f.ExecutorType)
	}
	if f.Since != "" {
		q += " AND ts >= ?"
		args = append(args, f.Since)
	}
	if f.Until != "" {
		q += " AND ts <= ?"
		args = append(args, f.Until)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, f.EffectiveLimit())

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InvocationEvent
	for rows.Next() {
		var id int64
		var evJSON sql.NullString
		if err := rows.Scan(&id, &evJSON); err != nil {
			return nil, err
		}
		var ev InvocationEvent
		if !evJSON.Valid || json.Unmarshal([]byte(evJSON.String), &ev) != nil {
			// Shown, not dropped: a record that cannot be read is itself
			// something a reader of the log needs to see.
			ev = InvocationEvent{StatusReason: "this record is missing or cannot be read"}
		}
		ev.ID = id
		out = append(out, ev)
	}
	return out, rows.Err()
}

// GetInvocationEvent returns one event by row id.
func (s *SandboxStore) GetInvocationEvent(id int64) (InvocationEvent, error) {
	var stored sql.NullString
	err := s.db.QueryRow(`SELECT event_json FROM invocation_log WHERE id = ?`, id).Scan(&stored)
	if err == sql.ErrNoRows {
		return InvocationEvent{}, fmt.Errorf("no invocation event with id %d", id)
	}
	if err != nil {
		return InvocationEvent{}, err
	}
	var ev InvocationEvent
	if !stored.Valid {
		return InvocationEvent{}, fmt.Errorf("event %d is missing its record", id)
	}
	if err := json.Unmarshal([]byte(stored.String), &ev); err != nil {
		return InvocationEvent{}, fmt.Errorf("event %d is not readable: %w", id, err)
	}
	ev.ID = id
	return ev, nil
}

// SummariseInvocations aggregates the log, optionally from a starting timestamp.
//
// Costs are grouped by unit and never totalled across units: a single number combining
// dollars, tokens and request counts would be arithmetically valid and completely
// meaningless. Rows with no cost are excluded from the totals and counted separately,
// because "nothing reported a cost" and "this was free" are different facts and only
// one of them is good news.
func (s *SandboxStore) SummariseInvocations(since string) (InvocationSummary, error) {
	out := InvocationSummary{
		ByStatus:   map[string]int64{},
		ByExecutor: map[string]int64{},
		CostByUnit: map[string]float64{},
	}
	// An "about to run" row is the first half of one action, not an action of
	// its own, so the totals count results only.
	where := " WHERE COALESCE(result_status, '') != 'started'"
	var args []any
	if since != "" {
		where += " AND ts >= ?"
		args = append(args, since)
	}

	err := s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(duration_ms),0), COALESCE(MIN(ts),''), COALESCE(MAX(ts),'')
		 FROM invocation_log`+where, args...).
		Scan(&out.Total, &out.TotalDuration, &out.FirstEvent, &out.LastEvent)
	if err != nil {
		return out, err
	}

	if err := s.tally(`SELECT result_status, COUNT(*) FROM invocation_log`+where+
		` GROUP BY result_status`, args, out.ByStatus); err != nil {
		return out, err
	}
	if err := s.tally(`SELECT COALESCE(executor_type,'unknown'), COUNT(*) FROM invocation_log`+where+
		` GROUP BY executor_type`, args, out.ByExecutor); err != nil {
		return out, err
	}

	costWhere := " WHERE cost_amount IS NOT NULL AND cost_unit IS NOT NULL AND cost_unit != ''"
	costArgs := args
	if since != "" {
		costWhere += " AND ts >= ?"
	} else {
		costArgs = nil
	}
	rows, err := s.db.Query(`SELECT cost_unit, SUM(cost_amount), COUNT(*) FROM invocation_log`+
		costWhere+` GROUP BY cost_unit`, costArgs...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var unit string
		var amount float64
		var n int64
		if err := rows.Scan(&unit, &amount, &n); err != nil {
			return out, err
		}
		out.CostByUnit[unit] = amount
		out.Costed += n
	}
	return out, rows.Err()
}

func (s *SandboxStore) tally(query string, args []any, into map[string]int64) error {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		if k == "" {
			k = "unknown"
		}
		into[k] = n
	}
	return rows.Err()
}
