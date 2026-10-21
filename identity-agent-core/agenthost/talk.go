package agenthost

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
)

// Delivery is one message as the Identity Agent hands it to this body.
type Delivery struct {
	Entry         agentmessage.Entry `json:"entry"`
	Body          string             `json:"body"`
	Countersigner *didcomm.DID       `json:"countersigner"`
	FromName      string             `json:"from_name"`
	// Record is what the entry says, once checked.
	Record agentmessage.Record `json:"-"`
}

// Inbox collects what is waiting for this body, waiting up to the Identity
// Agent's long-poll limit when nothing is.
func (h *Host) Inbox(ctx context.Context, wait bool) ([]Delivery, error) {
	path := "/api/agent-host/inbox"
	if wait {
		path += "?wait=1"
	}
	code, b, err := h.CallContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("the inbox answered %d: %s", code, b)
	}
	var out struct {
		Messages []Delivery `json:"messages"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("the inbox is unreadable: %w", err)
	}
	return out.Messages, nil
}

// trusted remembers which countersigning keys this body has checked against
// their identity's key log, so each is checked once per run.
type trusted struct {
	mu   sync.Mutex
	keys map[string]string // identifier -> the keys' digest, once checked
}

var checkedKeys = &trusted{keys: map[string]string{}}

// Check verifies a delivery before anything acts on it:
//
//   - the countersigner's keys belong to its identity — the Identity Agent
//     itself, or an AI agent the Identity Agent delegated — by that identity's
//     own published key log;
//   - the entry is countersigned by those keys, and its hash is the hash the
//     Identity Agent gave it;
//   - the sender's own signature, by its body's key or its person's
//     controller, is on what the entry says;
//   - the words are the words the entry's digest names;
//   - it is addressed to this body's AI agent.
//
// A failure means the message is not acted on.
func (h *Host) Check(d *Delivery) error {
	st, err := h.loadState()
	if err != nil {
		return err
	}
	if d.Countersigner == nil || d.Entry.Envelope == nil {
		return errors.New("the message carries no countersignature")
	}
	if err := h.checkCountersigner(st, d.Countersigner); err != nil {
		return err
	}
	rec, err := agentmessage.Open(d.Countersigner, d.Entry.Envelope)
	if err != nil {
		return fmt.Errorf("the countersignature does not verify: %w", err)
	}
	switch {
	case agentmessage.Hash(d.Entry.Envelope) != d.Entry.Hash:
		return errors.New("the entry's hash is not the hash of what was countersigned")
	case rec.MessageID != d.Entry.MessageID || rec.Conversation != d.Entry.Conversation:
		return errors.New("the entry is not the one countersigned")
	case rec.To != st.Agent:
		return errors.New("the message is not addressed to this AI agent")
	case agentmessage.HashBody([]byte(d.Body)) != rec.BodyHash:
		return errors.New("the words are not the ones the message's digest names")
	}
	// The countersigner speaks for the sender: the Identity Agent for a
	// person, the AI agent itself otherwise.
	if _, person := agentmessage.IsPerson(rec.From); person {
		if d.Countersigner.AID != st.IdentityAgent {
			return errors.New("a person's message must be countersigned by the Identity Agent")
		}
	} else if d.Countersigner.AID != rec.From {
		return errors.New("an AI agent's message must be countersigned as that AI agent")
	}
	if err := rec.CheckSenderProof(); err != nil {
		return fmt.Errorf("the sender's own signature does not hold: %w", err)
	}
	d.Record = rec
	return nil
}

// checkCountersigner accepts a countersigner's keys only if they belong to the
// Identity Agent this body enrolled with, or to an AI agent that Identity Agent
// delegated, by that identity's own published log.
func (h *Host) checkCountersigner(st State, did *didcomm.DID) error {
	digest, _ := json.Marshal(did)
	checkedKeys.mu.Lock()
	known := checkedKeys.keys[did.AID] == string(digest)
	checkedKeys.mu.Unlock()
	if known {
		return nil
	}
	kel, current, err := h.verifiedLog(st.IdentityAgentURL, did.AID, nil)
	if err != nil {
		return err
	}
	if did.AID != st.IdentityAgent {
		if len(kel) == 0 || kel[0]["di"] != st.IdentityAgent {
			return fmt.Errorf("%s is not delegated by the Identity Agent this machine enrolled with", did.AID)
		}
	}
	if _, err := didcomm.CheckKeysBelongTo(did, kel, current); err != nil {
		return fmt.Errorf("the countersigning keys do not belong to %s: %w", did.AID, err)
	}
	checkedKeys.mu.Lock()
	checkedKeys.keys[did.AID] = string(digest)
	checkedKeys.mu.Unlock()
	return nil
}

// Say sends one message as this body's AI agent: signed by the machine key,
// sealed to the Identity Agent. It returns the message id the Identity Agent
// gave it.
func (h *Host) Say(ctx context.Context, kind, conv, to, inReplyTo, body string, brain agentmessage.Brain) (string, error) {
	st, err := h.loadState()
	if err != nil {
		return "", err
	}
	cred := h.bodyCredential
	if cred == "" {
		status, err := h.Status()
		if err != nil {
			return "", err
		}
		cred, _ = status["credential_said"].(string)
		h.bodyCredential = cred
	}
	signer, _ := h.signer()
	host, _, err := agentbody.Identity(signer)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	statement := agentmessage.Statement{
		Conversation: conv, Kind: kind, From: st.Agent, To: to, InReplyTo: inReplyTo,
		BodyHash: agentmessage.HashBody([]byte(body)), Brain: brain, Host: host,
		HostNonce: base64.RawURLEncoding.EncodeToString(nonce),
		HostTime:  time.Now().UTC().Format(time.RFC3339), BodyCredential: cred,
	}
	sig, err := agentmessage.Sign(signer, statement)
	if err != nil {
		return "", err
	}
	payload, _ := json.Marshal(map[string]any{"statement": statement, "signature": sig, "body": body})
	code, b, err := h.CallContext(ctx, "POST", "/api/agent-host/messages", payload)
	if err != nil {
		return "", err
	}
	var out struct {
		MessageID string `json:"message_id"`
		Error     string `json:"error"`
	}
	_ = json.Unmarshal(b, &out)
	if code != http.StatusCreated {
		if out.Error == "" {
			out.Error = string(b)
		}
		return "", &Refusal{Status: code, Reason: out.Error}
	}
	return out.MessageID, nil
}

// Refusal is the Identity Agent declining what this body said, with its
// reason — which the brain is told, since it may be able to act on it.
type Refusal struct {
	Status int
	Reason string
}

func (r *Refusal) Error() string { return fmt.Sprintf("refused (%d): %s", r.Status, r.Reason) }

// Agent is another AI agent this body's AI agent may ask.
type Agent struct {
	AID  string `json:"aid"`
	Name string `json:"name"`
	Role string `json:"role,omitempty"`
}

// Agents lists the AI agents this body's AI agent may ask.
func (h *Host) Agents(ctx context.Context) ([]Agent, error) {
	code, b, err := h.CallContext(ctx, "GET", "/api/agent-host/agents", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("the Identity Agent answered %d: %s", code, b)
	}
	var out struct {
		Agents []Agent `json:"agents"`
	}
	return out.Agents, json.Unmarshal(b, &out)
}

// ── What this body remembers about its conversations ─────────────────────────

// convState is what a body keeps about one conversation: the brain session
// it runs in, the ask it is serving, and what it is waiting for.
type convState struct {
	// Session is the brain's session for this conversation, so each turn
	// continues the last rather than starting cold.
	Session string `json:"session"`
	// Started is whether the brain has run in this session yet.
	Started bool `json:"started"`
	// Serving is the ask this AI agent was given and owes an answer to, and
	// AskedBy who gave it.
	Serving string `json:"serving"`
	AskedBy string `json:"asked_by"`
	// Answered is whether that ask has had its answer.
	Answered bool `json:"answered"`
	// Awaiting is how many asks this AI agent sent that have not come back.
	Awaiting int       `json:"awaiting"`
	LastAt   time.Time `json:"last_at"`
}

type memory struct {
	Conversations map[string]*convState `json:"conversations"`
	// Seen is every message already acted on, so a message delivered twice is
	// acted on once.
	Seen map[string]time.Time `json:"seen"`
}

func (h *Host) memoryPath() string { return filepath.Join(h.DataDir, "conversations.json") }

func (h *Host) loadMemory() *memory {
	m := &memory{Conversations: map[string]*convState{}, Seen: map[string]time.Time{}}
	if b, err := os.ReadFile(h.memoryPath()); err == nil {
		_ = json.Unmarshal(b, m)
	}
	if m.Conversations == nil {
		m.Conversations = map[string]*convState{}
	}
	if m.Seen == nil {
		m.Seen = map[string]time.Time{}
	}
	return m
}

func (h *Host) saveMemory(m *memory) error {
	// Forget what is old enough that it can no longer be delivered again.
	for id, at := range m.Seen {
		if time.Since(at) > 7*24*time.Hour {
			delete(m.Seen, id)
		}
	}
	for id, c := range m.Conversations {
		if time.Since(c.LastAt) > 7*24*time.Hour {
			delete(m.Conversations, id)
		}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := h.memoryPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.memoryPath())
}
