package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/sandbox"
	"identity-agent-core/store"
)

// A message from another Identity Agent can be shown later, to somebody who
// does not trust this agent, to have come from its sender. Three things make
// that true, and each one closes a way to forge it:
//
//   - The sender's signed message is kept as it was inside the envelope, with
//     the keys it was checked against. The signature is then checkable by
//     anyone, without this agent's keys.
//   - Those keys are tied to the sender's identifier through the sender's key
//     history, as it stood when the message arrived and kept with the message:
//     committed in the identifier itself, or vouched for by the key the
//     history ended with then. Keys anybody can mint under any identifier
//     prove nothing until something ties them to it.
//   - The signed log row written when the message arrived commits to all of
//     it (receiptBinding). Somebody who can write the database but not the
//     log cannot swap the kept proof for another one later.

// keysOwn is the tie for one of this agent's own AI agents: an identifier
// whose key history opens with an inception delegated from this Identity
// Agent's root, approved in the root's own history, with keys this agent
// holds for it. Unlike the other two it is SELF-ASSERTED: it rests on this
// agent's own word that the keys are its AI agent's, so anything showing the
// proof to somebody else must say so.
const keysOwn = "own"

// receivedProof is what is kept with a received message so its sender can be
// shown later: the signed message (base64) and the sender's keys (JSON) as
// they were checked, and how those keys were tied to the sender then.
type receivedProof struct {
	Signed    string
	SenderDID string
	KeyTrust  string
	KELSaid   string
	KELEvents int
	KEL       string // the sender's key history then, as JSON
}

// proofOfReceipt builds the proof for a message that has just been unpacked
// and verified against senderDID.
func (s *CoreServer) proofOfReceipt(senderAID string, senderDID *didcomm.DID, signed []byte) *receivedProof {
	did, err := json.Marshal(senderDID)
	if err != nil || len(signed) == 0 {
		return nil
	}
	p := &receivedProof{Signed: base64.StdEncoding.EncodeToString(signed), SenderDID: string(did)}
	p.KeyTrust, p.KELSaid, p.KELEvents, p.KEL = s.senderKeysAtReceipt(senderAID, senderDID)
	return p
}

// senderKeysAtReceipt says how a sender's keys are tied to it now, from what
// this agent already holds: nothing is fetched on a sender's say-so, and
// nothing is written. It returns the evidence to keep with the message: the
// sender's key history then, or for one of this agent's own AI agents the
// delegation evidence (ownEvidence). Keys nothing ties to the sender are
// recorded as such; the message is still taken, as it always was, but it can
// never be shown to have come from that sender.
func (s *CoreServer) senderKeysAtReceipt(aid string, did *didcomm.DID) (trust, kelSaid string, kelEvents int, kel string) {
	untied := string(didcomm.KeysUntied)
	if evidence, err := s.ownAgentAtArrival(aid, did); err == nil {
		return keysOwn, "", 0, evidence
	}
	if s.DataStore == nil {
		return untied, "", 0, ""
	}
	rec, err := s.DataStore.GetContactKEL(aid)
	if err != nil || rec == nil || !rec.KelVerified || len(rec.KEL) == 0 {
		return untied, "", 0, ""
	}
	t, err := didcomm.CheckKeysBelongTo(did, rec.KEL, rec.CurrentPublicKey)
	if err != nil {
		return untied, "", 0, ""
	}
	events, err := json.Marshal(rec.KEL)
	if err != nil {
		return untied, "", 0, ""
	}
	said, _ := rec.KEL[len(rec.KEL)-1]["d"].(string)
	return string(t), said, len(rec.KEL), string(events)
}

// ownEvidence is what is kept with a message from one of this agent's own AI
// agents: the agent's delegated inception and the root's key history as they
// were when it arrived (the engine's original bytes, base64). With the keys
// kept beside it (SenderDID), it is checked again from these alone, so the AI
// agent being removed or rotated later does not break a genuine old proof.
type ownEvidence struct {
	Inception string   `json:"inception"`
	RootKEL   []string `json:"root_kel"`
}

// kelHolder is an engine that can find a key history by identifier, not only
// by the name it is held under. A name can be reused or renamed; the
// identifier cannot.
type kelHolder interface {
	GetKelByAID(aid string) (*drivers.DriverKelResponse, error)
}

// ownAgentAtArrival reports whether did is the keyset this agent holds for one
// of its own AI agents, and returns the evidence to keep if so. Neither an
// asset row nor a keyset file is enough: both are files this agent writes, and
// it can write them for anybody's identifier. The identifier must be an AI
// agent here, held with keys equal to did, and its key history must open with
// an inception delegated from this Identity Agent's root and approved in the
// root's own history (keri-go). Read only: a key history the engine does not
// already hold is a refusal, never a reason to make one.
func (s *CoreServer) ownAgentAtArrival(aid string, did *didcomm.DID) (string, error) {
	if s.findAgentAssetByAID(aid) == nil {
		return "", fmt.Errorf("%s is not one of this Identity Agent's AI agents", aid)
	}
	// Before keySetFor, which makes a keyset for an identifier it has none for.
	if !s.hasKeySet(aid) {
		return "", fmt.Errorf("this Identity Agent holds no keys for %s", aid)
	}
	ks, err := s.keySetFor(aid)
	if err != nil {
		return "", err
	}
	held, err := ks.DID()
	if err != nil {
		return "", err
	}
	if held.Ed != did.Ed || held.Dsa != did.Dsa || held.X25519 != did.X25519 || held.MlKem != did.MlKem {
		return "", fmt.Errorf("the keys are not the ones this Identity Agent holds for %s", aid)
	}
	root := s.OwnerRootAID()
	engine, ok := s.KeriDriver.(kelHolder)
	if root == "" || !ok {
		return "", fmt.Errorf("this Identity Agent has no root identity and key engine to check with")
	}
	kel, err := engine.GetKelByAID(aid)
	if err != nil || len(kel.RawEventsB64) == 0 {
		return "", fmt.Errorf("the key history of %s is not held here", aid)
	}
	rootKEL, err := engine.GetKelByAID(root)
	if err != nil {
		return "", fmt.Errorf("the root identity's key history is not held here")
	}
	e := ownEvidence{Inception: kel.RawEventsB64[0], RootKEL: rootKEL.RawEventsB64}
	if err := s.delegatedFromHere(aid, e); err != nil {
		return "", err
	}
	b, err := json.Marshal(e)
	return string(b), err
}

// delegatedFromHere checks, with keri-go, that the evidence shows aid opening
// with a delegated inception that this Identity Agent's root approved by a
// seal in its own key history.
func (s *CoreServer) delegatedFromHere(aid string, e ownEvidence) error {
	root := s.OwnerRootAID()
	if root == "" {
		return fmt.Errorf("this Identity Agent has no root identity to check with")
	}
	inception, err := base64.StdEncoding.DecodeString(e.Inception)
	if err != nil || len(inception) == 0 {
		return fmt.Errorf("the inception of %s is not readable", aid)
	}
	ev, err := keri.ParseEvent(inception)
	if err != nil || ev.Identifier != aid {
		return fmt.Errorf("the inception kept is not %s's", aid)
	}
	raws := make([][]byte, 0, len(e.RootKEL))
	for _, r := range e.RootKEL {
		b, err := base64.StdEncoding.DecodeString(r)
		if err != nil || len(b) == 0 {
			return fmt.Errorf("the root identity's key history is not readable")
		}
		raws = append(raws, b)
	}
	if len(raws) == 0 {
		return fmt.Errorf("no root key history was kept")
	}
	first, err := keri.ParseEvent(raws[0])
	if err != nil || first.Identifier != root {
		return fmt.Errorf("the root key history kept is not this Identity Agent's")
	}
	if err := keri.ValidateDelegation(inception, raws); err != nil {
		return fmt.Errorf("%s is not delegated from this Identity Agent: %w", aid, err)
	}
	return nil
}

// receiptBinding is what the log row for a received message commits to: the
// message, digests of its kept signed form, of the sender's keys and of the
// sender's key history then, and how those keys were tied to the sender. Recomputed from the kept message and
// compared with the row (sandbox.HashArgs) when the sender is shown later.
func receiptBinding(messageID string, p receivedProof) []byte {
	digest := func(v string) string {
		sum := sha256.Sum256([]byte(v))
		return hex.EncodeToString(sum[:])
	}
	b, _ := json.Marshal(map[string]any{
		"message": messageID, "signed": digest(p.Signed), "sender_keys": digest(p.SenderDID),
		"key_trust": p.KeyTrust, "kel_said": p.KELSaid, "kel_events": p.KELEvents, "kel": digest(p.KEL),
	})
	return b
}

// provedSender checks a kept message again: that the sender's signature over
// its signed form verifies against the keys it was received with; that what
// was kept is what was signed, naming the parties it was authenticated as;
// that those keys were tied to the sender by its key history as it stood when
// the message arrived; and that the signed log recorded exactly this proof
// when it did. Returns the signed message and how the keys were tied: keysOwn
// is this agent's own word, and whatever shows the proof must label it so.
//
// Each check is the first to catch its own kind of forgery, and says which.
func (s *CoreServer) provedSender(n store.Notification) (*didcomm.JWM, string, error) {
	if n.SignedMessage == "" || n.SenderDID == "" {
		return nil, "", fmt.Errorf("message %s was kept without its signed form, so its sender cannot be shown", n.ID)
	}
	signed, err := base64.StdEncoding.DecodeString(n.SignedMessage)
	if err != nil {
		return nil, "", fmt.Errorf("message %s: the signed form is not readable", n.ID)
	}
	var did didcomm.DID
	if err := json.Unmarshal([]byte(n.SenderDID), &did); err != nil {
		return nil, "", fmt.Errorf("message %s: the sender's keys are not readable", n.ID)
	}
	if did.AID != n.FromAID {
		return nil, "", fmt.Errorf("message %s: kept keys are %s's, not the sender %s's", n.ID, did.AID, n.FromAID)
	}
	jwm, err := didcomm.VerifySignedMessage(&did, signed)
	if err != nil {
		return nil, "", fmt.Errorf("message %s: %w", n.ID, err)
	}
	if jwm.ID != n.ID || (n.Payload != "" && n.Payload != string(jwm.Body)) {
		return nil, "", fmt.Errorf("message %s: what was kept is not what the sender signed", n.ID)
	}
	if err := jwm.NamesParties(n.FromAID, n.ToAID); err != nil {
		return nil, "", fmt.Errorf("message %s: %w", n.ID, err)
	}
	if err := s.keysWereTied(n, &did); err != nil {
		return nil, "", fmt.Errorf("message %s: the keys it was received with were not tied to %s: %w", n.ID, n.FromAID, err)
	}
	if err := s.receiptWasLogged(n); err != nil {
		return nil, "", fmt.Errorf("message %s: %w", n.ID, err)
	}
	return jwm, n.SenderKeyTrust, nil
}

// keysWereTied checks the tie recorded at receipt, against the sender's key
// history as it stood then, kept with the message. A rotation since does not
// break a genuine old message, and the contact's own record being refetched,
// shortened or removed does not either.
//
// A retired key cannot vouch for keys that arrived after it was retired, but
// only against somebody without this agent's log key: the receipt position is
// fixed by the signed log row, and whoever can sign log rows can write a new
// one. Anchoring the log's head in a witnessed key history, with its
// timestamps, is what closes that, and it is a separate step.
func (s *CoreServer) keysWereTied(n store.Notification, did *didcomm.DID) error {
	switch n.SenderKeyTrust {
	case keysOwn:
		// From what was kept: the keys were bound by the log row on arrival,
		// and the delegation is checked again from the bytes kept with them.
		var e ownEvidence
		if err := json.Unmarshal([]byte(n.SenderKEL), &e); err != nil {
			return fmt.Errorf("the delegation evidence was not kept with the message")
		}
		return s.delegatedFromHere(n.FromAID, e)
	case string(didcomm.KeysAnchored), string(didcomm.KeysVouched):
	default:
		return fmt.Errorf("nothing tied them to the sender when the message arrived")
	}
	var at []map[string]interface{}
	if err := json.Unmarshal([]byte(n.SenderKEL), &at); err != nil || n.SenderKELEvents < 1 || len(at) != n.SenderKELEvents {
		return fmt.Errorf("the sender's key history as it stood then was not kept with the message")
	}
	if said, _ := at[len(at)-1]["d"].(string); said != n.SenderKELSaid {
		return fmt.Errorf("the key history kept with the message is not the one it was received under")
	}
	if s.KeriDriver == nil {
		return fmt.Errorf("this device has no key engine to check the sender's key history with")
	}
	val, err := s.KeriDriver.ValidateKEL(n.FromAID, at)
	if err != nil || val == nil || !val.KelVerified || val.CurrentPublicKey == "" {
		return fmt.Errorf("the sender's key history as it stood then does not check out")
	}
	_, err = didcomm.CheckKeysBelongTo(did, at, val.CurrentPublicKey)
	return err
}

// receiptWasLogged finds the signed log row written when the message arrived
// and checks it committed to the proof kept now.
func (s *CoreServer) receiptWasLogged(n store.Notification) error {
	if s.SandboxManager == nil {
		return fmt.Errorf("there is no signed log here to check the kept proof against")
	}
	rows, err := s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID: "didcomm.message.received", CorrelationID: n.ID, CallerAID: n.FromAID, ResultStatus: "ok",
	})
	if err != nil {
		return fmt.Errorf("the signed log could not be read: %w", err)
	}
	want := sandbox.HashArgs(receiptBinding(n.ID, receivedProof{
		Signed: n.SignedMessage, SenderDID: n.SenderDID, KeyTrust: n.SenderKeyTrust,
		KELSaid: n.SenderKELSaid, KELEvents: n.SenderKELEvents, KEL: n.SenderKEL,
	}))
	for _, r := range rows {
		if r.ArgsHash == want {
			return nil
		}
	}
	return fmt.Errorf("the signed log has no record of receiving this proof, so it was changed or made after the fact")
}

// ── Recording refusals once, within each sender's quota ────────────────────

// A proven sender's refused messages are recorded once each, up to a quota
// per sender per window. The memory of them is kept apart from the replay
// cache, so refusals cannot fill the cache that stops replays, and per sender,
// so one sender's message ids cannot stand in for another's and one sender
// flooding the log silences only itself.
const (
	refusalQuota  = 100
	refusalWindow = time.Hour
)

type senderRefusals struct {
	start    time.Time
	seen     map[string]bool
	notified bool
}

var refusalsRecorded = struct {
	sync.Mutex
	m map[string]*senderRefusals
}{m: map[string]*senderRefusals{}}

// refusalToRecord says whether this sender's refusal of this message should
// be recorded. When the sender has used its quota, it returns the end of the
// window once, so one row can say that sender's further refusals are not
// recorded until then; after that, nothing until the window ends.
func refusalToRecord(sender, messageID string, now time.Time) (record bool, suppressedUntil time.Time) {
	refusalsRecorded.Lock()
	defer refusalsRecorded.Unlock()
	for k, r := range refusalsRecorded.m {
		if now.Sub(r.start) >= refusalWindow {
			delete(refusalsRecorded.m, k)
		}
	}
	r := refusalsRecorded.m[sender]
	if r == nil {
		r = &senderRefusals{start: now, seen: map[string]bool{}}
		refusalsRecorded.m[sender] = r
	}
	if r.seen[messageID] {
		return false, time.Time{}
	}
	if len(r.seen) >= refusalQuota {
		if r.notified {
			return false, time.Time{}
		}
		r.notified = true
		return false, r.start.Add(refusalWindow)
	}
	r.seen[messageID] = true
	return true, time.Time{}
}

// ── Which conversation a row is filed under ─────────────────────────────────

// conversationIDPattern is what conversation.NewID makes. Anything else named
// as a conversation is not one, and is not written into the log.
var conversationIDPattern = regexp.MustCompile(`^c_[A-Za-z0-9_-]{1,64}$`)

// partyConversation is the conversation a caller's refused message is filed
// under: one that exists here and that the caller is a party to. Anything else
// is filed under no conversation, so nobody can put rows into a conversation
// they are not in.
func (s *CoreServer) partyConversation(convID, party string) string {
	if !conversationIDPattern.MatchString(convID) {
		return ""
	}
	store, err := s.conversations()
	if err != nil {
		return ""
	}
	c, err := store.Get(convID)
	if err != nil {
		return ""
	}
	if c.OpenedBy != party && !store.IsParty(convID, party) {
		return ""
	}
	return convID
}

// conversationOf is the conversation a message between Identity Agents says
// it belongs to, if it names a well-formed one.
func conversationOf(body json.RawMessage) string {
	var b struct {
		Conversation string `json:"conversation"`
	}
	if json.Unmarshal(body, &b) != nil || !conversationIDPattern.MatchString(b.Conversation) {
		return ""
	}
	return b.Conversation
}

// trafficConversation is the conversation a message from sender is filed
// under. One held here is used only if the sender is a party to it; one this
// agent does not hold is the sender's thread, filed as named.
func (s *CoreServer) trafficConversation(sender string, body json.RawMessage) string {
	conv := conversationOf(body)
	if conv == "" {
		return ""
	}
	store, err := s.conversations()
	if err != nil {
		return conv
	}
	if _, err := store.Get(conv); err != nil {
		return conv
	}
	return s.partyConversation(conv, sender)
}

// ── A delivery is recorded once ─────────────────────────────────────────────

var deliveryRecordMu sync.Mutex

// recordDeliveryOnce writes one log row the first time a message is handed to
// a machine. A message still waiting is handed out again on every collection
// until its receipt comes back, and recording each would let a machine that
// never answers fill the log by asking.
func (s *CoreServer) recordDeliveryOnce(cc sandbox.CallerContext, messageID, host string) {
	if s.SandboxManager == nil {
		return
	}
	deliveryRecordMu.Lock()
	defer deliveryRecordMu.Unlock()
	rows, err := s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID: "agent.message.delivered", CorrelationID: messageID,
	})
	if err == nil {
		for _, r := range rows {
			if r.BodyHost == host {
				return
			}
		}
	}
	cc.CorrelationID = messageID
	s.SandboxManager.RecordGovernanceEvent(cc, "agent.message.delivered", "ok")
}
