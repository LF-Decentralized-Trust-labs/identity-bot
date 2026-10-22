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

	"identity-agent-core/didcomm"
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
//     history, as it stood when the message arrived: committed in the
//     identifier itself, or vouched for by the key the history ended with
//     then. Keys anybody can mint under any identifier prove nothing until
//     something ties them to it.
//   - The signed log row written when the message arrived commits to all of
//     it (receiptBinding). Somebody who can write the database but not the
//     log cannot swap the kept proof for another one later.

// keysOwn is the tie for one of this agent's own AI agents: its keys are
// this agent's to know, so they are checked against what it holds rather than
// against a key history it fetched. It proves only that this Identity Agent
// says its own AI agent sent the message, which is all it can.
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
}

// proofOfReceipt builds the proof for a message that has just been unpacked
// and verified against senderDID.
func (s *CoreServer) proofOfReceipt(senderAID string, senderDID *didcomm.DID, signed []byte) *receivedProof {
	did, err := json.Marshal(senderDID)
	if err != nil || len(signed) == 0 {
		return nil
	}
	p := &receivedProof{Signed: base64.StdEncoding.EncodeToString(signed), SenderDID: string(did)}
	p.KeyTrust, p.KELSaid, p.KELEvents = s.senderKeysAtReceipt(senderAID, senderDID)
	return p
}

// senderKeysAtReceipt says how a sender's keys are tied to it now, from what
// this agent already holds: nothing is fetched on a sender's say-so. Keys
// nothing ties to the sender are recorded as such; the message is still taken,
// as it always was, but it can never be shown to have come from that sender.
func (s *CoreServer) senderKeysAtReceipt(aid string, did *didcomm.DID) (trust, kelSaid string, kelEvents int) {
	if s.ownAgentKeys(aid, did) == nil {
		return keysOwn, "", 0
	}
	if s.DataStore == nil {
		return string(didcomm.KeysUntied), "", 0
	}
	rec, err := s.DataStore.GetContactKEL(aid)
	if err != nil || rec == nil || !rec.KelVerified || len(rec.KEL) == 0 {
		return string(didcomm.KeysUntied), "", 0
	}
	t, err := didcomm.CheckKeysBelongTo(did, rec.KEL, rec.CurrentPublicKey)
	if err != nil {
		return string(didcomm.KeysUntied), "", 0
	}
	said, _ := rec.KEL[len(rec.KEL)-1]["d"].(string)
	return string(t), said, len(rec.KEL)
}

// ownAgentKeys reports whether did is the keyset this agent holds for one of
// its own AI agents. A keyset merely held for an identifier is not enough: an
// agent can mint one under anybody's identifier.
func (s *CoreServer) ownAgentKeys(aid string, did *didcomm.DID) error {
	if s.findAgentAssetByAID(aid) == nil || !s.hasKeySet(aid) {
		return fmt.Errorf("%s is not one of this Identity Agent's AI agents", aid)
	}
	ks, err := s.keySetFor(aid)
	if err != nil {
		return err
	}
	own, err := ks.DID()
	if err != nil {
		return err
	}
	if own.Ed != did.Ed || own.Dsa != did.Dsa || own.X25519 != did.X25519 || own.MlKem != did.MlKem {
		return fmt.Errorf("the kept keys are not the ones this Identity Agent holds for %s", aid)
	}
	return nil
}

// receiptBinding is what the log row for a received message commits to: the
// message, digests of its kept signed form and of the sender's keys, and how
// those keys were tied to the sender. Recomputed from the kept message and
// compared with the row (sandbox.HashArgs) when the sender is shown later.
func receiptBinding(messageID string, p receivedProof) []byte {
	digest := func(v string) string {
		sum := sha256.Sum256([]byte(v))
		return hex.EncodeToString(sum[:])
	}
	b, _ := json.Marshal(map[string]any{
		"message": messageID, "signed": digest(p.Signed), "sender_keys": digest(p.SenderDID),
		"key_trust": p.KeyTrust, "kel_said": p.KELSaid, "kel_events": p.KELEvents,
	})
	return b
}

// provedSender checks a kept message again: that the sender's signature over
// its signed form verifies against the keys it was received with; that what
// was kept is what was signed, naming the parties it was authenticated as;
// that those keys were tied to the sender by its key history as it stood when
// the message arrived; and that the signed log recorded exactly this proof
// when it did. Returns the signed message.
//
// Each check is the first to catch its own kind of forgery, and says which.
func (s *CoreServer) provedSender(n store.Notification) (*didcomm.JWM, error) {
	if n.SignedMessage == "" || n.SenderDID == "" {
		return nil, fmt.Errorf("message %s was kept without its signed form, so its sender cannot be shown", n.ID)
	}
	signed, err := base64.StdEncoding.DecodeString(n.SignedMessage)
	if err != nil {
		return nil, fmt.Errorf("message %s: the signed form is not readable", n.ID)
	}
	var did didcomm.DID
	if err := json.Unmarshal([]byte(n.SenderDID), &did); err != nil {
		return nil, fmt.Errorf("message %s: the sender's keys are not readable", n.ID)
	}
	if did.AID != n.FromAID {
		return nil, fmt.Errorf("message %s: kept keys are %s's, not the sender %s's", n.ID, did.AID, n.FromAID)
	}
	jwm, err := didcomm.VerifySignedMessage(&did, signed)
	if err != nil {
		return nil, fmt.Errorf("message %s: %w", n.ID, err)
	}
	if jwm.ID != n.ID || (n.Payload != "" && n.Payload != string(jwm.Body)) {
		return nil, fmt.Errorf("message %s: what was kept is not what the sender signed", n.ID)
	}
	if err := jwm.NamesParties(n.FromAID, n.ToAID); err != nil {
		return nil, fmt.Errorf("message %s: %w", n.ID, err)
	}
	if err := s.keysWereTied(n, &did); err != nil {
		return nil, fmt.Errorf("message %s: the keys it was received with were not tied to %s: %w", n.ID, n.FromAID, err)
	}
	if err := s.receiptWasLogged(n); err != nil {
		return nil, fmt.Errorf("message %s: %w", n.ID, err)
	}
	return jwm, nil
}

// keysWereTied checks the tie recorded at receipt, against the sender's key
// history cut at the point it had reached then. A rotation since does not
// break a genuine old message, and a key the sender has since retired cannot
// vouch for keys that arrived after it was retired.
func (s *CoreServer) keysWereTied(n store.Notification, did *didcomm.DID) error {
	switch n.SenderKeyTrust {
	case keysOwn:
		return s.ownAgentKeys(n.FromAID, did)
	case string(didcomm.KeysAnchored), string(didcomm.KeysVouched):
	default:
		return fmt.Errorf("nothing tied them to the sender when the message arrived")
	}
	if s.DataStore == nil {
		return fmt.Errorf("there is no record of the sender's key history here")
	}
	rec, err := s.DataStore.GetContactKEL(n.FromAID)
	if err != nil || rec == nil || n.SenderKELEvents < 1 || len(rec.KEL) < n.SenderKELEvents {
		return fmt.Errorf("the sender's key history as it stood then is not on file")
	}
	at := rec.KEL[:n.SenderKELEvents]
	if said, _ := at[len(at)-1]["d"].(string); said != n.SenderKELSaid {
		return fmt.Errorf("the sender's key history on file is not the one the message was received under")
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
		KELSaid: n.SenderKELSaid, KELEvents: n.SenderKELEvents,
	}))
	for _, r := range rows {
		if r.ArgsHash == want {
			return nil
		}
	}
	return fmt.Errorf("the signed log has no record of receiving this proof, so it was changed or made after the fact")
}

// ── Recording refusals once ─────────────────────────────────────────────────

// maxRefusalEntries caps the memory of refusals already recorded. It is kept
// apart from the replay cache: a peer sending refusable envelopes must not be
// able to fill the cache that stops replays, and one sender's message ids must
// not stand in for another's.
const maxRefusalEntries = 10000

var refusalsRecorded = struct {
	sync.Mutex
	m map[string]time.Time
}{m: map[string]time.Time{}}

// firstRefusal reports whether this sender's refusal of this message is new,
// remembering it if so. Once full, it answers false: the refusal is still
// made, only not recorded again, which is the direction that cannot be used
// to fill the log.
func firstRefusal(sender, messageID string) bool {
	refusalsRecorded.Lock()
	defer refusalsRecorded.Unlock()
	now := time.Now()
	for k, exp := range refusalsRecorded.m {
		if now.After(exp) {
			delete(refusalsRecorded.m, k)
		}
	}
	key := sender + "\x00" + messageID
	if _, ok := refusalsRecorded.m[key]; ok {
		return false
	}
	if len(refusalsRecorded.m) >= maxRefusalEntries {
		return false
	}
	refusalsRecorded.m[key] = now.Add(maxEnvelopeLifetime)
	return true
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
