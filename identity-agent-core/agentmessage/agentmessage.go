// Package agentmessage is the format of a message between AI agents, as the
// Identity Agent that holds them records it.
//
// Every message is signed twice, by two parties, for two different claims.
//
//   - The sender's own statement. When an AI agent speaks, the statement is
//     signed by its body's machine key: which conversation, from whom, to whom,
//     a digest of the words, and what brain produced them. When a person speaks,
//     it is the request their controller signed. This is the part the Identity
//     Agent cannot forge: it never holds a body's key or a controller's key.
//   - The Identity Agent's countersignature, as the AI agent the message is
//     from. It adds what only the Identity Agent can know: the message's place
//     in the conversation, the hash of the entry before it, the grant that
//     allowed it, and the grade of the body it came from — stamped here rather
//     than claimed by the body, so a body cannot talk itself up.
//
// The two nest rather than sit side by side: the countersignature covers the
// sender's statement and its signature, so neither can be swapped without
// breaking the other. The sender cannot sign the message's place in the
// conversation, because another message may land first.
//
// The words themselves are not inside either signature. Both cover their
// digest, so the record can keep the words wherever the organisation chooses
// and still prove they are the ones that were sent.
package agentmessage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
)

// Kinds of message.
const (
	// KindAsk opens a turn: one party asks another for something.
	KindAsk = "ask"
	// KindReply answers an ask, inside the conversation it was asked in.
	KindReply = "reply"
	// KindReceipt is a body saying it received a message. It proves the
	// message reached the machine, not only that the Identity Agent sent it.
	KindReceipt = "receipt"
	// KindFailure closes a turn the brain could not answer — a crash, a
	// timeout, a usage limit — so no conversation waits on silence.
	KindFailure = "failure"
)

// PersonPrefix marks a party that is a person rather than an AI agent: the
// identifier after it is the person's identity on the organisation's roster.
const PersonPrefix = "person:"

// Person names a person as a party to a conversation.
func Person(aid string) string { return PersonPrefix + aid }

// IsPerson reports whether a party is a person, and which.
func IsPerson(party string) (string, bool) {
	if strings.HasPrefix(party, PersonPrefix) {
		return strings.TrimPrefix(party, PersonPrefix), true
	}
	return "", false
}

// MaxBody bounds the words in one message.
const MaxBody = 64 << 10

// Brain is what produced an AI agent's words, as its body reports it. It is
// the body's word, signed by the body — not anything the model's provider
// vouched for.
type Brain struct {
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	Session  string `json:"session,omitempty"`
	// RunHash is a digest of everything the brain was sent and returned in the
	// run that produced this message.
	RunHash string `json:"run_hash,omitempty"`
}

// Statement is what a body signs when its AI agent speaks.
type Statement struct {
	Conversation string `json:"conversation"`
	Kind         string `json:"kind"`
	// From is the AI agent speaking; To is the AI agent or person addressed.
	From string `json:"from"`
	To   string `json:"to"`
	// InReplyTo is the message this one answers, acknowledges or reports a
	// failure on — or, for an ask, the message the AI agent was handling when it
	// asked, which is how far down a chain of asks this one sits.
	InReplyTo string `json:"in_reply_to,omitempty"`
	BodyHash  string `json:"body_hash"`
	Brain     Brain  `json:"brain"`
	// Host is the body's identifier; HostNonce and HostTime make each
	// statement distinct and bound it in time.
	Host      string `json:"host"`
	HostNonce string `json:"host_nonce"`
	HostTime  string `json:"host_time"`
	// BodyCredential is the credential that made Host the AI agent's body.
	BodyCredential string `json:"body_credential"`
}

// Bytes is the string a body signs. One field per line, in a fixed order, so
// three implementations produce it identically without agreeing on a JSON
// encoder.
func (s Statement) Bytes() []byte {
	return []byte(strings.Join([]string{
		"IA-AGENT-MSG-V1",
		s.Conversation,
		s.Kind,
		s.From,
		s.To,
		s.InReplyTo,
		s.BodyHash,
		s.Brain.Provider,
		s.Brain.Model,
		s.Brain.Session,
		s.Brain.RunHash,
		s.Host,
		s.HostNonce,
		s.HostTime,
		s.BodyCredential,
	}, "\n"))
}

// HashBody is the digest a statement carries for its words.
func HashBody(body []byte) string { return iacrypto.Blake3QB64Must(body) }

// Check refuses a statement that is not well formed, before anything is
// verified: a newline in a field would let one statement be read as another.
func (s Statement) Check() error {
	fields := map[string]string{
		"conversation": s.Conversation, "kind": s.Kind, "from": s.From, "to": s.To,
		"body_hash": s.BodyHash, "host": s.Host, "host_nonce": s.HostNonce,
		"host_time": s.HostTime, "body_credential": s.BodyCredential,
	}
	for name, v := range fields {
		if v == "" {
			return fmt.Errorf("the message has no %s", name)
		}
	}
	for _, v := range []string{s.Conversation, s.Kind, s.From, s.To, s.InReplyTo, s.BodyHash,
		s.Brain.Provider, s.Brain.Model, s.Brain.Session, s.Brain.RunHash,
		s.Host, s.HostNonce, s.HostTime, s.BodyCredential} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("a message field may not contain a line break")
		}
	}
	switch s.Kind {
	case KindAsk, KindReply, KindReceipt, KindFailure:
	default:
		return fmt.Errorf("%q is not a kind of message", s.Kind)
	}
	// A body only ever speaks about a message it was given: it cannot open a
	// conversation, so even an ask names the message the AI agent was handling.
	if s.InReplyTo == "" {
		return fmt.Errorf("a %s from a body must name the message it acts on", s.Kind)
	}
	if len(s.HostNonce) < 16 {
		return errors.New("the message needs a nonce of at least 16 characters")
	}
	if _, err := time.Parse(time.RFC3339, s.HostTime); err != nil {
		return errors.New("the message's time must be RFC 3339")
	}
	return nil
}

// Sign is a body signing its statement.
func Sign(signer agentbody.Signer, s Statement) (string, error) {
	if err := s.Check(); err != nil {
		return "", err
	}
	return agentbody.Sign(signer, s.Bytes())
}

// Verify checks a body's signature on its statement.
func Verify(s Statement, verkey, signature string) error {
	if err := s.Check(); err != nil {
		return err
	}
	return agentbody.Verify(s.Host, verkey, signature, s.Bytes())
}

// ControllerProof is a person's own statement: the request their controller
// signed. Kept as the exact string signed, so it can be checked again without
// knowing how a controller builds it — the last line is the digest of the
// request's body, which carries the words' digest.
type ControllerProof struct {
	Controller string `json:"controller"`
	// PublicKey is the controller's key as its grant records it.
	PublicKey    string `json:"public_key"`
	SignedString string `json:"signed_string"`
	Signature    string `json:"signature"`
	// Request is the request body the controller signed.
	Request json.RawMessage `json:"request"`
	// ControllerGrant is the controller's Controller Grant credential: anchored
	// in the organisation's key log, it names the signer the controller acts as,
	// so the person behind a message is shown by a credential anybody can check
	// rather than by this Identity Agent's word. Empty for a controller granted
	// before machines were given one.
	ControllerGrant string `json:"controller_grant,omitempty"`
}

// Verify checks the controller signed this request.
func (p ControllerProof) Verify() error {
	ok, err := iacrypto.VerifyMachineSignature(p.PublicKey, p.Signature, []byte(p.SignedString))
	if err != nil || !ok {
		return errors.New("the request is not signed by the controller it names")
	}
	lines := strings.Split(p.SignedString, "\n")
	if len(lines) < 2 || lines[1] != p.Controller {
		return errors.New("the signed request names a different controller")
	}
	if lines[len(lines)-1] != iacrypto.Blake3QB64Must(p.Request) {
		return errors.New("the signed request is not this request")
	}
	return nil
}

// PersonRef is the person a controller acts for, as the Identity Agent
// established it when the message arrived.
type PersonRef struct {
	AID string `json:"aid"`
	// Standing is how the organisation knows them: "owner" (named in its own
	// key log), "signer" or "employee".
	Standing string `json:"standing"`
	// Credential is the credential that makes them an employee, or the
	// signature with which they founded the organisation.
	Credential string `json:"credential,omitempty"`
	Name       string `json:"name,omitempty"`
}

// Record is one entry in a conversation, as the Identity Agent signs it.
type Record struct {
	MessageID    string `json:"message_id"`
	Conversation string `json:"conversation"`
	Seq          int    `json:"seq"`
	// PrevHash is the hash of the entry before this one in the conversation;
	// empty for the first.
	PrevHash  string `json:"prev_hash"`
	IATime    string `json:"ia_time"`
	Kind      string `json:"kind"`
	From      string `json:"from"`
	To        string `json:"to"`
	InReplyTo string `json:"in_reply_to,omitempty"`
	BodyHash  string `json:"body_hash"`
	// Depth is how far down a chain of asks this entry sits: a person's
	// message is 0, the ask it leads to 1, and so on.
	Depth int `json:"depth"`

	// The sender's own proof: exactly one of these.
	Statement       *Statement       `json:"statement,omitempty"`
	HostSignature   string           `json:"host_signature,omitempty"`
	HostVerkey      string           `json:"host_verkey,omitempty"`
	ControllerProof *ControllerProof `json:"controller_proof,omitempty"`

	// What the Identity Agent vouches for.
	GrantSAID      string     `json:"grant_said,omitempty"`
	BodyGrade      string     `json:"body_grade,omitempty"`
	BodyCredential string     `json:"body_credential,omitempty"`
	Person         *PersonRef `json:"person,omitempty"`
	// OpenedBy is who opened the conversation. Every entry carries it, so each
	// can be read alone.
	OpenedBy string `json:"opened_by"`
}

// CheckSenderProof verifies the sender's own signature on a record, and that
// it agrees with what the record says.
func (r Record) CheckSenderProof() error {
	switch {
	case r.Statement != nil && r.ControllerProof != nil:
		return errors.New("a message carries one sender's proof, not two")
	case r.Statement != nil:
		st := *r.Statement
		if st.Conversation != r.Conversation || st.Kind != r.Kind || st.From != r.From ||
			st.To != r.To || st.InReplyTo != r.InReplyTo || st.BodyHash != r.BodyHash ||
			st.BodyCredential != r.BodyCredential {
			return errors.New("the record does not say what its body signed")
		}
		return Verify(st, r.HostVerkey, r.HostSignature)
	case r.ControllerProof != nil:
		if err := r.ControllerProof.Verify(); err != nil {
			return err
		}
		var req PersonMessage
		if err := json.Unmarshal(r.ControllerProof.Request, &req); err != nil {
			return errors.New("the signed request is unreadable")
		}
		// The person's controller signed the words themselves, so their digest
		// is taken from what was signed, never from a digest the app supplied.
		if req.To != r.To || HashBody([]byte(req.Body)) != r.BodyHash ||
			req.Conversation != r.Conversation && req.Conversation != "" || req.InReplyTo != r.InReplyTo {
			return errors.New("the record does not say what the person's controller signed")
		}
		return nil
	}
	return errors.New("the message carries no proof from its sender")
}

// PersonMessage is what a person's controller signs to say something to an AI
// agent: the words themselves, so the signature covers them directly.
type PersonMessage struct {
	// Conversation is empty to open a new one.
	Conversation string `json:"conversation,omitempty"`
	To           string `json:"to"`
	InReplyTo    string `json:"in_reply_to,omitempty"`
	Body         string `json:"body"`
	// Nonce keeps two identical messages from being one signed request.
	Nonce string `json:"nonce"`
}

// TypeRecord is the message type of a countersigned conversation entry.
const TypeRecord = didcomm.TypeAgentMessage

// Countersign is the Identity Agent signing a record as the party it is from:
// the AI agent's own keys for an AI agent's message, the organisation's for a
// person's.
func Countersign(as *didcomm.KeySet, r Record) (*didcomm.Envelope, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	to := r.To
	if aid, ok := IsPerson(to); ok {
		to = aid
	}
	return didcomm.PackSigned(as, &didcomm.JWM{
		ID: r.MessageID, Type: TypeRecord,
		From: "did:keri:" + as.AID, To: []string{"did:keri:" + to},
		CreatedTime: r.IATime, Body: body,
	})
}

// Open checks a countersigned entry against the keys of the party that
// countersigned it, and returns the record inside.
func Open(signer *didcomm.DID, env *didcomm.Envelope) (Record, error) {
	jwm, err := didcomm.UnpackSigned(signer, env)
	if err != nil {
		return Record{}, err
	}
	if jwm.Type != TypeRecord {
		return Record{}, fmt.Errorf("%q is not a conversation entry", jwm.Type)
	}
	var r Record
	if err := json.Unmarshal(jwm.Body, &r); err != nil {
		return Record{}, errors.New("the entry is unreadable")
	}
	if r.MessageID != jwm.ID {
		return Record{}, errors.New("the entry's id is not the one countersigned")
	}
	return r, nil
}

// Read returns the record inside a countersigned entry without checking the
// countersignature — for the Identity Agent reading its own record back. A
// body, or anybody else, checks with Open.
func Read(env *didcomm.Envelope) (Record, error) {
	if env == nil || env.Mode != "signed" {
		return Record{}, errors.New("not a countersigned entry")
	}
	raw, err := base64.RawURLEncoding.DecodeString(env.Plain)
	if err != nil {
		return Record{}, errors.New("the entry is unreadable")
	}
	var jwm didcomm.JWM
	if err := json.Unmarshal(raw, &jwm); err != nil || jwm.Type != TypeRecord {
		return Record{}, errors.New("the entry is unreadable")
	}
	var r Record
	if err := json.Unmarshal(jwm.Body, &r); err != nil {
		return Record{}, errors.New("the entry is unreadable")
	}
	return r, nil
}

// Hash is an entry's hash in its conversation's chain: over everything the
// countersignature covers and the countersignature itself.
func Hash(env *didcomm.Envelope) string {
	return iacrypto.Blake3QB64Must([]byte(env.Plain + "\n" + env.EdSig + "\n" + env.DsaSig))
}

// Entry is one conversation entry as the Identity Agent keeps and hands it
// out: the countersigned envelope, its place and hash, and where the words
// are kept.
type Entry struct {
	Conversation string `json:"conversation"`
	Seq          int    `json:"seq"`
	MessageID    string `json:"message_id"`
	Kind         string `json:"kind"`
	From         string `json:"from"`
	To           string `json:"to"`
	InReplyTo    string `json:"in_reply_to,omitempty"`
	Depth        int    `json:"depth"`
	BodyHash     string `json:"body_hash"`
	// ContentRef is where the record's content store keeps the words.
	ContentRef string `json:"content_ref"`
	// Envelope is the entry as the Identity Agent countersigned it.
	Envelope  *didcomm.Envelope `json:"envelope"`
	Hash      string            `json:"hash"`
	CreatedAt time.Time         `json:"created_at"`
}
