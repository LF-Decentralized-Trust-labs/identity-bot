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
	// KindProgress is a note from the AI agent an ask was put to, while it is
	// still working: what it has done so far. It goes to the asker and is not
	// the answer — the ask stays open, so the reply or failure that closes it
	// can still follow, and any number of notes may come before it.
	KindProgress = "progress"
	// KindClose is the one who opened a conversation saying the work is done,
	// or the organisation's owner stopping it. It takes no turn and carries no
	// words. Nothing closes a conversation for being quiet.
	KindClose = "close"
	// KindReopen is the opener undoing a close.
	KindReopen = "reopen"
	// KindLimit is the opener raising the number of turns the conversation may
	// hold. Its words are the new limit, in decimal digits.
	KindLimit = "limit"
)

// The turns a conversation may hold, and the most its opener may raise that to.
// An answer to an ask already made never counts against the limit.
const (
	DefaultTurnLimit = 40
	TurnLimitCeiling = 400
)

// IsControl says whether a kind changes how a conversation may go on rather
// than saying something in it: a close, a reopen or a raise of the limit. Such
// an entry takes no turn and acts on no message.
func IsControl(kind string) bool {
	return kind == KindClose || kind == KindReopen || kind == KindLimit
}

// ParseTurnLimit reads the words of a limit entry: decimal digits only, a
// whole number above the default and no higher than the ceiling.
func ParseTurnLimit(words []byte) (int, error) {
	n := 0
	if len(words) == 0 || len(words) > 4 {
		return 0, errors.New("a limit is a whole number, in digits")
	}
	for _, c := range words {
		if c < '0' || c > '9' {
			return 0, errors.New("a limit is a whole number, in digits")
		}
		n = n*10 + int(c-'0')
	}
	if n <= DefaultTurnLimit || n > TurnLimitCeiling {
		return 0, fmt.Errorf("a limit is above %d and no higher than %d", DefaultTurnLimit, TurnLimitCeiling)
	}
	return n, nil
}

// CapabilityMessageAgent is the grant entry that lets an AI agent ask
// another.
const CapabilityMessageAgent = "agent.message.send"

// AskArgs is what an ask is checked against in the asker's grant: the
// arguments its limits on CapabilityMessageAgent are applied to. One encoding,
// so the Identity Agent admitting an ask and a verifier checking it later
// apply the grant to the same thing.
func AskArgs(to, text string) []byte {
	b, _ := json.Marshal(map[string]string{"to": to, "text": text})
	return b
}

// CapabilityMessageOpen names the grant's limit on how often an AI agent opens
// a conversation. It is a key in the grant's resource constraints, read only
// by CheckOpeningGrant: {"agent.message.open": {"per_hour": 6}}. It is not a
// capability an AI agent is granted, so it never reaches
// permission.CheckResourceConstraints.
const CapabilityMessageOpen = "agent.message.open"

// CheckOpeningGrant refuses a grant that does not state, outright, whom an AI
// agent may open a conversation toward and how often (ADR-047, Amendment 3).
// permission.CheckResourceConstraints reads a missing constraint as no limit,
// which is right for an ask inside a conversation but not for opening one, so
// an opening fails closed: the grant's constraint on "to" must exist and name
// the AI agent asked, and its openings per hour must be a stated, positive
// count. The Identity Agent admitting an opening and a verifier checking one
// later both call it.
// MaxOpeningsPerHour is the most conversations a grant may let its AI agent
// open in an hour: a ceiling, so a grant cannot name a count that means none.
const MaxOpeningsPerHour = 60

func CheckOpeningGrant(limits map[string]interface{}, to string) error {
	send, _ := limits[CapabilityMessageAgent].(map[string]interface{})
	names, _ := send["to"].([]interface{})
	if len(names) == 0 {
		return fmt.Errorf("the grant does not name whom its AI agent may open a conversation toward: an opening needs an explicit %q constraint on %s", "to", CapabilityMessageAgent)
	}
	named := false
	for _, n := range names {
		if s, ok := n.(string); ok && s == to {
			named = true
		}
	}
	if !named {
		return fmt.Errorf("the grant does not let its AI agent open a conversation toward %s", to)
	}
	open, _ := limits[CapabilityMessageOpen].(map[string]interface{})
	if n, ok := open["per_hour"].(float64); !ok || n < 1 || n > MaxOpeningsPerHour || n != float64(int64(n)) {
		return fmt.Errorf("the grant states no count of conversations its AI agent may open per hour: an opening needs a whole %q from 1 to %d under %s", "per_hour", MaxOpeningsPerHour, CapabilityMessageOpen)
	}
	return nil
}

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

// Countersigner is the identity that countersigns a message sent by from: the
// Identity Agent, on a person's behalf, for a person's words; the AI agent
// itself for its own. The body that receives a message, the export that
// gathers its keys and the verifier that checks it all ask this one question.
func Countersigner(from, identityAgent string) string {
	if _, person := IsPerson(from); person {
		return identityAgent
	}
	return from
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

// Tiers a task may ask for: how much model the work deserves. A tier is
// advisory: it names a family of models, not a model; which model of the family runs is the
// receiving AI agent's to choose from the models its brain allows
// (asset.BrainConfig.Models). A sender adds a tier only when the receiver is
// known to read IA-AGENT-MSG-V2; within one organisation's Identity Agent it is.
const (
	TierQuick    = "quick"
	TierStandard = "standard"
	TierDeep     = "deep"
)

// ValidTier reports whether t is a tier a message may carry.
func ValidTier(t string) bool {
	return t == TierQuick || t == TierStandard || t == TierDeep
}

// Statement is what a body signs when its AI agent speaks.
type Statement struct {
	// Conversation is empty only on an ask that opens one (see Opens).
	Conversation string `json:"conversation,omitempty"`
	Kind         string `json:"kind"`
	// From is the AI agent speaking; To is the AI agent or person addressed.
	// A close, a reopen and a limit address nobody: To is empty.
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
	// Tier, on an ask, is the tier of model the asker wants the task run on:
	// quick, standard or deep. Absent means the receiver's default. It is
	// covered by the signature, so neither the Identity Agent nor anything
	// between can raise or lower it.
	Tier string `json:"tier,omitempty"`
}

// Opens says whether this is an ask that acts on no message: an AI agent
// opening a conversation toward another AI agent its grant names. Such a
// statement signs an empty conversation line, since the Identity Agent
// chooses the identifier.
func (s Statement) Opens() bool { return s.Kind == KindAsk && s.InReplyTo == "" }

// Bytes is the string a body signs. One field per line, in a fixed order, so
// three implementations produce it identically without agreeing on a JSON
// encoder.
//
// A statement with no tier is signed as IA-AGENT-MSG-V1, byte for byte as
// before the tier existed, so every earlier message still verifies. A
// statement with a tier is signed as IA-AGENT-MSG-V2: the same lines and then
// the tier. A reader that does not know tiers rebuilds the V1 string from the
// fields it knows, which is not what was signed, and so refuses the message
// rather than running it without the tier.
func (s Statement) Bytes() []byte {
	version := "IA-AGENT-MSG-V1"
	if s.Tier != "" {
		version = "IA-AGENT-MSG-V2"
	}
	lines := []string{
		version,
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
	}
	if s.Tier != "" {
		lines = append(lines, s.Tier)
	}
	return []byte(strings.Join(lines, "\n"))
}

// HashBody is the digest a statement carries for its words.
func HashBody(body []byte) string { return iacrypto.Blake3QB64Must(body) }

// Check refuses a statement that is not well formed, before anything is
// verified: a newline in a field would let one statement be read as another.
func (s Statement) Check() error {
	fields := map[string]string{
		"kind": s.Kind, "from": s.From,
		"body_hash": s.BodyHash, "host": s.Host, "host_nonce": s.HostNonce,
		"host_time": s.HostTime, "body_credential": s.BodyCredential,
	}
	// An ask that acts on no message opens a conversation, and the Identity
	// Agent chooses its identifier, so it names none (ADR-047, Amendment 3).
	// Any other statement names the conversation it is in.
	if !s.Opens() {
		fields["conversation"] = s.Conversation
	}
	if !IsControl(s.Kind) {
		fields["to"] = s.To
	}
	for name, v := range fields {
		if v == "" {
			return fmt.Errorf("the message has no %s", name)
		}
	}
	for _, v := range []string{s.Conversation, s.Kind, s.From, s.To, s.InReplyTo, s.BodyHash,
		s.Brain.Provider, s.Brain.Model, s.Brain.Session, s.Brain.RunHash,
		s.Host, s.HostNonce, s.HostTime, s.BodyCredential, s.Tier} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("a message field may not contain a line break")
		}
	}
	switch s.Kind {
	case KindAsk, KindReply, KindReceipt, KindFailure, KindProgress, KindClose, KindReopen, KindLimit:
	default:
		return fmt.Errorf("%q is not a kind of message", s.Kind)
	}
	if IsControl(s.Kind) && (s.To != "" || s.InReplyTo != "") {
		return fmt.Errorf("a %s addresses nobody and acts on no message", s.Kind)
	}
	if s.Tier != "" {
		if !ValidTier(s.Tier) {
			return fmt.Errorf("%q is not a tier: quick, standard or deep", s.Tier)
		}
		if s.Kind != KindAsk {
			return fmt.Errorf("only an ask carries a tier, not a %s", s.Kind)
		}
	}
	// A body speaks about a message it was given. The one exception is an ask
	// that opens a conversation, which names no message and no conversation:
	// the Identity Agent decides whether its grant lets it, and what it opens.
	if s.InReplyTo == "" && s.Kind != KindAsk && !IsControl(s.Kind) {
		return fmt.Errorf("a %s from a body must name the message it acts on", s.Kind)
	}
	if s.InReplyTo == "" && s.Conversation != "" && !IsControl(s.Kind) {
		return errors.New("an ask that acts on no message opens a conversation, so it cannot name one")
	}
	if agentbody.CheckNonce(s.HostNonce) != nil {
		return fmt.Errorf("the message needs a nonce of at least %d characters", agentbody.MinNonce)
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
//
// When an app's back end speaks for a person (AppBody and PersonStatement set),
// the proof carries no request: no RequestBytes, no Request, and no
// SignedString or Signature either, because the app's signature is over a body
// that holds the words and cannot be checked again without them. The app's
// signature is checked once, when the Identity Agent takes the request; what is
// kept is the person's own statement, which is the record (ADR-067, ADR-068).
type ControllerProof struct {
	Controller string `json:"controller"`
	// PublicKey is the controller's key as its grant records it.
	PublicKey    string `json:"public_key"`
	SignedString string `json:"signed_string"`
	Signature    string `json:"signature"`
	// RequestBytes is the request body the controller signed, byte for byte.
	// Absent when an app speaks for a person: the words of a conversation live
	// only in the app, never in the Identity Agent.
	// It is carried as bytes, not as JSON inside the record, because the
	// signed string commits to a digest of these exact bytes and any JSON
	// encoder that re-writes the record would re-write a nested value too:
	// Go's compacts it and escapes < > & as \u003c \u003e \u0026.
	RequestBytes []byte `json:"request_bytes,omitempty"`
	// Request is the same body nested as JSON, the form a record took before
	// RequestBytes existed. It is read so those records still check, never
	// written: see SignedRequest.
	Request json.RawMessage `json:"request,omitempty"`
	// ControllerGrant is the controller's Controller Grant credential: anchored
	// in the organisation's key log, it names the signer the controller acts as,
	// so the person behind a message is shown by a credential anybody can check
	// rather than by this Identity Agent's word. Empty for a controller granted
	// before machines were given one.
	ControllerGrant string `json:"controller_grant,omitempty"`
	// AppBody is, when an app's back end spoke for a person (ADR-072), the App
	// Body credential that names the key that signed: Controller is then that
	// key's identifier (the body's host) and PublicKey its verkey. The proof is
	// the person's statement alone (see StatementOnly): SignedString, Signature,
	// RequestBytes and Request are empty, and a proof that sets AppBody and any
	// of them is refused. The credential is carried in a bundle, so which app's
	// machine carried the statement is shown by a credential anybody can check.
	// Empty for a controller's request.
	AppBody string `json:"app_body,omitempty"`
	// PersonStatement is, when the controller was an app's back end speaking for
	// a person, that person's own signed statement over a fingerprint of their
	// words, as the app carried it (ADR-066, ADR-067). Absent when the
	// controller spoke as the signer it belongs to. The salt is not here: the
	// app that keeps the words keeps it.
	PersonStatement *PersonProof `json:"person_statement,omitempty"`
}

// StatementOnly is whether this is the proof of an app's back end speaking for
// a person, kept without the request: the person's statement and the App Body
// that admitted the app's key, and none of the request or the app's signature
// over it.
func (p ControllerProof) StatementOnly() bool {
	return p.AppBody != "" && p.SignedString == "" && p.Signature == ""
}

// errProofHoldsWords is a statement-only proof that carries the request after
// all, which would put a person's words in the record.
var errProofHoldsWords = errors.New("an app speaking for a person keeps their statement, never the request, which holds the words")

// errAppProofHoldsRequest is an app's proof that carries the app's signed
// request, which holds a person's words. An app's proof is statement-only.
var errAppProofHoldsRequest = errors.New("an app's proof is the person's statement alone: it carries no signed request, and a request that is carried is refused")

// Verify checks the controller signed this request. An app's proof is
// statement-only and has no request to check: it holds the person's own
// statement, which is checked. An app's proof of any other form is refused.
func (p ControllerProof) Verify() error {
	if p.StatementOnly() {
		if len(p.RequestBytes) > 0 || len(p.Request) > 0 {
			return errProofHoldsWords
		}
		if p.PersonStatement == nil {
			return errors.New("an app's back end speaks only with a person's own statement, and the proof carries none")
		}
		return nil
	}
	if p.AppBody != "" {
		return errAppProofHoldsRequest
	}
	ok, err := iacrypto.VerifyMachineSignature(p.PublicKey, p.Signature, []byte(p.SignedString))
	if err != nil || !ok {
		return errors.New("the request is not signed by the controller it names")
	}
	lines := strings.Split(p.SignedString, "\n")
	if len(lines) < 2 || lines[1] != p.Controller {
		return errors.New("the signed request names a different controller")
	}
	_, err = p.SignedRequest()
	return err
}

// SignedRequest is the request body exactly as the controller signed it: the
// bytes whose digest is the signed string's last line, and so the only bytes
// anything may read the person's words from.
//
// A record written before RequestBytes existed nests the body as JSON, which
// the Identity Agent's own encoder compacted and HTML-escaped when it
// countersigned the record. Such a body is taken as it stands, or else with
// that escaping undone; either is accepted only when its digest is the one the
// controller signed, so undoing the escaping can recover the signed bytes but
// can never make other bytes pass for them.
func (p ControllerProof) SignedRequest() ([]byte, error) {
	if p.AppBody != "" {
		return nil, errAppProofHoldsRequest
	}
	lines := strings.Split(p.SignedString, "\n")
	signed := lines[len(lines)-1]
	switch {
	case len(p.RequestBytes) > 0 && len(p.Request) > 0:
		return nil, errors.New("the proof carries the request twice")
	case len(p.RequestBytes) > 0:
		if iacrypto.Blake3QB64Must(p.RequestBytes) == signed {
			return p.RequestBytes, nil
		}
	case len(p.Request) > 0:
		for _, b := range [][]byte{p.Request, unescapeHTML(p.Request)} {
			if iacrypto.Blake3QB64Must(b) == signed {
				return b, nil
			}
		}
	}
	return nil, errors.New("the signed request is not this request")
}

// unescapeHTML undoes the escaping Go's JSON encoder applies by default:
// \u003c, \u003e, \u0026, \u2028 and \u2029 back to the characters they
// stand for. Only an escape is undone, never the same six characters after an
// escaped backslash, which are text.
func unescapeHTML(b []byte) []byte {
	repl := map[string]string{`\u003c`: "<", `\u003e`: ">", `\u0026`: "&", `\u2028`: "\u2028", `\u2029`: "\u2029"}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			out = append(out, b[i])
			continue
		}
		if i+6 <= len(b) {
			if r, ok := repl[string(b[i:i+6])]; ok {
				out = append(out, r...)
				i += 5
				continue
			}
		}
		// Any other escape is kept whole, so the character after the
		// backslash is never read as the start of an escape.
		out = append(out, b[i])
		if i+1 < len(b) {
			out = append(out, b[i+1])
			i++
		}
	}
	return out
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
	// PersonProof is a person's statement over the fingerprint of their words,
	// with no words in it (ADR-067, ADR-068). The same record, in the same
	// chain, holds a person's entry whichever way they signed it.
	PersonProof *PersonProof `json:"person_proof,omitempty"`
	// Refusal is why the Identity Agent refused a person's write before
	// forwarding anything. A refusal is an entry of the chain with a person's
	// proof, so it records who tried, when and why, and holds no words.
	Refusal string `json:"refusal,omitempty"`
	// CiphertextHash is, for an entry the Identity Agent holds only as
	// ciphertext, the fingerprint over the ciphertext (the statement's own).
	CiphertextHash string `json:"ciphertext_hash,omitempty"`
	// Outcome, on an entry of kind KindOutcome, is how an earlier entry ended.
	Outcome *Outcome `json:"outcome,omitempty"`

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
	case r.Outcome != nil:
		return r.checkOutcome()
	case r.Kind == KindOutcome:
		return errors.New("an outcome names the entry it is about")
	case r.PersonProof != nil:
		return r.checkPersonProof()
	case r.Statement != nil && r.ControllerProof != nil:
		return errors.New("a message carries one sender's proof, not two")
	case r.Statement != nil:
		st := *r.Statement
		// A statement that opens a conversation names none: the record gives
		// the identifier the Identity Agent chose, as for a person's request.
		// It opens only as the first entry, and it is the opener's own.
		if st.Opens() && (r.Seq != 1 || r.OpenedBy != r.From || r.Depth != 1) {
			return errors.New("an ask that acts on no message is the first entry of a conversation its sender opened")
		}
		if st.Conversation != r.Conversation && !st.Opens() || st.Kind != r.Kind || st.From != r.From ||
			st.To != r.To || st.InReplyTo != r.InReplyTo || st.BodyHash != r.BodyHash ||
			st.BodyCredential != r.BodyCredential {
			return errors.New("the record does not say what its body signed")
		}
		return Verify(st, r.HostVerkey, r.HostSignature)
	case r.ControllerProof != nil && r.ControllerProof.StatementOnly():
		if err := r.ControllerProof.Verify(); err != nil {
			return err
		}
		// There are no words to read the message id or the digest from: the
		// statement names the message, and its fingerprint is the record's.
		st := r.ControllerProof.PersonStatement.Statement
		if r.BodyHash != st.Fingerprint {
			return errors.New("the record does not say what the person signed")
		}
		return r.ControllerProof.checkPersonStatement(r, st.MessageID)
	case r.ControllerProof != nil:
		if err := r.ControllerProof.Verify(); err != nil {
			return err
		}
		signed, err := r.ControllerProof.SignedRequest()
		if err != nil {
			return err
		}
		var req PersonMessage
		if err := json.Unmarshal(signed, &req); err != nil {
			return errors.New("the signed request is unreadable")
		}
		// The person's controller signed the words themselves, so their digest
		// is taken from what was signed, never from a digest the app supplied.
		if req.To != r.To || HashBody([]byte(req.Body)) != r.BodyHash ||
			req.Conversation != r.Conversation && req.Conversation != "" || req.InReplyTo != r.InReplyTo {
			return errors.New("the record does not say what the person's controller signed")
		}
		if r.ControllerProof.PersonStatement == nil {
			return nil
		}
		return r.ControllerProof.checkPersonStatement(r, req.Nonce)
	}
	return errors.New("the message carries no proof from its sender")
}

// checkPersonStatement checks, when an app's back end spoke for a person, that
// the person's own statement is theirs and for this very entry: signed by the
// key it names, from the person the record is from, and naming the
// conversation, kind, recipient, reply and message the record and the app's
// signed request have. Whose the key is, and that the words are the ones the
// fingerprint is over (the salt is not kept), are not shown by the record.
func (p ControllerProof) checkPersonStatement(r Record, messageID string) error {
	if err := p.PersonStatement.Verify(); err != nil {
		return fmt.Errorf("the person's statement does not hold: %w", err)
	}
	st := p.PersonStatement.Statement
	if (st.Kind != PersonKindMessage && st.Kind != PersonKindAsk) || r.From != Person(st.From) ||
		st.Kind != r.Kind || st.To != r.To || st.InReplyTo != r.InReplyTo ||
		st.Conversation != r.Conversation || st.MessageID != messageID {
		return errors.New("the record does not say what the person signed")
	}
	return nil
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
	return CountersignWith(as.AID, func(m *didcomm.JWM) (*didcomm.Envelope, error) {
		return didcomm.PackSigned(as, m)
	}, r)
}

// CountersignWith is Countersign where the keys of as are held by whatever
// packs the message: pack signs m as as, as didcomm.PackSigned does.
func CountersignWith(as string, pack func(m *didcomm.JWM) (*didcomm.Envelope, error), r Record) (*didcomm.Envelope, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	to := r.To
	if aid, ok := IsPerson(to); ok {
		to = aid
	}
	if to == "" {
		// A close, a reopen and an outcome name no recipient: the envelope is
		// addressed to the one who signed it.
		to = as
	}
	return pack(&didcomm.JWM{
		ID: r.MessageID, Type: TypeRecord,
		From: "did:keri:" + as, To: []string{"did:keri:" + to},
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
