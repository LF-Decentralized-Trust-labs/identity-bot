// Package agentpeer is a message from an AI agent one Identity Agent holds to an
// AI agent another Identity Agent holds, as the two Identity Agents carry it
// (ADR-085). Whoever holds each Identity Agent, a person or an organisation, the
// message and its checks are the same.
//
// The envelope between two contacts already proves which Identity Agent sent a
// message. What it does not give is a record a third party can check later, so
// the sending Identity Agent also signs a KERI exchange message (exn) saying
// what was said, who it is between and what it answers, and sends the words
// beside it. The receiver checks the exchange message and keeps it, so each
// side can show the exchange to anybody without the other's help.
//
// The exchange message is KERI's own, built and read by keri-go (ADR-037), in
// the exact form keripy builds and a keripy Exchanger accepts. It is not a
// signed body shaped like one.
//
// What the signature proves, and what it does not: it proves that the
// SENDING IDENTITY AGENT vouched that an AI agent it holds sent these words to
// the named AI agent of the receiving Identity Agent. It does not prove which machine, brain or
// model produced the words, and the receiver cannot check the AI agent's own
// keys. The sending Identity Agent answers for the AI agents it holds.
//
// WHO SIGNS, AND HOW IT IS TIED TO THE KEY LOG. The key-log key of the identity
// an Identity Agent holds lives on the device that controls it, so it cannot
// sign every message the Identity Agent sends. The Identity Agent signs with its
// messaging keys, which its key log commits to (didcomm.DID.KelSig). The
// exchange message's sender (`i`) is therefore the Ed25519 messaging key as a
// non-transferable identifier, which is how keripy checks a signature with
// nothing else, and a receiver accepts it only when that key is the one in the
// sender's DID that its key log vouches for. A message is also signed with the
// ML-DSA messaging key (as everything else it signs is: no classical-only
// fallback), and a reader requires both.
package agentpeer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/didcomm"
	"identity-agent-core/fingerprint"
	"identity-agent-core/iacrypto"
)

// The kinds of message. Each is one of an ask and what answers it.
const (
	KindAsk      = "ask"
	KindReply    = "reply"
	KindFailure  = "failure"
	KindProgress = "progress"
)

// RoutePrefix begins the route of every exchange message here; the kind ends it.
// The route is what tells a reader how to read the message (KERI: `r`).
const RoutePrefix = "/ia/agent/peer/"

// FingerprintVersion is the fingerprint version a statement names (ADR-067).
// Only version 1, the salted one, is written or read: a new format does not
// start with the unsalted digest.
const FingerprintVersion = 1

// MaxWords bounds the words in one message, as between AI agents one Identity Agent holds
// (agentmessage.MaxBody, which a test holds equal: agentmessage imports this
// package, so it cannot be named here).
const MaxWords = 64 << 10

// MaxAge is how old, or how far ahead, a statement may be dated. It is the
// envelope's own bound on how long it may be declared valid.
const MaxAge = time.Hour

// maxField bounds an identifier a statement carries.
const maxField = 128

// sentAtLayout is how an exchange message is dated (keripy's own): ISO 8601
// with microseconds, in UTC written as +00:00.
const sentAtLayout = "2006-01-02T15:04:05.000000-07:00"

// pqDomain is put in front of what the ML-DSA signature covers, so that
// signature cannot be read as one made for anything else with the same key.
const pqDomain = "IA-AGENT-PEER-PQ-V1\n"

// Statement is what an exchange message says, in the terms this package uses.
// It is not the wire form: the wire form is the exchange message (Seal).
type Statement struct {
	Kind string `json:"kind"`
	// FromAID is the sending Identity Agent's identifier as its contacts know it,
	// and the one who signs. ToAID is the receiver's (the message's `rp`).
	FromAID string `json:"from_aid"`
	ToAID   string `json:"to_aid"`
	// FromAgent and ToAgent are the AI agents' identifiers.
	FromAgent string `json:"from_agent"`
	ToAgent   string `json:"to_agent"`
	MessageID string `json:"message_id"`
	// InReplyTo names the ask a reply, failure or progress note answers; an ask names none.
	InReplyTo string `json:"in_reply_to,omitempty"`
	// Fingerprint is the salted fingerprint of the words (ADR-067, version
	// FingerprintVersion). The salt travels with the words, never in a statement.
	Fingerprint string `json:"fingerprint"`
	// SentAt is the exchange message's `dt`, in its one spelling.
	SentAt string `json:"sent_at"`
}

// Signed is what an Identity Agent signed: the exchange message, with its
// Ed25519 signature attached as KERI attaches one, and the ML-DSA signature
// over it. It is what a record keeps of the other Identity Agent's say-so, and it
// holds no words.
type Signed struct {
	// Exn is the signed exchange message, as KERI text (CESR): the message
	// followed by one non-transferable signature couple.
	Exn string `json:"exn"`
	// PQSig is the ML-DSA-65 signature over the message (pqInput), in
	// unpadded base64url.
	PQSig string `json:"pq_sig"`
}

// Message is what an Identity Agent sends in an agent-peer-message envelope:
// the signed exchange message, and the words and the salt of their fingerprint.
type Message struct {
	Signed
	Words string `json:"words"`
	// Salt is the fingerprint's salt (16 to 1024 bytes) in unpadded base64url.
	// It travels and is kept with the words and nowhere else.
	Salt string `json:"salt"`
}

// Refusal is why a statement or a message was refused. Each is a different
// rule, so a test can say which one held; Code is stable, for an
// implementation that cannot match on text.
type Refusal struct {
	code, text string
}

func (r *Refusal) Error() string { return r.text }

// Code is the refusal's stable name.
func (r *Refusal) Code() string { return r.code }

func refuse(code, text string) *Refusal { return &Refusal{code, text} }

// CodeOf is the stable code of a refusal from this package, or "" for any other error.
func CodeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.code
	}
	return ""
}

// The refusals.
var (
	ErrNoEntry         = refuse("no_message", "the message carries no signed exchange message")
	ErrNotSigned       = refuse("not_signed", "the exchange message is not signed by the Identity Agent it names")
	ErrUnreadable      = refuse("unreadable", "the signed exchange message is unreadable")
	ErrWrongSender     = refuse("wrong_sender", "the message names another sender than the Identity Agent that sent it")
	ErrWrongRecipient  = refuse("wrong_recipient", "the message is for another Identity Agent than this one")
	ErrKind            = refuse("kind", "a message is an ask, a reply, a failure or a progress note")
	ErrReplyTo         = refuse("reply_to", "an ask answers nothing, and everything else answers an ask")
	ErrField           = refuse("field", "an identifier in the message is missing, too long, or uses a character an identifier may not")
	ErrFingerprint     = refuse("fingerprint", "the words are not the ones the message covers")
	ErrFingerprintVer  = refuse("fingerprint_version", "the message names a fingerprint version that is not the salted one")
	ErrSalt            = refuse("salt", "the fingerprint's salt is missing, too short or too long")
	ErrWords           = refuse("words", "the words are empty or too long")
	ErrTime            = refuse("time", "the message is not dated within the last hour")
	ErrPlaceID         = refuse("place_id", "a message or the one it answers is named like an entry's place in a conversation, which is not a message's own name")
	ErrNotInItsOneForm = refuse("not_one_form", "the exchange message is not in its one form")
)

// placeIDShaped reports whether id is "e" and a positive number, the shape a
// conversation uses for an entry's place (agentmessage.EntryID). A message's own
// name must not take that shape: a trail that files an entry by its place would
// otherwise read two different messages, in two conversations, as the same one,
// so a statement carrying such a name is refused and never kept.
func placeIDShaped(id string) bool {
	if len(id) < 2 || id[0] != 'e' {
		return false
	}
	for _, r := range id[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return id[1] != '0'
}

// plain says whether s is an identifier: one to 128 of the letters, digits and
// '_', '.', ':' and '-' that KERI identifiers and the ids an add-on makes are
// written in. Nothing else: no space, line break, control, text-direction or
// look-alike character, and no "/": a party is written Identity Agent/AI agent
// (agentmessage.Peer), and the record reads a trailing "/e<digits>" of a message
// id as a place.
func plain(s string) bool {
	if s == "" || len(s) > maxField {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// Route is the exchange message's route for a kind.
func Route(kind string) string { return RoutePrefix + kind }

func kindOfRoute(r string) string {
	if !strings.HasPrefix(r, RoutePrefix) {
		return ""
	}
	switch k := strings.TrimPrefix(r, RoutePrefix); k {
	case KindAsk, KindReply, KindFailure, KindProgress:
		return k
	}
	return ""
}

// Check says whether a statement is well formed by itself.
func (s Statement) Check() error {
	for _, f := range []string{s.FromAID, s.ToAID, s.FromAgent, s.ToAgent, s.MessageID} {
		if !plain(f) {
			return ErrField
		}
	}
	switch s.Kind {
	case KindAsk:
		if s.InReplyTo != "" {
			return ErrReplyTo
		}
	case KindReply, KindFailure, KindProgress:
		if !plain(s.InReplyTo) {
			return ErrReplyTo
		}
	default:
		return ErrKind
	}
	if placeIDShaped(s.MessageID) || (s.InReplyTo != "" && placeIDShaped(s.InReplyTo)) {
		return ErrPlaceID
	}
	if !isDigest(s.Fingerprint) {
		return ErrFingerprint
	}
	if _, err := parseSentAt(s.SentAt); err != nil {
		return ErrTime
	}
	return nil
}

// isDigest says whether s is a Blake3-256 digest as CESR (code E).
func isDigest(s string) bool {
	_, err := iacrypto.DecodeQB64("E", s, 32)
	return err == nil
}

func parseSentAt(s string) (time.Time, error) {
	t, err := time.Parse(sentAtLayout, s)
	if err != nil {
		return time.Time{}, err
	}
	if t.UTC().Format(sentAtLayout) != s {
		return time.Time{}, errors.New("not in its one spelling")
	}
	return t, nil
}

// attributes is `a` of the exchange message after the recipient (`i`): the
// fields in the order the message carries them.
type attributes struct {
	FromAID            string `json:"from_aid"`
	FromAgent          string `json:"from_agent"`
	ToAgent            string `json:"to_agent"`
	MessageID          string `json:"message_id"`
	InReplyTo          string `json:"in_reply_to,omitempty"`
	FingerprintVersion int    `json:"fingerprint_version"`
	Fingerprint        string `json:"fingerprint"`
}

// attributesOf is `a` without the recipient, for the exchange message builder.
func (s Statement) attributes() (json.RawMessage, error) {
	return json.Marshal(attributes{FromAID: s.FromAID, FromAgent: s.FromAgent, ToAgent: s.ToAgent,
		MessageID: s.MessageID, InReplyTo: s.InReplyTo, FingerprintVersion: FingerprintVersion,
		Fingerprint: s.Fingerprint})
}

// SenderIdentifier is the non-transferable identifier an Identity Agent's
// exchange messages are sent as: its Ed25519 messaging key. It is written by
// keri-go, the engine that signs and reads the message (ADR-037), so the
// identifier a message is built with and the one it is checked against come
// from one encoder.
func SenderIdentifier(edKey ed25519.PublicKey) (string, error) {
	if len(edKey) != ed25519.PublicKeySize {
		return "", errors.New("the messaging key is not an Ed25519 key")
	}
	return keri.MatterQB64(keri.CodeEd25519N, edKey)
}

// exchange builds the (unsigned) exchange message for a statement.
func (s Statement) exchange(sender string) ([]byte, error) {
	data, err := s.attributes()
	if err != nil {
		return nil, err
	}
	return keri.BuildExchange(keri.ExchangeInput{Sender: sender, Recipient: s.ToAID,
		DT: s.SentAt, Route: Route(s.Kind), Data: data})
}

func pqInput(rawExchange []byte) []byte {
	return append([]byte(pqDomain), rawExchange...)
}

// Seal signs a statement as the sending Identity Agent and returns the message
// to send. now is when it is sent. The statement's FromAID, Fingerprint and
// SentAt are set here: the sender is the keyset's identifier, the fingerprint is of
// the words under a salt made now, and the time is now.
func Seal(as *didcomm.KeySet, s Statement, words string, now time.Time) (Message, error) {
	salt, err := fingerprint.NewSalt()
	if err != nil {
		return Message{}, err
	}
	return sealUnder(as, s, words, salt, now)
}

// sealUnder is Seal under a salt the caller chose, for the published vectors,
// which have to be the same bytes every time.
func sealUnder(as *didcomm.KeySet, s Statement, words string, salt []byte, now time.Time) (Message, error) {
	if words == "" || len(words) > MaxWords {
		return Message{}, ErrWords
	}
	var err error
	s.FromAID = as.AID
	if s.Fingerprint, err = fingerprint.Of(salt, []byte(words)); err != nil {
		return Message{}, err
	}
	s.SentAt = now.UTC().Format(sentAtLayout)
	if err := s.Check(); err != nil {
		return Message{}, err
	}
	sender, err := SenderIdentifier(as.EdPub)
	if err != nil {
		return Message{}, err
	}
	raw, err := s.exchange(sender)
	if err != nil {
		return Message{}, err
	}
	stream, err := keri.SignExchange(raw, as.EdPriv)
	if err != nil {
		return Message{}, err
	}
	return Message{
		Signed: Signed{Exn: string(stream), PQSig: base64.RawURLEncoding.EncodeToString(as.SignPostQuantum(pqInput(raw)))},
		Words:  words,
		Salt:   base64.RawURLEncoding.EncodeToString(salt),
	}, nil
}

// ReadStatement checks the sending Identity Agent's signatures on what it signed and
// returns the statement it made, well formed. It does not know who the message
// was sent to or when: a verifier reading a kept message long after uses it, and
// Verify adds those checks for the one receiving it.
//
// signer is the sending Identity Agent's messaging keys as its key log vouches
// for them. The exchange message's sender must be exactly that Ed25519 key, its
// signature must hold, and so must the ML-DSA one.
func ReadStatement(m Signed, signer *didcomm.DID) (Statement, error) {
	if m.Exn == "" {
		return Statement{}, ErrNoEntry
	}
	signed, err := keri.VerifyExchangeSigned([]byte(m.Exn))
	if err != nil {
		return Statement{}, ErrUnreadable
	}
	edKey, err := signer.EdPublicKey()
	if err != nil {
		return Statement{}, ErrNotSigned
	}
	want, err := SenderIdentifier(edKey)
	if err != nil || signed.Sender != want {
		return Statement{}, ErrNotSigned
	}
	pq, err := iacrypto.DecodeBase64URLSized(m.PQSig, iacrypto.MLDSA65SigBytes)
	if err != nil || !signer.VerifyPostQuantum(pqInput(signed.Raw), pq) {
		return Statement{}, ErrNotSigned
	}
	kind := kindOfRoute(signed.Route)
	if kind == "" {
		return Statement{}, ErrKind
	}
	var a struct {
		I string `json:"i"`
		attributes
	}
	dec := json.NewDecoder(bytes.NewReader(signed.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return Statement{}, ErrUnreadable
	}
	if a.FingerprintVersion != FingerprintVersion {
		return Statement{}, ErrFingerprintVer
	}
	s := Statement{Kind: kind, FromAID: a.FromAID, ToAID: signed.Recipient, FromAgent: a.FromAgent,
		ToAgent: a.ToAgent, MessageID: a.MessageID, InReplyTo: a.InReplyTo,
		Fingerprint: a.Fingerprint, SentAt: signed.DT}
	if signed.Prior != "" || a.I != signed.Recipient {
		return Statement{}, ErrNotInItsOneForm
	}
	if s.FromAID != signer.AID {
		return Statement{}, ErrWrongSender
	}
	if err := s.Check(); err != nil {
		return Statement{}, err
	}
	// One spelling: what was read is rebuilt and must be the bytes that were
	// signed, so a message with an extra or reordered field, or a modifier, is
	// not read as equal to the one this package writes.
	again, err := s.exchange(signed.Sender)
	if err != nil || !bytes.Equal(again, signed.Raw) {
		return Statement{}, ErrNotInItsOneForm
	}
	return s, nil
}

// Verify checks a message against the sending Identity Agent's keys (signer)
// and says what the receiving Identity Agent (self) was told. sentBy is who the
// envelope it arrived in said sent it; a statement from anybody else is refused.
// It does not decide whether the receiver will take the message: whether the
// sender is a contact, and what its AI agents may reach, are the receiver's own
// rules, applied after this.
func Verify(m Message, signer *didcomm.DID, sentBy, self string, now time.Time) (Statement, error) {
	s, err := ReadStatement(m.Signed, signer)
	if err != nil {
		return Statement{}, err
	}
	if s.FromAID != sentBy {
		return Statement{}, ErrWrongSender
	}
	if s.ToAID != self {
		return Statement{}, ErrWrongRecipient
	}
	if m.Words == "" || len(m.Words) > MaxWords {
		return Statement{}, ErrWords
	}
	salt, err := iacrypto.DecodeBase64URL(m.Salt)
	if err != nil || len(salt) < fingerprint.MinSalt || len(salt) > fingerprint.MaxSalt {
		return Statement{}, ErrSalt
	}
	if f, err := fingerprint.Of(salt, []byte(m.Words)); err != nil || f != s.Fingerprint {
		return Statement{}, ErrFingerprint
	}
	at, err := parseSentAt(s.SentAt)
	if err != nil || now.Sub(at) > MaxAge || at.Sub(now) > MaxAge {
		return Statement{}, ErrTime
	}
	return s, nil
}

// String is a statement as a line a person can read in a log, with nothing in
// it a contact chose that is not an identifier (plain).
func (s Statement) String() string {
	return fmt.Sprintf("%s %s from %s/%s to %s/%s", s.Kind, s.MessageID, s.FromAID, s.FromAgent, s.ToAID, s.ToAgent)
}
