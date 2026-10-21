package agentmessage

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
)

type ed25519Signer struct{ priv ed25519.PrivateKey }

func (s ed25519Signer) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s ed25519Signer) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

// vectorSigner is a fixed key, so the vectors below are reproducible by any
// implementation: seed bytes 0x01..0x20.
func vectorSigner() ed25519Signer {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519Signer{ed25519.NewKeyFromSeed(seed)}
}

func vectorStatement(t *testing.T) Statement {
	host, _, err := agentbody.Identity(vectorSigner())
	if err != nil {
		t.Fatal(err)
	}
	return Statement{
		Conversation: "c_vector", Kind: KindReply, From: "EAGENT_B", To: "EAGENT_A", InReplyTo: "m_ask",
		BodyHash: HashBody([]byte("I run macOS 26.1 on a MacBook Pro.")),
		Brain:    Brain{Provider: "claude-code", Model: "claude-opus-5-5", Session: "s-1", RunHash: "Erun"},
		Host:     host, HostNonce: "nonce-0123456789abcdef", HostTime: "2026-10-20T12:00:00Z",
		BodyCredential: "EBODYCRED",
	}
}

// The published test vectors: the exact string a body signs, the digest of a
// message's words, and the signature the fixed key makes over it. An Agent
// Host, an Identity Agent and an offline verifier must all produce these.
func TestTheMessageFormatVectors(t *testing.T) {
	st := vectorStatement(t)
	wantBytes := strings.Join([]string{
		"IA-AGENT-MSG-V1", "c_vector", "reply", "EAGENT_B", "EAGENT_A", "m_ask",
		HashBody([]byte("I run macOS 26.1 on a MacBook Pro.")),
		"claude-code", "claude-opus-5-5", "s-1", "Erun",
		st.Host, "nonce-0123456789abcdef", "2026-10-20T12:00:00Z", "EBODYCRED",
	}, "\n")
	if string(st.Bytes()) != wantBytes {
		t.Fatalf("the signed string changed:\n%s", st.Bytes())
	}
	if got := HashBody([]byte("I run macOS 26.1 on a MacBook Pro.")); got != vectorBodyHash {
		t.Fatalf("the words' digest changed: %s", got)
	}
	if st.Host != vectorHost {
		t.Fatalf("the body's identifier changed: %s", st.Host)
	}
	sig, err := Sign(vectorSigner(), st)
	if err != nil {
		t.Fatal(err)
	}
	if sig != vectorSignature {
		t.Fatalf("the signature changed: %s", sig)
	}
	_, verkey, _ := agentbody.Identity(vectorSigner())
	if err := Verify(st, verkey, sig); err != nil {
		t.Fatalf("the vector does not verify: %v", err)
	}
}

const (
	vectorBodyHash  = "EDXyvxf9u_04aoMO0NTqpfrS5RZlVGjmguuOQ4jQNmJQ"
	vectorHost      = "BHm1Vi6P5lT5QHixEuipi6eQH4U65pW-1-DjkQutBJZk"
	vectorSignature = "0BD3LvzasdVNi6ctmuRlsjPaGI-kqIxFVKtm1M4SDtj84FXbBCKaPFK8QSbDxJEENwzgolk_20uV8X5-sAQAY0oB"
)

// Every field the body signs is bound: changing any one breaks the signature.
func TestEveryFieldABodySignsIsBound(t *testing.T) {
	st := vectorStatement(t)
	sig, _ := Sign(vectorSigner(), st)
	_, verkey, _ := agentbody.Identity(vectorSigner())
	for name, change := range map[string]func(*Statement){
		"conversation": func(s *Statement) { s.Conversation = "c_other" },
		"kind":         func(s *Statement) { s.Kind = KindAsk },
		"from":         func(s *Statement) { s.From = "EOTHER" },
		"to":           func(s *Statement) { s.To = "EOTHER" },
		"in_reply_to":  func(s *Statement) { s.InReplyTo = "m_other" },
		"body_hash":    func(s *Statement) { s.BodyHash = HashBody([]byte("yes")) },
		"brain":        func(s *Statement) { s.Brain.Model = "another" },
		"nonce":        func(s *Statement) { s.HostNonce = "nonce-ffffffffffffffff" },
		"time":         func(s *Statement) { s.HostTime = "2026-10-20T12:00:01Z" },
		"credential":   func(s *Statement) { s.BodyCredential = "EOTHERCRED" },
	} {
		changed := st
		change(&changed)
		if Verify(changed, verkey, sig) == nil {
			t.Errorf("changing %s left the signature valid", name)
		}
	}
}

// A field cannot smuggle a line break, which would let one statement be read
// as another; and a body cannot speak without naming what it acts on.
func TestAMalformedStatementIsRefusedBeforeSigning(t *testing.T) {
	st := vectorStatement(t)
	st.To = "EAGENT_A\nEAGENT_C"
	if _, err := Sign(vectorSigner(), st); err == nil {
		t.Fatal("a statement with a line break in a field was signed")
	}
	st = vectorStatement(t)
	st.InReplyTo = ""
	st.Kind = KindAsk
	if _, err := Sign(vectorSigner(), st); err == nil {
		t.Fatal("a body spoke without naming the message it acts on")
	}
}

// The countersignature covers the sender's statement and its signature: an
// entry whose inner statement is swapped no longer opens.
func TestTheCountersignatureCoversTheSendersSignature(t *testing.T) {
	ks, err := didcomm.GenerateKeySet("EAGENT_B")
	if err != nil {
		t.Fatal(err)
	}
	did, _ := ks.DID()
	st := vectorStatement(t)
	sig, _ := Sign(vectorSigner(), st)
	_, verkey, _ := agentbody.Identity(vectorSigner())
	rec := Record{MessageID: "m_1", Conversation: st.Conversation, Seq: 3, PrevHash: "Eprev", IATime: "2026-10-20T12:00:01Z",
		Kind: st.Kind, From: st.From, To: st.To, InReplyTo: st.InReplyTo, BodyHash: st.BodyHash,
		Statement: &st, HostSignature: sig, HostVerkey: verkey, BodyCredential: st.BodyCredential, OpenedBy: Person("EROB")}
	env, err := Countersign(ks, rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(did, env)
	if err != nil || got.CheckSenderProof() != nil {
		t.Fatalf("the entry does not open and verify: %v %v", err, got.CheckSenderProof())
	}
	read, _ := Read(env)
	if read.MessageID != "m_1" || Hash(env) == "" {
		t.Fatal("the entry cannot be read back")
	}
	tampered := *env
	tampered.Plain = strings.Replace(env.Plain, "A", "B", 1)
	if _, err := Open(did, &tampered); err == nil {
		t.Fatal("an altered entry still opened")
	}
	// A record that says something other than what the body signed is caught
	// even when the Identity Agent signed it.
	rec.To = "EAGENT_C"
	if rec.CheckSenderProof() == nil {
		t.Fatal("a record re-addressed after the body signed it was accepted")
	}
}

// The vectors are also published as a file, for implementations in other
// languages, and the file must say what this one does.
func TestThePublishedVectorFileMatches(t *testing.T) {
	b, err := os.ReadFile("testdata/message-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Words        string    `json:"words"`
		Statement    Statement `json:"statement"`
		BodyHash     string    `json:"body_hash"`
		Host         string    `json:"host"`
		Signature    string    `json:"signature"`
		SignedString string    `json:"signed_string"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	v.Statement.BodyHash, v.Statement.Host = v.BodyHash, v.Host
	if HashBody([]byte(v.Words)) != v.BodyHash || string(v.Statement.Bytes()) != v.SignedString {
		t.Fatal("the published vector file disagrees with this implementation")
	}
	if sig, _ := Sign(vectorSigner(), v.Statement); sig != v.Signature {
		t.Fatalf("the published signature is not this key's: %s", sig)
	}
}
