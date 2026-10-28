package agentmessage

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
)

type ed25519Signer struct{ priv ed25519.PrivateKey }

func (s ed25519Signer) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s ed25519Signer) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

// vectorSigner is a fixed key: seed bytes 0x01..0x20.
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
		Brain:    Brain{Provider: "example-harness", Model: "example-model", Session: "s-1", RunHash: "Erun"},
		Host:     host, HostNonce: "nonce-0123456789abcdef", HostTime: "2026-10-20T12:00:00Z",
		BodyCredential: "EBODYCRED",
	}
}

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
