package agentmessage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
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
	if _, err := Sign(vectorSigner(), st); err == nil {
		t.Fatal("a reply was signed without naming the message it acts on")
	}
	st.Kind = KindReceipt
	if _, err := Sign(vectorSigner(), st); err == nil {
		t.Fatal("a receipt was signed without naming the message it acts on")
	}
	// An ask that names a conversation but no message would borrow a
	// conversation the AI agent was never brought into.
	st.Kind = KindAsk
	if _, err := Sign(vectorSigner(), st); err == nil {
		t.Fatal("an ask naming a conversation but no message it acts on was signed")
	}
}

// An AI agent opens a conversation with an ask that names no message and no
// conversation (ADR-047, Amendment 3). Both are signed as empty lines, so it
// is still IA-AGENT-MSG-V1, and a record of it is only ever the first entry.
func TestAnAskThatActsOnNoMessageOpensAConversation(t *testing.T) {
	st := vectorStatement(t)
	st.Kind, st.InReplyTo, st.Conversation = KindAsk, "", ""
	sig, err := Sign(vectorSigner(), st)
	if err != nil {
		t.Fatalf("an ask opening a conversation was refused: %v", err)
	}
	if !st.Opens() || !strings.HasPrefix(string(st.Bytes()), "IA-AGENT-MSG-V1\n\n"+KindAsk+"\n") {
		t.Fatalf("an opening ask is not signed with an empty conversation line:\n%s", st.Bytes())
	}
	_, verkey, _ := agentbody.Identity(vectorSigner())
	if err := Verify(st, verkey, sig); err != nil {
		t.Fatal(err)
	}
	rec := Record{Conversation: "c_chosen", Seq: 1, Kind: KindAsk, From: st.From, To: st.To, BodyHash: st.BodyHash, Depth: 1,
		Statement: &st, HostSignature: sig, HostVerkey: verkey, BodyCredential: st.BodyCredential, OpenedBy: st.From}
	if err := rec.CheckSenderProof(); err != nil {
		t.Fatalf("a body's opening ask, in the conversation the Identity Agent chose, was refused: %v", err)
	}
	// Opening is the first entry, the sender's own, at depth 1: anywhere else
	// the same signed ask would be a way into somebody else's conversation.
	for name, change := range map[string]func(*Record){
		"later in a conversation":    func(r *Record) { r.Seq = 2 },
		"in somebody else's opening": func(r *Record) { r.OpenedBy = "EAGENT_C" },
		"at the depth of a person":   func(r *Record) { r.Depth = 0 },
	} {
		moved := rec
		change(&moved)
		if moved.CheckSenderProof() == nil {
			t.Errorf("an ask that acts on no message was accepted %s", name)
		}
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

// A statement with no tier is signed exactly as before tiers existed, and a
// reader that does not know tiers refuses a tiered one instead of running it
// without its tier: it rebuilds the V1 string from the fields it knows.
func TestATierIsSignedAndAReaderWithoutTiersRefusesIt(t *testing.T) {
	_, verkey, _ := agentbody.Identity(vectorSigner())
	plain := vectorStatement(t)
	plain.Kind = KindAsk
	if !strings.HasPrefix(string(plain.Bytes()), "IA-AGENT-MSG-V1\n") || strings.Count(string(plain.Bytes()), "\n") != 14 {
		t.Fatalf("a statement with no tier is not the V1 string: %q", plain.Bytes())
	}
	tiered := plain
	tiered.Tier = TierDeep
	if !strings.HasPrefix(string(tiered.Bytes()), "IA-AGENT-MSG-V2\n") || !strings.HasSuffix(string(tiered.Bytes()), "\n"+TierDeep) {
		t.Fatalf("a tiered statement is not V2 ending in its tier: %q", tiered.Bytes())
	}
	sig, err := Sign(vectorSigner(), tiered)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(tiered, verkey, sig); err != nil {
		t.Fatal(err)
	}
	// What a reader of the version before tiers has: the same JSON, the tier
	// dropped as an unknown field.
	if err := Verify(plain, verkey, sig); err == nil {
		t.Fatal("a reader that drops the tier accepted the signature")
	}
	// The tier is bound: changing it breaks the signature.
	other := tiered
	other.Tier = TierQuick
	if Verify(other, verkey, sig) == nil {
		t.Fatal("changing the tier left the signature valid")
	}
}

func TestOnlyAnAskCarriesAKnownTier(t *testing.T) {
	st := vectorStatement(t)
	st.Tier = TierQuick // st is a reply
	if st.Check() == nil {
		t.Error("a reply with a tier was accepted")
	}
	st.Kind = KindAsk
	for _, tier := range []string{TierQuick, TierStandard, TierDeep} {
		st.Tier = tier
		if err := st.Check(); err != nil {
			t.Errorf("%s: %v", tier, err)
		}
	}
	for _, bad := range []string{"turbo", "Deep", "deep\nquick"} {
		st.Tier = bad
		if st.Check() == nil {
			t.Errorf("tier %q was accepted", bad)
		}
	}
}

// An empty tier is no tier, whether it was never set or arrived as "tier":"":
// the statement is V1, and it is written without a tier field.
func TestAnEmptyTierIsAbsent(t *testing.T) {
	var st Statement
	if err := json.Unmarshal([]byte(`{"kind":"ask","tier":""}`), &st); err != nil {
		t.Fatal(err)
	}
	plain := vectorStatement(t)
	plain.Kind = KindAsk
	empty := plain
	empty.Tier = ""
	if !bytes.Equal(empty.Bytes(), plain.Bytes()) || !strings.HasPrefix(string(empty.Bytes()), "IA-AGENT-MSG-V1\n") {
		t.Fatalf("an empty tier changed the signed string: %q", empty.Bytes())
	}
	if err := empty.Check(); err != nil {
		t.Fatalf("an empty tier was refused: %v", err)
	}
	reply := vectorStatement(t)
	reply.Tier = ""
	if err := reply.Check(); err != nil {
		t.Fatalf("an empty tier on a reply was refused: %v", err)
	}
	b, _ := json.Marshal(empty)
	if strings.Contains(string(b), `"tier"`) {
		t.Fatalf("an empty tier was written: %s", b)
	}
}

// A progress note is a kind of message a body may sign, and it carries no tier:
// only an ask does.
func TestAProgressNoteIsAMessageButNotAnAsk(t *testing.T) {
	st := vectorStatement(t)
	st.Kind = KindProgress
	if _, err := Sign(vectorSigner(), st); err != nil {
		t.Fatalf("a progress note was refused: %v", err)
	}
	st.Tier = TierQuick
	if st.Check() == nil {
		t.Fatal("a progress note carrying a tier was accepted")
	}
}
