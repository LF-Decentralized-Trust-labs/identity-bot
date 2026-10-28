package agentmessage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/contractcheck"
)

// Every published vector is what this package produces: the string a body
// signs, the digest of the words, the body's signature; and for the
// conversation, the record inside each countersigned entry and the hash that
// chains it to the next. A change to any of them breaks this test before it
// breaks another implementation.
func TestThePublishedMessageVectorsHold(t *testing.T) {
	if os.Getenv("IA_WRITE_CONTRACTS") == "1" {
		writeMessageVectors(t)
	}
	set, err := MessageVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Statements) == 0 || len(set.RefusedStatements) == 0 || len(set.Conversation) < 2 {
		t.Fatal("the vector file is missing a section")
	}
	// Recomputed into a second copy read from the file, so nothing the
	// recomputation writes can reach the values it is compared with.
	want, err := MessageVectors()
	if err != nil {
		t.Fatal(err)
	}
	if err := fillMessageVectors(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set, want) {
		got, _ := json.MarshalIndent(set, "", "  ")
		recomputed, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("the published message vectors are not what this package produces:\n file:\n%s\n recomputed:\n%s", got, recomputed)
	}
	for _, s := range set.Statements {
		if err := Verify(s.Statement, set.Verkey, s.Signature); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
	}
	for _, r := range set.RefusedStatements {
		if r.Statement.Check() == nil {
			t.Fatalf("%s was accepted; it must be refused", r.Name)
		}
	}
	prev := ""
	for i, e := range set.Conversation {
		if e.Record.PrevHash != prev {
			t.Fatalf("entry %d names %q as the entry before it, not %q", i, e.Record.PrevHash, prev)
		}
		if err := e.Record.CheckSenderProof(); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		prev = e.Hash
	}
}

// The objects a conversation entry is made of are the ones the schema in
// contracts/agent-message describes.
func TestTheMessageSchemaDescribesTheseTypes(t *testing.T) {
	s, err := contractcheck.Read("../contracts/agent-message/agent-message.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var faults []string
	for def, v := range map[string]any{
		"statement":        Statement{},
		"brain":            Brain{},
		"record":           Record{},
		"controller_proof": ControllerProof{},
		"person_ref":       PersonRef{},
		"person_message":   PersonMessage{},
		"envelope":         didcomm.Envelope{},
		"jwm":              didcomm.JWM{},
		"messaging_keys":   didcomm.DID{},
	} {
		faults = append(faults, s.Matches(def, v)...)
	}
	for _, f := range faults {
		t.Error(f)
	}
}

// fillMessageVectors computes every derived value in set from its inputs.
func fillMessageVectors(set *MessageVectorSet) error {
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil {
		return err
	}
	signer := ed25519Signer{edKey(seed)}
	if set.Host, set.Verkey, err = agentbody.Identity(signer); err != nil {
		return err
	}
	for i := range set.Statements {
		s := &set.Statements[i]
		s.Statement.Host = set.Host
		s.Statement.BodyHash = HashBody([]byte(s.Body))
		s.Signed = string(s.Statement.Bytes())
		if s.Signature, err = Sign(signer, s.Statement); err != nil {
			return err
		}
	}
	for i := range set.Conversation {
		e := &set.Conversation[i]
		if e.Record, err = Open(&set.Countersigner, e.Envelope); err != nil {
			return err
		}
		e.Hash = Hash(e.Envelope)
	}
	return nil
}

// writeMessageVectors writes message-vectors.json from the inputs below. Run
// it with IA_WRITE_CONTRACTS=1 when the format changes on purpose, and review
// the diff: every changed line is a change another implementation has to make.
// The countersignatures are made afresh each time, so the envelopes change
// even when nothing else did.
func writeMessageVectors(t *testing.T) {
	t.Helper()
	var set MessageVectorSet
	set.About = "AI agent messages, worked through. A body signs the lines of a statement, in the order of " +
		"the schema's statement_bytes, joined with a newline (0x0a), no trailing newline; an absent field is an " +
		"empty line. body_hash is Blake3-256 (CESR code E) of the words. Statement signatures are the body's " +
		"Ed25519 key's, reproducible from seed_hex. The conversation is countersigned by the AI agent each entry " +
		"is from; each entry's hash is Blake3-256 of plaintext, a newline, ed_sig, a newline, mldsa_sig, and the " +
		"next entry's record names it as prev_hash."
	set.SeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	type stmt = struct {
		Name      string    `json:"name"`
		Statement Statement `json:"statement"`
		Body      string    `json:"body"`
		Signed    string    `json:"signed"`
		Signature string    `json:"signature"`
	}
	ask := Statement{Conversation: "c_vector", Kind: KindAsk, From: "EAGENT_A", To: "EAGENT_B", InReplyTo: "m_person",
		Brain: Brain{Provider: "codex", Model: "gpt-5", Session: "s-0"}, HostNonce: "nonce-fedcba9876543210",
		HostTime: "2026-10-20T11:59:30Z", BodyCredential: "EBODYCRED"}
	reply := Statement{Conversation: "c_vector", Kind: KindReply, From: "EAGENT_B", To: "EAGENT_A", InReplyTo: "m_ask",
		Brain:     Brain{Provider: "claude-code", Model: "claude-opus-5-5", Session: "s-1", RunHash: "Erun"},
		HostNonce: "nonce-0123456789abcdef", HostTime: "2026-10-20T12:00:00Z", BodyCredential: "EBODYCRED"}
	receipt := Statement{Conversation: "c_vector", Kind: KindReceipt, From: "EAGENT_A", To: "EAGENT_B", InReplyTo: "m_reply",
		HostNonce: "nonce-receipt-00000001", HostTime: "2026-10-20T12:00:02Z", BodyCredential: "EBODYCRED"}
	set.Statements = []stmt{
		{Name: "a reply", Statement: reply, Body: "I run macOS 26.1 on a MacBook Pro."},
		{Name: "an ask", Statement: ask, Body: "Which operating system are you on?"},
		{Name: "a receipt, with no brain", Statement: receipt, Body: ""},
	}
	type refused = struct {
		Name      string    `json:"name"`
		Statement Statement `json:"statement"`
	}
	withHost := func(s Statement) Statement { s.Host, s.BodyHash = "BHOST", "EHASH"; return s }
	lineBreak := withHost(reply)
	lineBreak.To = "EAGENT_A\nEAGENT_C"
	noTarget := withHost(ask)
	noTarget.InReplyTo = ""
	otherKind := withHost(reply)
	otherKind.Kind = "order"
	shortNonce := withHost(reply)
	shortNonce.HostNonce = "short"
	badTime := withHost(reply)
	badTime.HostTime = "20 October 2026"
	set.RefusedStatements = []refused{
		{"a line break in a field", lineBreak},
		{"an ask that names no message it acts on", noTarget},
		{"an unknown kind", otherKind},
		{"a nonce under 16 characters", shortNonce},
		{"a time that is not RFC 3339", badTime},
	}
	if err := fillMessageVectors(&set); err != nil {
		t.Fatal(err)
	}

	// Two entries from AI agent B, countersigned with its messaging keys.
	ks, err := didcomm.GenerateKeySet("EAGENT_B")
	if err != nil {
		t.Fatal(err)
	}
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	set.Countersigner = *did
	prev := ""
	for i, at := range []string{"2026-10-20T12:00:01Z", "2026-10-20T12:05:01Z"} {
		st := set.Statements[0].Statement
		st.HostNonce = st.HostNonce[:len(st.HostNonce)-1] + string(rune('0'+i))
		st.HostTime = at
		sig, err := Sign(ed25519Signer{edKey(hexSeed(set.SeedHex))}, st)
		if err != nil {
			t.Fatal(err)
		}
		rec := Record{MessageID: "m_reply_" + string(rune('1'+i)), Conversation: st.Conversation, Seq: i + 1,
			PrevHash: prev, IATime: at, Kind: st.Kind, From: st.From, To: st.To, InReplyTo: st.InReplyTo,
			BodyHash: st.BodyHash, Depth: 1, Statement: &st, HostSignature: sig, HostVerkey: set.Verkey,
			GrantSAID: "EGRANT", BodyGrade: agentbody.GradeSoftware, BodyCredential: st.BodyCredential,
			OpenedBy: Person("EPERSON")}
		env, err := Countersign(ks, rec)
		if err != nil {
			t.Fatal(err)
		}
		set.Conversation = append(set.Conversation, struct {
			Envelope *didcomm.Envelope `json:"envelope"`
			Record   Record            `json:"record"`
			Hash     string            `json:"hash"`
		}{Envelope: env, Record: rec, Hash: Hash(env)})
		prev = Hash(env)
	}
	if err := fillMessageVectors(&set); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(set); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("message-vectors.json", out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	messageVectors = out.Bytes()
}

func edKey(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

func hexSeed(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
