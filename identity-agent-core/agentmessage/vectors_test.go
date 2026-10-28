package agentmessage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"identity-agent-core/agentbody"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/contractcheck"
	"identity-agent-core/internal/fixedkeys"
	"identity-agent-core/internal/vectorseeds"
)

// Every published vector is what this package produces: the string a body
// signs, the digest of the words, the body's signature; and for the
// conversation, the record, the countersigned envelope and the hash that
// chains each entry to the next. A change to any of them breaks this test
// before it breaks another implementation.
func TestThePublishedMessageVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		writeMessageVectors(t)
	}
	set, err := MessageVectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Statements) == 0 || len(set.RefusedStatements) == 0 || len(set.Conversation) < 2 || len(set.RefusedEntries) == 0 {
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
		rec, err := Open(&set.Countersigner, e.Envelope)
		if err != nil {
			t.Fatalf("entry %d does not open: %v", i, err)
		}
		if !reflect.DeepEqual(rec, e.Record) {
			t.Fatalf("entry %d opens to another record: %+v", i, rec)
		}
		if rec.PrevHash != prev {
			t.Fatalf("entry %d names %q as the entry before it, not %q", i, rec.PrevHash, prev)
		}
		if err := rec.CheckSenderProof(); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		prev = e.Hash
	}
	for _, r := range set.RefusedEntries {
		if _, err := Open(&set.Countersigner, r.Envelope); err == nil {
			t.Fatalf("%s was opened; it must be refused", r.Name)
		}
	}
}

// The objects a conversation entry is made of are the ones the schema in
// contracts/agent-message describes, and every object it defines is one of
// them.
func TestTheMessageSchemaDescribesTheseTypes(t *testing.T) {
	s, err := contractcheck.Read("../contracts/agent-message/agent-message.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]any{
		"statement":        Statement{},
		"brain":            Brain{},
		"record":           Record{},
		"controller_proof": ControllerProof{},
		"person_ref":       PersonRef{},
		"person_message":   PersonMessage{},
		"envelope":         didcomm.Envelope{},
		"jwm":              didcomm.JWM{},
		"messaging_keys":   didcomm.DID{},
	}
	var faults []string
	for def, v := range held {
		faults = append(faults, s.Matches(def, v)...)
	}
	faults = append(faults, s.Unheld(held)...)
	for _, f := range faults {
		t.Error(f)
	}
}

// An implementation written from the schema's prose, in another language,
// agrees with the vector file.
func TestAnIndependentImplementationAgreesWithTheMessageVectors(t *testing.T) {
	contractcheck.Independently(t, "../contracts", "message-vectors.json")
}

// fillMessageVectors computes every derived value in set from its inputs.
func fillMessageVectors(set *MessageVectorSet) error {
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil {
		return err
	}
	signer := ed25519Signer{ed25519.NewKeyFromSeed(seed)}
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

	if len(set.Conversation) == 0 {
		return fmt.Errorf("no conversation")
	}
	ks, err := fixedkeys.KeySet(set.Conversation[0].Record.From, set.CountersignerSeeds)
	if err != nil {
		return err
	}
	did, err := ks.DID()
	if err != nil {
		return err
	}
	set.Countersigner = *did
	prev := ""
	for i := range set.Conversation {
		e := &set.Conversation[i]
		r := &e.Record
		st := r.Statement
		st.Host = set.Host
		st.BodyHash = HashBody([]byte(e.Body))
		r.BodyHash = st.BodyHash
		r.PrevHash = prev
		if r.HostSignature, err = Sign(signer, *st); err != nil {
			return err
		}
		r.HostVerkey = set.Verkey
		if e.Envelope, err = Countersign(ks, *r); err != nil {
			return err
		}
		e.Hash = Hash(e.Envelope)
		prev = e.Hash
	}

	// Countersigned with the right keys, but the message's id is not the
	// record's: the countersignature then vouches for a different entry.
	first := set.Conversation[0].Record
	body, err := json.Marshal(first)
	if err != nil {
		return err
	}
	mismatched, err := didcomm.PackSigned(ks, &didcomm.JWM{
		ID: first.MessageID + "-other", Type: TypeRecord,
		From: "did:keri:" + ks.AID, To: []string{"did:keri:" + first.To},
		CreatedTime: first.IATime, Body: body,
	})
	if err != nil {
		return err
	}
	set.RefusedEntries = []struct {
		Name     string            `json:"name"`
		Envelope *didcomm.Envelope `json:"envelope"`
	}{{Name: "a message id that is not the record's", Envelope: mismatched}}
	return nil
}

// writeMessageVectors writes message-vectors.json from the inputs below. Run
// it with IA_WRITE_CONTRACTS=1 when the format changes on purpose, and review
// the diff: every changed line is a change another implementation has to make.
func writeMessageVectors(t *testing.T) {
	t.Helper()
	var set MessageVectorSet
	set.About = "Messages between AI agents, worked through; the rules are in " +
		"contracts/agent-message/agent-message.schema.json. The body's statement signatures are Ed25519, from " +
		"seed_hex. The countersigner's keys come from countersigner_seeds as contracts/README.md describes, and " +
		"every envelope reproduces exactly."
	set.SeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	set.CountersignerSeeds = vectorseeds.Seeds{
		Ed25519:  run(0x30, 32),
		MLDSA65:  run(0x31, 32),
		X25519:   run(0x32, 32),
		MLKEM768: run(0x33, 64),
	}
	type stmt = struct {
		Name      string    `json:"name"`
		Statement Statement `json:"statement"`
		Body      string    `json:"body"`
		Signed    string    `json:"signed"`
		Signature string    `json:"signature"`
	}
	brain := Brain{Provider: "example-harness", Model: "example-model", Session: "s-1", RunHash: "Erun"}
	ask := Statement{Conversation: "c_vector", Kind: KindAsk, From: "EAGENT_A", To: "EAGENT_B", InReplyTo: "m_person",
		Brain: Brain{Provider: "example-harness", Model: "example-model", Session: "s-0"}, HostNonce: "nonce-fedcba9876543210",
		HostTime: "2026-10-20T11:59:30Z", BodyCredential: "EBODYCRED"}
	reply := Statement{Conversation: "c_vector", Kind: KindReply, From: "EAGENT_B", To: "EAGENT_A", InReplyTo: "m_ask",
		Brain: brain, HostNonce: "nonce-0123456789abcdef", HostTime: "2026-10-20T12:00:00Z", BodyCredential: "EBODYCRED"}
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
	shortNonce.HostNonce = "fifteen-chars-0"
	badTime := withHost(reply)
	badTime.HostTime = "20 October 2026"
	set.RefusedStatements = []refused{
		{"a line break in a field", lineBreak},
		{"an ask that names no message it acts on", noTarget},
		{"an unknown kind", otherKind},
		{"a nonce of 15 characters", shortNonce},
		{"a time that is not RFC 3339", badTime},
	}

	// AI agent B answers AI agent A, then tells the person who asked.
	toPerson := reply
	toPerson.To, toPerson.InReplyTo = Person("EPERSON"), "m_person"
	toPerson.HostNonce, toPerson.HostTime = "nonce-0123456789abcdf0", "2026-10-20T12:05:00Z"
	for i, e := range []struct {
		st    Statement
		at    string
		words string
	}{
		{reply, "2026-10-20T12:00:01Z", "I run macOS 26.1 on a MacBook Pro."},
		{toPerson, "2026-10-20T12:05:01Z", "AI agent A is on macOS 26.1."},
	} {
		st := e.st
		set.Conversation = append(set.Conversation, struct {
			Body     string            `json:"body"`
			Record   Record            `json:"record"`
			Envelope *didcomm.Envelope `json:"envelope"`
			Hash     string            `json:"hash"`
		}{Body: e.words, Record: Record{MessageID: fmt.Sprintf("m_reply_%d", i+1), Conversation: st.Conversation,
			Seq: i + 2, IATime: e.at, Kind: st.Kind, From: st.From, To: st.To, InReplyTo: st.InReplyTo, Depth: 1,
			Statement: &st, GrantSAID: "EGRANT", BodyGrade: agentbody.GradeSoftware, BodyCredential: st.BodyCredential,
			OpenedBy: Person("EPERSON")}})
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

// run is n bytes counting up from start, hex.
func run(start byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return hex.EncodeToString(b)
}
