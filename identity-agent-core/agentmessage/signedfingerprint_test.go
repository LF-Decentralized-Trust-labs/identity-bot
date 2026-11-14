package agentmessage

import (
	"bytes"
	"identity-agent-core/agentbody"
	"strings"
	"testing"
)

func personFixture(t *testing.T, words string) (PersonStatement, []byte, ed25519Signer) {
	t.Helper()
	signer := vectorSigner()
	id, _, err := agentbody.Identity(signer)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{7}, MinSalt)
	fp, err := Fingerprint(salt, []byte(words))
	if err != nil {
		t.Fatal(err)
	}
	return PersonStatement{
		Agent: "EAGENTHOST", Conversation: "c_1", MessageID: "m_1", Kind: PersonKindMessage, From: "EPERSON",
		Signer: id, To: "EAGENT", Nonce: "nonce-0123456789abcdef", Time: "2026-11-06T10:00:00Z",
		FingerprintVersion: FingerprintV1, Fingerprint: fp,
	}, salt, signer
}

func TestAFingerprintNeedsItsSaltAndWordsAndNothingElseFits(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, MinSalt)
	fp, err := Fingerprint(salt, []byte("yes"))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Fingerprint(bytes.Repeat([]byte{2}, MinSalt), []byte("yes"))
	if fp == other {
		t.Fatal("the same words under two salts gave one fingerprint")
	}
	if fp == HashBody([]byte("yes")) {
		t.Fatal("a salted fingerprint equals the unsalted hash, so it can be guessed")
	}
	// The length is in the preimage: moving a byte between salt and words must
	// not give the same fingerprint.
	a, _ := Fingerprint(append(bytes.Repeat([]byte{1}, MinSalt), 'x'), []byte("yes"))
	b, _ := Fingerprint(bytes.Repeat([]byte{1}, MinSalt), []byte("xyes"))
	if a == b {
		t.Fatal("a byte moved from the salt to the words gave the same fingerprint")
	}
	if _, err := Fingerprint(salt[:MinSalt-1], nil); err == nil {
		t.Fatal("a salt under 128 bits was accepted")
	}
	if _, err := Fingerprint(make([]byte, MaxSalt+1), nil); err == nil {
		t.Fatal("an oversize salt was accepted")
	}
}

func TestVersionZeroVerifiesOnlyARecordMadeBefore(t *testing.T) {
	words := []byte("old words")
	fp := HashBody(words)
	if err := CheckFingerprint(FingerprintV0, nil, words, fp, true); err != nil {
		t.Fatalf("a recorded version 0 fingerprint was refused: %v", err)
	}
	if CheckFingerprint(FingerprintV0, nil, words, fp, false) == nil {
		t.Fatal("version 0 was accepted for a new write")
	}
	if CheckFingerprint(FingerprintV0, []byte("salt"), words, fp, true) == nil {
		t.Fatal("version 0 was accepted with a salt")
	}
	if CheckFingerprint(7, nil, words, fp, true) == nil {
		t.Fatal("an unknown version was accepted")
	}
	// A new statement cannot fall back to version 0, even with a hash that is right.
	s, _, _ := personFixture(t, "x")
	s.FingerprintVersion, s.Fingerprint = FingerprintV0, fp
	if s.Check() == nil {
		t.Fatal("a statement carrying version 0 passed Check")
	}
}

func TestAPersonsStatementVerifiesAndEveryFieldIsBound(t *testing.T) {
	s, salt, signer := personFixture(t, "hello")
	_, verkey, _ := agentbody.Identity(signer)
	sig, err := SignPerson(signer, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPersonWords(s, verkey, sig, salt, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if VerifyPersonWords(s, verkey, sig, salt, []byte("hellO")) == nil {
		t.Fatal("other words passed under the same fingerprint")
	}
	// Changing any signed field must break the signature (the case that would
	// fail if a field were left out of Bytes).
	for name, mutate := range map[string]func(*PersonStatement){
		"conversation": func(p *PersonStatement) { p.Conversation = "c_2" },
		"message id":   func(p *PersonStatement) { p.MessageID = "m_2" },
		"kind":         func(p *PersonStatement) { p.Kind = PersonKindAsk },
		"from":         func(p *PersonStatement) { p.From = "EOTHER" },
		"to":           func(p *PersonStatement) { p.To = "EELSE" },
		"in reply to":  func(p *PersonStatement) { p.InReplyTo = "m_0" },
		"nonce":        func(p *PersonStatement) { p.Nonce = "nonce-ffffffffffffffff" },
		"time":         func(p *PersonStatement) { p.Time = "2026-11-06T10:00:01Z" },
		"fingerprint":  func(p *PersonStatement) { p.Fingerprint = HashBody([]byte("z")) },
	} {
		m := s
		mutate(&m)
		if VerifyPerson(m, verkey, sig) == nil {
			t.Errorf("changing the %s left the signature valid", name)
		}
	}
}

func TestASplitNamesItsRangeAndNothingElseDoes(t *testing.T) {
	s, _, _ := personFixture(t, "x")
	s.Kind = PersonKindSplit
	if s.Check() == nil {
		t.Fatal("a split with no range passed")
	}
	s.RangeFirst, s.RangeLast = "m_a", "m_b"
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	s.Kind = PersonKindMessage
	if s.Check() == nil {
		t.Fatal("a message naming a range passed")
	}
}

func TestACloseNamesNoRecipientAndOthersMust(t *testing.T) {
	s, _, _ := personFixture(t, "")
	s.Kind = PersonKindClose
	if s.Check() == nil {
		t.Fatal("a close naming a recipient passed")
	}
	s.To = ""
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	s.Kind, s.To = PersonKindHandOff, ""
	if s.Check() == nil {
		t.Fatal("a hand-off with no new owner passed")
	}
}

func TestAMalformedStatementIsRefused(t *testing.T) {
	good, _, _ := personFixture(t, "x")
	for name, mutate := range map[string]func(*PersonStatement){
		"a line break":       func(p *PersonStatement) { p.To = "A\nB" },
		"no message id":      func(p *PersonStatement) { p.MessageID = "" },
		"no identity agent":  func(p *PersonStatement) { p.Agent = "" },
		"a short nonce":      func(p *PersonStatement) { p.Nonce = "short" },
		"a bad time":         func(p *PersonStatement) { p.Time = "yesterday" },
		"an unknown kind":    func(p *PersonStatement) { p.Kind = "shout" },
		"an unknown version": func(p *PersonStatement) { p.FingerprintVersion = 9 },
	} {
		m := good
		mutate(&m)
		if m.Check() == nil {
			t.Errorf("%s passed", name)
		}
	}
	if !strings.HasPrefix(string(good.Bytes()), "IA-PERSON-MSG-V1\n") {
		t.Fatal("the signed string does not lead with its version")
	}
}

func TestASignerMustBeTheKeyTheStatementNames(t *testing.T) {
	s, _, _ := personFixture(t, "x")
	s.Signer = "Dsomeoneelse"
	if _, err := SignPerson(vectorSigner(), s); err == nil {
		t.Fatal("a key signed a statement naming another key")
	}
}

func TestVersionZeroIsOldOnlyBeforeTheFirstSaltedEntry(t *testing.T) {
	for name, ok := range map[string]struct {
		versions []int
		fine     bool
	}{
		"nothing":                             {nil, true},
		"only unsalted, a record made before": {[]int{0, 0, 0}, true},
		"unsalted and then salted":            {[]int{0, 0, 1, 1}, true},
		"only salted":                         {[]int{1, 1}, true},
		"unsalted after salted":               {[]int{0, 1, 0}, false},
		"unsalted straight after":             {[]int{1, 0}, false},
		"an unknown version":                  {[]int{0, 2}, false},
	} {
		if err := CheckVersionOrder(ok.versions); (err == nil) != ok.fine {
			t.Errorf("%s: fine=%v, got %v", name, ok.fine, err)
		}
	}
}

// A list is for no conversation: it names the fixed value and no recipient, it
// answers nothing, and nothing that is for one conversation may name that value.
func TestAListIsForNoConversationAndNothingElseIsForTheList(t *testing.T) {
	s, _, signer := personFixture(t, "")
	s.Kind, s.To, s.Conversation, s.Audience = PersonKindList, "", ListConversation, "ASSETCHAT"
	if err := s.Check(); err != nil {
		t.Fatalf("a well formed list was refused: %v", err)
	}
	if sig, err := SignPerson(signer, s); err != nil {
		t.Fatal(err)
	} else if _, vk, _ := agentbody.Identity(signer); VerifyPerson(s, vk, sig) != nil {
		t.Fatal("a signed list did not verify")
	}
	for name, mutate := range map[string]func(*PersonStatement){
		"a list for a conversation":     func(s *PersonStatement) { s.Conversation = "c_abcdefghijklmnopqrstuv" },
		"a list naming a recipient":     func(s *PersonStatement) { s.To = "EAGENT" },
		"a list answering something":    func(s *PersonStatement) { s.InReplyTo = "m_0" },
		"a list naming a range":         func(s *PersonStatement) { s.RangeFirst, s.RangeLast = "1", "2" },
		"a list with an unsalted print": func(s *PersonStatement) { s.FingerprintVersion = FingerprintV0 },
		"a close for the list":          func(s *PersonStatement) { s.Kind = PersonKindClose },
		"a message for the list":        func(s *PersonStatement) { s.Kind, s.To = PersonKindMessage, "EAGENT" },
		"a reopen for the list":         func(s *PersonStatement) { s.Kind = PersonKindReopen },
		"a limit for the list":          func(s *PersonStatement) { s.Kind = PersonKindLimit },
	} {
		c := s
		mutate(&c)
		if c.Check() == nil {
			t.Errorf("%s passed", name)
		}
	}
	// Every field is bound: a list's kind and conversation are in what is signed.
	other := s
	other.Kind, other.Conversation = PersonKindClose, "c_abcdefghijklmnopqrstuv"
	if bytes.Equal(s.Bytes(), other.Bytes()) {
		t.Fatal("a list and a close sign the same bytes")
	}
}
