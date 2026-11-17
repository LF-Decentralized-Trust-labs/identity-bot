package agentpeer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	keri "github.com/grapeid/keri-go"

	"identity-agent-core/didcomm"
	"identity-agent-core/fingerprint"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
)

// vectorParty is one Identity Agent of the published vectors: keys from seeds.
type vectorParty struct {
	name string
	set  *didcomm.KeySet
	did  *didcomm.DID
	keys VectorKeys
}

func vectorPartyOf(name, aidSeed string, edByte, dsaByte byte) vectorParty {
	aid := iacrypto.Blake3QB64Must([]byte(aidSeed))
	edSeed, dsaSeed := make([]byte, 32), make([]byte, 32)
	for i := range edSeed {
		edSeed[i], dsaSeed[i] = edByte, dsaByte
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	var ds [32]byte
	copy(ds[:], dsaSeed)
	dsaPub, dsaPriv := mldsa65.NewKeyFromSeed(&ds)
	dsaB, _ := dsaPub.MarshalBinary()
	edPub := edPriv.Public().(ed25519.PublicKey)
	set := &didcomm.KeySet{AID: aid, EdPub: edPub, EdPriv: edPriv, DsaPub: dsaPub, DsaPriv: dsaPriv}
	sender, _ := SenderIdentifier(edPub)
	b64 := base64.RawURLEncoding
	return vectorParty{name, set, &didcomm.DID{AID: aid, Ed: b64.EncodeToString(edPub), Dsa: b64.EncodeToString(dsaB)},
		VectorKeys{AID: aid, EdSeedHex: hex.EncodeToString(edSeed), EdPublic: b64.EncodeToString(edPub),
			DsaSeedHex: hex.EncodeToString(dsaSeed), DsaPublic: b64.EncodeToString(dsaB), SenderIdentifier: sender}}
}

func agentID(label string) string {
	return iacrypto.Blake3QB64Must([]byte("agent-peer vector AI agent " + label))
}

var (
	vectorNow = time.Date(2026, 11, 14, 12, 0, 30, 0, time.UTC)
	vectorAt  = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
)

func vectorInputs(t *testing.T) VectorSet {
	t.Helper()
	alpha := vectorPartyOf("alpha", "agent-peer vector Identity Agent alpha", 0x11, 0x12)
	beta := vectorPartyOf("beta", "agent-peer vector Identity Agent beta", 0x21, 0x22)
	other := vectorPartyOf("other", "agent-peer vector Identity Agent other", 0x31, 0x32)
	parties := map[string]vectorParty{"alpha": alpha, "beta": beta}
	v := VectorSet{
		About: "Messages an Identity Agent signs to say an AI agent it holds sent words to an AI agent another Identity Agent holds (ADR-085). The message is a KERI exchange message (exn), built as keripy builds one and accepted by a keripy Exchanger: `exchange_message` is its bytes, `exn` is those bytes followed by one non-transferable signature couple (-CAB, the sender's identifier, the Ed25519 signature over `exchange_message`), and `pq_sig` is the ML-DSA-65 signature over the bytes \"IA-AGENT-PEER-PQ-V1\\n\" followed by `exchange_message`. The words and their salt travel beside it; the fingerprint is ADR-067's version 1, Blake3-256 over \"IA-FINGERPRINT-V1\", the salt's length (two bytes, big-endian), the salt and the words. `keys` are the two Identity Agents' messaging keys from published seeds. A message is checked against the sending Identity Agent's keys: the exchange message's sender must be its Ed25519 key as a non-transferable identifier, and both signatures must hold. `refused` messages each break one rule and carry its stable `code`. `directories` are what a contact says its AI agents are called (the agent-peer-directory payload); `grants` are what an AI agent's grant lets it message.",
		Keys:  map[string]VectorKeys{"alpha": alpha.keys, "beta": beta.keys, "other": other.keys},
	}
	reviewer, requester := agentID("reviewer (beta)"), agentID("review requester (alpha)")
	ask := Statement{Kind: KindAsk, ToAID: beta.keys.AID, FromAgent: requester, ToAgent: reviewer, MessageID: "m-1"}
	reply := Statement{Kind: KindReply, ToAID: alpha.keys.AID, FromAgent: reviewer, ToAgent: requester, MessageID: "m-2", InReplyTo: "m-1"}
	salt := func(b byte) []byte {
		s := make([]byte, 16)
		for i := range s {
			s[i] = b
		}
		return s
	}
	type sc struct {
		name, from, to string
		st             Statement
		words          string
		salt           byte
	}
	for _, c := range []sc{
		{"an ask", "alpha", "beta", ask, "Please review the change on branch fix-1.", 0xa1},
		{"a reply", "beta", "alpha", reply, "Reviewed: two changes asked for.", 0xa2},
		{"a failure", "beta", "alpha", func() Statement { s := reply; s.Kind, s.MessageID = KindFailure, "m-3"; return s }(), "Could not be answered.", 0xa3},
		{"a progress note", "beta", "alpha", func() Statement { s := reply; s.Kind, s.MessageID = KindProgress, "m-4"; return s }(), "Halfway through.", 0xa4},
		{"a short answer, which a fingerprint without a salt would give away", "beta", "alpha", func() Statement { s := reply; s.MessageID = "m-5"; return s }(), "yes", 0xa5},
	} {
		m, err := sealUnder(parties[c.from].set, c.st, c.words, salt(c.salt), vectorAt)
		if err != nil {
			t.Fatal(err)
		}
		st, err := ReadStatement(m.Signed, parties[c.from].did)
		if err != nil {
			t.Fatal(err)
		}
		ex, _ := keri.VerifyExchangeSigned([]byte(m.Exn))
		v.Signed = append(v.Signed, SignedCase{Name: c.name, From: c.from, To: c.to, Statement: st, Words: c.words,
			Salt: m.Salt, Said: ex.SAID, Raw: string(ex.Raw), Exn: m.Exn, PQSig: m.PQSig, Now: vectorNow.Format(time.RFC3339)})
	}

	// The refusals. Each message is signed again after its edit, by the keys of
	// its sender, so that only the one rule under test can refuse it.
	good := func(st Statement, words string) (parts, string) {
		sl := salt(0xb1)
		st.FromAID = alpha.keys.AID
		st.Fingerprint, _ = fingerprintOf(sl, words)
		st.SentAt = vectorAt.Format(sentAtLayout)
		return parts{st: st}, base64.RawURLEncoding.EncodeToString(sl)
	}
	signed := func(edit func(*parts)) Message {
		pt, sl := good(ask, "Please review the change on branch fix-1.")
		if edit != nil {
			edit(&pt)
		}
		return pt.sealWith(t, alpha.set, "Please review the change on branch fix-1.", sl)
	}
	base := signed(nil)
	type rc struct {
		name, signer, sentBy, self string
		at                         time.Time
		m                          Message
		want                       *Refusal
	}
	A, B := alpha.keys.AID, beta.keys.AID
	mut := func(f func(*Message)) Message { m := base; f(&m); return m }
	for _, c := range []rc{
		{"no message", "alpha", A, B, vectorNow, Message{Words: "x"}, ErrNoEntry},
		{"not an exchange message", "alpha", A, B, vectorNow, mut(func(m *Message) { m.Exn = "{}" }), ErrUnreadable},
		{"checked against other keys than the ones that signed", "other", A, B, vectorNow, base, ErrNotSigned},
		{"sent as another key than the sender's", "alpha", A, B, vectorNow, signed(func(p *parts) { p.sender = other.keys.SenderIdentifier; p.edBy = other.set }), ErrNotSigned},
		{"no post-quantum signature", "alpha", A, B, vectorNow, mut(func(m *Message) { m.PQSig = "" }), ErrNotSigned},
		{"a post-quantum signature over something else", "alpha", A, B, vectorNow, mut(func(m *Message) {
			m.PQSig = base64.RawURLEncoding.EncodeToString(alpha.set.SignPostQuantum([]byte("something else")))
		}), ErrNotSigned},
		{"the envelope came from another Identity Agent", "alpha", B, B, vectorNow, base, ErrWrongSender},
		{"for another Identity Agent", "alpha", A, A, vectorNow, base, ErrWrongRecipient},
		{"words changed after signing", "alpha", A, B, vectorNow, mut(func(m *Message) { m.Words = "Please approve the change on branch fix-1." }), ErrFingerprint},
		{"no words", "alpha", A, B, vectorNow, mut(func(m *Message) { m.Words = "" }), ErrWords},
		{"no salt", "alpha", A, B, vectorNow, mut(func(m *Message) { m.Salt = "" }), ErrSalt},
		{"a salt that is too short", "alpha", A, B, vectorNow, mut(func(m *Message) { m.Salt = base64.RawURLEncoding.EncodeToString(salt(1)[:8]) }), ErrSalt},
		{"dated more than an hour before it is taken", "alpha", A, B, vectorAt.Add(2 * time.Hour), base, ErrTime},
		{"dated more than an hour ahead", "alpha", A, B, vectorAt.Add(-2 * time.Hour), base, ErrTime},
		{"a reply that answers nothing", "alpha", A, B, vectorNow, signed(func(p *parts) { p.st.Kind = KindReply }), ErrReplyTo},
		{"an ask that answers something", "alpha", A, B, vectorNow, signed(func(p *parts) { p.st.InReplyTo = "m-0" }), ErrReplyTo},
		{"a route that is not a kind of message", "alpha", A, B, vectorNow, signed(func(p *parts) { p.route = "/ia/agent/peer/order" }), ErrKind},
		{"an identifier with a line break", "alpha", A, B, vectorNow, signed(func(p *parts) { p.st.ToAgent = "E\nX" }), ErrField},
		{"an identifier with a terminal escape", "alpha", A, B, vectorNow, signed(func(p *parts) { p.st.FromAgent = "E\x1b[2J" }), ErrField},
		{"a message named like an entry's place", "alpha", A, B, vectorNow, signed(func(p *parts) { p.st.MessageID = "e1" }), ErrPlaceID},
		{"the sender named is not the one that signed", "alpha", A, B, vectorNow, signed(func(p *parts) { p.st.FromAID = B }), ErrWrongSender},
		{"a field the message does not define", "alpha", A, B, vectorNow, signed(func(p *parts) {
			a, _ := p.st.attributes()
			p.data = strings.TrimSuffix(string(a), "}") + `,"also":"this"}`
		}), ErrUnreadable},
		{"a modifier (q)", "alpha", A, B, vectorNow, signed(func(p *parts) { p.modifiers = json.RawMessage(`{"x":"y"}`) }), ErrNotInItsOneForm},
		{"a prior message (p)", "alpha", A, B, vectorNow, signed(func(p *parts) { p.prior = iacrypto.Blake3QB64Must([]byte("a prior message")) }), ErrNotInItsOneForm},
		{"the unsalted fingerprint version", "alpha", A, B, vectorNow, signed(func(p *parts) {
			a, _ := p.st.attributes()
			p.data = strings.Replace(string(a), `"fingerprint_version":1`, `"fingerprint_version":0`, 1)
		}), ErrFingerprintVer},
	} {
		v.Refused = append(v.Refused, RefusedCase{Name: c.name, Signer: c.signer, SentBy: c.sentBy, Self: c.self,
			Now: c.at.Format(time.RFC3339), Message: c.m, Code: c.want.Code(), Refuse: c.want.Error()})
	}

	v.Directories = append(v.Directories, DirectoryCase{
		Name:      "two AI agents, one with a role",
		Directory: Directory{Agents: []DirectoryEntry{{AID: "EREVIEWER", Name: "reviewer", Role: "reviews branches"}, {AID: "EBUILDER", Name: "builder"}}},
	})
	for _, c := range []struct {
		name string
		d    Directory
	}{
		{"a name with an @", Directory{Agents: []DirectoryEntry{{AID: "E1", Name: "boss@alias"}}}},
		{"a name with a line break", Directory{Agents: []DirectoryEntry{{AID: "E1", Name: "a\nb"}}}},
		{"a name with a text-direction override", Directory{Agents: []DirectoryEntry{{AID: "E1", Name: "a‮b"}}}},
		{"two AI agents of one name", Directory{Agents: []DirectoryEntry{{AID: "E1", Name: "x"}, {AID: "E2", Name: "X"}}}},
		{"one AI agent named twice", Directory{Agents: []DirectoryEntry{{AID: "E1", Name: "x"}, {AID: "E1", Name: "y"}}}},
		{"a space in an identifier", Directory{Agents: []DirectoryEntry{{AID: "E 1", Name: "x"}}}},
	} {
		v.Directories = append(v.Directories, DirectoryCase{Name: c.name, Directory: c.d, Refuse: c.d.Check().Error()})
	}

	lim := func(c map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{CapabilityMessagePeer: c}
	}
	list := func(s ...string) []interface{} {
		o := make([]interface{}, len(s))
		for i, x := range s {
			o[i] = x
		}
		return o
	}
	for _, c := range []GrantCase{
		{"the contact named, no AI agent narrowing", lim(map[string]interface{}{"contact": list("EBETA")}), "EBETA", "EANY", true},
		{"the contact and the AI agent named", lim(map[string]interface{}{"contact": list("EBETA"), "agent": list("EREVIEWER")}), "EBETA", "EREVIEWER", true},
		{"no constraint at all", map[string]interface{}{}, "EBETA", "EANY", false},
		{"the capability with no contact", lim(map[string]interface{}{}), "EBETA", "EANY", false},
		{"another contact named", lim(map[string]interface{}{"contact": list("EGAMMA")}), "EBETA", "EANY", false},
		{"another AI agent named", lim(map[string]interface{}{"contact": list("EBETA"), "agent": list("EREVIEWER")}), "EBETA", "EBUILDER", false},
		{"agent given as text", lim(map[string]interface{}{"contact": list("EBETA"), "agent": "EREVIEWER"}), "EBETA", "EBUILDER", false},
		{"agent given as an empty list", lim(map[string]interface{}{"contact": list("EBETA"), "agent": []interface{}{}}), "EBETA", "EBUILDER", false},
		{"contact given as text", lim(map[string]interface{}{"contact": "EBETA"}), "EBETA", "EANY", false},
		{"a constraint nobody defined", lim(map[string]interface{}{"contact": list("EBETA"), "also": list("x")}), "EBETA", "EANY", false},
	} {
		v.Grants = append(v.Grants, c)
	}
	return v
}

func fingerprintOf(salt []byte, words string) (string, error) {
	return fingerprint.Of(salt, []byte(words))
}

// Every published vector is what this package produces, every signed message is
// taken, and every refused one is refused with its code.
func TestThePublishedPeerVectorsHold(t *testing.T) {
	want := vectorInputs(t)
	if contractcheck.Writing(t) {
		b, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile("peer-vectors.json", append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", "  ")
		w, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("the published peer vectors are not what this package produces:\n file:\n%s\n recomputed:\n%s", g, w)
	}
	dids := map[string]*didcomm.DID{}
	for name, k := range got.Keys {
		dids[name] = &didcomm.DID{AID: k.AID, Ed: k.EdPublic, Dsa: k.DsaPublic}
	}
	for _, c := range got.Signed {
		now, _ := time.Parse(time.RFC3339, c.Now)
		s, err := Verify(Message{Signed: Signed{Exn: c.Exn, PQSig: c.PQSig}, Words: c.Words, Salt: c.Salt},
			dids[c.From], got.Keys[c.From].AID, got.Keys[c.To].AID, now)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if s != c.Statement {
			t.Errorf("%s: read %+v, published %+v", c.Name, s, c.Statement)
		}
	}
	for _, c := range got.Refused {
		now, _ := time.Parse(time.RFC3339, c.Now)
		_, err := Verify(c.Message, dids[c.Signer], c.SentBy, c.Self, now)
		if CodeOf(err) != c.Code || err == nil || err.Error() != c.Refuse {
			t.Errorf("%s: refused with %v (%q), want %q", c.Name, err, CodeOf(err), c.Code)
		}
	}
	for _, c := range got.Directories {
		err := c.Directory.Check()
		if c.Refuse == "" && err != nil {
			t.Errorf("%s: a kept directory was refused: %v", c.Name, err)
		}
		if c.Refuse != "" && (err == nil || err.Error() != c.Refuse) {
			t.Errorf("%s: refused with %v, want %q", c.Name, err, c.Refuse)
		}
	}
	for _, c := range got.Grants {
		if err := CheckPeerGrant(c.Limits, c.Contact, c.Agent); (err == nil) != c.Allow {
			t.Errorf("%s: grant answered %v, want allow=%v", c.Name, err, c.Allow)
		}
	}
}

// An implementation written from the prose, in Python, agrees with the vector
// file: the exchange message and its identifier, the signatures it can check,
// the fingerprint, and every message, directory and grant the format refuses.
func TestAnIndependentImplementationAgreesWithThePeerVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_peer_vectors.py", "peer-vectors.json", "blake3")
}
