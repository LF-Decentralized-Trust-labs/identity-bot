package conversationbundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"identity-agent-core/activitylog"
	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"
	"identity-agent-core/trail"

	keri "github.com/grapeid/keri-go"
)

// A whole world for the conversation builder (person_entries_test.go): the
// organisation's root key log, the AI agent and the record identity it
// delegates, the registry and credentials that make a machine the AI agent's
// body and say what it may do, the governance log signed by its own identity,
// and the record identity's anchors. conversation.export gathers them with the
// entries the trail wrote into one bundle, the way an Identity Agent's export
// does, so conversationbundle.Verify can be run over all of it. It is test
// code only: nothing here is a second way of writing a conversation.

// someKeys is one identity's key log as the world builds it: a key that signs,
// and the events so far with their signatures.
type someKeys struct {
	seed    []byte
	signer  keri.Signer
	pub     string
	aid     string
	raws    [][]byte
	sigs    []string
	lastID  string
	lastSN  int
	nextKey someKeyPair
}

type someKeyPair struct {
	pub    string
	digest string
}

func aKeyFrom(t *testing.T, n byte) (seed []byte, s keri.Signer, pub string) {
	t.Helper()
	seed = bytes.Repeat([]byte{n}, ed25519.SeedSize)
	s, err := keri.NewSoftwareSigner(seed, true)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return seed, s, pub
}

// newKeys is an identity whose key is derived from n, with the digest of the
// next key it would rotate to.
func newKeys(t *testing.T, n byte) *someKeys {
	t.Helper()
	k := &someKeys{}
	k.seed, k.signer, k.pub = aKeyFrom(t, n)
	_, _, nextPub := aKeyFrom(t, n+100)
	d, err := keri.NextDigest(nextPub)
	if err != nil {
		t.Fatal(err)
	}
	k.nextKey = someKeyPair{pub: nextPub, digest: d}
	return k
}

func (k *someKeys) sign(t *testing.T, raw []byte) string {
	t.Helper()
	sig, err := k.signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	q, err := keri.MatterQB64(keri.CodeEd25519Sig, sig)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// add puts an event of this identity into its log, signed by its key.
func (k *someKeys) add(t *testing.T, raw []byte) *keri.Event {
	t.Helper()
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	k.raws, k.sigs = append(k.raws, raw), append(k.sigs, k.sign(t, raw))
	k.lastID, k.lastSN = ev.SAID, int(ev.SN)
	return ev
}

// incept founds the identity with a plain inception.
func (k *someKeys) incept(t *testing.T) {
	t.Helper()
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{k.pub}, NextDigests: []string{k.nextKey.digest}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	k.aid = k.add(t, raw).Identifier
}

// inceptDelegated founds the identity as delegated from delegator. Until the
// delegator's log seals the inception, it is a claim and nothing more.
func (k *someKeys) inceptDelegated(t *testing.T, delegator string) []byte {
	t.Helper()
	raw, err := keri.BuildDelegatedInception(keri.DelegationInput{Delegator: delegator, Keys: []string{k.pub}, NextDigests: []string{k.nextKey.digest}})
	if err != nil {
		t.Fatal(err)
	}
	k.aid = k.add(t, raw).Identifier
	return raw
}

// seal adds an interaction that seals the given seals, and returns its place.
func (k *someKeys) seal(t *testing.T, seals ...any) *keri.Event {
	t.Helper()
	var data []json.RawMessage
	for _, s := range seals {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, raw)
	}
	raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: k.aid, PriorSAID: k.lastID, SN: k.lastSN + 1, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	return k.add(t, raw)
}

// theSeal is the seal of an event of subject that a log anchors.
type theSeal struct {
	I string `json:"i"`
	S string `json:"s"`
	D string `json:"d"`
}

func sealOf(ev *keri.Event) theSeal {
	return theSeal{I: ev.Identifier, S: fmt.Sprintf("%x", ev.SN), D: ev.SAID}
}

func (k *someKeys) keyLog() KeyLog {
	kl := KeyLog{AID: k.aid}
	for i, raw := range k.raws {
		kl.Events = append(kl.Events, Event{Raw: base64.StdEncoding.EncodeToString(raw), Signature: k.sigs[i]})
	}
	return kl
}

// vouched is the messaging keys of an identity, signed by its current key as
// the Identity Agent publishes them.
func (k *someKeys) vouched(t *testing.T, ks *didcomm.KeySet) didcomm.DID {
	t.Helper()
	did, err := ks.DID()
	if err != nil {
		t.Fatal(err)
	}
	if did.KelSig, err = login.SignString(string(did.SigningInput()), k.seed); err != nil {
		t.Fatal(err)
	}
	return *did
}

// logSigner signs the governance log's rows with an identity's key.
type logSigner struct {
	aid  string
	priv ed25519.PrivateKey
}

func (s logSigner) SignEvent(payload []byte) (string, string, error) {
	return s.aid, base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, payload)), nil
}

// theWorld is everything beside the entries that a genuine export carries.
type theWorld struct {
	root, agent, record, logger *someKeys
	registry                    string
	vcp                         []byte
	creds                       []Credential
	bodySAID, grantSAID         string
	hostSeed                    []byte
	hostSigner                  edSigner
	agentKeys                   *didcomm.KeySet
	log                         *activitylog.Log
}

const telLayout = "2006-01-02T15:04:05.000000-07:00"

// aWorld founds the organisation and its AI agent, and returns a conversation
// the trail writes in it. The conversation's Identity Agent is the root and
// the AI agent a person addresses is the delegated one.
func aWorld(t *testing.T) *conversation {
	t.Helper()
	w := &theWorld{root: newKeys(t, 1), agent: newKeys(t, 2), record: newKeys(t, 3), logger: newKeys(t, 4)}
	w.root.incept(t)
	for _, d := range []*someKeys{w.agent, w.record} {
		dip := d.inceptDelegated(t, w.root.aid)
		ev, _ := keri.ParseEvent(dip)
		w.root.seal(t, sealOf(ev))
	}
	w.logger.incept(t)

	// The registry the credentials are in is the root's, sealed in its log.
	vcp, err := keri.BuildRegistryInception(keri.RegistryInput{Issuer: w.root.aid, Nonce: "a-registry-for-a-whole-bundle"})
	if err != nil {
		t.Fatal(err)
	}
	vev, err := keri.VerifyTELEvent(vcp)
	if err != nil {
		t.Fatal(err)
	}
	w.registry, w.vcp = vev.Subject, vcp
	w.root.seal(t, theSeal{I: vev.Subject, S: "0", D: vev.SAID})

	// The machine that speaks for the AI agent.
	w.hostSeed = bytes.Repeat([]byte{9}, ed25519.SeedSize)
	w.hostSigner = edSigner{ed25519.NewKeyFromSeed(w.hostSeed)}
	host, verkey, err := agentbody.Identity(w.hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	w.bodySAID = w.issue(t, schemas.AIAgentBody.Schema.SAID, map[string]any{
		"asset_type": "ai_agent", "name": "Research assistant", "host": host, "verkey": verkey, "grade": "software"}, issued)
	w.grantSAID = w.issue(t, schemas.AIAgentGrant.Schema.SAID, map[string]any{
		"asset_type": "ai_agent", "name": "Research assistant", "capabilities": []string{agentmessage.CapabilityMessageAgent}}, issued)

	if w.agentKeys, err = didcomm.GenerateKeySet(w.agent.aid); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if w.log, err = activitylog.Open(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.log.Close() })
	w.log.SetEventSigner(logSigner{aid: w.logger.aid, priv: ed25519.NewKeyFromSeed(w.logger.seed)})

	c := newConversationIn(t, allowAll{bot: w.agent.aid}, nil, w.root.aid, w.agent.aid)
	c.world = w
	return c
}

// issue issues a credential to the AI agent from the root's registry: the
// credential, its issuance, and the root's key log sealing the issuance.
func (w *theWorld) issue(t *testing.T, schema string, attrs map[string]any, at time.Time) string {
	t.Helper()
	data := map[string]any{"d": "", "i": w.agent.aid, "dt": at.Format(telLayout)}
	for k, v := range attrs {
		data[k] = v
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	acdc, err := keri.BuildCredential(keri.CredentialInput{SchemaSAID: schema, Issuer: w.root.aid, Recipient: w.agent.aid, Registry: w.registry, Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := keri.VerifyCredential(acdc)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: cred.SAID, Registry: w.registry, DT: at.Format(telLayout)})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.VerifyTELEvent(iss)
	if err != nil {
		t.Fatal(err)
	}
	w.root.seal(t, theSeal{I: cred.SAID, S: "0", D: ev.SAID})
	w.creds = append(w.creds, Credential{SAID: cred.SAID, Raw: base64.StdEncoding.EncodeToString(acdc), Log: []string{base64.StdEncoding.EncodeToString(iss)}})
	return cred.SAID
}

// agentSays appends an AI agent's reply to the conversation's chain as its own
// body signs it and the AI agent countersigns it, the way ADR-047 has it.
func (c *conversation) agentSays(id, inReplyTo, to, words string) {
	c.t.Helper()
	w := c.world
	host, verkey, err := agentbody.Identity(w.hostSigner)
	if err != nil {
		c.t.Fatal(err)
	}
	at := c.now.Add(time.Second)
	st := agentmessage.Statement{Conversation: "c1", Kind: agentmessage.KindReply, From: w.agent.aid, To: to, InReplyTo: inReplyTo,
		BodyHash: agentmessage.HashBody([]byte(words)), Host: host, HostNonce: fmt.Sprintf("host-nonce-%016d", len(c.tr.Chain("c1"))),
		HostTime: at.Format(time.RFC3339), BodyCredential: w.bodySAID}
	sig, err := agentmessage.Sign(w.hostSigner, st)
	if err != nil {
		c.t.Fatal(err)
	}
	rec := agentmessage.Record{MessageID: id, Conversation: "c1", Seq: len(c.tr.Chain("c1")) + 1, PrevHash: c.tr.Head("c1"),
		IATime: at.Format(time.RFC3339Nano), Kind: st.Kind, From: st.From, To: st.To, InReplyTo: inReplyTo, BodyHash: st.BodyHash,
		Statement: &st, HostSignature: sig, HostVerkey: verkey, GrantSAID: w.grantSAID, BodyGrade: "software", BodyCredential: w.bodySAID,
		OpenedBy: agentmessage.Person("EALICE")}
	env, err := agentmessage.Countersign(w.agentKeys, rec)
	if err != nil {
		c.t.Fatal(err)
	}
	entry := agentmessage.Entry{Conversation: "c1", Seq: rec.Seq, MessageID: id, Kind: rec.Kind, From: rec.From, To: rec.To, InReplyTo: inReplyTo, BodyHash: rec.BodyHash, Envelope: env, Hash: agentmessage.Hash(env)}
	if err := c.tr.AppendAgent("c1", entry); err != nil {
		c.t.Fatal(err)
	}
	// The words are carried beside the entry with no salt: an AI agent's entry
	// is checked by the hash its record carries.
	c.words[id] = kept{nil, []byte(words)}
}

// export is the whole conversation as an Identity Agent exports it: the
// entries, and every key log, credential, row of the governance log and
// anchor the check of them rests on.
func (c *conversation) export() *Bundle {
	c.t.Helper()
	w := c.world
	b := c.bundle(true)
	chain := c.tr.Chain("c1")

	// A row of the governance log for every entry, as the Identity Agent
	// writes one when it takes an entry in.
	at := c.now
	row := func(caller, capability, reason string) int64 {
		at = at.Add(time.Second)
		id := w.log.RecordInvocation(permission.CallerContext{CallerAID: caller, WorkItem: "c1", Reason: reason, Transport: "controller"},
			capability, "governance", nil, "ok", at)
		if id == 0 {
			c.t.Fatalf("the row for %s was not written", capability)
		}
		return id
	}
	var first int64
	for _, e := range chain {
		id := row(e.From, "agent.message."+e.Kind, fmt.Sprintf("%s %s in c1, from %s to %s", e.Kind, e.MessageID, e.From, e.To))
		if first == 0 {
			first = id
		}
	}
	// The anchoring: a row that says the record is being anchored, then the
	// record identity's interaction that seals what it fixes.
	anchoring := row(c.root, activitylog.CapabilityRecordAnchoring, "anchoring the record")
	stored, err := w.log.StoredRows(anchoring, anchoring)
	if err != nil || len(stored) != 1 {
		c.t.Fatalf("the anchoring row cannot be read back: %v", err)
	}
	statement, err := json.Marshal(activitylog.AnchorStatement{
		Log:           activitylog.AnchoredLog{Row: anchoring, Head: activitylog.HashRecord([]byte(stored[0].Record))},
		Conversations: []activitylog.AnchoredConversation{{ID: "c1", Seq: len(chain), Head: chain[len(chain)-1].Hash}},
		At:            at.Format(time.RFC3339Nano), Signer: w.logger.aid})
	if err != nil {
		c.t.Fatal(err)
	}
	digest, err := iacrypto.Blake3QB64(statement)
	if err != nil {
		c.t.Fatal(err)
	}
	w.record.seal(c.t, map[string]string{"d": digest})
	b.Anchors = []Anchor{{Seq: len(w.record.raws) - 1, Statement: string(statement)}}

	// Last, the export itself is a row of the log.
	b.ExportedBy = "BExportedByTheOwner0123456789ABCDEFGHIJKLMNOP"
	b.ExportedAt = at.Add(time.Second).UTC().Format(time.RFC3339Nano)
	last := row(b.ExportedBy, "agent.conversation.export", "exported c1")
	rows, err := w.log.StoredRows(first, last)
	if err != nil {
		c.t.Fatal(err)
	}
	b.Log = Log{Signer: w.logger.aid, Rows: rows}

	b.Root, b.RecordIdentity = w.root.aid, w.record.aid
	for _, k := range []*someKeys{w.root, w.agent, w.record, w.logger} {
		b.KeyLogs = append(b.KeyLogs, k.keyLog())
	}
	b.Registries = []Registry{{SAID: w.registry, Inception: base64.StdEncoding.EncodeToString(w.vcp)}}
	b.Credentials = w.creds
	b.Countersigners = []didcomm.DID{w.root.vouched(c.t, c.keys), w.agent.vouched(c.t, w.agentKeys)}
	return b
}

// aMixedWholeConversation writes, through trail.Write and the AI agent's own
// countersigning, a conversation of every kind of entry: a person's statement
// that is kept, an AI agent's reply, a refusal, and a statement the app did
// not keep.
func aMixedWholeConversation(t *testing.T) *conversation {
	t.Helper()
	c := aWorld(t)
	ask := func(s *agentmessage.PersonStatement) { s.Kind = agentmessage.PersonKindAsk }
	if r := c.say("EALICE", "what is the weather", ask); r.State != trail.Committed { // e1, e2
		t.Fatalf("the person's statement was %+v", r)
	}
	c.agentSays("m-agent-1", "e1", agentmessage.Person("EALICE"), "dry and cold") // e3
	reuse := c.say("EALICE", "again", func(s *agentmessage.PersonStatement) { ask(s); s.MessageID = "m1" })
	if reuse.State != trail.Refused { // e4
		t.Fatalf("the reuse of an id was %+v", reuse)
	}
	c.app.wrong = true
	if r := c.say("EALICE", "and tomorrow", ask); r.State != trail.NotKept { // e5, e6
		t.Fatalf("a statement the app did not confirm was %+v", r)
	}
	c.app.wrong = false
	return c
}

// marshalBundle is the bundle as an export writes it.
func marshalBundle(b *Bundle) ([]byte, error) { return json.MarshalIndent(b, "", "  ") }
