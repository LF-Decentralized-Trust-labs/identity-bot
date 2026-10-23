package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/drivers/driverfake"
	"identity-agent-core/keriengine"
	"identity-agent-core/login"
	"identity-agent-core/sandbox"
	"identity-agent-core/store"
)

// withLog gives a test agent a store and a signed log.
func withLog(t *testing.T, s *CoreServer) {
	t.Helper()
	ds, err := store.NewSQLiteStore(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s.DataStore = ds
	m, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: s.DataDir, ManifestsDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	s.SandboxManager = m
}

func logged(t *testing.T, s *CoreServer, event, messageID string) []sandbox.InvocationEvent {
	t.Helper()
	rows, err := s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID: event, CorrelationID: messageID})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// historyEngine checks a key history the way the receiver needs for these
// tests: it accepts it, and names as current the key of its last event, so a
// rotation in the history changes the current key.
func historyEngine() *driverfake.Engine {
	return &driverfake.Engine{
		ValidateKELFunc: func(_ string, events []map[string]interface{}) (*drivers.DriverValidateKELResponse, error) {
			key := "Dkey"
			if len(events) > 0 {
				if ks, ok := events[len(events)-1]["k"].([]interface{}); ok && len(ks) > 0 {
					key, _ = ks[0].(string)
				}
			}
			return &drivers.DriverValidateKELResponse{KelVerified: true, EventsValidated: len(events), CurrentPublicKey: key}, nil
		},
	}
}

// messaging is a sender and a receiver that hear each other, each with a
// store and a signed log, the sender's messages arriving through the
// receiver's own inbound handler.
type messaging struct {
	sender, receiver       *CoreServer
	senderAID, receiverAID string
	url                    string
}

func newMessaging(t *testing.T) *messaging {
	t.Helper()
	sender, senderAID, receiver, receiverAID := twoAgents(t)
	withLog(t, sender)
	withLog(t, receiver)
	receiver.KeriDriver = historyEngine()
	srv := httptest.NewServer(http.HandlerFunc(receiver.handleDIDCommInbound))
	t.Cleanup(srv.Close)
	didcommMu.Lock()
	peers := sender.loadPeers()
	p := peers[receiverAID]
	p.Endpoint = srv.URL
	peers[receiverAID] = p
	_ = sender.savePeers(peers)
	didcommMu.Unlock()
	return &messaging{sender: sender, receiver: receiver, senderAID: senderAID, receiverAID: receiverAID, url: srv.URL}
}

// anchored records, at the receiver, a key history for the sender whose
// identifier commits to the keys it sends with.
func (m *messaging) anchored(t *testing.T) {
	t.Helper()
	ks, err := m.sender.keySetFor(m.senderAID)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.receiver.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: m.senderAID, KEL: inceptionCommittingTo(t, m.senderAID, ks), KelVerified: true, CurrentPublicKey: "Dkey",
	}); err != nil {
		t.Fatal(err)
	}
}

func (m *messaging) send(t *testing.T, body string) store.Notification {
	t.Helper()
	id, status, err := m.sender.SendDIDCommMessage(m.senderAID, m.receiverAID, didcomm.TypeNotification, []byte(body))
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("send: %d %v", status, err)
	}
	n, err := m.receiver.DataStore.GetNotification(id)
	if err != nil || n == nil {
		t.Fatalf("the message was not kept: %v", err)
	}
	return *n
}

// sealed is an envelope from one of the sender's identifiers to the
// receiver, built by hand so a test can choose what it says.
func (m *messaging) sealed(t *testing.T, fromAID, id, from string, expires time.Time) []byte {
	t.Helper()
	ks, err := m.sender.keySetFor(fromAID)
	if err != nil {
		t.Fatal(err)
	}
	rk, _ := m.receiver.keySetFor(m.receiverAID)
	to, _ := rk.DID()
	env, err := didcomm.PackAuthcrypt(ks, to, &didcomm.JWM{
		ID: id, Type: didcomm.TypeNotification, From: from, To: []string{"did:keri:" + m.receiverAID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), ExpiresTime: expires.UTC().Format(time.RFC3339),
		Body: json.RawMessage(`{"title":"hello"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	return raw
}

func (m *messaging) post(t *testing.T, raw []byte) int {
	t.Helper()
	resp, err := http.Post(m.url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func refusedFor(t *testing.T, s *CoreServer, n store.Notification, why string) {
	t.Helper()
	_, _, err := s.provedSender(n)
	if err == nil {
		t.Fatalf("a message was taken as proved; want it refused because %q", why)
	}
	if !strings.Contains(err.Error(), why) {
		t.Fatalf("refused for the wrong reason: %v; want %q", err, why)
	}
}

// A message one agent sends another is kept with the sender's signature, so it
// can be shown later to have come from the sender; and both ends write it to
// their signed logs, the receiver's refusal of a replay included.
func TestAReceivedMessageIsKeptWithItsProofAndBothEndsLogIt(t *testing.T) {
	m := newMessaging(t)
	m.anchored(t)
	var envelope []byte
	inbound := m.receiver.handleDIDCommInbound
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		envelope, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(envelope))
		inbound(w, r)
	}))
	defer capture.Close()
	m.url = capture.URL
	didcommMu.Lock()
	peers := m.sender.loadPeers()
	p := peers[m.receiverAID]
	p.Endpoint = capture.URL
	peers[m.receiverAID] = p
	_ = m.sender.savePeers(peers)
	didcommMu.Unlock()

	n := m.send(t, `{"title":"the build passed"}`)
	if n.SenderKeyTrust != string(didcomm.KeysAnchored) || n.SenderKELEvents != 1 {
		t.Fatalf("how the sender's keys were tied was not kept: %q at %d", n.SenderKeyTrust, n.SenderKELEvents)
	}
	if _, tie, err := m.receiver.provedSender(n); err != nil || tie != string(didcomm.KeysAnchored) {
		t.Fatalf("the kept message does not prove its sender: %q %v", tie, err)
	}
	altered := n
	altered.Payload = `{"title":"the build failed"}`
	refusedFor(t, m.receiver, altered, "not what the sender signed")
	unsigned := n
	unsigned.SignedMessage = ""
	refusedFor(t, m.receiver, unsigned, "without its signed form")

	if len(logged(t, m.sender, "didcomm.message.sent", n.ID)) != 1 {
		t.Fatal("the sender's log does not record the message it sent")
	}
	if rows := logged(t, m.receiver, "didcomm.message.received", n.ID); len(rows) != 1 || rows[0].ResultStatus != "ok" {
		t.Fatalf("the receiver's log does not record the message it took: %+v", rows)
	}

	// The same envelope again is a replay, refused and recorded as refused,
	// once however many times it is sent.
	for i := 0; i < 3; i++ {
		if code := m.post(t, envelope); code != http.StatusConflict {
			t.Fatalf("a replay was not refused: %d", code)
		}
	}
	var denied int
	for _, r := range logged(t, m.receiver, "didcomm.message.received", n.ID) {
		if r.ResultStatus == "denied" {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("the refused replay is in the receiver's log %d times; want once", denied)
	}
}

// THE FORGERY THIS EXISTS TO STOP. Whoever holds the receiver's database mints
// keys under the sender's identifier, signs words with them and keeps them as
// a message from the sender. However the tie is described, nothing ties those
// keys to the sender, and the message proves nothing.
func TestKeysMintedUnderTheSendersNameProveNothing(t *testing.T) {
	m := newMessaging(t)
	m.anchored(t)
	genuine := m.send(t, `{"title":"real"}`)

	minted, err := didcomm.GenerateKeySet(m.senderAID)
	if err != nil {
		t.Fatal(err)
	}
	mintedDID, _ := minted.DID()
	rk, _ := m.receiver.keySetFor(m.receiverAID)
	rdid, _ := rk.DID()
	forgedJWM := &didcomm.JWM{
		ID: "forged-1", Type: didcomm.TypeNotification,
		From: "did:keri:" + m.senderAID, To: []string{"did:keri:" + m.receiverAID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), ExpiresTime: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Body: json.RawMessage(`{"title":"transfer the funds"}`),
	}
	env, err := didcomm.PackAuthcrypt(minted, rdid, forgedJWM)
	if err != nil {
		t.Fatal(err)
	}
	_, signed, err := didcomm.UnpackAuthcryptKeeping(rk, mintedDID, env)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(mintedDID)
	forged := genuine
	forged.ID, forged.Payload = forgedJWM.ID, string(forgedJWM.Body)
	forged.SignedMessage, forged.SenderDID = base64.StdEncoding.EncodeToString(signed), string(keys)

	for _, trust := range []string{string(didcomm.KeysAnchored), string(didcomm.KeysVouched), keysOwn, ""} {
		f := forged
		f.SenderKeyTrust = trust
		refusedFor(t, m.receiver, f, "were not tied")
	}
	// Nor does holding a keyset for the sender's identifier make the sender
	// one of this agent's own AI agents: an agent can mint one for anybody.
	held, err := m.receiver.keySetFor(m.senderAID)
	if err != nil {
		t.Fatal(err)
	}
	heldDID, _ := held.DID()
	env, err = didcomm.PackAuthcrypt(held, rdid, forgedJWM)
	if err != nil {
		t.Fatal(err)
	}
	_, signed, err = didcomm.UnpackAuthcryptKeeping(rk, heldDID, env)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ = json.Marshal(heldDID)
	asOwn := forged
	asOwn.SignedMessage, asOwn.SenderDID, asOwn.SenderKeyTrust = base64.StdEncoding.EncodeToString(signed), string(keys), keysOwn
	refusedFor(t, m.receiver, asOwn, "were not tied")
}

// Keys vouched for by the key the sender's history ended with when a message
// arrived stay good for that message after the sender rotates. They are no
// good for anything arriving after the rotation, and the old position cannot
// be claimed for a later message: the signed log recorded which position each
// message arrived under.
func TestARotationNeitherBreaksAnOldMessageNorLetsTheRetiredKeyVouch(t *testing.T) {
	m := newMessaging(t)
	seed1, key1 := signingPair(t, 21)
	_, key2 := signingPair(t, 42)
	icp := map[string]interface{}{"v": "KERI10JSON", "t": "icp", "s": "0", "i": m.senderAID, "d": "Eicp", "k": []interface{}{key1}}
	if err := m.receiver.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: m.senderAID, KEL: []map[string]interface{}{icp}, KelVerified: true, CurrentPublicKey: key1,
	}); err != nil {
		t.Fatal(err)
	}
	// The receiver holds the sender's keys vouched for by the first key.
	didcommMu.Lock()
	peers := m.receiver.loadPeers()
	p := peers[m.senderAID]
	sig, err := login.SignString(string(p.DID.SigningInput()), seed1)
	if err != nil {
		didcommMu.Unlock()
		t.Fatal(err)
	}
	p.DID.KelSig = sig
	peers[m.senderAID] = p
	_ = m.receiver.savePeers(peers)
	didcommMu.Unlock()

	before := m.send(t, `{"title":"before the rotation"}`)
	if before.SenderKeyTrust != string(didcomm.KeysVouched) || before.SenderKELSaid != "Eicp" {
		t.Fatalf("the tie at receipt was not kept: %q at %q", before.SenderKeyTrust, before.SenderKELSaid)
	}

	// The sender rotates to a second key.
	rot := map[string]interface{}{"v": "KERI10JSON", "t": "rot", "s": "1", "i": m.senderAID, "d": "Erot", "k": []interface{}{key2}}
	if err := m.receiver.DataStore.SaveContactKEL(store.ContactKELRecord{
		AID: m.senderAID, KEL: []map[string]interface{}{icp, rot}, KelVerified: true, CurrentPublicKey: key2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.receiver.provedSender(before); err != nil {
		t.Fatalf("a genuine message stopped proving its sender when the sender rotated: %v", err)
	}

	// Keys still vouched for only by the retired key, arriving after it was
	// retired, were tied to nothing when they arrived.
	after := m.send(t, `{"title":"after the rotation"}`)
	refusedFor(t, m.receiver, after, "were not tied")

	// And whoever holds the database cannot move that message back to the
	// position where the retired key was current: the log says where it
	// arrived.
	moved := after
	moved.SenderKeyTrust, moved.SenderKELSaid, moved.SenderKELEvents, moved.SenderKEL = string(didcomm.KeysVouched), "Eicp", 1, before.SenderKEL
	refusedFor(t, m.receiver, moved, "signed log has no record")

	// Nor can the kept history be edited: the log committed to it.
	var events []map[string]interface{}
	_ = json.Unmarshal([]byte(before.SenderKEL), &events)
	events[0]["note"] = "edited"
	edited, _ := json.Marshal(events)
	tampered := before
	tampered.SenderKEL = string(edited)
	refusedFor(t, m.receiver, tampered, "signed log has no record")

	// The contact going, and its record being refetched shorter, leave the
	// proof intact: the history it was received under is kept with it.
	if err := m.receiver.DataStore.DeleteContact(m.senderAID); err != nil {
		t.Fatal(err)
	}
	if err := m.receiver.DataStore.SaveContactKEL(store.ContactKELRecord{AID: m.senderAID}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.receiver.provedSender(before); err != nil {
		t.Fatalf("removing the contact broke a genuine message's proof: %v", err)
	}
}

// Each check in provedSender is the first to catch its own forgery.
func TestEachPartOfAKeptMessageIsChecked(t *testing.T) {
	m := newMessaging(t)
	m.anchored(t)
	n := m.send(t, `{"title":"hello"}`)

	other := n
	other.FromAID = "ESOMEBODYELSE"
	refusedFor(t, m.receiver, other, "kept keys are")

	renamed := n
	renamed.ID = "a-different-message"
	refusedFor(t, m.receiver, renamed, "not what the sender signed")

	readdressed := n
	readdressed.ToAID = "ESOMEBODYELSE"
	refusedFor(t, m.receiver, readdressed, "not addressed to")
}

// A sender cannot sign a message that names somebody else as its sender: the
// message is refused when it arrives, and recorded as refused.
func TestAMessageNamingAnotherSenderIsRefused(t *testing.T) {
	m := newMessaging(t)
	raw := m.sealed(t, m.senderAID, "names-another", "did:keri:ESOMEBODYELSE", time.Now().Add(5*time.Minute))
	if code := m.post(t, raw); code != http.StatusForbidden {
		t.Fatalf("a message naming another sender was answered %d", code)
	}
	if n, _ := m.receiver.DataStore.GetNotification("names-another"); n != nil {
		t.Fatal("a message naming another sender was kept")
	}
	if rows := logged(t, m.receiver, "didcomm.message.received", "names-another"); len(rows) != 1 || rows[0].ResultStatus != "denied" {
		t.Fatalf("the refusal is not in the log: %+v", rows)
	}
}

// Recording refusals cannot fill the cache that stops replays, and one
// sender's message ids do not stand in for another's.
func resetRefusals(t *testing.T) {
	t.Helper()
	refusalsRecorded.Lock()
	refusalsRecorded.m = map[string]*senderRefusals{}
	refusalsRecorded.Unlock()
}

func TestRefusalsAreRecordedApartFromReplays(t *testing.T) {
	resetRefusals(t)
	m := newMessaging(t)
	const second = "ESECOND"
	ks, err := m.sender.keySetFor(second)
	if err != nil {
		t.Fatal(err)
	}
	did, _ := ks.DID()
	didcommMu.Lock()
	peers := m.receiver.loadPeers()
	peers[second] = peerRecord{AID: second, DID: *did}
	_ = m.receiver.savePeers(peers)
	didcommMu.Unlock()

	didcommSeen.Lock()
	before := len(didcommSeen.m)
	didcommSeen.Unlock()
	expired := time.Now().Add(-time.Minute)
	for i := 0; i < 20; i++ {
		raw := m.sealed(t, m.senderAID, "expired-"+string(rune('a'+i)), "did:keri:"+m.senderAID, expired)
		if code := m.post(t, raw); code != http.StatusForbidden {
			t.Fatalf("an expired envelope was answered %d", code)
		}
	}
	didcommSeen.Lock()
	after := len(didcommSeen.m)
	didcommSeen.Unlock()
	if after != before {
		t.Fatalf("refused envelopes filled the replay cache: %d entries before, %d after", before, after)
	}

	// The same message id from two senders: two refusals, each recorded.
	for _, from := range []string{m.senderAID, second} {
		raw := m.sealed(t, from, "shared-id", "did:keri:"+from, expired)
		if code := m.post(t, raw); code != http.StatusForbidden {
			t.Fatalf("an expired envelope was answered %d", code)
		}
	}
	callers := map[string]bool{}
	for _, r := range logged(t, m.receiver, "didcomm.message.received", "shared-id") {
		if r.ResultStatus == "denied" {
			callers[r.CallerAID] = true
		}
	}
	if !callers[m.senderAID] || !callers[second] {
		t.Fatalf("one sender's refusal hid another's: recorded for %v", callers)
	}
}

// A message between Identity Agents that belongs to a conversation is filed
// under it at both ends.
func TestTrafficIsFiledUnderItsConversation(t *testing.T) {
	m := newMessaging(t)
	n := m.send(t, `{"title":"part of a thread","conversation":"c_thread1"}`)
	for _, side := range []struct {
		s     *CoreServer
		event string
	}{{m.sender, "didcomm.message.sent"}, {m.receiver, "didcomm.message.received"}} {
		rows := logged(t, side.s, side.event, n.ID)
		if len(rows) != 1 || rows[0].WorkItem != "c_thread1" {
			t.Fatalf("%s is not filed under its conversation: %+v", side.event, rows)
		}
	}
	long := m.send(t, `{"title":"x","conversation":"c_`+strings.Repeat("x", 500)+`"}`)
	if rows := logged(t, m.receiver, "didcomm.message.received", long.ID); len(rows) != 1 || rows[0].WorkItem != "" {
		t.Fatalf("a malformed conversation was written into the log: %+v", rows)
	}
}

// One sender flooding refusals silences only itself: its refusals are recorded
// up to its quota, then one row says the rest are not recorded until the
// window ends, and another sender's refusals are still recorded.
func TestOneSendersFloodOfRefusalsSilencesOnlyItself(t *testing.T) {
	resetRefusals(t)
	m := newMessaging(t)
	const other = "EOTHERSENDER"
	ks, err := m.sender.keySetFor(other)
	if err != nil {
		t.Fatal(err)
	}
	did, _ := ks.DID()
	didcommMu.Lock()
	peers := m.receiver.loadPeers()
	peers[other] = peerRecord{AID: other, DID: *did}
	_ = m.receiver.savePeers(peers)
	didcommMu.Unlock()

	expired := time.Now().Add(-time.Minute)
	for i := 0; i < refusalQuota+50; i++ {
		raw := m.sealed(t, m.senderAID, fmt.Sprintf("flood-%d", i), "did:keri:"+m.senderAID, expired)
		if code := m.post(t, raw); code != http.StatusForbidden {
			t.Fatalf("an expired envelope was answered %d", code)
		}
	}
	raw := m.sealed(t, other, "from-the-other", "did:keri:"+other, expired)
	if code := m.post(t, raw); code != http.StatusForbidden {
		t.Fatalf("an expired envelope was answered %d", code)
	}

	count := func(event, caller string) int {
		rows, err := m.receiver.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
			CapabilityID: event, CallerAID: caller, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if n := count("didcomm.message.received", m.senderAID); n != refusalQuota {
		t.Fatalf("the flooding sender has %d refusals recorded; want its quota of %d", n, refusalQuota)
	}
	if n := count("didcomm.refusals.suppressed", m.senderAID); n != 1 {
		t.Fatalf("%d rows say the flooding sender's refusals are suppressed; want one", n)
	}
	if n := count("didcomm.message.received", other); n != 1 {
		t.Fatalf("another sender's refusal was not recorded while one sender flooded: %d", n)
	}
}

// "Own" is this Identity Agent's word that the keys are its AI agent's, and it
// takes more than files this agent writes: an asset row and a keyset can be
// written for anybody's identifier, so the identifier's key history must be
// delegated from this agent's root and approved in the root's own history.
func TestOwnIsOnlyAnAIAgentDelegatedFromHere(t *testing.T) {
	w := newTalkWorld(t)
	genuine, err := w.s.keySetFor(w.a.PairwiseAID)
	if err != nil {
		t.Fatal(err)
	}
	gdid, _ := genuine.DID()
	if _, err := w.s.ownAgentAtArrival(w.a.PairwiseAID, gdid); err != nil {
		t.Fatalf("an AI agent this Identity Agent delegated is not taken as its own: %v", err)
	}
	// Its identifier with keys it does not hold is not its own AI agent speaking.
	stranger, _ := didcomm.GenerateKeySet(w.a.PairwiseAID)
	sdid, _ := stranger.DID()
	if _, err := w.s.ownAgentAtArrival(w.a.PairwiseAID, sdid); err == nil || !strings.Contains(err.Error(), "not the ones") {
		t.Fatalf("keys this agent does not hold were taken as its AI agent's: %v", err)
	}

	// Somebody else's identifier, written in as if it were an AI agent here.
	const victim = "EVICTIMSOMEWHEREELSE0000000000000000000000000"
	if err := w.s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID: "forged-asset", DisplayName: "Forged", AssetType: "ai_agent", PairwiseAID: victim,
	}); err != nil {
		t.Fatal(err)
	}
	minted, err := w.s.keySetFor(victim)
	if err != nil {
		t.Fatal(err)
	}
	mdid, _ := minted.DID()
	if _, err := w.s.ownAgentAtArrival(victim, mdid); err == nil {
		t.Fatal("a forged asset row and a minted keyset were taken as this agent's own AI agent")
	}

	// A row pointing at a key history the engine does hold, but one that no
	// delegation from the root opens: the root identity itself.
	identity, _ := w.s.DataStore.GetIdentity()
	if err := w.s.assetHandler.Store.UpsertAsset(asset.Asset{
		ID: "forged-root", DisplayName: identity.AID, AssetType: "ai_agent", PairwiseAID: identity.AID,
	}); err != nil {
		t.Fatal(err)
	}
	rootKeys, err := w.s.keySetFor(identity.AID)
	if err != nil {
		t.Fatal(err)
	}
	rootDID, _ := rootKeys.DID()
	_, err = w.s.ownAgentAtArrival(identity.AID, rootDID)
	if err == nil || !strings.Contains(err.Error(), "not delegated from this Identity Agent") {
		t.Fatalf("an identifier whose history is not a delegation from the root was taken as an AI agent here: %v", err)
	}

	// And a message kept as the victim's, tied as "own", proves nothing.
	jwm := &didcomm.JWM{
		ID: "forged-own", Type: didcomm.TypeNotification,
		From: "did:keri:" + victim, To: []string{"did:keri:" + identity.AID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), ExpiresTime: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		Body: json.RawMessage(`{"title":"forged"}`),
	}
	rk, err := w.s.keySetFor(identity.AID)
	if err != nil {
		t.Fatal(err)
	}
	rdid, _ := rk.DID()
	env, err := didcomm.PackAuthcrypt(minted, rdid, jwm)
	if err != nil {
		t.Fatal(err)
	}
	_, signed, err := didcomm.UnpackAuthcryptKeeping(rk, mdid, env)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := json.Marshal(mdid)
	refusedFor(t, w.s, store.Notification{
		ID: jwm.ID, FromAID: victim, ToAID: identity.AID, Payload: string(jwm.Body),
		SignedMessage: base64.StdEncoding.EncodeToString(signed), SenderDID: string(keys), SenderKeyTrust: keysOwn,
	}, "were not tied")
}

// "Own" means an AI agent: another kind of identifier this agent holds, a
// machine or a domain, does not speak as one.
func TestOwnIsOnlyAnAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	ks, _ := w.s.keySetFor(w.a.PairwiseAID)
	did, _ := ks.DID()
	a, ok := w.s.assetHandler.Store.GetAsset(w.a.ID)
	if !ok {
		t.Fatal("no asset")
	}
	a.AssetType = "domain"
	if err := w.s.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.ownAgentAtArrival(w.a.PairwiseAID, did); err == nil {
		t.Fatal("an identifier that is not an AI agent was taken as one of this agent's AI agents")
	}
}

// The key history is found by identifier: renaming the AI agent does not lose
// it, and another identity held under its old name cannot stand in for it.
func TestOwnIsLookedUpByIdentifier(t *testing.T) {
	w := newTalkWorld(t)
	ks, _ := w.s.keySetFor(w.a.PairwiseAID)
	did, _ := ks.DID()
	a, _ := w.s.assetHandler.Store.GetAsset(w.a.ID)
	a.DisplayName = w.b.DisplayName
	if err := w.s.assetHandler.Store.UpsertAsset(a); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.ownAgentAtArrival(w.a.PairwiseAID, did); err != nil {
		t.Fatalf("renaming an AI agent lost its key history: %v", err)
	}
}

// writeCounting is the engine with every call that makes an identity counted.
type writeCounting struct {
	drivers.KeriEngine
	writes int
}

func (e *writeCounting) GetKelByAID(string) (*drivers.DriverKelResponse, error) {
	return nil, fmt.Errorf("not held")
}
func (e *writeCounting) CreateInceptionNamed(a, b, c string) (*drivers.DriverInceptionResponse, error) {
	e.writes++
	return e.KeriEngine.CreateInceptionNamed(a, b, c)
}
func (e *writeCounting) ReinstateDelegatedIdentity(a, b, c, d string) (*drivers.DriverDelegatedInceptionResponse, error) {
	e.writes++
	return e.KeriEngine.ReinstateDelegatedIdentity(a, b, c, d)
}
func (e *writeCounting) CreateDelegatedInception(a, b, c, d string) (*drivers.DriverDelegatedInceptionResponse, error) {
	e.writes++
	return e.KeriEngine.CreateDelegatedInception(a, b, c, d)
}

// Checking a message never writes: a key history the engine does not already
// hold is a refusal, not a reason to make one.
func TestCheckingOwnNeverWrites(t *testing.T) {
	w := newTalkWorld(t)
	ks, _ := w.s.keySetFor(w.a.PairwiseAID)
	did, _ := ks.DID()
	counting := &writeCounting{KeriEngine: w.s.KeriDriver}
	w.s.KeriDriver = counting
	if _, err := w.s.ownAgentAtArrival(w.a.PairwiseAID, did); err == nil {
		t.Fatal("an AI agent whose key history is not held was taken as one")
	}
	if counting.writes != 0 {
		t.Fatalf("checking an AI agent made %d identities in the engine", counting.writes)
	}
}

// A genuine message from one of this agent's own AI agents still proves itself
// after the AI agent is removed: the delegation evidence is kept with it.
func TestOwnProofOutlivesTheAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	if _, err := w.s.ensureLocalPeer(w.a.PairwiseAID); err != nil {
		t.Fatal(err)
	}
	from, _ := w.s.keySetFor(w.a.PairwiseAID)
	toKS, _ := w.s.keySetFor(w.b.PairwiseAID)
	to, _ := toKS.DID()
	env, err := didcomm.PackAuthcrypt(from, to, &didcomm.JWM{
		ID: "from-own-agent", Type: didcomm.TypeNotification,
		From: "did:keri:" + w.a.PairwiseAID, To: []string{"did:keri:" + w.b.PairwiseAID},
		CreatedTime: time.Now().UTC().Format(time.RFC3339), ExpiresTime: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
		Body: json.RawMessage(`{"title":"done"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	rec := httptest.NewRecorder()
	w.s.handleDIDCommInbound(rec, httptest.NewRequest("POST", "/didcomm", bytes.NewReader(raw)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("the message was answered %d: %s", rec.Code, rec.Body.String())
	}
	n, err := w.s.DataStore.GetNotification("from-own-agent")
	if err != nil || n == nil {
		t.Fatalf("not kept: %v", err)
	}
	if _, tie, err := w.s.provedSender(*n); err != nil || tie != keysOwn {
		t.Fatalf("a message from this agent's own AI agent is not proved as its own: %q %v", tie, err)
	}
	if err := w.s.assetHandler.Store.DeleteAsset(w.a.ID); err != nil {
		t.Fatal(err)
	}
	if _, tie, err := w.s.provedSender(*n); err != nil || tie != keysOwn {
		t.Fatalf("removing the AI agent broke a genuine old proof: %q %v", tie, err)
	}
}

// Kept delegation evidence counts only if it is about this identifier and its
// approval sits in this Identity Agent's root history, not a root of somebody
// else's making.
func TestDelegationEvidenceMustBeThisAgentsAndThisRoot(t *testing.T) {
	w := newTalkWorld(t)
	engine := w.s.KeriDriver.(kelHolder)
	evidence := func(aid string) ownEvidence {
		kel, err := engine.GetKelByAID(aid)
		if err != nil {
			t.Fatal(err)
		}
		root, err := engine.GetKelByAID(w.s.OwnerRootAID())
		if err != nil {
			t.Fatal(err)
		}
		return ownEvidence{Inception: kel.RawEventsB64[0], RootKEL: root.RawEventsB64}
	}
	if err := w.s.delegatedFromHere(w.a.PairwiseAID, evidence(w.a.PairwiseAID)); err != nil {
		t.Fatalf("genuine evidence was refused: %v", err)
	}
	if err := w.s.delegatedFromHere(w.a.PairwiseAID, evidence(w.b.PairwiseAID)); err == nil ||
		!strings.Contains(err.Error(), "is not "+w.a.PairwiseAID+"'s") {
		t.Fatalf("another AI agent's evidence was taken for this one: %v", err)
	}

	// A root and a delegate of somebody else's making, internally consistent.
	other := keriengine.New()
	s1, k1 := signingPair(t, 61)
	_, k2 := signingPair(t, 62)
	_, k3 := signingPair(t, 63)
	_, k4 := signingPair(t, 64)
	signsWithSeeds(other, s1)
	if _, err := other.CreateInceptionNamed(k1, k2, "elsewhere"); err != nil {
		t.Fatal(err)
	}
	d, err := other.CreateDelegatedInception(k3, k4, "their-agent", "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	dk, _ := other.GetKel("their-agent")
	rk, _ := other.GetKel("elsewhere")
	err = w.s.delegatedFromHere(d.AID, ownEvidence{Inception: dk.RawEventsB64[0], RootKEL: rk.RawEventsB64})
	if err == nil || !strings.Contains(err.Error(), "not this Identity Agent's") {
		t.Fatalf("a delegation from another root was taken as one from here: %v", err)
	}
}
