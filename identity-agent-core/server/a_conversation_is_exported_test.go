package server

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/agentmessage"
	"identity-agent-core/authprovider"
	"identity-agent-core/conversation"
	"identity-agent-core/conversationbundle"
	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/permission"
	"identity-agent-core/sandbox"

	_ "modernc.org/sqlite"
)

// exportWorld is the organisation with two AI agents, its governance log signed
// as it is in a running Identity Agent.
func exportWorld(t *testing.T) *talkWorld {
	t.Helper()
	w := newTalkWorld(t)
	w.s.SandboxManager.SetEventSigner(&invocationSigner{s: w.s})
	return w
}

// talkEndToEnd is the whole of a conversation: the person asks the desk
// assistant, which asks the build server, which answers, and the desk
// assistant answers the person. It returns the conversation.
func (w *talkWorld) talkEndToEnd(t *testing.T) string {
	t.Helper()
	code, out := w.personSays(t, w.a, "", "find out what the build server runs")
	if code != http.StatusCreated {
		t.Fatalf("the person's message: %d %v", code, out)
	}
	brainA := scripted{name: "test-brain", act: func(turn Turn) (string, error) {
		if strings.Contains(turn.Prompt, "asks you") {
			if text, failed := useTool(turn, "ask_agent", map[string]string{"to": "Build server", "text": "what do you run?"}); failed {
				t.Errorf("asking the build server: %s", text)
			}
			return "", nil
		}
		return "The build server says: " + turn.Prompt, nil
	}}
	brainB := scripted{name: "test-brain", act: func(turn Turn) (string, error) { return "a build machine", nil }}
	for _, step := range []struct {
		h     *agenthost.Host
		brain agenthost.Brain
	}{{w.hostA, brainA}, {w.hostB, brainB}, {w.hostA, brainA}} {
		if err := step.h.Run(context.Background(), agenthost.RunOptions{Brain: step.brain, Once: true, Workspace: t.TempDir()}); err != nil {
			t.Fatalf("running a host: %v", err)
		}
	}
	return out["conversation"].(string)
}

// export asks for the bundle as the person's paired app does.
func (w *talkWorld) export(t *testing.T, conv string) (int, []byte) {
	t.Helper()
	req := asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, "GET", "/api/mcp/conversations/"+conv+"/export", "", w.ctlSeed, "", time.Time{})
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (w *talkWorld) bundle(t *testing.T, conv string) *conversationbundle.Bundle {
	t.Helper()
	code, raw := w.export(t, conv)
	if code != http.StatusOK {
		t.Fatalf("exporting: %d %s", code, raw)
	}
	var b conversationbundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("the bundle is not JSON: %v", err)
	}
	return &b
}

// copyOf is an independent copy of a bundle, to change without touching the
// original.
func copyOf(t *testing.T, b *conversationbundle.Bundle) *conversationbundle.Bundle {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var out conversationbundle.Bundle
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func faultsOf(r conversationbundle.Report) string {
	var parts []string
	for _, f := range r.Faults {
		parts = append(parts, f.Where+": "+f.Why)
	}
	return strings.Join(parts, "\n")
}

func failsWith(t *testing.T, r conversationbundle.Report, where, words string) {
	t.Helper()
	if r.Verified {
		t.Fatalf("the bundle verified, and should not have")
	}
	for _, f := range r.Faults {
		if strings.Contains(f.Where, where) && strings.Contains(f.Why, words) {
			return
		}
	}
	t.Fatalf("no fault at %q saying %q; the faults were:\n%s", where, words, faultsOf(r))
}

// A conversation two AI agents had through a real Identity Agent and two real
// hosts exports as one bundle, and the bundle verifies with nothing else: every
// entry, its sender's own signature, the credentials it rests on, the log rows
// and the anchors.
func TestAnExportedConversationVerifiesOffline(t *testing.T) {
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	b := w.bundle(t, conv)

	r := conversationbundle.Verify(b)
	if !r.Verified {
		t.Fatalf("a genuine conversation does not verify:\n%s", faultsOf(r))
	}
	if len(r.Messages) != 7 {
		t.Fatalf("the report covers %d messages, not the 7 that were exchanged", len(r.Messages))
	}
	for _, m := range r.Messages {
		if !m.Holds || !m.Anchored {
			t.Fatalf("message %d: holds %v, anchored %v", m.Seq, m.Holds, m.Anchored)
		}
	}
	if m := r.Messages[0]; m.Sender != "controller" || m.Person != talkSigner {
		t.Fatalf("the opening is not shown as the signer's, from their app: %+v", m)
	}
	if m := r.Messages[2]; m.Sender != "body" || m.Grade != agentbody.GradeHardwareAsserted {
		t.Fatalf("the desk assistant's ask is not shown as its body's, at its grade: %+v", m)
	}
	if len(r.UnanchoredEntries) != 0 || r.AnchoredThrough != 7 {
		t.Fatalf("exporting anchors first, yet entries %v are reported after the last anchor", r.UnanchoredEntries)
	}
	if len(r.Trusts) == 0 || len(r.CannotRuleOut) == 0 {
		t.Fatal("the report does not say what it trusts and what it cannot rule out")
	}

	// The export is itself in the governance log, and in the bundle.
	rows, err := w.s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID: "agent.conversation.export", WorkItem: conv,
	})
	if err != nil || len(rows) != 1 || rows[0].CallerAID != w.ctlAID {
		t.Fatalf("the export was not recorded as the app's: %v %+v", err, rows)
	}
}

// Changing one byte of anything the bundle proves is caught, wherever it is.
func TestAOneByteEditFailsVerification(t *testing.T) {
	w := exportWorld(t)
	b := w.bundle(t, w.talkEndToEnd(t))
	if r := conversationbundle.Verify(b); !r.Verified {
		t.Fatalf("the genuine bundle does not verify:\n%s", faultsOf(r))
	}
	flip := func(s string, at int) string {
		bs := []byte(s)
		bs[at%len(bs)] ^= 0x01
		return string(bs)
	}
	flipB64 := func(s string, at int) string {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		raw[at%len(raw)] ^= 0x01
		return base64.StdEncoding.EncodeToString(raw)
	}
	flipURL := func(s string, at int) string {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		raw[at%len(raw)] ^= 0x01
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	for _, c := range []struct {
		name   string
		change func(b *conversationbundle.Bundle)
	}{
		{"a word of the person's message", func(b *conversationbundle.Bundle) { b.Entries[0].Body = flipB64(b.Entries[0].Body, 3) }},
		{"a word of the build server's reply", func(b *conversationbundle.Bundle) { b.Entries[4].Body = flipB64(b.Entries[4].Body, 0) }},
		{"the countersigned entry", func(b *conversationbundle.Bundle) {
			b.Entries[2].Envelope.Plain = flipURL(b.Entries[2].Envelope.Plain, 200)
		}},
		{"the countersignature", func(b *conversationbundle.Bundle) {
			b.Entries[3].Envelope.EdSig = flipURL(b.Entries[3].Envelope.EdSig, 5)
		}},
		{"a log row", func(b *conversationbundle.Bundle) {
			i := len(b.Log.Rows) / 2
			b.Log.Rows[i].Record = strings.Replace(b.Log.Rows[i].Record, `"ok"`, `"ko"`, 1)
		}},
		{"a body credential", func(b *conversationbundle.Bundle) { b.Credentials[0].Raw = flipB64(b.Credentials[0].Raw, 60) }},
		{"a credential's log", func(b *conversationbundle.Bundle) { b.Credentials[1].Log[0] = flipB64(b.Credentials[1].Log[0], 40) }},
		{"the root's key log", func(b *conversationbundle.Bundle) {
			for i := range b.KeyLogs {
				if b.KeyLogs[i].AID == b.Root {
					b.KeyLogs[i].Events[1].Raw = flipB64(b.KeyLogs[i].Events[1].Raw, 30)
				}
			}
		}},
		{"an anchor statement", func(b *conversationbundle.Bundle) {
			b.Anchors[len(b.Anchors)-1].Statement = flip(b.Anchors[len(b.Anchors)-1].Statement, 20)
		}},
		{"a messaging key", func(b *conversationbundle.Bundle) { b.Countersigners[0].Ed = flipURL(b.Countersigners[0].Ed, 2) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := copyOf(t, b)
			c.change(changed)
			r := conversationbundle.Verify(changed)
			if r.Verified {
				t.Fatalf("one byte of %s was changed and the bundle still verifies", c.name)
			}
			t.Logf("caught: %s: %s", r.Faults[0].Where, r.Faults[0].Why)
		})
	}
}

// Removing what an anchor fixes is caught: the newest entries, and the newest
// rows of the log.
func TestDeletingRowsAfterAnAnchorIsDetected(t *testing.T) {
	w := exportWorld(t)
	b := w.bundle(t, w.talkEndToEnd(t))

	lastTwo := copyOf(t, b)
	lastTwo.Entries = lastTwo.Entries[:len(lastTwo.Entries)-2]
	failsWith(t, conversationbundle.Verify(lastTwo), "anchor", "fixes entry 7 of this conversation")

	// The newest anchor fixes the newest row when the export was made: cut the
	// log there.
	var newest conversationbundle.AnchorStatement
	if err := json.Unmarshal([]byte(b.Anchors[len(b.Anchors)-1].Statement), &newest); err != nil {
		t.Fatal(err)
	}
	trimmed := copyOf(t, b)
	for len(trimmed.Log.Rows) > 0 && trimmed.Log.Rows[len(trimmed.Log.Rows)-1].ID >= newest.Log.Row {
		trimmed.Log.Rows = trimmed.Log.Rows[:len(trimmed.Log.Rows)-1]
	}
	failsWith(t, conversationbundle.Verify(trimmed), "anchor", "rows the anchor fixes have been removed")

	// A row taken from the middle.
	middle := copyOf(t, b)
	i := len(middle.Log.Rows) / 2
	middle.Log.Rows = append(middle.Log.Rows[:i], middle.Log.Rows[i+1:]...)
	failsWith(t, conversationbundle.Verify(middle), "log row", "are missing")

	// And an anchor's statement withheld.
	withheld := copyOf(t, b)
	withheld.Anchors = withheld.Anchors[:len(withheld.Anchors)-1]
	failsWith(t, conversationbundle.Verify(withheld), "anchor", "does not carry the statement")
}

// sayAsBody is the Identity Agent recording a message from a body as though it
// had admitted it: signed by the machine, countersigned as the AI agent, and
// written to the log. It stands for an Identity Agent that did not refuse what
// it should have, which is what the verifier must catch on its own.
func (w *talkWorld) sayAsBody(t *testing.T, conv string, m testMachine, from, to, inReplyTo, text string) {
	t.Helper()
	b, ok := w.s.bodies().ActiveByHost(func() string { h, _, _ := agentbody.Identity(m); return h }())
	if !ok {
		// Revoked: read the binding from the record of every body.
		host, _, _ := agentbody.Identity(m)
		ref := w.s.findAgentAssetByAID(from)
		for _, x := range w.s.bodies().ForAgent(ref.ID) {
			if x.Host == host {
				b = x
			}
		}
	}
	st := agentmessage.Statement{
		Conversation: conv, Kind: agentmessage.KindAsk, From: from, To: to, InReplyTo: inReplyTo,
		BodyHash: agentmessage.HashBody([]byte(text)), Brain: agentmessage.Brain{Provider: "test-brain"},
		Host: b.Host, HostNonce: conversation.NewID("n_"), HostTime: time.Now().UTC().Format(time.RFC3339),
		BodyCredential: b.CredentialSAID,
	}
	sig, err := agentmessage.Sign(m, st)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := w.s.conversations()
	ks, _, err := w.s.messagingKeys(from)
	if err != nil {
		t.Fatal(err)
	}
	grant := w.s.findCapabilityGrant(from)
	c, _ := store.Get(conv)
	id := conversation.NewID("m_")
	e, err := store.Append(context.Background(), conv, nil, []byte(text), []string{to}, nil,
		func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
			rec := agentmessage.Record{
				MessageID: id, Conversation: conv, Seq: seq, PrevHash: prev,
				IATime: time.Now().UTC().Format(time.RFC3339Nano), Kind: st.Kind, From: from, To: to,
				InReplyTo: inReplyTo, BodyHash: st.BodyHash, Depth: 1,
				Statement: &st, HostSignature: sig, HostVerkey: b.Verkey,
				GrantSAID: grant.SAID, BodyGrade: b.Grade, BodyCredential: b.CredentialSAID, OpenedBy: c.OpenedBy,
			}
			env, err := agentmessage.Countersign(ks, rec)
			return env, rec, err
		})
	if err != nil {
		t.Fatal(err)
	}
	w.s.recordMessage(permission.CallerContext{CallerAID: from, Transport: "body"}, e)
}

// A message a body sends after its binding was revoked fails verification,
// even where the Identity Agent recorded it; what it sent while the binding was
// live still holds.
func TestARevokedBindingsLaterMessageFails(t *testing.T) {
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	host, _, _ := agentbody.Identity(w.machineA)
	b, ok := w.s.bodies().ActiveByHost(host)
	if !ok {
		t.Fatal("the desk assistant has no live body")
	}
	if _, err := w.s.bodies().Revoke(b.ID, w.a.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec, _ := w.s.DataStore.GetCredential(b.CredentialSAID)
	if _, _, err := w.s.withdrawCredential(rec); err != nil {
		t.Fatalf("revoking the body credential: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	store, _ := w.s.conversations()
	first, _ := store.EntryAt(conv, 1)
	w.sayAsBody(t, conv, w.machineA, w.a.PairwiseAID, w.b.PairwiseAID, first.MessageID, "one more thing")

	b2 := w.bundle(t, conv)
	r := conversationbundle.Verify(b2)
	failsWith(t, r, "entry 8", "body credential was not in force when it was sent: it was revoked")
	for _, m := range r.Messages[:7] {
		if !m.Holds {
			t.Fatalf("message %d, sent while the binding was live, no longer holds:\n%s", m.Seq, faultsOf(r))
		}
	}

	// Leaving the revocation out of the bundle does not hide it: the root's
	// key log anchors it.
	withheld := copyOf(t, b2)
	for i := range withheld.Credentials {
		if withheld.Credentials[i].SAID == b.CredentialSAID {
			withheld.Credentials[i].Log = withheld.Credentials[i].Log[:1]
		}
	}
	failsWith(t, conversationbundle.Verify(withheld), "credential "+b.CredentialSAID, "does not carry")

	// Nor does stripping the anchors make the bundle pass.
	stripped := copyOf(t, b2)
	stripped.Entries = stripped.Entries[:7]
	stripped.RecordIdentity, stripped.Anchors = "", nil
	var keep []conversationbundle.KeyLog
	for _, kl := range stripped.KeyLogs {
		if kl.AID != b2.RecordIdentity {
			keep = append(keep, kl)
		}
	}
	stripped.KeyLogs = keep
	failsWith(t, conversationbundle.Verify(stripped), "log row", "the bundle carries no anchors")
}

// aSecondMachine is another app paired to the organisation, with its own key.
func aSecondMachine(t *testing.T, s *CoreServer) (ControllerGrant, []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, []byte("a second machine, granted then removed"))
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	g, err := s.controllers().Grant(ControllerGrant{
		ControllerAID: iacrypto.NonTransferableAIDQB64(pub), PublicKey: iacrypto.VerkeyQB64(pub),
		Label: "the old laptop", Grade: GradeEnrolled, Signer: talkSigner,
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	granted, err := s.grantController(g, time.Now().UTC(), authority{})
	if err != nil {
		t.Fatalf("anchoring the second machine's grant: %v", err)
	}
	return granted, seed
}

// openAs is the Identity Agent opening a conversation on a request an app
// signed, as though it had admitted it, recording it in the log.
func (w *talkWorld) openAs(t *testing.T, g ControllerGrant, seed []byte, signedAt time.Time, text string) string {
	t.Helper()
	return w.openAsFor(t, w.s.thisIdentityAgentsIdentifier(), g, seed, signedAt, text)
}

// openAsFor is openAs on a request the app signed for the Identity Agent named.
func (w *talkWorld) openAsFor(t *testing.T, target string, g ControllerGrant, seed []byte, signedAt time.Time, text string) string {
	t.Helper()
	conv := conversation.NewID("c_")
	body, _ := json.Marshal(agentmessage.PersonMessage{To: w.a.PairwiseAID, Body: text, Nonce: conversation.NewID("n_")})
	path := "/api/mcp/agents/" + w.a.ID + "/conversations"
	stamp := signedAt.UTC().Format(time.RFC3339)
	return w.openSigned(t, g, seed, conv, body, text,
		canonicalControllerRequest(g.ControllerAID, target, "POST", path, stamp, authprovider.Unmeasured(""), body))
}

// openSigned records an opening on exactly the string given, signed by the
// machine's seed, so a test can open a conversation on a request in any form.
func (w *talkWorld) openSigned(t *testing.T, g ControllerGrant, seed []byte, conv string, body []byte, text, signed string) string {
	t.Helper()
	identity, _ := w.s.DataStore.GetIdentity()
	sig, err := login.SignString(signed, seed)
	if err != nil {
		t.Fatal(err)
	}
	proof := &agentmessage.ControllerProof{
		Controller: g.ControllerAID, PublicKey: g.PublicKey, SignedString: signed, Signature: sig,
		RequestBytes: body, ControllerGrant: g.CredentialSAID,
	}
	ks, _, err := w.s.messagingKeys(identity.AID)
	if err != nil {
		t.Fatal(err)
	}
	opener := agentmessage.Person(talkSigner)
	person := agentmessage.PersonRef{AID: talkSigner, Standing: "signer", Name: "Alex"}
	store, _ := w.s.conversations()
	id := conversation.NewID("m_")
	e, err := store.Append(context.Background(), conv, &conversation.Conversation{OpenedBy: opener, FirstAgent: w.a.PairwiseAID},
		[]byte(text), []string{w.a.PairwiseAID}, nil,
		func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
			rec := agentmessage.Record{
				MessageID: id, Conversation: conv, Seq: seq, PrevHash: prev,
				IATime: time.Now().UTC().Format(time.RFC3339Nano), Kind: agentmessage.KindAsk,
				From: opener, To: w.a.PairwiseAID, BodyHash: agentmessage.HashBody([]byte(text)),
				ControllerProof: proof, Person: &person, OpenedBy: opener,
			}
			env, err := agentmessage.Countersign(ks, rec)
			return env, rec, err
		})
	if err != nil {
		t.Fatal(err)
	}
	w.s.recordMessage(permission.CallerContext{CallerAID: opener, Transport: "controller"}, e)
	return conv
}

// A conversation opened on a request signed by an app whose grant had been
// withdrawn is refused by the verifier, even where the Identity Agent took it.
func TestAnOpeningSignedByAnUnauthorisedControllerIsRejected(t *testing.T) {
	w := exportWorld(t)
	g, seed := aSecondMachine(t, w.s)
	if err := w.s.revokeController(g.ControllerAID); err != nil {
		t.Fatal(err)
	}
	// Signed a moment after the grant was withdrawn.
	conv := w.openAs(t, g, seed, time.Now().Add(2*time.Second), "open the safe")
	failsWith(t, conversationbundle.Verify(w.bundle(t, conv)), "entry 1", "Controller Grant was not in force")

	// And one whose key no grant names at all.
	stranger := g
	strangerSeed := make([]byte, ed25519.SeedSize)
	copy(strangerSeed, []byte("a machine nobody paired"))
	stranger.PublicKey = iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(strangerSeed).Public().(ed25519.PublicKey))
	conv = w.openAs(t, stranger, strangerSeed, time.Now(), "open the safe")
	failsWith(t, conversationbundle.Verify(w.bundle(t, conv)), "entry 1", "a key the Controller Grant does not name")

	// Signed while the grant was in force, it holds.
	g2, seed2 := aSecondMachine(t, w.s)
	conv = w.openAs(t, g2, seed2, time.Now(), "what time is it?")
	if r := conversationbundle.Verify(w.bundle(t, conv)); !r.Verified {
		t.Fatalf("an opening from an app in force does not verify:\n%s", faultsOf(r))
	}

	// Signed by that same app in force, but for another Identity Agent: a
	// request for one authorises nothing at another.
	conv = w.openAsFor(t, "EAnotherIdentityAgentAltogether", g2, seed2, time.Now(), "what time is it?")
	failsWith(t, conversationbundle.Verify(w.bundle(t, conv)), "entry 1", "for \"EAnotherIdentityAgentAltogether\"")

	// Signed in the form that names an Identity Agent, but naming none: that
	// is a request for no Identity Agent, not one for any.
	conv = w.openAsFor(t, "", g2, seed2, time.Now(), "what time is it?")
	failsWith(t, conversationbundle.Verify(w.bundle(t, conv)), "entry 1", "for \"\"")
}

// An opening signed in the first form, which names no Identity Agent, is read
// so a record made before requests named one still checks, and the bundle
// says that which Identity Agent the app meant is the Identity Agent's word.
func TestAnOpeningInTheFirstFormSaysItsTargetIsTheIdentityAgentsWord(t *testing.T) {
	w := exportWorld(t)
	g, seed := aSecondMachine(t, w.s)
	conv := conversation.NewID("c_")
	body, _ := json.Marshal(agentmessage.PersonMessage{To: w.a.PairwiseAID, Body: "what time is it?", Nonce: conversation.NewID("n_")})
	v2 := canonicalControllerRequest(g.ControllerAID, "", "POST", "/api/mcp/agents/"+w.a.ID+"/conversations",
		time.Now().UTC().Format(time.RFC3339), authprovider.Unmeasured(""), body)
	lines := strings.Split(v2, "\n")
	v1 := strings.Join(append([]string{"IA-CONTROLLER-REQ-V1", lines[1]}, lines[3:]...), "\n")
	conv = w.openSigned(t, g, seed, conv, body, "what time is it?", v1)
	r := conversationbundle.Verify(w.bundle(t, conv))
	if !r.Verified {
		t.Fatalf("an opening in the first form does not verify:\n%s", faultsOf(r))
	}
	said := false
	for _, c := range r.CannotRuleOut {
		said = said || strings.Contains(c, "first form")
	}
	if !said {
		t.Fatalf("the bundle does not say the first form's target is the Identity Agent's word: %v", r.CannotRuleOut)
	}
}

// An export whose words cannot be had from the record store fails, and says
// which message — it never hands out a bundle without them.
func TestAnExportMissingItsWordsFailsLoudly(t *testing.T) {
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	store, _ := w.s.conversations()
	e, _ := store.EntryAt(conv, 3)
	db, err := sql.Open("sqlite", filepath.Join(w.s.DataDir, "conversations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM contents WHERE ref = ?`, e.ContentRef); err != nil {
		t.Fatal(err)
	}
	code, raw := w.export(t, conv)
	if code == http.StatusOK || !strings.Contains(string(raw), e.MessageID) {
		t.Fatalf("an export missing the words of %s answered %d %s", e.MessageID, code, raw)
	}
	if n := strings.Count(string(raw), conversationbundle.ErrIncomplete.Error()); n != 1 {
		t.Fatalf("the refusal says it is incomplete %d times: %s", n, raw)
	}
	rows, _ := w.s.SandboxManager.Store().QueryInvocationEvents(sandbox.InvocationEventFilter{
		CapabilityID: "agent.conversation.export", WorkItem: conv, ResultStatus: "error",
	})
	if len(rows) != 1 {
		t.Fatalf("the failed export was not recorded: %+v", rows)
	}
}

// What the Identity Agent hands Build fails plainly: Build alone says the bundle
// is incomplete, so a refusal says it once rather than once per layer.
func TestTheIdentityAgentsSideFailsPlainly(t *testing.T) {
	w := exportWorld(t)
	w.talkEndToEnd(t)
	identity, _ := w.s.DataStore.GetIdentity()
	signer, found, err := readInvocationSignerRecord(w.s.DataDir)
	if err != nil || !found {
		t.Fatalf("no log signer: %v", err)
	}
	ctx := context.Background()
	ids := exportedIdentities{s: w.s, root: identity.AID, signer: signer}
	creds := exportedCredentials{s: w.s}
	wrongSeed := make([]byte, 32)
	agentLog, err := w.s.KeriDriver.(kelHolder).GetKelByAID(w.b.PairwiseAID)
	if err != nil {
		t.Fatal(err)
	}
	var raws [][]byte
	for _, r := range agentLog.RawEventsB64 {
		b, _ := base64.StdEncoding.DecodeString(r)
		raws = append(raws, b)
	}
	for name, fails := range map[string]func() error{
		"a key log not held here": func() error {
			_, err := w.s.exportKeyLog("EUnknownIdentityAltogether", nil)
			return err
		},
		"an unsigned event whose key is not held": func() error {
			return signWhereUnsigned(w.b.PairwiseAID, raws, make([]string, len(raws)), wrongSeed)
		},
		"a log signer the keys do not make": func() error {
			_, err := w.s.exportLogSigner(invocationSignerRecord{AID: "EUnknownIdentityAltogether", Index: signer.Index + 1000})
			return err
		},
		"an identity that is no AI agent here": func() error {
			_, err := ids.KeyLog(ctx, "EUnknownIdentityAltogether")
			return err
		},
		"messaging keys not held": func() error {
			_, err := ids.MessagingKeys(ctx, "EUnknownIdentityAltogether")
			return err
		},
		"a credential not on record": func() error {
			_, _, err := creds.Credential(ctx, "EUnknownCredential")
			return err
		},
		"a registry not kept": func() error {
			_, err := creds.Registry(ctx, "EUnknownRegistry")
			return err
		},
	} {
		err := fails()
		if err == nil {
			t.Fatalf("%s did not fail", name)
		}
		if errors.Is(err, conversationbundle.ErrIncomplete) {
			t.Fatalf("%s says the bundle is incomplete itself, so the refusal would say it twice: %v", name, err)
		}
	}
}

// An Identity Agent with no governance log signer on record exports nothing,
// and says that is why, rather than reading the signer as an unknown identity.
func TestAnExportWithNoLogSignerOnRecordSaysSo(t *testing.T) {
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	if err := os.Remove(filepath.Join(w.s.DataDir, "invocation_signer.json")); err != nil {
		t.Fatal(err)
	}
	code, raw := w.export(t, conv)
	if code == http.StatusOK || !strings.Contains(string(raw), "no log signer on record") {
		t.Fatalf("an export with no log signer on record answered %d %s", code, raw)
	}
}

// Only the owner and the apps the owner paired may export.
func TestOnlyTheOwnerOrAPairedAppExports(t *testing.T) {
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	req := httptest.NewRequest("GET", "/api/mcp/conversations/"+conv+"/export", nil)
	req.RemoteAddr = "203.0.113.9:4000"
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("an export was handed to a caller who is neither the owner nor a paired app: %s", rec.Body.String())
	}
}

// The command checks a bundle file as the person holding it would.
func TestTheVerifierCommandChecksABundleFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the command")
	}
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	code, raw := w.export(t, conv)
	if code != http.StatusOK {
		t.Fatalf("exporting: %d %s", code, raw)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var b conversationbundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.Entries[0].Body = base64.StdEncoding.EncodeToString([]byte("something else"))
	edited, _ := json.Marshal(b)
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "verify-conversation")
	if out, err := exec.Command("go", "build", "-o", bin, "identity-agent-core/cmd/verify-conversation").CombinedOutput(); err != nil {
		t.Fatalf("building the command: %v\n%s", err, out)
	}
	var genuine conversationbundle.Bundle
	_ = json.Unmarshal(raw, &genuine)
	out, err := exec.Command(bin, "--root", genuine.Root, good).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "VERIFIED") || !strings.Contains(string(out), "This result trusts") {
		t.Fatalf("the genuine bundle: %v\n%s", err, out)
	}
	out, err = exec.Command(bin, bad).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.HasPrefix(string(out), "NOT VERIFIED") {
		t.Fatalf("the edited bundle: %v\n%s", err, out)
	}
}

// Changing any one byte of the exported file, at positions spread through the
// whole of it, either leaves the file unreadable as a bundle, changes nothing
// it says, or fails verification. Nothing the bundle carries goes unchecked.
func TestChangingAnyByteOfTheFileFails(t *testing.T) {
	w := exportWorld(t)
	code, raw := w.export(t, w.talkEndToEnd(t))
	if code != http.StatusOK {
		t.Fatalf("exporting: %d %s", code, raw)
	}
	original, err := conversationbundle.Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r := conversationbundle.Verify(original); !r.Verified {
		t.Fatalf("the genuine bundle does not verify:\n%s", faultsOf(r))
	}
	positions := 600
	if testing.Short() {
		positions = 60
	}
	step := len(raw) / positions
	if step == 0 {
		step = 1
	}
	checked := 0
	for at := 0; at < len(raw); at += step {
		changed := append([]byte(nil), raw...)
		changed[at] ^= 0x01
		b, err := conversationbundle.Read(changed)
		if err != nil || reflect.DeepEqual(b, original) {
			continue // not a bundle, or the same bundle
		}
		checked++
		if r := conversationbundle.Verify(b); r.Verified {
			lo, hi := at-60, at+60
			if lo < 0 {
				lo = 0
			}
			if hi > len(raw) {
				hi = len(raw)
			}
			t.Fatalf("byte %d was changed and the bundle still verifies; around it:\n%s", at, raw[lo:hi])
		}
	}
	if checked < positions/3 {
		t.Fatalf("only %d of the changed files were readable bundles, too few to show anything", checked)
	}
}

// A bundle is checked against the organisation the reader expects: one naming
// another root fails, and one checked without naming any says so.
func TestABundleIsCheckedAgainstTheOrganisationExpected(t *testing.T) {
	w := exportWorld(t)
	b := w.bundle(t, w.talkEndToEnd(t))
	if r := conversationbundle.VerifyAgainst(b, b.Root); !r.Verified || r.Root != b.Root {
		t.Fatalf("checked against its own organisation, the bundle does not verify:\n%s", faultsOf(r))
	}
	failsWith(t, conversationbundle.VerifyAgainst(b, "EAnotherOrganisationAltogether"), "root", "not EAnotherOrganisationAltogether")
	r := conversationbundle.VerifyAgainst(b, "")
	if !r.Verified || !strings.Contains(r.CannotRuleOut[0], "taken from the bundle") {
		t.Fatalf("checked against no organisation, the report does not say the root came from the bundle: %v", r.CannotRuleOut)
	}
}

// A body's signed statement stands for one entry: recorded a second time, even
// countersigned in its proper place in the chain, it fails.
func TestASignedStatementRecordedTwiceFails(t *testing.T) {
	w := exportWorld(t)
	conv := w.talkEndToEnd(t)
	store, _ := w.s.conversations()
	ask, _ := store.EntryAt(conv, 3)
	orig, err := agentmessage.Read(ask.Envelope)
	if err != nil || orig.Statement == nil {
		t.Fatalf("entry 3 is not a body's ask: %v", err)
	}
	body, _ := store.Contents().Get(context.Background(), ask.ContentRef)
	ks, _, _ := w.s.messagingKeys(orig.From)
	id := conversation.NewID("m_")
	e, err := store.Append(context.Background(), conv, nil, body, nil, nil,
		func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
			rec := orig
			rec.MessageID, rec.Seq, rec.PrevHash, rec.IATime = id, seq, prev, time.Now().UTC().Format(time.RFC3339Nano)
			env, err := agentmessage.Countersign(ks, rec)
			return env, rec, err
		})
	if err != nil {
		t.Fatal(err)
	}
	w.s.recordMessage(permission.CallerContext{CallerAID: orig.From, Transport: "body"}, e)
	failsWith(t, conversationbundle.Verify(w.bundle(t, conv)), "entry 8", "same signed signature as entry 3")
}
