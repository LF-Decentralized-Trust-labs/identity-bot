package aiagents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/activitylog"
	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/conversation"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/sandbox"
	"identity-agent-core/sandboxedapps"
	"identity-agent-core/server"
)

// talkWorld is an organisation with a signer on its roster, a controller paired
// to it, and two AI agents — "Desk assistant" and "Build server" — each allowed to
// message the other, each enrolled with a body.
type talkWorld struct {
	s            *server.CoreServer
	srv          *httptest.Server
	ctlAID       string
	ctlSeed      []byte
	a, b         *asset.Asset
	hostA, hostB *agenthost.Host
	machineA     testMachine
}

func newTalkWorld(t *testing.T, caps ...string) *talkWorld {
	t.Helper()
	if len(caps) == 0 {
		caps = []string{capabilityMessageAgent}
	}
	w := &talkWorld{}
	w.s, w.srv, w.ctlAID, w.ctlSeed = fixtures.AControllerWorld(t)
	s := w.s
	mgr, err := sandbox.NewManager(sandbox.ManagerConfig{Log: fixtures.LogForTest(s, t, s.DataDir), Vault: fixtures.VaultForTest(s, s.DataDir), DataDir: s.DataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	sandboxedapps.UseManager(s, mgr)
	w.a = w.provision(t, "Desk assistant", caps)
	w.b = w.provision(t, "Build server", caps)
	w.hostA, w.machineA = w.enrolBody(t, w.a)
	w.hostB, _ = w.enrolBody(t, w.b)
	return w
}

func (w *talkWorld) provision(t *testing.T, name string, caps []string) *asset.Asset {
	t.Helper()
	a, err := hostOf(w.s).AssetHandler().ProvisionAgentAsset(name, caps, &asset.AgentConfig{Role: "the " + name + " machine"}, nil, nil)
	if err != nil {
		t.Fatalf("provisioning %s: %v", name, err)
	}
	if _, err := hostOf(w.s).IssueCapabilityGrant(a, coretypes.Authority{}); err != nil {
		t.Fatalf("granting %s: %v", name, err)
	}
	return a
}

func (w *talkWorld) enrolBody(t *testing.T, a *asset.Asset) (*agenthost.Host, testMachine) {
	t.Helper()
	m := newTestMachine(t)
	host, _, _ := agentbody.Identity(m)
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: m, Hardware: true, PollEvery: 20 * time.Millisecond}
	done := make(chan error, 1)
	approveWhenAsked(t, w.s, a.ID, strings.Join(agentbody.Words(host), " "), done)
	if _, err := h.Enrol(enrolmentVia(t, w.s, w.srv.URL, a.ID), "computer", 20*time.Second); err != nil {
		t.Fatalf("enrolling %s: %v", a.DisplayName, err)
	}
	<-done
	return h, m
}

// personSays is the signer, from their paired app, saying something to an AI
// agent.
func (w *talkWorld) personSays(t *testing.T, a *asset.Asset, conv, text string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(agentmessage.PersonMessage{
		Conversation: conv, To: a.PairwiseAID, Body: text, Nonce: conversation.NewID("n_"),
	})
	return w.personSends(t, a, string(body))
}

// personSends is the person's app sending this exact request body, signed as
// the app signs it.
func (w *talkWorld) personSends(t *testing.T, a *asset.Asset, body string) (int, map[string]any) {
	t.Helper()
	path := "/api/mcp/agents/" + a.ID + "/conversations"
	req := fixtures.AsThatMachineTo(t, hostOf(w.s).ThisIdentityAgentsIdentifier(), w.ctlAID, "POST", path, body, w.ctlSeed, "", time.Time{})
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// scripted is a brain that does what a test says, through the host's own
// tools — the same tool server the MCP bridge reaches.
type scripted struct {
	name string
	act  func(t Turn) (string, error)
}

type Turn = agenthost.Turn

func (b scripted) Name() string { return b.name }
func (b scripted) Run(_ context.Context, t agenthost.Turn) (agenthost.Outcome, error) {
	text, err := b.act(t)
	return agenthost.Outcome{Text: text, Brain: agentmessage.Brain{Provider: b.name, Session: t.Session}}, err
}

// useTool calls one of the host's tools as a brain's MCP server would.
func useTool(t Turn, name string, args map[string]string) (string, bool) {
	body, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	req, _ := http.NewRequest("POST", t.ToolsURL, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+t.ToolsToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err.Error(), true
	}
	defer resp.Body.Close()
	var out struct {
		Text    string `json:"text"`
		IsError bool   `json:"is_error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Text, out.IsError
}

func (w *talkWorld) read(t *testing.T, conv string) []entryView {
	t.Helper()
	rec := httptest.NewRecorder()
	of(w.s).handleReadConversation(rec, withRoute(httptest.NewRequest("GET", "/", nil), map[string]string{"cid": conv}))
	if rec.Code != http.StatusOK {
		t.Fatalf("reading the conversation: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Entries []entryView `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Entries
}

// The whole of it, across a real Identity Agent and two real hosts: a signer
// asks the desk assistant to find out what the build server runs; the desk assistant's brain
// asks the build server; the build server's brain answers from system_info; the
// desk assistant answers the person. Every entry is chained, countersigned as its
// sender, and carries the sender's own signature.
func TestTwoAIAgentsTalkThroughTheIdentityAgent(t *testing.T) {
	w := newTalkWorld(t)
	code, out := w.personSays(t, w.a, "", "find out what the build server runs")
	if code != http.StatusCreated {
		t.Fatalf("the person's message: %d %v", code, out)
	}
	conv := out["conversation"].(string)

	brainA := scripted{name: "test-brain", act: func(turn Turn) (string, error) {
		switch {
		case strings.Contains(turn.Prompt, "asks you"):
			if text, failed := useTool(turn, "ask_agent", map[string]string{"to": "Build server", "text": "what OS and hardware are you on?"}); failed {
				t.Errorf("asking the build server: %s", text)
			}
			return "", nil
		case strings.Contains(turn.Prompt, "answered you"):
			if text, failed := useTool(turn, "reply", map[string]string{"text": "The build server says: " + turn.Prompt}); failed {
				t.Errorf("replying to the person: %s", text)
			}
			return "", nil
		}
		t.Errorf("brain A was given %q", turn.Prompt)
		return "", nil
	}}
	brainB := scripted{name: "test-brain", act: func(turn Turn) (string, error) {
		info, failed := useTool(turn, "system_info", nil)
		if failed || !strings.Contains(info, `"architecture"`) {
			t.Errorf("system_info: %s", info)
		}
		// Ending the turn with words is the answer.
		return "I run " + info, nil
	}}
	ctx := context.Background()
	for _, step := range []struct {
		h     *agenthost.Host
		brain agenthost.Brain
	}{{w.hostA, brainA}, {w.hostB, brainB}, {w.hostA, brainA}} {
		if err := step.h.Run(ctx, agenthost.RunOptions{Brain: step.brain, Once: true, Workspace: t.TempDir()}); err != nil {
			t.Fatalf("running a host: %v", err)
		}
	}

	entries := w.read(t, conv)
	var kinds []string
	for _, e := range entries {
		kinds = append(kinds, e.Kind+":"+partyLabel(e.From)+">"+partyLabel(e.To))
	}
	want := []string{
		"ask:person>A", "receipt:A>person", "ask:A>B", "receipt:B>A", "reply:B>A", "receipt:A>B", "reply:A>person",
	}
	got := strings.Join(rename(kinds, w), " ")
	if got != strings.Join(want, " ") {
		t.Fatalf("the conversation went\n  %s\nnot\n  %s", got, strings.Join(want, " "))
	}

	prev := ""
	for i, e := range entries {
		if e.Seq != i+1 || e.Record.PrevHash != prev {
			t.Fatalf("entry %d is out of the chain: seq %d, prev %q, want %q", i, e.Seq, e.Record.PrevHash, prev)
		}
		prev = e.Hash
		if !e.BodyVerified {
			t.Fatalf("entry %d's words do not match its digest", e.Seq)
		}
		if err := e.Record.CheckSenderProof(); err != nil {
			t.Fatalf("entry %d (%s) carries no valid signature from its sender: %v", e.Seq, e.Kind, err)
		}
		signer := e.From
		if _, person := agentmessage.IsPerson(e.From); person {
			id, _ := w.s.DataStore.GetIdentity()
			signer = id.AID
		}
		_, did, err := of(w.s).messagingKeys(signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agentmessage.Open(did, e.Envelope); err != nil {
			t.Fatalf("entry %d is not countersigned as %s: %v", e.Seq, signer, err)
		}
		if e.Record.Statement != nil && e.Record.BodyGrade != agentbody.GradeHardwareAsserted {
			t.Fatalf("entry %d does not carry its body's grade, stamped by the Identity Agent: %q", e.Seq, e.Record.BodyGrade)
		}
	}
	if p := entries[0].Record.Person; p == nil || p.AID != fixtures.TalkSigner() || p.Standing != "signer" {
		t.Fatalf("the conversation does not name the person who opened it: %+v", p)
	}
	if !strings.Contains(entries[6].Body, `"architecture"`) {
		t.Fatalf("the answer did not reach the person: %q", entries[6].Body)
	}
}

func partyLabel(party string) string {
	if _, ok := agentmessage.IsPerson(party); ok {
		return "person"
	}
	return party
}

func rename(kinds []string, w *talkWorld) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		k = strings.ReplaceAll(k, w.a.PairwiseAID, "A")
		out[i] = strings.ReplaceAll(k, w.b.PairwiseAID, "B")
	}
	return out
}

// openedWith is a conversation a person opened with the desk assistant, and the id
// of their message.
func (w *talkWorld) openedWith(t *testing.T) (conv, msg string) {
	t.Helper()
	code, out := w.personSays(t, w.a, "", "hello")
	if code != http.StatusCreated {
		t.Fatalf("opening: %d %v", code, out)
	}
	return out["conversation"].(string), out["message_id"].(string)
}

func refusedWith(t *testing.T, err error, words string) {
	t.Helper()
	var r *agenthost.Refusal
	if !errors.As(err, &r) || !strings.Contains(r.Reason, words) {
		t.Fatalf("expected a refusal saying %q, got %v", words, err)
	}
}

// A body cannot speak in a conversation it was never brought into, even naming
// a real message in it: otherwise a machine could borrow a conversation
// somebody with wider reach opened.
func TestABodySpeaksOnlyInsideAConversationItWasBroughtInto(t *testing.T) {
	w := newTalkWorld(t)
	conv, msg := w.openedWith(t)
	_, err := w.hostB.Say(context.Background(), agentmessage.KindAsk, conv, w.a.PairwiseAID, msg, "let me in", agentmessage.Brain{})
	refusedWith(t, err, "has not been brought into")
}

// Nor can it invent a conversation.
func TestABodyCannotOpenAConversation(t *testing.T) {
	w := newTalkWorld(t)
	_, err := w.hostA.Say(context.Background(), agentmessage.KindAsk, "c_made_up", w.b.PairwiseAID, "m_made_up", "hi", agentmessage.Brain{})
	refusedWith(t, err, "no such conversation")
}

// Messaging another AI agent is a grant, and an AI agent without it cannot.
func TestAnAIAgentWithoutTheGrantCannotAskAnother(t *testing.T) {
	w := newTalkWorld(t, "infra.zone.list")
	conv, msg := w.openedWith(t)
	if _, err := w.hostA.Inbox(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_, err := w.hostA.Say(context.Background(), agentmessage.KindAsk, conv, w.b.PairwiseAID, msg, "what are you?", agentmessage.Brain{})
	refusedWith(t, err, "does not let it message other AI agents")
}

// A reply goes only to whoever asked. The desk assistant was asked by the person, so
// it cannot "reply" to the build server — which would reach an AI agent without
// any grant being checked.
func TestAReplyGoesOnlyToWhoAsked(t *testing.T) {
	w := newTalkWorld(t)
	conv, msg := w.openedWith(t)
	_, err := w.hostA.Say(context.Background(), agentmessage.KindReply, conv, w.b.PairwiseAID, msg, "psst", agentmessage.Brain{})
	refusedWith(t, err, "goes only to the sender of an ask")
}

// A body's message that is signed but not sealed is refused: its words would
// be readable wherever TLS ends on the way.
func TestAnUnsealedMessageIsRefused(t *testing.T) {
	w := newTalkWorld(t)
	// The live body itself, signing correctly, but not sealing.
	req := w.machineA.signed(t, w.s, "GET", "/api/agent-host/inbox", nil)
	rec := httptest.NewRecorder()
	hostOf(w.s).Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "sealed") {
		t.Fatalf("an unsealed request reached the inbox: %d %s", rec.Code, rec.Body.String())
	}
}

// Nobody the organisation cannot prove opens a conversation: with no signer on
// the roster and no owner named, the paired app's request is refused, and the
// refusal recorded.
func TestOnlyAPersonTheOrganisationCanProveOpensAConversation(t *testing.T) {
	w := newTalkWorld(t)
	if _, _, err := hostOf(w.s).AssetHandler().Store.SetEmployeeStatus(fixtures.TalkSigner(), "revoked", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(w.s.DataDir, helpers.OwnerAuthorityFile())); err != nil {
		t.Fatal(err)
	}
	code, out := w.personSays(t, w.a, "", "hello")
	if code != http.StatusForbidden || !strings.Contains(out["error"].(string), "no signer") {
		t.Fatalf("a conversation was opened with nobody provable asking: %d %v", code, out)
	}
	denied, _ := w.s.ActivityLog.QueryInvocationEvents(activitylog.InvocationEventFilter{
		CapabilityID: "agent.message.ask", ResultStatus: "denied"})
	if len(denied) == 0 {
		t.Fatal("the refusal is not in the governance record")
	}
}

// The owner the organisation names is a person it can prove, whether or not
// founding put them on the roster: off the roster, they open a conversation as the owner, the
// paired app becomes theirs, and when somebody else becomes the owner the AI
// agents can no longer ask in their name.
func TestTheOwnerTheOrganisationNamesMayAsk(t *testing.T) {
	w := newTalkWorld(t)
	if _, _, err := hostOf(w.s).AssetHandler().Store.SetEmployeeStatus(fixtures.TalkSigner(), "revoked", ""); err != nil {
		t.Fatal(err)
	}
	conv, _ := w.openedWith(t)
	entries := w.read(t, conv)
	if p := entries[0].Record.Person; p == nil || p.AID != fixtures.TalkSigner() || p.Standing != "owner" {
		t.Fatalf("the conversation was not opened by the owner: %+v", entries[0].Record.Person)
	}
	if g := mustGrant(t, w); g.Signer != fixtures.TalkSigner() {
		t.Fatalf("the paired app was not tied to the owner: %q", g.Signer)
	}

	d := sayTo(t, w.hostA)
	if err := w.s.ReSealOwnerAuthority(server.OwnerAuthority{
		AID: "EOWNER_sam", PublicKey: "DEC4FUUdUvgDKk07vt2cJUOaSGVLBGnbeGGjHvJTMUgo",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := w.hostA.Say(context.Background(), agentmessage.KindAsk, d.Record.Conversation, w.b.PairwiseAID,
		d.Entry.MessageID, "what are you?", agentmessage.Brain{})
	refusedWith(t, err, "no longer someone the organisation can prove")
}

// The list of AI agents always says what limits each grant carries, even when
// there are none, so a front end can tell "no limits" from "not reported".
func TestTheAgentListAlwaysReportsAGrantsLimits(t *testing.T) {
	w := newTalkWorld(t)
	rec := httptest.NewRecorder()
	of(w.s).handleListAgents(rec, httptest.NewRequest("GET", "/", nil))
	var out struct {
		Agents []map[string]json.RawMessage `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Agents) == 0 {
		t.Fatalf("listing: %d %s", rec.Code, rec.Body.String())
	}
	for _, a := range out.Agents {
		if c, ok := a["resource_constraints"]; !ok || string(c) != "{}" {
			t.Fatalf("an AI agent with no limits did not report them as none: %s", rec.Body.String())
		}
	}
}

// What arrives at a body is checked before it is acted on: words that are not
// the words the entry's digest names are refused.
func TestABodyRefusesAMessageWhoseWordsWereChanged(t *testing.T) {
	w := newTalkWorld(t)
	w.openedWith(t)
	ds, err := w.hostA.Inbox(context.Background(), false)
	if err != nil || len(ds) != 1 {
		t.Fatalf("collecting: %v %d", err, len(ds))
	}
	if err := w.hostA.Check(&ds[0]); err != nil {
		t.Fatalf("the genuine message was refused: %v", err)
	}
	ds[0].Body = "delete everything"
	if err := w.hostA.Check(&ds[0]); err == nil {
		t.Fatal("a message whose words were changed was accepted")
	}
}

// A person's words are countersigned by the Identity Agent, never by an AI
// agent it delegated, though that AI agent's keys are genuinely its own: a
// body refuses one countersigned by anyone else.
func TestABodyRefusesAPersonsMessageCountersignedByAnAIAgent(t *testing.T) {
	w := newTalkWorld(t)
	w.openedWith(t)
	ds, err := w.hostA.Inbox(context.Background(), false)
	if err != nil || len(ds) != 1 {
		t.Fatalf("collecting: %v %d", err, len(ds))
	}
	rec, err := agentmessage.Read(ds[0].Entry.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	ks, did, err := of(w.s).messagingKeys(w.b.PairwiseAID)
	if err != nil {
		t.Fatal(err)
	}
	env, err := agentmessage.Countersign(ks, rec)
	if err != nil {
		t.Fatal(err)
	}
	ds[0].Entry.Envelope, ds[0].Entry.Hash, ds[0].Countersigner = env, agentmessage.Hash(env), did
	err = w.hostA.Check(&ds[0])
	if err == nil || !strings.Contains(err.Error(), "countersigned by the Identity Agent") {
		t.Fatalf("a person's message countersigned by an AI agent was accepted: %v", err)
	}
}

// Two AI agents asking each other cannot go on forever: a chain of asks stops
// at its depth, and the brain is told why.
func TestAChainOfAsksStopsAtItsDepth(t *testing.T) {
	w := newTalkWorld(t)
	w.openedWith(t)
	var stopped string
	ping := func(other string) scripted {
		return scripted{name: "test-brain", act: func(turn Turn) (string, error) {
			text, failed := useTool(turn, "ask_agent", map[string]string{"to": other, "text": "and you?"})
			if failed {
				stopped = text
				return "I could not ask " + other, nil
			}
			return "", nil
		}}
	}
	ctx := context.Background()
	for i := 0; i < 6 && stopped == ""; i++ {
		_ = w.hostA.Run(ctx, agenthost.RunOptions{Brain: ping("Build server"), Once: true, Workspace: t.TempDir()})
		_ = w.hostB.Run(ctx, agenthost.RunOptions{Brain: ping("Desk assistant"), Once: true, Workspace: t.TempDir()})
	}
	if !strings.Contains(stopped, "deep") {
		t.Fatalf("the chain of asks was not stopped at its depth: %q", stopped)
	}
}

// Where the words are kept is reported, with the choice of keeping them
// elsewhere listed and not yet available.
func TestTheRecordSaysWhereItsWordsAreKept(t *testing.T) {
	s := fixtures.AgentWithDerivedIdentity(t)
	rec := httptest.NewRecorder()
	of(s).handleConversationRecordSetting(rec, httptest.NewRequest("GET", "/", nil))
	var out struct {
		Kept    string           `json:"kept"`
		Choices []map[string]any `json:"choices"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Kept != conversation.KindOnThisIdentityAgent || len(out.Choices) != 2 || out.Choices[1]["available"] != false {
		t.Fatalf("the record's setting: %s", rec.Body.String())
	}
}

// A body follows its Identity Agent to a new address, and only its own: an
// address answering as another Identity Agent is refused, and the body keeps
// the address it had.
func TestABodyMovesOnlyToItsOwnIdentityAgent(t *testing.T) {
	w := newTalkWorld(t)
	same := httptest.NewServer(hostOf(w.s).Router())
	defer same.Close()
	if _, err := w.hostA.Move(same.URL); err != nil {
		t.Fatalf("moving to the same Identity Agent at a new address: %v", err)
	}
	if code, _, err := w.hostA.Call("GET", "/api/agent-host/agents", nil); err != nil || code != http.StatusOK {
		t.Fatalf("the body could not speak at its new address: %d %v", code, err)
	}

	other, _ := bodyWorld(t)
	fixtures.RebuildRouter(other)
	elsewhere := httptest.NewServer(hostOf(other).Router())
	defer elsewhere.Close()
	if _, err := w.hostA.Move(elsewhere.URL); err == nil {
		t.Fatal("the body moved to another Identity Agent")
	}
	if code, _, err := w.hostA.Call("GET", "/api/agent-host/agents", nil); err != nil || code != http.StatusOK {
		t.Fatalf("a refused move changed where the body speaks: %d %v", code, err)
	}
}

// sayTo is a body acting on the last message waiting for it: it takes it from
// its inbox, acknowledges it, and returns it.
func sayTo(t *testing.T, h *agenthost.Host) agenthost.Delivery {
	t.Helper()
	ds, err := h.Inbox(context.Background(), false)
	if err != nil || len(ds) == 0 {
		t.Fatalf("nothing waiting: %v", err)
	}
	d := ds[len(ds)-1]
	if err := h.Check(&d); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Say(context.Background(), agentmessage.KindReceipt, d.Record.Conversation, d.Record.From,
		d.Entry.MessageID, d.Entry.Hash, agentmessage.Brain{}); err != nil {
		t.Fatal(err)
	}
	return d
}

// An ask is answered once. A body that could answer again and again could
// make the asker's brain run again and again, on somebody's bill.
func TestAnAskIsAnsweredOnlyOnce(t *testing.T) {
	w := newTalkWorld(t)
	w.openedWith(t)
	d := sayTo(t, w.hostA)
	ctx := context.Background()
	if _, err := w.hostA.Say(ctx, agentmessage.KindReply, d.Record.Conversation, d.Record.From, d.Entry.MessageID, "first", agentmessage.Brain{}); err != nil {
		t.Fatal(err)
	}
	_, err := w.hostA.Say(ctx, agentmessage.KindFailure, d.Record.Conversation, d.Record.From, d.Entry.MessageID, "again", agentmessage.Brain{})
	refusedWith(t, err, "already been answered")
}

// A receipt is for a message still waiting: an old message cannot be
// acknowledged again to keep a conversation alive.
func TestAReceiptIsOnlyForAMessageStillWaiting(t *testing.T) {
	w := newTalkWorld(t)
	w.openedWith(t)
	d := sayTo(t, w.hostA)
	_, err := w.hostA.Say(context.Background(), agentmessage.KindReceipt, d.Record.Conversation, d.Record.From,
		d.Entry.MessageID, d.Entry.Hash, agentmessage.Brain{})
	refusedWith(t, err, "not waiting")
}

// The grant's constraint on whom an AI agent may message is enforced.
func TestAnAIAgentMessagesOnlyWhomItsGrantNames(t *testing.T) {
	w := newTalkWorld(t)
	if _, err := hostOf(w.s).AssetHandler().SetAgentGrantConstraints(w.a.ID, map[string]interface{}{
		capabilityMessageAgent: map[string]interface{}{"to": []interface{}{"ESOMEBODY_ELSE"}},
	}); err != nil {
		t.Fatal(err)
	}
	a, _ := of(w.s).aiAgentAsset(w.a.ID)
	if _, err := hostOf(w.s).IssueCapabilityGrant(&a, coretypes.Authority{}); err != nil {
		t.Fatal(err)
	}
	w.openedWith(t)
	d := sayTo(t, w.hostA)
	_, err := w.hostA.Say(context.Background(), agentmessage.KindAsk, d.Record.Conversation, w.b.PairwiseAID,
		d.Entry.MessageID, "what are you?", agentmessage.Brain{})
	refusedWith(t, err, "does not let it message that AI agent")
}

// When a person who opened a conversation stops being someone the
// organisation can prove, the AI agents in it can no longer ask on their
// behalf.
func TestAnAskStopsWhenTheOpenerNoLongerStands(t *testing.T) {
	w := newTalkWorld(t)
	w.openedWith(t)
	d := sayTo(t, w.hostA)
	if _, _, err := hostOf(w.s).AssetHandler().Store.SetEmployeeStatus(fixtures.TalkSigner(), "revoked", ""); err != nil {
		t.Fatal(err)
	}
	_, err := w.hostA.Say(context.Background(), agentmessage.KindAsk, d.Record.Conversation, w.b.PairwiseAID,
		d.Entry.MessageID, "what are you?", agentmessage.Brain{})
	refusedWith(t, err, "no longer someone the organisation can prove")
}

// A brain that fails closes the turn with a signed failure notice, so the
// one who asked is not left waiting.
func TestAFailedBrainSendsAFailureNotice(t *testing.T) {
	w := newTalkWorld(t)
	conv, _ := w.openedWith(t)
	broken := scripted{name: "test-brain", act: func(Turn) (string, error) { return "", errors.New("usage limit reached") }}
	if err := w.hostA.Run(context.Background(), agenthost.RunOptions{Brain: broken, Once: true, Workspace: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	entries := w.read(t, conv)
	last := entries[len(entries)-1]
	if last.Kind != agentmessage.KindFailure || !strings.Contains(last.Body, "usage limit reached") {
		t.Fatalf("no failure notice closed the turn: %s %q", last.Kind, last.Body)
	}
}

// A conversation holds a bounded number of turns.
func TestAConversationRunsOutOfTurns(t *testing.T) {
	w := newTalkWorld(t)
	conv, _ := w.openedWith(t)
	var code int
	var out map[string]any
	for i := 0; i < conversation.MaxTurns+1; i++ {
		if code, out = w.personSays(t, w.a, conv, "and another thing"); code != http.StatusCreated {
			break
		}
	}
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "turns") {
		t.Fatalf("the conversation did not run out of turns: %d %v", code, out)
	}
}

// A body can read back what has been said in a conversation it is in, and
// not one it is not.
func TestABodyReadsOnlyConversationsItIsIn(t *testing.T) {
	w := newTalkWorld(t)
	conv, _ := w.openedWith(t)
	code, b, err := w.hostA.Call("GET", "/api/agent-host/conversations/"+conv, nil)
	if err != nil || code != http.StatusOK || !strings.Contains(string(b), "hello") {
		t.Fatalf("the desk assistant could not read its own conversation: %d %s %v", code, b, err)
	}
	if code, _, _ := w.hostB.Call("GET", "/api/agent-host/conversations/"+conv, nil); code != http.StatusForbidden {
		t.Fatalf("the build server read a conversation it is not in: %d", code)
	}
}

// A message a body cannot check is acknowledged — so it does not wait in the
// queue for ever — and answered with a failure notice saying why, so the one
// who asked is not left waiting either.
func TestAMessageThatDoesNotCheckOutIsAnsweredWithWhy(t *testing.T) {
	w := newTalkWorld(t)
	conv, _ := w.openedWith(t)
	ds, err := w.hostA.Inbox(context.Background(), false)
	if err != nil || len(ds) != 1 {
		t.Fatalf("collecting: %v %d", err, len(ds))
	}
	ds[0].Body = "something else"
	why := w.hostA.Check(&ds[0])
	if why == nil {
		t.Fatal("an altered message checked out")
	}
	if !w.hostA.Refuse(context.Background(), &ds[0], why) {
		t.Fatal("the refused message was not taken off the queue")
	}
	if left, _ := w.hostA.Inbox(context.Background(), false); len(left) != 0 {
		t.Fatalf("the refused message is still waiting: %d", len(left))
	}
	entries := w.read(t, conv)
	last := entries[len(entries)-1]
	if last.Kind != agentmessage.KindFailure || !strings.Contains(last.Body, "did not check out") {
		t.Fatalf("the asker was not told why: %s %q", last.Kind, last.Body)
	}
}

// An ask that takes a conversation's last turn can still be answered.
func TestTheLastAskCanStillBeAnswered(t *testing.T) {
	w := newTalkWorld(t)
	conv, _ := w.openedWith(t)
	for i := 1; i < conversation.MaxTurns; i++ {
		if code, out := w.personSays(t, w.a, conv, "and another thing"); code != http.StatusCreated {
			t.Fatalf("turn %d: %d %v", i+1, code, out)
		}
	}
	st, _ := mustStore(t, w)
	c, _ := st.Get(conv)
	if c.Turns != conversation.MaxTurns {
		t.Fatalf("expected the conversation full, at %d turns", c.Turns)
	}
	d := sayTo(t, w.hostA)
	if _, err := w.hostA.Say(context.Background(), agentmessage.KindReply, conv, d.Record.From, d.Entry.MessageID,
		"here is the answer", agentmessage.Brain{}); err != nil {
		t.Fatalf("the last ask could not be answered: %v", err)
	}
}

func mustStore(t *testing.T, w *talkWorld) (*conversation.Store, error) {
	t.Helper()
	st, err := of(w.s).conversations()
	if err != nil {
		t.Fatal(err)
	}
	return st, nil
}

// A machine paired while the organisation has one signer belongs to that
// signer from the moment it is paired.
func TestAMachinePairedWithOneSignerBelongsToThem(t *testing.T) {
	w := newTalkWorld(t)
	body := `{"controller_aid":"` + w.ctlAID + `","public_key":"` + mustGrant(t, w).PublicKey + `","label":"again","grade":"enrolled"}`
	_ = fixtures.RevokeControllerRow(w.s, w.ctlAID)
	rec := httptest.NewRecorder()
	hostOf(w.s).HandleGrantController(rec, httptest.NewRequest("POST", "/", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("granting: %d %s", rec.Code, rec.Body.String())
	}
	if g := mustGrant(t, w); g.Signer != fixtures.TalkSigner() {
		t.Fatalf("the machine was not bound to the only signer when paired: %q", g.Signer)
	}
}

func mustGrant(t *testing.T, w *talkWorld) server.ControllerGrant {
	t.Helper()
	g, live, err := fixtures.LiveControllerRow(w.s, w.ctlAID, time.Now())
	if err != nil || !live {
		t.Fatalf("no live grant: %v", err)
	}
	return g
}
