package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agenthost"
	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/conversation"
	"identity-agent-core/sandbox"
)

// talkWorld is an organisation with a signer on its roster, a controller paired
// to it, and two AI agents — "Mac Mini" and "MacBook Pro" — each allowed to
// message the other, each enrolled with a body.
type talkWorld struct {
	s            *CoreServer
	srv          *httptest.Server
	a, b         *asset.Asset
	hostA, hostB *agenthost.Host
	ctlAID       string
	ctlSeed      []byte
}

func newTalkWorld(t *testing.T, caps ...string) *talkWorld {
	t.Helper()
	if len(caps) == 0 {
		caps = []string{capabilityMessageAgent}
	}
	s, _ := grantWorld(t)
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	mgr, err := sandbox.NewManager(sandbox.ManagerConfig{DataDir: s.DataDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Stop)
	s.SandboxManager = mgr
	w := &talkWorld{s: s}
	w.a = w.provision(t, "Mac Mini", caps)
	w.b = w.provision(t, "MacBook Pro", caps)
	if err := s.assetHandler.Store.UpsertEmployee(asset.Employee{
		PairwiseAID: "ESIGNER_rob", Name: "Rob", Role: "Owner", Status: "active", IsSigner: true, VouchSig: "0Bvouch",
	}); err != nil {
		t.Fatal(err)
	}
	w.ctlAID, w.ctlSeed = anAuthorisedMachine(t, s, GradeEnrolled)

	// The sealed transport replays what it opens through the server's own
	// router, as it does in production.
	s.router = s.buildRouter("")
	w.srv = httptest.NewServer(s.router)
	t.Cleanup(w.srv.Close)
	t.Setenv("PUBLIC_URL", w.srv.URL)
	w.hostA = w.enrolBody(t, w.a)
	w.hostB = w.enrolBody(t, w.b)
	return w
}

func (w *talkWorld) provision(t *testing.T, name string, caps []string) *asset.Asset {
	t.Helper()
	a, err := w.s.assetHandler.ProvisionAgentAsset(name, caps, &asset.AgentConfig{Role: "the " + name + " machine"}, nil, nil)
	if err != nil {
		t.Fatalf("provisioning %s: %v", name, err)
	}
	if _, err := w.s.issueCapabilityGrant(a); err != nil {
		t.Fatalf("granting %s: %v", name, err)
	}
	return a
}

func (w *talkWorld) enrolBody(t *testing.T, a *asset.Asset) *agenthost.Host {
	t.Helper()
	m := newTestMachine(t)
	host, _, _ := agentbody.Identity(m)
	h := &agenthost.Host{DataDir: t.TempDir(), Signer: m, Hardware: true}
	done := make(chan error, 1)
	approveWhenAsked(t, w.s, a.ID, strings.Join(agentbody.Words(host), " "), done)
	if _, err := h.Enrol(enrolmentVia(t, w.s, w.srv.URL, a.ID), "computer", 20*time.Second); err != nil {
		t.Fatalf("enrolling %s: %v", a.DisplayName, err)
	}
	<-done
	return h
}

// personSays is the signer, from their paired app, saying something to an AI
// agent.
func (w *talkWorld) personSays(t *testing.T, a *asset.Asset, conv, text string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(agentmessage.PersonMessage{
		Conversation: conv, To: a.PairwiseAID, Body: text, Nonce: conversation.NewID("n_"),
	})
	path := "/api/mcp/agents/" + a.ID + "/conversations"
	req := asThatMachine(t, w.ctlAID, "POST", path, string(body), w.ctlSeed, "", time.Time{})
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
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
	w.s.handleReadConversation(rec, withRoute(httptest.NewRequest("GET", "/", nil), map[string]string{"cid": conv}))
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
// asks the Mac Mini to find out what the MacBook Pro runs; the Mac Mini's brain
// asks the MacBook Pro; the MacBook Pro's brain answers from system_info; the
// Mac Mini answers the person. Every entry is chained, countersigned as its
// sender, and carries the sender's own signature.
func TestTwoAIAgentsTalkThroughTheIdentityAgent(t *testing.T) {
	w := newTalkWorld(t)
	code, out := w.personSays(t, w.a, "", "find out what the MacBook Pro runs")
	if code != http.StatusCreated {
		t.Fatalf("the person's message: %d %v", code, out)
	}
	conv := out["conversation"].(string)

	brainA := scripted{name: "test-brain", act: func(turn Turn) (string, error) {
		switch {
		case strings.Contains(turn.Prompt, "asks you"):
			if text, failed := useTool(turn, "ask_agent", map[string]string{"to": "MacBook Pro", "text": "what OS and hardware are you on?"}); failed {
				t.Errorf("asking the MacBook Pro: %s", text)
			}
			return "", nil
		case strings.Contains(turn.Prompt, "answered you"):
			if text, failed := useTool(turn, "reply", map[string]string{"text": "The MacBook Pro says: " + turn.Prompt}); failed {
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
		_, did, err := w.s.messagingKeys(signer)
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
	if p := entries[0].Record.Person; p == nil || p.AID != "ESIGNER_rob" || p.Standing != "signer" {
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

// openedWith is a conversation a person opened with the Mac Mini, and the id
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

// A reply goes only to whoever asked. The Mac Mini was asked by the person, so
// it cannot "reply" to the MacBook Pro — which would reach an AI agent without
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
	m := newTestMachine(t)
	req := m.signed(t, "GET", "/api/agent-host/inbox", nil)
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "sealed") {
		t.Fatalf("an unsealed request reached the inbox: %d %s", rec.Code, rec.Body.String())
	}
}

// Nobody the organisation cannot prove opens a conversation: with no signer on
// the roster, the paired app's request is refused, and the refusal recorded.
func TestOnlyAPersonTheOrganisationCanProveOpensAConversation(t *testing.T) {
	w := newTalkWorld(t)
	if _, _, err := w.s.assetHandler.Store.SetEmployeeStatus("ESIGNER_rob", "revoked", ""); err != nil {
		t.Fatal(err)
	}
	code, out := w.personSays(t, w.a, "", "hello")
	if code != http.StatusForbidden || !strings.Contains(out["error"].(string), "no signer") {
		t.Fatalf("a conversation was opened with nobody provable asking: %d %v", code, out)
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
		_ = w.hostA.Run(ctx, agenthost.RunOptions{Brain: ping("MacBook Pro"), Once: true, Workspace: t.TempDir()})
		_ = w.hostB.Run(ctx, agenthost.RunOptions{Brain: ping("Mac Mini"), Once: true, Workspace: t.TempDir()})
	}
	if !strings.Contains(stopped, "deep") {
		t.Fatalf("the chain of asks was not stopped at its depth: %q", stopped)
	}
}

// Where the words are kept is reported, with the choice of keeping them
// elsewhere listed and not yet available.
func TestTheRecordSaysWhereItsWordsAreKept(t *testing.T) {
	s := agentWithDerivedIdentity(t)
	rec := httptest.NewRecorder()
	s.handleConversationRecordSetting(rec, httptest.NewRequest("GET", "/", nil))
	var out struct {
		Kept    string           `json:"kept"`
		Choices []map[string]any `json:"choices"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Kept != conversation.KindOnThisIdentityAgent || len(out.Choices) != 2 || out.Choices[1]["available"] != false {
		t.Fatalf("the record's setting: %s", rec.Body.String())
	}
}
