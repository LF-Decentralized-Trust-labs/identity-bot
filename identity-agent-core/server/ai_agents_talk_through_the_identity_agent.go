package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/asset"
	"identity-agent-core/conversation"
	"identity-agent-core/didcomm"
	"identity-agent-core/login"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// AI agents talk through the Identity Agent that holds them.
//
// A person asks an AI agent they may use. That AI agent's body may then ask
// another AI agent, which answers, and the first answers the person. Every one
// of those legs enters here, and is admitted, countersigned and recorded here,
// before it goes on. Nothing travels from one machine to another directly.
//
// Who may do what is decided here and nowhere else:
//
//   - A person is someone the organisation can prove. In this version that is
//     a signer, speaking through a controller the owner paired. An employee's
//     device is never made a controller, because a controller can do nearly
//     everything the owner can.
//   - The Identity Agent opens the conversation and chooses its id. A body
//     speaks only inside a conversation it was brought into, and only about a
//     message it was given, so it cannot shed the limits of the person who
//     opened the conversation by starting another.
//   - An ask from one AI agent to another needs the asker's grant to allow
//     messaging that AI agent, and the person who opened the conversation to be
//     allowed to reach it. An AI agent acting for a person reaches no further
//     than that person.
//   - A reply goes only to the sender of the message it answers, which must
//     have been addressed to the one replying.
//
// A refusal is written to the signed governance record, so the record shows
// what was attempted as well as what was said.

// capabilityMessageAgent is the grant entry that lets an AI agent ask another.
const capabilityMessageAgent = "agent.message.send"

// conversationWait bounds one long-poll, well inside the shortest relay limit
// on any path to an Identity Agent.
const conversationWait = 25 * time.Second

var conversationStores sync.Map

// conversations is this Identity Agent's conversation record.
func (s *CoreServer) conversations() (*conversation.Store, error) {
	dir, err := filepath.Abs(s.DataDir)
	if err != nil {
		dir = s.DataDir
	}
	if v, ok := conversationStores.Load(dir); ok {
		return v.(*conversation.Store), nil
	}
	st, err := conversation.OpenStore(dir)
	if err != nil {
		return nil, err
	}
	if v, loaded := conversationStores.LoadOrStore(dir, st); loaded {
		_ = st.Close()
		return v.(*conversation.Store), nil
	}
	return st, nil
}

func (s *CoreServer) mountConversationRoutes(r chi.Router) {
	// A person, from a paired app.
	r.Post("/mcp/agents/{id}/conversations", s.handlePersonSays)
	r.Get("/mcp/agents/{id}/conversations", s.handleListAgentConversations)
	r.Get("/mcp/conversations/{cid}", s.handleReadConversation)
	r.Get("/mcp/conversations/{cid}/export", s.handleExportConversation)
	r.Get("/mcp/conversation-record", s.handleConversationRecordSetting)
	// A body, signed by its machine key and sealed to this Identity Agent.
	r.Post("/agent-host/messages", s.handleBodySays)
	r.Get("/agent-host/inbox", s.handleBodyInbox)
	r.Get("/agent-host/agents", s.handleBodyListAgents)
	r.Get("/agent-host/conversations/{cid}", s.handleBodyConversationHistory)
}

// ── Who is asking ────────────────────────────────────────────────────────────

// errNoProvablePerson is a request that does not come from a person the
// organisation can prove.
var errNoProvablePerson = errors.New("a person speaks to an AI agent from an app paired to this " +
	"organisation, so the record can show which person asked")

// thePersonAsking is the person behind a request a controller signed, and the
// controller's signature as proof of what they said.
func (s *CoreServer) thePersonAsking(r *http.Request) (agentmessage.PersonRef, *agentmessage.ControllerProof, error) {
	grant, ok := TheControllerThatAsked(r)
	if !ok {
		return agentmessage.PersonRef{}, nil, errNoProvablePerson
	}
	// The person is read from the machine's record only where that record is
	// what its grant says: a signer or an expiry written into the file is
	// refused, not attributed. A machine with no grant awaits the owner's
	// approval; one whose grant waits for another device is believed only
	// where the key really is elsewhere.
	if current, had, err := s.controllers().Get(grant.ControllerAID); err == nil && had {
		switch {
		case current.CredentialSAID != "":
			if err := s.rowIsItsGrant(current); err != nil {
				return agentmessage.PersonRef{}, nil, err
			}
		case !current.CredentialPending || !s.keyIsElsewhere():
			return agentmessage.PersonRef{}, nil, fmt.Errorf("this machine was paired before machines were given grants, and awaits the owner's approval")
		}
		grant = current
	}
	person, err := s.signerOf(grant)
	if err != nil {
		return agentmessage.PersonRef{}, nil, err
	}
	// Settling the signer re-issues the machine's grant, so the grant named is
	// read again rather than taken from before.
	if g, ok, err := s.controllers().Get(grant.ControllerAID); err == nil && ok {
		grant.CredentialSAID = g.CredentialSAID
	}
	signed, sig, err := s.theRequestAsSigned(r, grant)
	if err != nil {
		return agentmessage.PersonRef{}, nil, err
	}
	body, err := readSignedBody(r)
	if err != nil {
		return agentmessage.PersonRef{}, nil, err
	}
	return person, &agentmessage.ControllerProof{
		Controller: grant.ControllerAID, PublicKey: grant.PublicKey, SignedString: signed,
		Signature: sig, Request: body, ControllerGrant: grant.CredentialSAID,
	}, nil
}

// theOwner is the person this organisation answers to: the owner its own
// inception event names, or, with no such anchor, the one sealed when it was
// provisioned. Never the organisation itself, which is what ownerAuthority
// falls back to when nobody was named.
func (s *CoreServer) theOwner() (string, bool) {
	oa, err := s.ownerAuthority()
	if err != nil || oa == nil || oa.AID == "" {
		return "", false
	}
	if s.DataStore != nil {
		if id, _ := s.DataStore.GetIdentity(); id != nil && id.AID == oa.AID {
			return "", false
		}
	}
	return oa.AID, true
}

// signers are the people who sign for the organisation: every active signer
// on its roster, and its owner. The owner counts whether or not founding put
// them on the roster, because the organisation's own key log names them, which
// is the strongest proof of a person it has. Their standing says which, so the
// record shows what the proof is.
func (s *CoreServer) signers() []agentmessage.PersonRef {
	var out []agentmessage.PersonRef
	seen := map[string]bool{}
	if s.assetHandler != nil {
		for _, e := range s.assetHandler.Store.ListEmployees() {
			if e.IsSigner && e.Status == "active" {
				out = append(out, agentmessage.PersonRef{AID: e.PairwiseAID, Standing: "signer", Credential: e.VouchSig, Name: e.Name})
				seen[e.PairwiseAID] = true
			}
		}
	}
	if owner, ok := s.theOwner(); ok && !seen[owner] {
		out = append(out, agentmessage.PersonRef{AID: owner, Standing: "owner", Name: "The owner"})
	}
	return out
}

// signerOf is the signer a controller belongs to: the one its grant names.
// A grant that names none is bound, the first time it is needed, to the
// organisation's only signer — so the machine keeps speaking as that person
// whoever joins later, rather than as whoever happens to be the only signer
// at the time of each message.
func (s *CoreServer) signerOf(g ControllerGrant) (agentmessage.PersonRef, error) {
	signers := s.signers()
	if g.Signer != "" {
		for _, p := range signers {
			if p.AID == g.Signer {
				return p, nil
			}
		}
		return agentmessage.PersonRef{}, fmt.Errorf("the signer this app belongs to is no longer an active signer of the organisation")
	}
	switch len(signers) {
	case 0:
		return agentmessage.PersonRef{}, fmt.Errorf("this organisation has no signer on its roster and names no owner, " +
			"so nobody it can prove is asking. A signer joins by accepting the organisation's signer invitation from their own identity")
	case 1:
		if _, err := s.bindSigner(g.ControllerAID, signers[0].AID); err != nil {
			return agentmessage.PersonRef{}, fmt.Errorf("which signer this app belongs to could not be recorded: %w", err)
		}
		return signers[0], nil
	}
	return agentmessage.PersonRef{}, fmt.Errorf("this organisation has more than one signer, and this app has not " +
		"been tied to one of them, so the record could not say which person asked")
}

// onlyActiveSigner is the organisation's signer when it has exactly one, and
// empty otherwise.
func (s *CoreServer) onlyActiveSigner() string {
	if signers := s.signers(); len(signers) == 1 {
		return signers[0].AID
	}
	return ""
}

// personStillStands reports whether the person who opened a conversation is
// still someone the organisation can prove — checked on every ask made in
// their name, not only when they opened it.
func (s *CoreServer) personStillStands(p agentmessage.PersonRef) bool {
	if p.AID == "" {
		return false
	}
	if p.Standing == "owner" {
		owner, ok := s.theOwner()
		return ok && owner == p.AID
	}
	if s.assetHandler == nil {
		return false
	}
	for _, e := range s.assetHandler.Store.ListEmployees() {
		if e.PairwiseAID == p.AID && e.Status == "active" && (p.Standing != "signer" || e.IsSigner) {
			return true
		}
	}
	return false
}

// personMayUse reports whether a person may use an AI agent. A signer or the
// owner may use every AI agent of the organisation they sign for.
func personMayUse(p agentmessage.PersonRef, _ asset.Asset) bool {
	return p.Standing == "signer" || p.Standing == "owner"
}

// personRefFor is the person who opened a conversation, from the record.
func personRefFor(entries []conversation.Entry, opener string) (agentmessage.PersonRef, bool) {
	aid, ok := agentmessage.IsPerson(opener)
	if !ok {
		return agentmessage.PersonRef{}, false
	}
	for _, e := range entries {
		if e.From == opener {
			if r, err := agentmessage.Read(e.Envelope); err == nil && r.Person != nil {
				return *r.Person, true
			}
		}
	}
	return agentmessage.PersonRef{AID: aid}, false
}

// ── Countersigning ───────────────────────────────────────────────────────────

// messagingKeys are the keys the Identity Agent countersigns with as one
// party — an AI agent it holds, or itself for a person's message — and the
// public half, vouched for by that identity's own signing key, so a body can
// check them against the identity's key log.
func (s *CoreServer) messagingKeys(aid string) (*didcomm.KeySet, *didcomm.DID, error) {
	var seed []byte
	var err error
	if id, _ := s.DataStore.GetIdentity(); id != nil && id.AID == aid {
		seed, err = s.identitySigningSeed()
	} else if ref := s.findAgentAssetByAID(aid); ref != nil {
		a, ok := s.aiAgentAsset(ref.ID)
		if !ok {
			return nil, nil, fmt.Errorf("%s is not an AI agent here", aid)
		}
		seed, err = asset.AssetSigningSeed(s.DataDir, a.SigningIndex)
	} else {
		return nil, nil, fmt.Errorf("this Identity Agent does not speak for %s", aid)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("the signing key of %s is unavailable: %w", aid, err)
	}
	ks, err := s.keySetFor(aid)
	if err != nil {
		return nil, nil, err
	}
	did, err := ks.DID()
	if err != nil {
		return nil, nil, err
	}
	if did.KelSig, err = login.SignString(string(did.SigningInput()), seed); err != nil {
		return nil, nil, err
	}
	return ks, did, nil
}

// refuse writes a refusal to the governance record and answers with it.
func (s *CoreServer) refuseMessage(w http.ResponseWriter, cc sandbox.CallerContext, kind, why string, status int) {
	// The event is named from the kind only when it is one; a sender does not
	// get to name events in the record.
	switch kind {
	case agentmessage.KindAsk, agentmessage.KindReply, agentmessage.KindReceipt, agentmessage.KindFailure:
	default:
		kind = "unrecognised"
	}
	log.Printf("[conversation] refused %s from %s: %s", kind, cc.CallerAID, why)
	if s.SandboxManager != nil {
		cc.Reason = clampWhy(why)
		s.SandboxManager.RecordGovernanceEvent(cc, "agent.message."+kind, "denied")
	}
	jsonError(w, why, status)
}

func (s *CoreServer) recordMessage(cc sandbox.CallerContext, e conversation.Entry) {
	if s.SandboxManager == nil {
		return
	}
	// The conversation is the piece of work every one of its messages is for,
	// so the log is read per conversation by asking for that.
	cc.WorkItem = e.Conversation
	cc.Reason = clampWhy(fmt.Sprintf("%s %s in %s, from %s to %s", e.Kind, e.MessageID, e.Conversation, e.From, e.To))
	s.SandboxManager.RecordGovernanceEvent(cc, "agent.message."+e.Kind, "ok")
	s.noteRecorded()
}

// ── A person speaks ──────────────────────────────────────────────────────────

func (s *CoreServer) handlePersonSays(w http.ResponseWriter, r *http.Request) {
	cc := sandbox.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r), Transport: "controller"}
	if g, ok := TheControllerThatAsked(r); ok {
		cc.CallerAID = g.ControllerAID
	}
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		s.refuseMessage(w, cc, agentmessage.KindAsk, "AI agent not found", http.StatusNotFound)
		return
	}
	person, proof, err := s.thePersonAsking(r)
	if err != nil {
		s.refuseMessage(w, cc, agentmessage.KindAsk, err.Error(), http.StatusForbidden)
		return
	}
	cc.CallerAID = agentmessage.Person(person.AID)
	var req agentmessage.PersonMessage
	if err := json.Unmarshal(proof.Request, &req); err != nil {
		s.refuseMessage(w, cc, agentmessage.KindAsk, "the message must be JSON", http.StatusBadRequest)
		return
	}
	// Filed under the conversation it names only if this person opened it: a
	// refusal must not land in somebody else's conversation.
	cc.WorkItem = s.partyConversation(req.Conversation, agentmessage.Person(person.AID))
	body := []byte(req.Body)
	switch {
	case len(body) == 0 || len(body) > agentmessage.MaxBody:
		s.refuseMessage(w, cc, agentmessage.KindAsk, "the message must have words, and not too many", http.StatusBadRequest)
		return
	case req.To != a.PairwiseAID:
		s.refuseMessage(w, cc, agentmessage.KindAsk, "the message is addressed to a different AI agent from the one in the address", http.StatusBadRequest)
		return
	case req.Conversation == "" && req.InReplyTo != "":
		s.refuseMessage(w, cc, agentmessage.KindAsk, "a message that opens a conversation answers nothing in it", http.StatusBadRequest)
		return
	}
	if !personMayUse(person, a) {
		s.refuseMessage(w, cc, agentmessage.KindAsk, "this person may not use "+a.DisplayName, http.StatusForbidden)
		return
	}
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		jsonError(w, "this Identity Agent has no identity yet", http.StatusServiceUnavailable)
		return
	}
	ks, _, err := s.messagingKeys(identity.AID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	opener := agentmessage.Person(person.AID)
	convID := req.Conversation
	var opening *conversation.Conversation
	if convID == "" {
		convID = conversation.NewID("c_")
		opening = &conversation.Conversation{OpenedBy: opener, FirstAgent: a.PairwiseAID}
	} else {
		c, err := store.Get(convID)
		switch {
		case err != nil:
			s.refuseMessage(w, cc, agentmessage.KindAsk, "no such conversation", http.StatusNotFound)
			return
		case c.OpenedBy != opener:
			s.refuseMessage(w, cc, agentmessage.KindAsk, "only the person who opened a conversation speaks in it", http.StatusForbidden)
			return
		case c.FirstAgent != a.PairwiseAID:
			s.refuseMessage(w, cc, agentmessage.KindAsk, "a conversation is with the AI agent it was opened with", http.StatusBadRequest)
			return
		}
		if req.InReplyTo != "" {
			prior, err := store.Message(req.InReplyTo)
			if err != nil || prior.Conversation != convID || prior.To != opener {
				s.refuseMessage(w, cc, agentmessage.KindAsk, "the message answered is not one addressed to this person in this conversation", http.StatusBadRequest)
				return
			}
		}
	}

	msgID := conversation.NewID("m_")
	e, err := store.Append(r.Context(), convID, opening, body, []string{a.PairwiseAID}, stillOpen(true),
		func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
			rec := agentmessage.Record{
				MessageID: msgID, Conversation: convID, Seq: seq, PrevHash: prev,
				IATime: time.Now().UTC().Format(time.RFC3339Nano), Kind: agentmessage.KindAsk,
				From: opener, To: a.PairwiseAID, InReplyTo: req.InReplyTo, BodyHash: agentmessage.HashBody(body),
				ControllerProof: proof, Person: &person, OpenedBy: opener,
			}
			env, err := agentmessage.Countersign(ks, rec)
			return env, rec, err
		})
	if err != nil {
		s.refuseAppend(w, cc, agentmessage.KindAsk, err)
		return
	}
	s.recordMessage(cc, e)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"conversation": convID, "message_id": e.MessageID, "seq": e.Seq, "hash": e.Hash,
	})
}

// errClosed and errNoTurnsLeft are the conversation's own limits, decided
// inside the record's transaction.
var (
	errClosed      = errors.New("this conversation has closed; open a new one")
	errNoTurnsLeft = errors.New("this conversation has used all its turns")
)

// stillOpen is the check every entry but a receipt passes: the conversation
// is open, and has turns left.
func stillOpen(counts bool) conversation.Check {
	return func(c conversation.Conversation) error {
		if c.Seq == 0 {
			return nil // being opened by this entry
		}
		if !c.Open(time.Now()) {
			return errClosed
		}
		if counts && c.Turns >= conversation.MaxTurns {
			return errNoTurnsLeft
		}
		return nil
	}
}

// refuseAppend answers an entry the record would not take, recording the
// refusal when it is one of the conversation's rules rather than a fault.
func (s *CoreServer) refuseAppend(w http.ResponseWriter, cc sandbox.CallerContext, kind string, err error) {
	switch {
	case errors.Is(err, errClosed), errors.Is(err, errNoTurnsLeft), errors.Is(err, conversation.ErrAlreadyAnswered):
		s.refuseMessage(w, cc, kind, err.Error(), http.StatusConflict)
	default:
		jsonError(w, err.Error(), http.StatusInternalServerError)
	}
}

// entryView is an entry as a reader sees it: with its words, checked against
// the digest the record holds.
type entryView struct {
	conversation.Entry
	Body string `json:"body"`
	// BodyVerified is false when the words kept do not match the record — they
	// are shown anyway, marked, rather than hidden.
	BodyVerified bool `json:"body_verified"`
	// Record is the countersigned entry, readable.
	Record agentmessage.Record `json:"record"`
}

func (s *CoreServer) viewEntries(ctx context.Context, store *conversation.Store, entries []conversation.Entry) []entryView {
	out := make([]entryView, 0, len(entries))
	for _, e := range entries {
		v := entryView{Entry: e}
		if body, err := store.Contents().Get(ctx, e.ContentRef); err == nil {
			v.Body = string(body)
			v.BodyVerified = agentmessage.HashBody(body) == e.BodyHash
		}
		v.Record, _ = agentmessage.Read(e.Envelope)
		out = append(out, v)
	}
	return out
}

func (s *CoreServer) handleReadConversation(w http.ResponseWriter, r *http.Request) {
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	c, err := store.Get(chi.URLParam(r, "cid"))
	if err != nil {
		jsonError(w, "no such conversation", http.StatusNotFound)
		return
	}
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	// Subscribed before reading, so an entry added between the read and the
	// wait still ends the wait.
	news, done := store.Subscribe(c.ID)
	defer done()
	entries, err := store.Entries(c.ID, after)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Waiting for news: return the moment something is added, or after the
	// wait, whichever comes first.
	if len(entries) == 0 && r.URL.Query().Get("wait") != "" {
		select {
		case <-news:
		case <-time.After(conversationWait):
		case <-r.Context().Done():
		}
		if c, err = store.Get(c.ID); err == nil {
			entries, _ = store.Entries(c.ID, after)
		}
	}
	// Reading the record is itself recorded — once per opening of it, not on
	// every wait for news.
	if after == 0 && s.SandboxManager != nil {
		reader := sandbox.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r), Transport: "controller",
			Reason: "read conversation " + c.ID}
		if g, ok := TheControllerThatAsked(r); ok {
			reader.CallerAID = g.ControllerAID
		} else {
			reader.CallerAID = "owner"
		}
		s.SandboxManager.RecordGovernanceEvent(reader, "agent.conversation.read", "ok")
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"conversation": c, "open": c.Open(time.Now()), "entries": s.viewEntries(r.Context(), store, entries),
		"kept": store.Contents().Kind(),
	})
}

func (s *CoreServer) handleListAgentConversations(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	list, err := store.List(a.PairwiseAID, 50)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"agent_aid": a.PairwiseAID, "conversations": list})
}

// ── A body speaks ────────────────────────────────────────────────────────────

// bodySays is what a body sends: its signed statement and the words.
type bodySays struct {
	Statement agentmessage.Statement `json:"statement"`
	Signature string                 `json:"signature"`
	Body      string                 `json:"body"`
}

// theBodyAsking is the AI agent a sealed, body-signed request comes from.
// Messages between AI agents are only ever taken sealed: their words would
// otherwise be readable wherever TLS ends on the way here.
func (s *CoreServer) theBodyAsking(r *http.Request) (sandbox.CallerContext, agentbody.Binding, error) {
	host := r.Header.Get(agentbody.HeaderHost)
	if host == "" || s.sealedSender(r) != host {
		return sandbox.CallerContext{}, agentbody.Binding{}, errors.New("a body sends and collects messages sealed to this " +
			"Identity Agent, signed by its own key")
	}
	cc := s.resolveCaller(r)
	if cc.Transport != "body" || cc.BodyHost != host {
		return cc, agentbody.Binding{}, errors.New("this machine is not the live body of an AI agent here")
	}
	b, ok := s.bodies().ActiveByHost(host)
	if !ok {
		return cc, agentbody.Binding{}, errors.New("this machine is not the live body of an AI agent here")
	}
	return cc, b, nil
}

// refuseBody answers a request that is not from a live body, recording the
// refusal under whatever the request claimed to be.
func (s *CoreServer) refuseBody(w http.ResponseWriter, r *http.Request, cc sandbox.CallerContext, err error) {
	if cc.CallerAID == "" {
		cc = sandbox.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r), Transport: "body",
			CallerAID: "body:" + clampWhy(r.Header.Get(agentbody.HeaderHost))}
	}
	s.refuseMessage(w, cc, "", err.Error(), http.StatusForbidden)
}

func (s *CoreServer) handleBodySays(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		s.refuseBody(w, r, cc, err)
		return
	}
	var req bodySays
	if err := json.NewDecoder(io.LimitReader(r.Body, agentmessage.MaxBody+16<<10)).Decode(&req); err != nil {
		s.refuseMessage(w, cc, "", "the message is unreadable", http.StatusBadRequest)
		return
	}
	st := req.Statement
	body := []byte(req.Body)
	kind := st.Kind
	refuse := func(why string, status int) { s.refuseMessage(w, cc, kind, why, status) }

	// What the body signed.
	switch {
	case st.Check() != nil:
		refuse(st.Check().Error(), http.StatusBadRequest)
		return
	case st.Host != b.Host || st.From != b.Agent || st.BodyCredential != b.CredentialSAID:
		refuse("the statement does not name this body, its AI agent and its credential", http.StatusForbidden)
		return
	case len(body) > agentmessage.MaxBody || st.BodyHash != agentmessage.HashBody(body):
		refuse("the statement's digest is not the digest of the words", http.StatusBadRequest)
		return
	}
	if err := agentmessage.Verify(st, b.Verkey, req.Signature); err != nil {
		refuse("the statement is not signed by this body: "+err.Error(), http.StatusForbidden)
		return
	}
	// Signed by this body: from here a refusal is filed under the conversation
	// it names, if its AI agent is in it. Not before, and not otherwise, or a
	// caller could put rows into a conversation it is not part of.
	cc.WorkItem = s.partyConversation(st.Conversation, st.From)
	if when, _ := time.Parse(time.RFC3339, st.HostTime); time.Since(when) > agentbody.RequestWindow || time.Until(when) > agentbody.RequestWindow {
		refuse("the statement's time is outside the window this Identity Agent accepts", http.StatusForbidden)
		return
	}
	if rememberSignature(req.Signature, time.Now()) {
		refuse("this statement was already sent", http.StatusConflict)
		return
	}

	// Where it stands in the conversation.
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	c, err := store.Get(st.Conversation)
	if err != nil {
		refuse("no such conversation; a body speaks only inside one it was brought into", http.StatusNotFound)
		return
	}
	if !store.IsParty(c.ID, st.From) {
		refuse("this AI agent has not been brought into that conversation", http.StatusForbidden)
		return
	}
	prompt, err := store.Message(st.InReplyTo)
	if err != nil || prompt.Conversation != c.ID || !store.WasQueuedFor(prompt.MessageID, st.From) {
		refuse("the message this acts on was not given to this AI agent in this conversation", http.StatusForbidden)
		return
	}

	depth := prompt.Depth
	var deliverTo []string
	check := stillOpen(true)
	switch kind {
	case agentmessage.KindReceipt:
		// A receipt is for a message still waiting for this body, and goes to
		// its sender. It neither counts as a turn nor keeps the conversation
		// open, so an old message cannot be used to reopen one.
		if st.To != prompt.From {
			refuse("a receipt goes to the sender of the message received", http.StatusBadRequest)
			return
		}
		if !store.IsWaiting(prompt.MessageID, st.From) {
			refuse("that message is not waiting for this body", http.StatusConflict)
			return
		}
		check = nil
	case agentmessage.KindReply, agentmessage.KindFailure:
		if prompt.Kind != agentmessage.KindAsk || prompt.To != st.From || st.To != prompt.From {
			refuse("a reply goes only to the sender of an ask that was addressed to the one replying", http.StatusForbidden)
			return
		}
		if store.Answered(prompt.MessageID, st.From) {
			refuse(conversation.ErrAlreadyAnswered.Error(), http.StatusConflict)
			return
		}
		// An answer counts as a turn, but is never refused for want of one:
		// an ask that took the last turn must still be answerable, or it would
		// wait unanswered until the conversation closed.
		check = stillOpen(false)
		// An answer travels back up the chain, to the asker's depth.
		if depth = prompt.Depth - 1; depth < 0 {
			depth = 0
		}
		if _, person := agentmessage.IsPerson(st.To); !person {
			deliverTo = []string{st.To}
		}
	case agentmessage.KindAsk:
		depth = prompt.Depth + 1
		target := s.findAgentAssetByAID(st.To)
		switch {
		case target == nil:
			refuse("the AI agent asked is not one this Identity Agent holds", http.StatusNotFound)
			return
		case st.To == st.From:
			refuse("an AI agent does not ask itself", http.StatusBadRequest)
			return
		case depth > conversation.MaxDepth:
			refuse(fmt.Sprintf("a chain of asks may go %d deep, and this would be %d", conversation.MaxDepth, depth), http.StatusConflict)
			return
		}
		if !hasScope(cc.Scopes, capabilityMessageAgent) {
			refuse("this AI agent's grant does not let it message other AI agents", http.StatusForbidden)
			return
		}
		args, _ := json.Marshal(map[string]string{"to": st.To, "text": req.Body})
		if err := sandbox.CheckResourceConstraints(cc.ResourceConstraints, capabilityMessageAgent, args); err != nil {
			refuse("this AI agent's grant does not let it message that AI agent: "+err.Error(), http.StatusForbidden)
			return
		}
		// The opener's reach, as the opener stands now.
		entries, _ := store.Entries(c.ID, 0)
		opener, _ := personRefFor(entries, c.OpenedBy)
		if !s.personStillStands(opener) {
			refuse("the person who opened this conversation is no longer someone the organisation can prove", http.StatusForbidden)
			return
		}
		ta, _ := s.aiAgentAsset(target.ID)
		if !personMayUse(opener, ta) {
			refuse("the person who opened this conversation may not reach "+ta.DisplayName, http.StatusForbidden)
			return
		}
		deliverTo = []string{st.To}
	}

	ks, _, err := s.messagingKeys(st.From)
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	msgID := conversation.NewID("m_")
	e, err := store.Append(r.Context(), c.ID, nil, body, deliverTo, check,
		func(seq int, prev string) (*didcomm.Envelope, agentmessage.Record, error) {
			rec := agentmessage.Record{
				MessageID: msgID, Conversation: c.ID, Seq: seq, PrevHash: prev,
				IATime: time.Now().UTC().Format(time.RFC3339Nano), Kind: kind,
				From: st.From, To: st.To, InReplyTo: st.InReplyTo, BodyHash: st.BodyHash, Depth: depth,
				Statement: &st, HostSignature: req.Signature, HostVerkey: b.Verkey,
				GrantSAID: cc.GrantSAID, BodyGrade: b.Grade, BodyCredential: b.CredentialSAID,
				OpenedBy: c.OpenedBy,
			}
			env, err := agentmessage.Countersign(ks, rec)
			return env, rec, err
		})
	if err != nil {
		s.refuseAppend(w, cc, kind, err)
		return
	}
	if kind == agentmessage.KindReceipt {
		if _, err := store.Delivered(prompt.MessageID, st.From, e.MessageID); err != nil {
			log.Printf("[conversation] receipt %s recorded, but %s not marked delivered: %v", e.MessageID, prompt.MessageID, err)
		}
	}
	s.recordMessage(cc, e)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"conversation": c.ID, "message_id": e.MessageID, "seq": e.Seq, "hash": e.Hash,
	})
}

// delivery is one message as a body collects it: the countersigned entry,
// the words, and the countersigner's public keys, which the body checks
// against that identity's key log before believing any of it.
type delivery struct {
	Entry       conversation.Entry `json:"entry"`
	Body        string             `json:"body"`
	Countersign *didcomm.DID       `json:"countersigner"`
	// FromName is the sender's name, for the brain to read. Not signed: the
	// record names the sender by identifier.
	FromName string `json:"from_name"`
}

func (s *CoreServer) handleBodyInbox(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		s.refuseBody(w, r, cc, err)
		return
	}
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Subscribed before reading, so a message queued between the read and the
	// wait still ends the wait.
	news, done := store.Subscribe(b.Agent)
	defer done()
	out, err := s.deliveriesFor(r.Context(), store, b.Agent)
	if err == nil && len(out) == 0 && r.URL.Query().Get("wait") != "" {
		select {
		case <-news:
		case <-time.After(conversationWait):
		case <-r.Context().Done():
		}
		out, err = s.deliveriesFor(r.Context(), store, b.Agent)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Each message handed to the body is a delivery, recorded the first time
	// it is handed to this machine. A message still waiting is handed out again
	// on the next collection; the receipt, not the delivery, is what says the
	// body took it.
	for _, d := range out {
		dc := cc
		dc.WorkItem = d.Entry.Conversation
		dc.Reason = clampWhy(fmt.Sprintf("%s %s in %s, to %s at %s", d.Entry.Kind, d.Entry.MessageID,
			d.Entry.Conversation, b.Agent, b.Host))
		s.recordDeliveryOnce(dc, d.Entry.MessageID, b.Host)
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"messages": out})
}

// deliveriesFor is what is waiting for an AI agent, ready to hand to its body.
// An entry whose words are missing or altered is not handed out — the body
// could not check it — and is logged, so it is seen rather than retried
// silently.
func (s *CoreServer) deliveriesFor(ctx context.Context, store *conversation.Store, agent string) ([]delivery, error) {
	// More than a body handles at once, so a few entries that cannot be
	// handed out do not hide the rest.
	waiting, err := store.Waiting(agent, 50)
	if err != nil {
		return nil, err
	}
	identity, _ := s.DataStore.GetIdentity()
	out := []delivery{}
	for _, e := range waiting {
		body, err := store.Contents().Get(ctx, e.ContentRef)
		if err != nil || agentmessage.HashBody(body) != e.BodyHash {
			log.Printf("[conversation] the words of %s are missing or altered; not delivered", e.MessageID)
			continue
		}
		signer := e.From
		name := e.From
		if _, person := agentmessage.IsPerson(e.From); person && identity != nil {
			signer = identity.AID
			if rec, err := agentmessage.Read(e.Envelope); err == nil && rec.Person != nil && rec.Person.Name != "" {
				name = rec.Person.Name
			}
		} else if ref := s.findAgentAssetByAID(e.From); ref != nil {
			if a, ok := s.aiAgentAsset(ref.ID); ok {
				name = a.DisplayName
			}
		}
		_, did, err := s.messagingKeys(signer)
		if err != nil {
			log.Printf("[conversation] %s cannot be delivered: %v", e.MessageID, err)
			continue
		}
		out = append(out, delivery{Entry: e, Body: string(body), Countersign: did, FromName: name})
	}
	return out, nil
}

// handleBodyConversationHistory gives a body what has been said in a
// conversation its AI agent is in — and only one it is in.
func (s *CoreServer) handleBodyConversationHistory(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		s.refuseBody(w, r, cc, err)
		return
	}
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	cid := chi.URLParam(r, "cid")
	if !store.IsParty(cid, b.Agent) {
		s.refuseMessage(w, cc, "", "this AI agent is not in that conversation", http.StatusForbidden)
		return
	}
	entries, err := store.Entries(cid, 0)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.SandboxManager != nil {
		reader := cc
		reader.Reason = "read conversation " + cid
		s.SandboxManager.RecordGovernanceEvent(reader, "agent.conversation.read", "ok")
	}
	type said struct {
		Seq  int    `json:"seq"`
		Kind string `json:"kind"`
		From string `json:"from"`
		To   string `json:"to"`
		Body string `json:"body"`
	}
	out := []said{}
	for _, v := range s.viewEntries(r.Context(), store, entries) {
		if v.Kind == agentmessage.KindReceipt {
			continue
		}
		out = append(out, said{Seq: v.Seq, Kind: v.Kind, From: s.partyName(v.From, v.Record), To: s.partyName(v.To, v.Record), Body: v.Body})
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"conversation": cid, "said": out})
}

// partyName is a party as a reader knows it: a person by name, an AI agent by
// its name here.
func (s *CoreServer) partyName(party string, rec agentmessage.Record) string {
	if _, person := agentmessage.IsPerson(party); person {
		if rec.Person != nil && rec.Person.Name != "" {
			return rec.Person.Name
		}
		return "a person"
	}
	if ref := s.findAgentAssetByAID(party); ref != nil {
		if a, ok := s.aiAgentAsset(ref.ID); ok {
			return a.DisplayName
		}
	}
	return party
}

// handleBodyListAgents tells a body which AI agents its AI agent may ask, by
// name, so its brain can address them.
func (s *CoreServer) handleBodyListAgents(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		s.refuseBody(w, r, cc, err)
		return
	}
	type agentView struct {
		AID  string `json:"aid"`
		Name string `json:"name"`
		Role string `json:"role,omitempty"`
	}
	out := []agentView{}
	if hasScope(cc.Scopes, capabilityMessageAgent) && s.assetHandler != nil {
		for _, a := range s.assetHandler.Store.ListAssets() {
			if a.AssetType != "ai_agent" || a.PairwiseAID == b.Agent || a.PairwiseAID == "" {
				continue
			}
			args, _ := json.Marshal(map[string]string{"to": a.PairwiseAID, "text": ""})
			if sandbox.CheckResourceConstraints(cc.ResourceConstraints, capabilityMessageAgent, args) != nil {
				continue
			}
			v := agentView{AID: a.PairwiseAID, Name: a.DisplayName}
			if a.AgentConfig != nil {
				v.Role = a.AgentConfig.Role
			}
			out = append(out, v)
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"agents": out})
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// sealedSender is the identifier whose envelope carried this request, when the
// sealed transport replayed it — and empty for anything that arrived directly,
// whatever headers it carries.
func (s *CoreServer) sealedSender(r *http.Request) string {
	if r.RemoteAddr != sealedRemoteAddr {
		return ""
	}
	return r.Header.Get(headerSealedFrom)
}

// handleConversationRecordSetting says where the conversation record's words
// are kept, and where they could be. The proof — every entry's signatures and
// hashes — always stays on this Identity Agent; only the words can move.
func (s *CoreServer) handleConversationRecordSetting(w http.ResponseWriter, r *http.Request) {
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"kept": store.Contents().Kind(),
		"choices": []map[string]any{
			{"kind": conversation.KindOnThisIdentityAgent, "available": true},
			// Another location receives the words only encrypted here first,
			// addressed by the ciphertext's digest. Not built yet.
			{"kind": "elsewhere", "available": false},
		},
	})
}
