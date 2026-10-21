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
	"strings"
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
	r.Get("/mcp/conversation-record", s.handleConversationRecordSetting)
	// A body, signed by its machine key and sealed to this Identity Agent.
	r.Post("/agent-host/messages", s.handleBodySays)
	r.Get("/agent-host/inbox", s.handleBodyInbox)
	r.Get("/agent-host/agents", s.handleBodyListAgents)
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
	person, err := s.signerOf(grant)
	if err != nil {
		return agentmessage.PersonRef{}, nil, err
	}
	signed, _, err := s.theStringThisMachineSigned(r, grant.ControllerAID,
		strings.TrimSpace(r.Header.Get(headerControllerTimestamp)), time.Now().UTC())
	if err != nil {
		return agentmessage.PersonRef{}, nil, err
	}
	body, err := readSignedBody(r)
	if err != nil {
		return agentmessage.PersonRef{}, nil, err
	}
	return person, &agentmessage.ControllerProof{
		Controller: grant.ControllerAID, PublicKey: grant.PublicKey, SignedString: signed,
		Signature: strings.TrimSpace(r.Header.Get(headerControllerSig)), Request: body,
	}, nil
}

// signerOf is the signer a controller belongs to: the one its grant names, or
// the organisation's only signer.
func (s *CoreServer) signerOf(g ControllerGrant) (agentmessage.PersonRef, error) {
	if s.assetHandler == nil {
		return agentmessage.PersonRef{}, errNoProvablePerson
	}
	var signers []asset.Employee
	for _, e := range s.assetHandler.Store.ListEmployees() {
		if e.IsSigner && e.Status == "active" {
			signers = append(signers, e)
		}
	}
	pick := func(e asset.Employee) agentmessage.PersonRef {
		return agentmessage.PersonRef{AID: e.PairwiseAID, Standing: "signer", Credential: e.VouchSig, Name: e.Name}
	}
	if g.Signer != "" {
		for _, e := range signers {
			if e.PairwiseAID == g.Signer {
				return pick(e), nil
			}
		}
		return agentmessage.PersonRef{}, fmt.Errorf("the signer this app belongs to is no longer an active signer of the organisation")
	}
	switch len(signers) {
	case 0:
		return agentmessage.PersonRef{}, fmt.Errorf("this organisation has no signer on its roster, so nobody it can " +
			"prove is asking. A signer joins by founding the organisation from their Grape ID")
	case 1:
		return pick(signers[0]), nil
	}
	return agentmessage.PersonRef{}, fmt.Errorf("this organisation has more than one signer, and this app was not " +
		"paired to one of them. Pair it again, naming its signer")
}

// personMayUse reports whether a person may use an AI agent. A signer may use
// every AI agent of the organisation they sign for.
func personMayUse(p agentmessage.PersonRef, _ asset.Asset) bool {
	return p.Standing == "signer"
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
	cc.Reason = clampWhy(fmt.Sprintf("%s %s in %s, from %s to %s", e.Kind, e.MessageID, e.Conversation, e.From, e.To))
	s.SandboxManager.RecordGovernanceEvent(cc, "agent.message."+e.Kind, "ok")
}

// ── A person speaks ──────────────────────────────────────────────────────────

func (s *CoreServer) handlePersonSays(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	cc := sandbox.CallerContext{Remote: true, CorrelationID: requestCorrelationID(r), Transport: "controller"}
	if g, ok := TheControllerThatAsked(r); ok {
		cc.CallerAID = g.ControllerAID
	}
	person, proof, err := s.thePersonAsking(r)
	if err != nil {
		s.refuseMessage(w, cc, agentmessage.KindAsk, err.Error(), http.StatusForbidden)
		return
	}
	cc.CallerAID = agentmessage.Person(person.AID)
	var req agentmessage.PersonMessage
	if err := json.Unmarshal(proof.Request, &req); err != nil {
		jsonError(w, "the message must be JSON", http.StatusBadRequest)
		return
	}
	body := []byte(req.Body)
	switch {
	case len(body) == 0 || len(body) > agentmessage.MaxBody:
		jsonError(w, "the message must have words, and not too many", http.StatusBadRequest)
		return
	case req.To != a.PairwiseAID:
		jsonError(w, "the message is addressed to a different AI agent from the one in the address", http.StatusBadRequest)
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
			jsonError(w, "no such conversation", http.StatusNotFound)
			return
		case c.OpenedBy != opener:
			s.refuseMessage(w, cc, agentmessage.KindAsk, "only the person who opened a conversation speaks in it", http.StatusForbidden)
			return
		case !c.Open(time.Now()):
			s.refuseMessage(w, cc, agentmessage.KindAsk, "this conversation has closed; open a new one", http.StatusConflict)
			return
		case c.Turns >= conversation.MaxTurns:
			s.refuseMessage(w, cc, agentmessage.KindAsk, "this conversation has used all its turns", http.StatusConflict)
			return
		}
		if req.InReplyTo != "" {
			prior, err := store.Message(req.InReplyTo)
			if err != nil || prior.Conversation != convID || prior.To != opener {
				jsonError(w, "the message answered is not one addressed to this person in this conversation", http.StatusBadRequest)
				return
			}
		}
	}

	msgID := conversation.NewID("m_")
	e, err := store.Append(r.Context(), convID, opening, body, []string{a.PairwiseAID},
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
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.recordMessage(cc, e)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"conversation": convID, "message_id": e.MessageID, "seq": e.Seq, "hash": e.Hash,
	})
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
	entries, err := store.Entries(c.ID, after)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Waiting for news: return the moment something is added, or after the
	// wait, whichever comes first.
	if len(entries) == 0 && r.URL.Query().Get("wait") != "" {
		ctx, cancel := context.WithTimeout(r.Context(), conversationWait)
		store.Wait(ctx, c.ID)
		cancel()
		if c, err = store.Get(c.ID); err == nil {
			entries, _ = store.Entries(c.ID, after)
		}
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

func (s *CoreServer) handleBodySays(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	var req bodySays
	if err := json.NewDecoder(io.LimitReader(r.Body, agentmessage.MaxBody+16<<10)).Decode(&req); err != nil {
		jsonError(w, "the message is unreadable", http.StatusBadRequest)
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
	if kind != agentmessage.KindReceipt && !c.Open(time.Now()) {
		refuse("this conversation has closed", http.StatusConflict)
		return
	}

	depth := prompt.Depth
	var deliverTo []string
	switch kind {
	case agentmessage.KindReceipt:
		if st.To != prompt.From {
			refuse("a receipt goes to the sender of the message received", http.StatusBadRequest)
			return
		}
	case agentmessage.KindReply, agentmessage.KindFailure:
		if prompt.Kind != agentmessage.KindAsk || prompt.To != st.From || st.To != prompt.From {
			refuse("a reply goes only to the sender of an ask that was addressed to the one replying", http.StatusForbidden)
			return
		}
		// An answer travels back up the chain, to the asker's depth.
		if depth = prompt.Depth - 1; depth < 0 {
			depth = 0
		}
		if kind == agentmessage.KindReply && c.Turns >= conversation.MaxTurns {
			refuse("this conversation has used all its turns", http.StatusConflict)
			return
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
		case c.Turns >= conversation.MaxTurns:
			refuse("this conversation has used all its turns", http.StatusConflict)
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
		entries, _ := store.Entries(c.ID, 0)
		opener, _ := personRefFor(entries, c.OpenedBy)
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
	e, err := store.Append(r.Context(), c.ID, nil, body, deliverTo,
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
		jsonError(w, err.Error(), http.StatusInternalServerError)
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
	_, b, err := s.theBodyAsking(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	store, err := s.conversations()
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	waiting, err := store.Waiting(b.Agent, 10)
	if err == nil && len(waiting) == 0 && r.URL.Query().Get("wait") != "" {
		ctx, cancel := context.WithTimeout(r.Context(), conversationWait)
		store.Wait(ctx, b.Agent)
		cancel()
		waiting, err = store.Waiting(b.Agent, 10)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	identity, _ := s.DataStore.GetIdentity()
	out := []delivery{}
	for _, e := range waiting {
		body, err := store.Contents().Get(r.Context(), e.ContentRef)
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
	writeJSONStatus(w, http.StatusOK, map[string]any{"messages": out})
}

// handleBodyListAgents tells a body which AI agents its AI agent may ask, by
// name, so its brain can address them.
func (s *CoreServer) handleBodyListAgents(w http.ResponseWriter, r *http.Request) {
	cc, b, err := s.theBodyAsking(r)
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
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
