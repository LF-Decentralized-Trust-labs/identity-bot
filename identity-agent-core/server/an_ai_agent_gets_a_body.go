package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/asset"
	"identity-agent-core/didcomm"
	"identity-agent-core/sandbox"
	"identity-agent-core/schemas"
	"identity-agent-core/screenview"

	"github.com/go-chi/chi/v5"
)

// An AI agent gets a body: a machine whose key speaks as the AI agent.
//
// The ceremony is agentbody's. This file is the Identity Agent's half of it:
//
//   - the owner (or an authorised controller) asks for an enrolment string for
//     one AI agent;
//   - the machine enrols with it, signed by its own key K, and waits;
//   - the owner sees six words derived from K, compares them with the ones on
//     the machine, and approves or rejects;
//   - approving issues the AI agent body credential, and from then on requests
//     the machine signs with K are taken as the AI agent's, at the body's grade.
//
// Nothing here gives the machine anything of the AI agent's. The AI agent's own
// key never leaves this Identity Agent, and its grant still decides what it may
// do. A body only decides WHERE a request may come from, and how strongly that
// is proven.

var bodyStoreOnce sync.Map

func (s *CoreServer) bodies() *agentbody.Store {
	// Keyed by the absolute directory, so one directory named two ways is one
	// store with one lock, not two writing over each other.
	dir, err := filepath.Abs(s.DataDir)
	if err != nil {
		dir = s.DataDir
	}
	v, _ := bodyStoreOnce.LoadOrStore(dir, agentbody.NewStore(dir))
	return v.(*agentbody.Store)
}

// recordBodyEvent writes what happened to a body into the signed record, as
// the AI agent, naming the body and its grade — so who approved which machine,
// and when, is provable rather than only logged.
func (s *CoreServer) recordBodyEvent(a asset.Asset, b agentbody.Binding, event, status, why string) {
	log.Printf("[body] %s: %s for AI agent %s (%s, words %q): %s", event, b.Host, a.PairwiseAID, b.Grade, strings.Join(b.Words, " "), why)
	if s.SandboxManager == nil {
		return
	}
	s.SandboxManager.RecordGovernanceEvent(sandbox.CallerContext{
		CallerAID: a.PairwiseAID, DelegationChain: []string{a.PairwiseAID, a.DelegatorAID},
		Transport: "body", BodyHost: b.Host, BodyGrade: b.Grade, BodyCredential: b.CredentialSAID,
		Reason: why,
	}, "agent.body."+event, status)
}

func (s *CoreServer) mountBodyRoutes(r chi.Router) {
	r.Post("/mcp/agents/{id}/body-enrolment", s.handleCreateBodyEnrolment)
	r.Get("/mcp/agents/{id}/bodies", s.handleListBodies)
	r.Post("/mcp/agents/{id}/bodies/{bid}/approve", s.handleApproveBody)
	r.Post("/mcp/agents/{id}/bodies/{bid}/reject", s.handleRejectBody)
	r.Delete("/mcp/agents/{id}/bodies/{bid}", s.handleRevokeBody)
	// The machine's side. Public: the machine has no standing until a person
	// approves it, and what it sends is checked against a one-time secret and a
	// signature by its own key.
	r.Post("/agent-host/enrol", s.handleBodyEnrol)
	r.Get("/agent-host/binding", s.handleBodyStatus)
}

// aiAgentAsset finds an AI agent by its asset id.
func (s *CoreServer) aiAgentAsset(id string) (asset.Asset, bool) {
	if s.assetHandler == nil {
		return asset.Asset{}, false
	}
	a, ok := s.assetHandler.Store.GetAsset(id)
	if !ok || a.AssetType != "ai_agent" {
		return asset.Asset{}, false
	}
	return a, true
}

// enrolmentFor issues a fresh one-time secret for an AI agent and renders the
// string the machine is given. It names this Identity Agent and the newest event
// in its key log, so the machine accepts only a log that is this identity's and
// contains that event.
func (s *CoreServer) enrolmentFor(r *http.Request, a asset.Asset) (string, time.Time, error) {
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", time.Time{}, fmt.Errorf("this Identity Agent has no identity yet")
	}
	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil || len(events) == 0 {
		return "", time.Time{}, fmt.Errorf("this Identity Agent's key log is unavailable")
	}
	last := events[len(events)-1]
	var ev struct {
		D string `json:"d"`
	}
	if json.Unmarshal([]byte(last.EventJSON), &ev) != nil || ev.D == "" {
		return "", time.Time{}, fmt.Errorf("this Identity Agent's latest key event is unreadable")
	}
	secret, expires, err := s.bodies().Invite(a.ID, time.Now())
	if err != nil {
		return "", time.Time{}, err
	}
	str, err := agentbody.Enrolment{
		URL: strings.TrimRight(s.getPublicURL(r), "/"), IdentityAgent: identity.AID,
		KeyStateSN: last.SequenceNumber, KeyStateSAID: ev.D,
		Agent: a.PairwiseAID, AgentName: a.DisplayName, Secret: secret, Expires: expires,
	}.Encode()
	return str, expires, err
}

func (s *CoreServer) handleCreateBodyEnrolment(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	if s.refuseIfRevoked(w, a.ID) {
		return
	}
	str, expires, err := s.enrolmentFor(r, a)
	if err != nil {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"enrolment":  str,
		"expires_at": expires,
		"note": "run `agent-host enrol <this string>` on the machine within 15 minutes, " +
			"then compare the six words it shows with the ones shown here before approving",
	})
}

// bodyView is a binding as the owner sees it.
type bodyView struct {
	agentbody.Binding
	// WordsLine is the six words as one line, for showing beside the machine's.
	WordsLine string `json:"words_line"`
	// Screen is the machine's screen, when it has one that can be watched now.
	Screen *screenOf `json:"screen,omitempty"`
	// ScreenNotAvailableYet says the machine is a Mac or a Windows computer,
	// whose screen cannot be watched yet.
	ScreenNotAvailableYet bool `json:"screen_not_available_yet,omitempty"`
}

func (s *CoreServer) handleListBodies(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	out := []bodyView{}
	for _, b := range s.bodies().ForAgent(a.ID) {
		sc := s.screenOfBody(b)
		out = append(out, bodyView{Binding: b, WordsLine: strings.Join(b.Words, " "), Screen: sc,
			ScreenNotAvailableYet: sc == nil && screenNotYet(b)})
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"agent_aid": a.PairwiseAID, "bodies": out})
}

// whoDecided names who approved or rejected a body, for the record.
func whoDecided(r *http.Request) string {
	if g, ok := TheControllerThatAsked(r); ok {
		return g.ControllerAID
	}
	return "owner"
}

// handleApproveBody is the person saying "the words match". It issues the body
// credential first; only when that succeeds is the binding live, so there is
// never a live body with nothing a verifier could check.
func (s *CoreServer) handleApproveBody(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	unlock := lockAgentGrant(a.ID)
	defer unlock()
	if s.refuseIfRevoked(w, a.ID) {
		return
	}
	b, ok := s.bodies().Get(chi.URLParam(r, "bid"))
	if !ok || b.AgentAssetID != a.ID {
		jsonError(w, "no such body for this AI agent", http.StatusNotFound)
		return
	}
	if b.State != agentbody.StatePending {
		jsonError(w, "this body is "+b.State+", not waiting for approval", http.StatusConflict)
		return
	}
	if s.KeriDriver == nil {
		jsonError(w, "a body is bound by a credential, and this build has no KERI engine to issue one",
			http.StatusServiceUnavailable)
		return
	}
	claims := map[string]interface{}{
		"name": a.DisplayName, "host": b.Host, "verkey": b.Verkey,
		"keys_digest": b.KeysDigest(), "grade": b.Grade, "claimed_grade": b.ClaimedGrade,
		"platform": b.Platform, "placement": b.Placement,
	}
	by, release, err := s.authorityOf(r)
	if err != nil {
		jsonError(w, "who approved this machine: "+err.Error(), http.StatusForbidden)
		return
	}
	defer release()
	by.About = b.ID
	credSAID, err := s.issueAssetCredential(schemas.AIAgentBody, a.PairwiseAID, a.DelegatorAID, claims, "", by)
	if err != nil {
		jsonError(w, "the body credential could not be issued, so the body was not approved: "+err.Error(),
			http.StatusBadGateway)
		return
	}
	decided, err := s.bodies().Decide(b.ID, a.ID, agentbody.StateActive, whoDecided(r), credSAID, time.Now())
	if err != nil {
		// The credential was issued and the binding did not become live — it
		// expired, or the record could not be written. Withdraw the credential,
		// or the registry would show a live body the owner never got.
		if rec, _ := s.DataStore.GetCredential(credSAID); rec != nil {
			if _, _, rerr := s.withdrawCredential(rec); rerr != nil {
				log.Printf("[body] credential %s issued for a body that did not become live, and its revocation failed: %v", credSAID, rerr)
				_ = s.DataStore.UpdateCredentialStatus(credSAID, "revoked")
			}
		}
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	s.recordBodyEvent(a, decided, "approved", "ok", "approved by "+decided.DecidedBy)
	s.machines().Approved(decided.ID, time.Now())
	writeJSONStatus(w, http.StatusOK, bodyView{Binding: decided, WordsLine: strings.Join(decided.Words, " ")})
}

// handleRejectBody is the person saying "the words do not match". The secret
// was already spent, so whoever used it gets nothing more; a fresh string is
// returned so the real machine can try again.
func (s *CoreServer) handleRejectBody(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	// Under the same lock as approving, so an approval and a rejection of one
	// request cannot both proceed.
	unlock := lockAgentGrant(a.ID)
	defer unlock()
	decided, err := s.bodies().Decide(chi.URLParam(r, "bid"), a.ID, agentbody.StateRejected, whoDecided(r), "", time.Now())
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	s.recordBodyEvent(a, decided, "rejected", "denied", "the words did not match, according to "+decided.DecidedBy)
	// A machine a provider made whose words did not match is destroyed.
	s.machineGone(decided)
	str, expires, err := s.enrolmentFor(r, a)
	if err != nil {
		jsonError(w, "rejected, but a fresh enrolment string could not be made: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"rejected": decided, "enrolment": str, "expires_at": expires})
}

// handleRevokeBody ends a body: the machine can no longer speak as the AI agent.
// The revocation is written to the registry, so anybody checking the body
// credential sees it.
func (s *CoreServer) handleRevokeBody(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	unlock := lockAgentGrant(a.ID)
	defer unlock()
	b, ok := s.bodies().Get(chi.URLParam(r, "bid"))
	if !ok || b.AgentAssetID != a.ID || (b.State != agentbody.StateActive && b.State != agentbody.StateRevoked) {
		jsonError(w, "no body by that id for this AI agent", http.StatusNotFound)
		return
	}
	// The binding is ended first, so the machine stops being admitted at once.
	// Writing the revocation to the registry follows; if that fails, the answer
	// says so, and asking again retries it.
	if b.State == agentbody.StateActive {
		var err error
		if b, err = s.endBinding(a, b, "removed by "+whoDecided(r)); err != nil {
			jsonError(w, err.Error(), http.StatusConflict)
			return
		}
	}
	rec, _ := s.DataStore.GetCredential(b.CredentialSAID)
	if rec == nil || rec.Status == "revoked" {
		writeJSONStatus(w, http.StatusOK, map[string]any{"revoked": b, "tel_revoked": rec != nil})
		return
	}
	telRevoked, status, err := s.withdrawCredential(rec)
	if err != nil {
		jsonError(w, "the machine can no longer speak as the AI agent, but the revocation could not be "+
			"written to the registry, so others checking it would still see it live — try again: "+err.Error(),
			http.StatusBadGateway)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"revoked": b, "tel_revoked": telRevoked, "status": status})
}

// endBinding ends a live body: it stops being admitted at once, whoever was
// watching it stops, what was lent to it is withdrawn, and a machine a
// provider made for it is destroyed. The caller holds the AI agent's lock.
func (s *CoreServer) endBinding(a asset.Asset, b agentbody.Binding, why string) (agentbody.Binding, error) {
	b, err := s.bodies().Revoke(b.ID, a.ID, time.Now())
	if err != nil {
		return b, err
	}
	s.recordBodyEvent(a, b, "removed", "ok", why)
	// Whoever was watching it is no longer watching this AI agent.
	s.screens().EndBody(b.Host, screenview.EndedBodyRemoved)
	s.endLendsNoLongerGranted("a machine was removed as an AI agent's body")
	// A machine a provider made for it is destroyed; a provider makes no more.
	s.machineGone(b)
	return b, nil
}

func (s *CoreServer) handleBodyEnrol(w http.ResponseWriter, r *http.Request) {
	var sealed agentbody.SealedEnrolment
	if err := json.NewDecoder(io.LimitReader(r.Body, 128<<10)).Decode(&sealed); err != nil || sealed.Envelope == nil {
		jsonError(w, "the enrolment must arrive sealed to this Identity Agent", http.StatusBadRequest)
		return
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		jsonError(w, "this Identity Agent has no identity yet", http.StatusServiceUnavailable)
		return
	}
	if err := sealed.Sender.CheckSealingKeys(); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	ks, err := s.keySetFor(identity.AID)
	if err != nil {
		jsonError(w, "this Identity Agent's sealing keys are unavailable", http.StatusServiceUnavailable)
		return
	}
	msg, err := didcomm.UnpackAuthcrypt(ks, sealed.Sender.DID(), sealed.Envelope)
	if err != nil || msg.Type != didcomm.TypeBodyEnrolment {
		jsonError(w, "the enrolment could not be opened as one sealed to this Identity Agent by the keys it names", http.StatusForbidden)
		return
	}
	var req agentbody.EnrolRequest
	if err := json.Unmarshal(msg.Body, &req); err != nil {
		jsonError(w, "the sealed enrolment is unreadable", http.StatusBadRequest)
		return
	}
	// The keys inside, which K signs, are the keys it was sealed from.
	if req.Keys != sealed.Sender {
		jsonError(w, "the keys inside the enrolment are not the keys it was sealed from", http.StatusForbidden)
		return
	}
	ref := s.findAgentAssetByAID(req.Agent)
	if ref == nil {
		jsonError(w, agentbody.ErrInvitation.Error(), http.StatusForbidden)
		return
	}
	if _, revoked := s.revokedAIAgents().Get(ref.ID); revoked {
		jsonError(w, agentbody.ErrInvitation.Error(), http.StatusForbidden)
		return
	}
	if agentbody.CheckNonce(req.Nonce) != nil {
		jsonError(w, "the enrolment needs a fresh nonce", http.StatusBadRequest)
		return
	}
	// Proof of possession: the machine holds the key it is offering, and signed
	// this enrolment — this secret, this AI agent, this Identity Agent, these
	// sealing keys — with it. Submitting somebody else's key fails here.
	proof := agentbody.EnrolProof(agentbody.Enrolment{IdentityAgent: identity.AID, Agent: req.Agent, Secret: req.Secret},
		req.Nonce, req.Keys, req.ClaimedGrade, req.Platform, req.Placement)
	if err := agentbody.Verify(req.Keys.Host, req.Keys.Verkey, req.Signature, proof); err != nil {
		jsonError(w, "the enrolment is not signed by the key it offers: "+err.Error(), http.StatusForbidden)
		return
	}
	grade, clamped := agentbody.Grade(req.ClaimedGrade)
	b, err := s.bodies().Claim(req.Secret, agentbody.Binding{
		AgentAssetID: ref.ID, Agent: req.Agent, Keys: req.Keys, Words: agentbody.Words(req.Keys.Host),
		Grade: grade, ClaimedGrade: req.ClaimedGrade, GradeClamped: clamped,
		Platform: clampWhy(req.Platform), Placement: clampWhy(req.Placement),
	}, time.Now())
	switch {
	case errors.Is(err, agentbody.ErrInvitation), errors.Is(err, agentbody.ErrHostTaken):
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	why := "a machine asked to become a body"
	if clamped {
		why += fmt.Sprintf("; it claimed grade %q and was recorded at %q, because nothing has checked evidence for more",
			req.ClaimedGrade, grade)
	}
	if a, ok := s.aiAgentAsset(ref.ID); ok {
		s.recordBodyEvent(a, b, "requested", "pending", why)
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"binding_id": b.ID, "state": b.State, "words": b.Words,
		"grade": b.Grade, "grade_clamped": b.GradeClamped,
	})
}

// verifyBodySignature checks a request a body signed, against a given binding:
// the signature over the request as sent — the Identity Agent it names, target,
// nonce, body, stated purpose and session — the timestamp window, and that the
// signature has not been spent.
//
// me is this Identity Agent's identifier. A request naming any other is
// refused before its signature is looked at: a copy of a request made to a
// different Identity Agent that has the same machine enrolled is worth nothing
// here, though each keeps its own memory of spent signatures.
func verifyBodySignature(r *http.Request, b agentbody.Binding, me string) error {
	if named := r.Header.Get(agentbody.HeaderFor); named != me {
		if named == "" {
			return fmt.Errorf("the request does not name the Identity Agent it is for")
		}
		return fmt.Errorf("the request was signed for a different Identity Agent")
	}
	ts := r.Header.Get(agentbody.HeaderTimestamp)
	when, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return fmt.Errorf("the request carries no readable timestamp")
	}
	now := time.Now()
	if d := now.Sub(when); d > agentbody.RequestWindow || d < -agentbody.RequestWindow {
		return fmt.Errorf("the request's timestamp is outside the window this Identity Agent accepts")
	}
	nonce := r.Header.Get(agentbody.HeaderNonce)
	if agentbody.CheckNonce(nonce) != nil {
		return fmt.Errorf("the request carries no nonce")
	}
	body, err := readSignedBody(r)
	if err != nil {
		return err
	}
	sig := r.Header.Get(agentbody.HeaderSignature)
	msg := agentbody.SignedRequest{
		For: me, Host: b.Host, Method: r.Method, Target: r.URL.RequestURI(), Timestamp: ts, Nonce: nonce,
		Body: body, WorkItem: r.Header.Get(agentbody.HeaderWorkItem), Reason: r.Header.Get(agentbody.HeaderReason),
		Session: r.Header.Get(agentbody.HeaderSession),
	}.Bytes()
	if err := agentbody.Verify(b.Host, b.Verkey, sig, msg); err != nil {
		return err
	}
	if rememberSignature(sig, now) {
		return fmt.Errorf("this signed request was already used")
	}
	return nil
}

// identifyBody returns the live binding a body-signed request comes from, or
// says why it was not admitted. Absent headers are not an error: most requests
// are not from a body.
func (s *CoreServer) identifyBody(r *http.Request) (agentbody.Binding, bool, error) {
	host := r.Header.Get(agentbody.HeaderHost)
	if host == "" {
		return agentbody.Binding{}, false, nil
	}
	b, ok := s.bodies().ActiveByHost(host)
	if !ok {
		return agentbody.Binding{}, true, fmt.Errorf("this machine key is not the live body of any AI agent")
	}
	// The binding is live only while its credential is: a body revoked in the
	// registry but somehow still marked active here is refused.
	if rec, _ := s.DataStore.GetCredential(b.CredentialSAID); rec == nil || !isUsableStatus(rec.Status) || s.issuedUnderFirstVersionTooLate(rec) {
		return agentbody.Binding{}, true, fmt.Errorf("this body's credential is not in force")
	}
	me, err := s.whoThisIdentityAgentIs()
	if err != nil {
		return agentbody.Binding{}, true, err
	}
	if err := verifyBodySignature(r, b, me); err != nil {
		return agentbody.Binding{}, true, err
	}
	return b, true, nil
}

// handleBodyStatus tells a waiting machine whether it was approved, rejected or
// revoked. It answers only the machine itself, by its signature.
func (s *CoreServer) handleBodyStatus(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get(agentbody.HeaderHost)
	b, ok := s.bodies().LatestByHost(host)
	if host == "" || !ok {
		jsonError(w, "this machine key has not enrolled here", http.StatusNotFound)
		return
	}
	me, err := s.whoThisIdentityAgentIs()
	if err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := verifyBodySignature(r, b, me); err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	out := map[string]any{
		"binding_id": b.ID, "state": b.State, "agent": b.Agent, "grade": b.Grade,
		"grade_clamped": b.GradeClamped, "credential_said": b.CredentialSAID, "words": b.Words,
	}
	// A live body also learns how its AI agent is meant to operate: its name,
	// role, instructions and brain. These configure the AI agent and grant
	// nothing; what it may do is still its grant's to say. Only when the
	// request came sealed: a machine still waiting for approval asks unsealed,
	// and the instructions are not for whatever can read that.
	if a, ok := s.aiAgentAsset(b.AgentAssetID); ok && b.State == agentbody.StateActive && s.sealedSender(r) == host {
		out["agent_name"] = a.DisplayName
		if a.AgentConfig != nil {
			out["role"] = a.AgentConfig.Role
			out["system_prompt"] = a.AgentConfig.SystemPrompt
			out["brain"] = map[string]string{
				"kind": a.AgentConfig.Brain.Kind, "provider": a.AgentConfig.Brain.Provider, "model": a.AgentConfig.Brain.Model,
			}
		}
	}
	writeJSONStatus(w, http.StatusOK, out)
}
