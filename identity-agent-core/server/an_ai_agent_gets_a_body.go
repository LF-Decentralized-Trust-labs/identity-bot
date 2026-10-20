package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/asset"
	"identity-agent-core/schemas"

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
	v, _ := bodyStoreOnce.LoadOrStore(s.DataDir, agentbody.NewStore(s.DataDir))
	return v.(*agentbody.Store)
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
}

func (s *CoreServer) handleListBodies(w http.ResponseWriter, r *http.Request) {
	a, ok := s.aiAgentAsset(chi.URLParam(r, "id"))
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	out := []bodyView{}
	for _, b := range s.bodies().ForAgent(a.ID) {
		out = append(out, bodyView{Binding: b, WordsLine: strings.Join(b.Words, " ")})
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
		"keys_digest": b.KeysDigest(), "grade": b.Grade,
		"platform": b.Platform, "placement": b.Placement,
	}
	credSAID, err := s.issueAssetCredential(schemas.AIAgentBody, a.PairwiseAID, a.DelegatorAID, claims, "")
	if err != nil {
		jsonError(w, "the body credential could not be issued, so the body was not approved: "+err.Error(),
			http.StatusBadGateway)
		return
	}
	decided, err := s.bodies().Decide(b.ID, a.ID, agentbody.StateActive, whoDecided(r), credSAID, time.Now())
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	log.Printf("[body] %s is now a body of AI agent %s at %s (credential %s, approved by %s)",
		decided.Host, a.PairwiseAID, decided.Grade, credSAID, decided.DecidedBy)
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
	decided, err := s.bodies().Decide(chi.URLParam(r, "bid"), a.ID, agentbody.StateRejected, whoDecided(r), "", time.Now())
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	log.Printf("[body] rejected %s as a body of AI agent %s (words %q), by %s",
		decided.Host, a.PairwiseAID, strings.Join(decided.Words, " "), decided.DecidedBy)
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
	if !ok || b.AgentAssetID != a.ID || b.State != agentbody.StateActive {
		jsonError(w, "no live body by that id for this AI agent", http.StatusNotFound)
		return
	}
	// The binding is ended first, so the machine stops being admitted even if
	// writing the revocation to the registry then fails — which is reported.
	revoked, err := s.bodies().Revoke(b.ID, a.ID, time.Now())
	if err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	telRevoked := false
	if rec, _ := s.DataStore.GetCredential(b.CredentialSAID); rec != nil {
		if telRevoked, err = s.revokeIssuedCredential(rec); err != nil {
			log.Printf("[body] %s ended, but its revocation was not written to the registry: %v", b.Host, err)
		}
		if err := s.DataStore.UpdateCredentialStatus(rec.SAID, "revoked"); err != nil {
			log.Printf("[body] %s ended, but its credential is not marked revoked: %v", b.Host, err)
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"revoked": revoked, "tel_revoked": telRevoked})
}

// bodyEnrolRequest is what a machine sends to ask to become a body.
type bodyEnrolRequest struct {
	Secret       string         `json:"secret"`
	Agent        string         `json:"agent"`
	Keys         agentbody.Keys `json:"keys"`
	Nonce        string         `json:"nonce"`
	ClaimedGrade string         `json:"claimed_grade"`
	Platform     string         `json:"platform"`
	Placement    string         `json:"placement"`
	Signature    string         `json:"signature"`
}

func (s *CoreServer) handleBodyEnrol(w http.ResponseWriter, r *http.Request) {
	var req bodyEnrolRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		jsonError(w, "the enrolment request is unreadable", http.StatusBadRequest)
		return
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		jsonError(w, "this Identity Agent has no identity yet", http.StatusServiceUnavailable)
		return
	}
	ref := s.findAgentAssetByAID(req.Agent)
	if ref == nil {
		jsonError(w, agentbody.ErrInvitation.Error(), http.StatusForbidden)
		return
	}
	if len(req.Nonce) < 16 {
		jsonError(w, "the enrolment needs a fresh nonce", http.StatusBadRequest)
		return
	}
	if err := checkSealingKeys(req.Keys); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
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
	if clamped {
		log.Printf("[body] %s claimed grade %q, recorded at %q: nothing has checked evidence for more",
			b.Host, req.ClaimedGrade, grade)
	}
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"binding_id": b.ID, "state": b.State, "words": b.Words,
		"grade": b.Grade, "grade_clamped": b.GradeClamped,
	})
}

// checkSealingKeys refuses sealing keys of the wrong size: they are stored and
// later used to seal messages to the machine, so a malformed one is refused now
// rather than discovered then.
func checkSealingKeys(k agentbody.Keys) error {
	x, err := base64.RawURLEncoding.DecodeString(k.X25519)
	if err != nil || len(x) != 32 {
		return fmt.Errorf("the X25519 sealing key must be 32 bytes, base64url")
	}
	m, err := base64.RawURLEncoding.DecodeString(k.MLKEM768)
	if err != nil || len(m) != 1184 {
		return fmt.Errorf("the ML-KEM-768 sealing key must be 1184 bytes, base64url")
	}
	return nil
}

// verifyBodySignature checks a request a body signed, against a given binding:
// the signature, the timestamp window, and that the signature has not been
// spent. The body is read and put back for the handler.
func verifyBodySignature(r *http.Request, b agentbody.Binding, path string) error {
	ts := r.Header.Get(agentbody.HeaderTimestamp)
	when, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return fmt.Errorf("the request carries no readable timestamp")
	}
	now := time.Now()
	if d := now.Sub(when); d > agentbody.RequestWindow || d < -agentbody.RequestWindow {
		return fmt.Errorf("the request's timestamp is outside the window this Identity Agent accepts")
	}
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, maxSignedBodyBytes+1))
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("the request body is unreadable")
		}
		if int64(len(body)) > maxSignedBodyBytes {
			return fmt.Errorf("this request is larger than a signed request may carry")
		}
	}
	sig := r.Header.Get(agentbody.HeaderSignature)
	msg := agentbody.RequestToSign(b.Host, r.Method, path, ts, body)
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
	if rec, _ := s.DataStore.GetCredential(b.CredentialSAID); rec == nil || !isUsableStatus(rec.Status) {
		return agentbody.Binding{}, true, fmt.Errorf("this body's credential is not in force")
	}
	if err := verifyBodySignature(r, b, r.URL.Path); err != nil {
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
	if err := verifyBodySignature(r, b, r.URL.Path); err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"binding_id": b.ID, "state": b.State, "agent": b.Agent, "grade": b.Grade,
		"grade_clamped": b.GradeClamped, "credential_said": b.CredentialSAID, "words": b.Words,
	})
}
