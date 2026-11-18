package server

// A computer asks to act for an identity, by an Ask like any other (ADR-041 Amendment 1).
//
// The computer's own core cannot be reached from the owner's phone, which is why its offer used to
// travel whole inside the QR: a dense, self-contained device code. It can, though, reach the Identity
// Agent it wants to act for, and so can the phone. So the computer leaves its signed offer THERE, the
// Identity Agent holds it behind a short token, and the code the computer shows is that Identity Agent's
// bare pointer, https://{agent}/i/{token}. The phone's Identity Agent fetches the Ask at the pointer
// through the same scan gate as a sign-in, checks the computer's signature over the offer exactly as it
// always has, and shows the person what is asking. The person's answer is the grant the owner already
// signs (POST /api/controllers): leaving a request here never grants anything.
//
//	POST /api/controller/requests  {aid, public_key, protected_by, agent_origin, timestamp, signature,
//	                                label?, org_name?}  -> {token, url, expires_at}   (public)
//	GET  /i/{token}                -> the Ask, t = 8                                  (public, by token)
//
// Who may leave one: anybody, because the computer asking has no standing here yet and that is the
// point of asking. What bounds it: the offer must verify (signed by the key it names, fresh), a body is
// at most a few kilobytes, each caller address is rate limited, at most maxPendingControllerRequests wait
// at once, one machine has at most one waiting (a new offer replaces its old token), and each expires
// with the offer's own window. Nothing lists them. The only way to read one is to hold its token, which
// is unguessable, and what it holds is a public key and two display strings, nothing about the identity.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ActionActForIdentity is the action code of "Let a computer act for you" (actions/registry.json).
const ActionActForIdentity = 8

func init() { registerAsk(ActionActForIdentity, actForIdentityAsk{}) }

// maxPendingControllerRequests is how many computers may be waiting at once. A person authorises a
// computer in the minute they stand at it, so a handful is generous; the bound is what stops a stranger
// filling memory with requests nobody will approve.
const maxPendingControllerRequests = 32

// controllerRequestsPerCaller is how many requests one caller address may leave per minute. Showing a
// fresh code is a deliberate press, so a person never comes near it.
const controllerRequestsPerCaller = 10

// maxShownLength bounds the two strings a computer suggests for display, which nothing checks.
const maxShownLength = 80

// controllerRequestTokenBytes is the token's randomness: 128 bits, 22 characters unpadded base64url.
const controllerRequestTokenBytes = 16

// controllerRequest is one computer waiting for its owner.
type controllerRequest struct {
	askBytes []byte
	aid      string
	expires  time.Time
}

// controllerRequestAsk is the Ask served at the pointer. The offer's six fields are exactly what the
// computer signed and what the owner's device checks; label, org_name and expiry are carried beside
// them, unsigned, as they always were: two are display only and the third may only shorten the window.
type controllerRequestAsk struct {
	V string `json:"v"`
	T int    `json:"t"`
	ControllerOffer
	Label   string `json:"label,omitempty"`
	OrgName string `json:"org_name,omitempty"`
	Expiry  string `json:"expiry"`
}

// handleLeaveAControllerRequest takes a computer's signed offer and holds it behind a short token.
func (s *CoreServer) handleLeaveAControllerRequest(w http.ResponseWriter, r *http.Request) {
	if !s.controllerRequestLimiterFor().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "too many requests from here; wait a minute and show a new code", "")
		return
	}
	var req struct {
		ControllerOffer
		Label   string `json:"label"`
		OrgName string `json:"org_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "the request could not be read", err.Error())
		return
	}
	now := time.Now().UTC()
	if err := s.checkControllerOffer(req.ControllerOffer, now); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "this offer could not be trusted", err.Error())
		return
	}
	label, err := shownString(req.Label)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the name this computer suggests cannot be shown", err.Error())
		return
	}
	orgName, err := shownString(req.OrgName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the organisation name cannot be shown", err.Error())
		return
	}
	token, expires, err := s.holdControllerRequest(req.ControllerOffer, label, orgName, now)
	if errors.Is(err, errTooManyControllerRequests) {
		writeError(w, http.StatusTooManyRequests, err.Error(), "")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "the request could not be held", err.Error())
		return
	}
	writeJSON(w, map[string]string{
		"token": token,
		// The pointer is built on the origin the computer signed, not on whatever this server thinks its
		// own address is, because the owner's device refuses a request served from anywhere else.
		"url":        controllerRequestPointer(req.AgentOrigin, token),
		"expires_at": expires.Format(time.RFC3339),
	})
}

// controllerRequestPointer is the bare pointer a computer shows.
func controllerRequestPointer(agentOrigin, token string) string {
	return strings.TrimRight(agentOrigin, "/") + "/i/" + token
}

var errTooManyControllerRequests = errors.New("too many computers are waiting to be approved here; try again in a few minutes")

// holdControllerRequest stores a checked offer as the Ask for a new token, replacing any earlier one
// from the same machine.
func (s *CoreServer) holdControllerRequest(offer ControllerOffer, label, orgName string, now time.Time) (string, time.Time, error) {
	signedAt, err := time.Parse(time.RFC3339, offer.Timestamp)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := signedAt.Add(controllerOfferWindow)
	ask, err := json.Marshal(controllerRequestAsk{
		V: "ASK1", T: ActionActForIdentity, ControllerOffer: offer,
		Label: label, OrgName: orgName, Expiry: expires.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	tb := make([]byte, controllerRequestTokenBytes)
	if _, err := rand.Read(tb); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(tb)

	s.controllerRequestMu.Lock()
	defer s.controllerRequestMu.Unlock()
	if s.controllerRequests == nil {
		s.controllerRequests = map[string]*controllerRequest{}
	}
	for t, p := range s.controllerRequests {
		// One machine, one waiting code: a new code makes the old one stop working, so a code left on a
		// screen somebody walked away from is not still good.
		if !now.Before(p.expires) || p.aid == offer.AID {
			delete(s.controllerRequests, t)
		}
	}
	if len(s.controllerRequests) >= maxPendingControllerRequests {
		return "", time.Time{}, errTooManyControllerRequests
	}
	s.controllerRequests[token] = &controllerRequest{askBytes: ask, aid: offer.AID, expires: expires}
	return token, expires, nil
}

// controllerRequestAskBytes is the Ask behind a token, while it stands.
func (s *CoreServer) controllerRequestAskBytes(token string) ([]byte, bool) {
	s.controllerRequestMu.Lock()
	defer s.controllerRequestMu.Unlock()
	p, ok := s.controllerRequests[token]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(p.expires) {
		delete(s.controllerRequests, token)
		return nil, false
	}
	return p.askBytes, true
}

// retireControllerRequestsFor ends the waiting code of a machine the owner has just granted, so the
// token is used once.
func (s *CoreServer) retireControllerRequestsFor(aid string) {
	s.controllerRequestMu.Lock()
	defer s.controllerRequestMu.Unlock()
	for t, p := range s.controllerRequests {
		if p.aid == aid {
			delete(s.controllerRequests, t)
		}
	}
}

func (s *CoreServer) controllerRequestLimiterFor() *ipRateLimiter {
	s.controllerRequestMu.Lock()
	defer s.controllerRequestMu.Unlock()
	if s.controllerRequestLimiter == nil {
		s.controllerRequestLimiter = newIPRateLimiter(controllerRequestsPerCaller, time.Minute)
	}
	return s.controllerRequestLimiter
}

// shownString is a display string a computer suggests: bounded, one line, no control characters.
func shownString(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !utf8.ValidString(v) {
		return "", errors.New("it is not text")
	}
	if utf8.RuneCountInString(v) > maxShownLength {
		return "", fmt.Errorf("it is longer than %d characters", maxShownLength)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return "", errors.New("it contains a character that cannot be shown")
		}
	}
	return v, nil
}

// t = 8 -> act_for_identity. The owner's half: their Identity Agent read the Ask at the pointer, and this
// checks it and says what is asking. It never grants. The grant needs the owner's own signed request to
// the Identity Agent the computer will act for, and a scan can be executed by anything that reaches the
// scan gate, including a computer already authorised, which must never be able to authorise another.
type actForIdentityAsk struct{}

func (actForIdentityAsk) Action() string { return "act_for_identity" }

// AskAuth: the Ask is the computer's own signed offer. A computer is named by its key and publishes no
// key log, so there is no signer address for the base layer to read; the handler checks the offer's
// signature against the key the offer names, which the identifier is.
func (actForIdentityAsk) AskAuth() askAuth { return authSelfVerifying }

// readActForIdentity checks everything about the Ask that does not need a person.
func readActForIdentity(s *CoreServer, ctx AskContext, now time.Time) (controllerRequestAsk, error) {
	var a controllerRequestAsk
	if err := json.Unmarshal(ctx.AskBytes, &a); err != nil {
		return a, errors.New("this request is not readable")
	}
	if a.T != ActionActForIdentity {
		return a, errors.New("this is not a computer asking to act for you")
	}
	if err := s.checkControllerOffer(a.ControllerOffer, now); err != nil {
		return a, err
	}
	// Served where it says it is for. The computer signed which Identity Agent it asks to act for; a
	// genuine request served again from somewhere else is refused, so a pointer cannot be made to show
	// one Identity Agent's request on another's behalf.
	if !sameOrigin(ctx.Base, a.AgentOrigin) {
		return a, errors.New("this request was not served by the Identity Agent it asks to act for")
	}
	// The expiry beside the offer is unsigned, so it may shorten the window and never lengthen it.
	signedAt, _ := time.Parse(time.RFC3339, a.Timestamp)
	if a.Expiry != "" {
		exp, err := time.Parse(time.RFC3339, a.Expiry)
		if err != nil {
			return a, errors.New("this request's expiry cannot be read")
		}
		if exp.After(signedAt.Add(controllerOfferWindow)) {
			return a, errors.New("this request claims to last longer than the computer's offer does")
		}
		if !now.Before(exp) {
			return a, errors.New("this code has expired; ask the computer to show a new one")
		}
	}
	if _, err := shownString(a.Label); err != nil {
		return a, errors.New("the name this computer suggests cannot be shown")
	}
	if _, err := shownString(a.OrgName); err != nil {
		return a, errors.New("the organisation name cannot be shown")
	}
	return a, nil
}

func (actForIdentityAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	a, err := readActForIdentity(s, ctx, time.Now().UTC())
	if err != nil {
		return GenericPreview{}, err
	}
	subtitle := a.AgentOrigin
	if a.OrgName != "" {
		subtitle = a.OrgName
	}
	details := []PreviewDetail{
		{Label: "Computer", Value: a.AID},
		{Label: "Its key is held by", Value: orDefault(a.ProtectedBy, "not stated")},
		{Label: "Identity Agent", Value: a.AgentOrigin},
		{Label: "Code expires", Value: a.Expiry},
	}
	if a.Label != "" {
		details = append(details, PreviewDetail{Label: "It calls itself", Value: a.Label})
	}
	return GenericPreview{
		T:            ActionActForIdentity,
		Action:       "act_for_identity",
		Title:        "Let this computer act for you",
		Subtitle:     subtitle,
		Counterparty: a.AID,
		Details:      details,
		Warning: "Approve only the computer you are standing at, showing this code now. " +
			"It will be able to act for this identity until you remove it.",
	}, nil
}

// Execute never grants. On approval it hands back the checked machine, for the owner's device to grant
// with its own signed request; on refusal there is nothing to do, and the code expires by itself.
func (actForIdentityAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	a, err := readActForIdentity(s, ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if !d.Approved {
		return map[string]interface{}{"ok": true, "approved": false}, nil
	}
	return map[string]interface{}{
		"ok":       true,
		"approved": true,
		// Said in the answer so no client reads approval as a grant.
		"granted": false,
		"machine": map[string]string{
			"controller_aid": a.AID,
			"public_key":     a.PublicKey,
			"protected_by":   a.ProtectedBy,
			"agent_origin":   a.AgentOrigin,
			"label":          a.Label,
			"org_name":       a.OrgName,
		},
	}, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
