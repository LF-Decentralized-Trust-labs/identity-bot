package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/login"
)

// A controller that redeemed an invite may ask the app that issued it for
// whatever that app publishes for the invite.
//
// Redeeming an invite leaves the redeemer talking to the inviting app already:
// it fetched the invite from there and posted its redeem there. When the inviting
// app has something further for the redeemer — an address, a code — it can
// publish it against the invite, and the redeemer asks for it here instead of
// being handed a second code to scan.
//
// Only the transport is new. This hands back what the inviting app published and
// does nothing with it; whether and how to act on it is the caller's, under the
// caller's own key.
//
// THE ADDRESS IS NEVER THE CALLER'S. It is the base the invite was redeemed at,
// remembered at the redeem. A route that signed a request to an address the
// caller named would be a way to make this agent sign for anywhere.
//
// THE SIGNING KEY IS THE ONE THE REDEEM WAS MADE WITH, so the inviting app can
// check the poll against the key it recorded at the redeem, and a token read
// off a screen is not enough to ask.
//
// Held in memory, for the window an invite is open. Past it the entry is
// dropped and the caller starts again with a fresh invite.

// WHERE THE INVITING APP ANSWERS IS THE INVITING APP'S TO SAY. It names the path
// in the answer to the redeem ("published_at"), relative to the address the
// invite was redeemed at. An app that publishes nothing names none, and a poll
// for its invite is answered here with 404 and nothing is sent.

// InvitePollText is what the redeemer signs to ask: the invite, its own clock
// and a nonce it chose for this one ask. The inviting app builds the same text
// from what it received to check it.
func InvitePollText(token, timestamp, nonce string) string {
	return "identity-agent invite-published-poll v1\n" + token + "\n" + timestamp + "\n" + nonce
}

const (
	// HeaderInvitePollTimestamp, HeaderInvitePollNonce and HeaderInvitePollSignature
	// carry the signed ask.
	HeaderInvitePollTimestamp = "X-Invite-Poll-Timestamp"
	HeaderInvitePollNonce     = "X-Invite-Poll-Nonce"
	HeaderInvitePollSignature = "X-Invite-Poll-Signature"

	// InvitePollSkew is how far a signed ask's clock may be from the inviting
	// app's own.
	InvitePollSkew = 2 * time.Minute

	// redeemedInviteMemory is how long a redeemed invite is remembered. The
	// inviting app's own window is shorter; this only bounds what is held.
	redeemedInviteMemory = 15 * time.Minute

	// publishedBodyLimit bounds what is read back from the inviting app.
	publishedBodyLimit = 16 << 10
)

type redeemedInvite struct {
	base string
	// publishedPath is where, under base, the inviting app answers; empty when
	// it said it publishes nothing.
	publishedPath string
	siteAID       string
	siteOOBI      string
	at            time.Time
}

type redeemedInviteBook struct {
	mu  sync.Mutex
	m   map[string]redeemedInvite
	now func() time.Time
}

func (b *redeemedInviteBook) clock() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

func (b *redeemedInviteBook) remember(token string, in redeemedInvite) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string]redeemedInvite{}
	}
	now := b.clock()
	for t, v := range b.m {
		if now.Sub(v.at) > redeemedInviteMemory {
			delete(b.m, t)
		}
	}
	in.at = now
	b.m[token] = in
}

func (b *redeemedInviteBook) recall(token string) (redeemedInvite, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[token]
	if !ok || b.clock().Sub(v.at) > redeemedInviteMemory {
		delete(b.m, token)
		return redeemedInvite{}, false
	}
	return v, true
}

func (s *CoreServer) mountRedeemedInviteRoutes(r chi.Router) {
	r.Post("/api/redeemed-invites/published", s.handleWhatTheInvitingAppPublished)
}

// handleWhatTheInvitingAppPublished asks, once, for what the inviting app has
// published for an invite this agent redeemed.
//
// 200 {"ready":true,"published":{...}} when it has published something; 202
// {"ready":false} while it has not; the inviting app's own refusal (403, 404,
// 410) passed through with its reason; 404 here for an invite this agent did not
// redeem. The caller polls; this never waits.
func (s *CoreServer) handleWhatTheInvitingAppPublished(w http.ResponseWriter, r *http.Request) {
	// The invite's code is a secret, so it travels in the body and never in this
	// agent's own path, which is logged.
	var body struct {
		InviteToken string `json:"invite_token"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body) != nil || body.InviteToken == "" {
		http.Error(w, "invite_token required", http.StatusBadRequest)
		return
	}
	token := body.InviteToken
	in, ok := s.redeemedInvites.recall(token)
	if !ok || s.loginHandler == nil {
		http.Error(w, "this agent has not redeemed that invite, or it was long enough ago to be forgotten", http.StatusNotFound)
		return
	}
	if in.publishedPath == "" {
		http.Error(w, "the app that issued that invite publishes nothing against it", http.StatusNotFound)
		return
	}
	rel, err := s.loginHandler.GetOrCreateRelationship(in.siteAID, &login.ChallengeBundle{SiteAID: in.siteAID, SiteOOBI: in.siteOOBI})
	if err != nil || rel == nil {
		http.Error(w, "the key this invite was redeemed with could not be loaded", http.StatusInternalServerError)
		return
	}
	seed, err := s.loginHandler.RelationshipSeed(rel)
	if err != nil {
		http.Error(w, "the key this invite was redeemed with could not be loaded", http.StatusInternalServerError)
		return
	}
	nonce, err := newPollNonce()
	if err != nil {
		http.Error(w, "could not sign the request", http.StatusInternalServerError)
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	sig, err := login.SignString(InvitePollText(token, ts, nonce), seed)
	if err != nil {
		http.Error(w, "could not sign the request", http.StatusInternalServerError)
		return
	}
	target := strings.TrimRight(in.base, "/") + in.publishedPath
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	req.Header.Set(HeaderInvitePollTimestamp, ts)
	req.Header.Set(HeaderInvitePollNonce, nonce)
	req.Header.Set(HeaderInvitePollSignature, sig)
	resp, err := siteClient(15*time.Second, target).Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("the inviting app could not be reached: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, publishedBodyLimit))
	switch resp.StatusCode {
	case http.StatusOK:
		if !json.Valid(raw) {
			http.Error(w, "the inviting app answered with something unreadable", http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]interface{}{"ready": true, "published": json.RawMessage(raw)})
	case http.StatusAccepted:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ready":false}`))
	default:
		reason := strings.TrimSpace(string(raw))
		if reason == "" {
			reason = fmt.Sprintf("status %d", resp.StatusCode)
		}
		http.Error(w, reason, resp.StatusCode)
	}
}

func newPollNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// publishedPathFrom reads, from the inviting app's answer to a redeem, the path
// it says it answers polls at. Only a plain absolute path is accepted: the
// address it is joined to is the one the invite was redeemed at, and a value
// that could name another host, carry a query or climb out of the app's own
// paths is treated as no path at all.
func publishedPathFrom(redeemAnswer []byte) string {
	var a struct {
		PublishedAt string `json:"published_at"`
	}
	if json.Unmarshal(redeemAnswer, &a) != nil {
		return ""
	}
	p := a.PublishedAt
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "?#\\") {
		return ""
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != p {
		return ""
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return ""
		}
	}
	return p
}

// VerifyInvitePoll checks a signed ask received by an inviting app: that it was
// made with redeemerKey (the key the redeem recorded) over this token, a clock
// within InvitePollSkew of now, and a nonce. It returns the nonce so the app can
// refuse one it has already seen -- remembering them is the app's, because only
// it knows how long an invite lives.
func VerifyInvitePoll(r *http.Request, token, redeemerKey string, now time.Time) (nonce string, err error) {
	ts := r.Header.Get(HeaderInvitePollTimestamp)
	nonce = r.Header.Get(HeaderInvitePollNonce)
	sig := r.Header.Get(HeaderInvitePollSignature)
	stamp, perr := time.Parse(time.RFC3339, ts)
	if perr != nil || stamp.Before(now.Add(-InvitePollSkew)) || stamp.After(now.Add(InvitePollSkew)) || sig == "" || nonce == "" || len(nonce) > 128 {
		return "", errors.New("the request must be signed with a current timestamp and a nonce")
	}
	pub, derr := login.DecodeVerkey(redeemerKey)
	if derr != nil {
		return "", errors.New("not the agent that redeemed this invite")
	}
	if good, verr := login.VerifyString(InvitePollText(token, ts, nonce), sig, pub); verr != nil || !good {
		return "", errors.New("not the agent that redeemed this invite")
	}
	return nonce, nil
}
