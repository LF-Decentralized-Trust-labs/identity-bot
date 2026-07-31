package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Letting a person reach their own agent from a browser.
//
// Ownership is proved by signing the request with the owner key. That works for
// an app holding the key and not at all for a browser, which holds nothing and
// should not be given the key to hold. A hosted agent is therefore correctly
// locked and completely unusable: every owner route answers "sign this", and the
// person who owns it has no way to.
//
// So the phone does the proving, once, and the browser carries the result.
//
//	the browser asks for a challenge, keeping a secret only it knows
//	the phone reads the code, and grants it with a signed request
//	the browser exchanges its secret for a session
//
// WHY THE BROWSER'S SECRET EXISTS. The code is shown on a screen. Anybody who
// can see that screen — over a shoulder, in a shared office, in a screenshot —
// knows it. Without a secret the browser never displays, seeing the code would
// be enough to collect the session the owner just granted, and the owner would
// have authorised a stranger while watching their own screen.
//
// WHAT A SESSION IS ALLOWED TO DO is deliberately less than what the key can do.
// A session reads everything and performs the day-to-day; anything that changes
// the identity itself — its keys, who may sign for it, who witnesses it — goes
// back to the phone. A browser session is a convenience, and a convenience
// should not be able to give the identity away.
//
// SESSIONS DO NOT SURVIVE A RESTART. They are held in memory on purpose: an
// agent that has just restarted is an agent that may have just been updated,
// and re-proving on a device you are holding costs one scan. Persisting them
// would trade that for a token that outlives the software it was issued by.

const (
	// browserChallengeTTL is how long a displayed code is worth reading. Long
	// enough to find your phone, short enough that a code left on a screen
	// stops being useful quickly.
	browserChallengeTTL = 3 * time.Minute

	// browserSessionTTL bounds a session. A day is a working day; longer starts
	// to mean somebody stays signed in on a machine they no longer have.
	browserSessionTTL = 12 * time.Hour

	headerSessionToken = "Authorization"
)

// browserChallenge is a login in progress.
type browserChallenge struct {
	// Code is what the person reads off one screen and into the other. Short
	// and unambiguous rather than long and secure — its secrecy is not what
	// protects the session.
	Code string
	// ClaimHash is the digest of the secret the browser kept. Stored hashed so
	// that reading this agent's memory does not hand over pending logins.
	ClaimHash string
	Granted   bool
	// Token is minted at grant and held until the browser collects it, so the
	// phone's request completes without waiting for the browser to poll.
	Token     string
	ExpiresAt time.Time
}

// browserSession is a granted session.
type browserSession struct {
	// TokenHash, not the token. A session store that holds live credentials in
	// clear is a store worth stealing.
	TokenHash string
	GrantedAt time.Time
	ExpiresAt time.Time
}

type browserSessions struct {
	mu         sync.Mutex
	challenges map[string]*browserChallenge
	sessions   map[string]*browserSession
}

func newBrowserSessions() *browserSessions {
	return &browserSessions{
		challenges: map[string]*browserChallenge{},
		sessions:   map[string]*browserSession{},
	}
}

func randomToken(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// readableCode is what a person carries from one screen to another.
//
// No vowels and no look-alike characters, because this gets read aloud and
// typed by hand, and 0/O or 1/l is a failure that reads as "the login is
// broken". Its secrecy is not load-bearing — the browser's secret is.
func readableCode() (string, error) {
	const alphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, b := range raw {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(b)%len(alphabet)])
	}
	return string(out), nil
}

func hashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sweep drops what has expired. Called on every operation rather than on a
// timer: the maps are small, and a login flow that leaves stale grants around
// is one where a code keeps working after it visibly stopped being displayed.
func (b *browserSessions) sweep(now time.Time) {
	for id, c := range b.challenges {
		if now.After(c.ExpiresAt) {
			delete(b.challenges, id)
		}
	}
	for id, s := range b.sessions {
		if now.After(s.ExpiresAt) {
			delete(b.sessions, id)
		}
	}
}

func (b *browserSessions) newChallenge(claimHash string) (id, code string, expires time.Time, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	b.sweep(now)

	id, err = randomToken(16)
	if err != nil {
		return "", "", time.Time{}, err
	}
	code, err = readableCode()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires = now.Add(browserChallengeTTL)
	b.challenges[id] = &browserChallenge{
		Code: code, ClaimHash: claimHash, ExpiresAt: expires,
	}
	return id, code, expires, nil
}

// grant marks the challenge matching a code as approved and mints its token.
//
// Matching is by code because that is what the person carrying it can see. The
// challenge id never leaves the browser, so asking the phone for it would mean
// asking somebody to read a random string off a screen they are not looking at.
func (b *browserSessions) grant(code string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	b.sweep(now)

	code = strings.ToUpper(strings.TrimSpace(code))
	for _, c := range b.challenges {
		if c.Code != code {
			continue
		}
		if c.Granted {
			// Refused rather than re-granted. A code that has already been used
			// being usable again is how one displayed code becomes two
			// sessions.
			return fmt.Errorf("that code has already been used")
		}
		token, err := randomToken(32)
		if err != nil {
			return err
		}
		c.Granted = true
		c.Token = token
		return nil
	}
	return fmt.Errorf("no login is waiting for that code")
}

// claim exchanges the browser's secret for the session the phone granted.
func (b *browserSessions) claim(id, secret string) (token string, expires time.Time, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	b.sweep(now)

	c, ok := b.challenges[id]
	if !ok {
		return "", time.Time{}, fmt.Errorf("that login has expired or was never started")
	}
	// Constant time: this compares a secret, and a comparison that returns
	// early tells an attacker how much of it they had right.
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(c.ClaimHash)) != 1 {
		return "", time.Time{}, fmt.Errorf("this is not the browser that started that login")
	}
	if !c.Granted {
		return "", time.Time{}, errSessionNotGranted
	}

	// Spent on collection. A challenge that can be claimed twice is a session
	// that can be handed to a second browser.
	delete(b.challenges, id)

	expires = now.Add(browserSessionTTL)
	b.sessions[hashSecret(c.Token)] = &browserSession{
		TokenHash: hashSecret(c.Token), GrantedAt: now, ExpiresAt: expires,
	}
	return c.Token, expires, nil
}

// errSessionNotGranted is distinguished so the browser can keep waiting rather
// than treating "not yet" as "no".
var errSessionNotGranted = fmt.Errorf("not granted yet")

// valid reports whether a token names a live session.
func (b *browserSessions) valid(token string) bool {
	if token == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	b.sweep(now)
	s, ok := b.sessions[hashSecret(token)]
	return ok && now.Before(s.ExpiresAt)
}

func (b *browserSessions) revoke(token string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.sessions[hashSecret(token)]
	delete(b.sessions, hashSecret(token))
	return ok
}

// bearerToken pulls a session token out of the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get(headerSessionToken)
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// hasBrowserSession reports whether this request carries a live session.
func (s *CoreServer) hasBrowserSession(r *http.Request) bool {
	if s.BrowserSessions == nil {
		return false
	}
	return s.BrowserSessions.valid(bearerToken(r))
}

func (s *CoreServer) mountBrowserSessionRoutes(r chi.Router) {
	r.Post("/session/challenge", s.handleSessionChallenge)
	r.Post("/session/grant", s.handleSessionGrant)
	r.Post("/session/claim", s.handleSessionClaim)
	r.Post("/session/end", s.handleSessionEnd)
}

// handleSessionChallenge starts a login. Public: nobody is authenticated yet,
// which is the entire problem being solved.
func (s *CoreServer) handleSessionChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClaimHash string `json:"claim_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	// The browser sends a HASH, never the secret. A secret that travelled here
	// would be a secret this agent could use to claim the session itself, which
	// defeats the point of the browser holding one.
	if len(req.ClaimHash) != 64 {
		writeError(w, http.StatusBadRequest, "claim_hash must be a sha256 hex digest",
			"the browser keeps the secret and sends only its digest")
		return
	}

	id, code, expires, err := s.BrowserSessions.newChallenge(strings.ToLower(req.ClaimHash))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start a login", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"challenge_id": id,
		"code":         code,
		"expires_at":   expires.Format(time.RFC3339),
	})
}

// handleSessionGrant approves a login. Owner-only, which is what makes the
// whole flow mean something: the phone signs this request with the owner key,
// exactly as it signs any other.
func (s *CoreServer) handleSessionGrant(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only",
			"granting a browser session is the owner's decision, signed with the owner key")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code required", "")
		return
	}
	if err := s.BrowserSessions.grant(req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "could not grant", err.Error())
		return
	}
	log.Printf("[session] a browser session was granted by the owner")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"granted": true})
}

// handleSessionClaim exchanges the browser's secret for its session.
func (s *CoreServer) handleSessionClaim(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challenge_id"`
		ClaimSecret string `json:"claim_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	token, expires, err := s.BrowserSessions.claim(req.ChallengeID, req.ClaimSecret)
	if err != nil {
		if err == errSessionNotGranted {
			// Distinguished so a browser can keep waiting. Collapsing it into a
			// failure would make every poll look like a rejection.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]any{"granted": false})
			return
		}
		writeError(w, http.StatusForbidden, "could not claim", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"granted":    true,
		"token":      token,
		"expires_at": expires.Format(time.RFC3339),
	})
}

// handleSessionEnd signs a browser out.
//
// Reachable with the session itself rather than owner-only. Being able to end
// your own session should not require the device that started it — that is
// exactly the situation where you most want to.
func (s *CoreServer) handleSessionEnd(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusBadRequest, "no session", "send the session token to end it")
		return
	}
	ended := s.BrowserSessions.revoke(token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ended": ended})
}
