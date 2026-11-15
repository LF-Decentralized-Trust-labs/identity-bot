package server

// A person signs a statement an app hands them, with their own Identity Agent (Ask action 6).
//
// This file is the ASKER's half: the Identity Agent that holds the app's website asset starts the Ask for
// a page, serves it at /i/{token} like any Ask, takes the person's signed answer at
// /api/statement/callback, checks it, and gives it only to the page that started the Ask, once. The
// person's half (what they see, and the signing) is ask_sign_statement.go. The format of a statement and
// of what is signed is statements/ and docs/statement-signature.md; the reasons it is safe enough are
// ADR-080.
//
// What the asker does NOT do is decide whether the signature is the right person's for the app's purpose:
// the app checks that against the identity it expects (the console checks it against its owner's key
// history). The asker checks that it is a signature, by the signer's own current key, over exactly what it
// asked, and names no one else.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/login"
	"identity-agent-core/statements"
)

// ActionSignStatement is the action code of "Sign a statement" (actions/registry.json).
const ActionSignStatement = 6

// CapabilityAskToSign is the right an app's grant holds to ask a person to sign a statement. Only an
// app whose owner has granted it, on the owner's own device, may start one.
const CapabilityAskToSign = "app.statement.ask"

const (
	statementAskWindow = 10 * time.Minute
	maxStatementAsks   = 1000
)

type statementResult struct {
	Signature string
	SignerAID string
	KelSN     int
}

// statementAsk is one statement asked of a person, as the asker remembers it. In memory only: an Identity
// Agent that restarts forgets it, and the page, which finds the Ask gone, offers to start again.
type statementAsk struct {
	assetID   string
	askBytes  []byte
	siteAID   string
	nonce     string
	statement string
	expires   time.Time
	collector [32]byte

	fetched     bool // the person's device has fetched the Ask
	declined    bool // the person's device said no. Advisory: only a signature settles an Ask
	lastRefusal string
	done        bool
	released    bool
	result      statementResult
}

// maxStatementBody bounds what a page sends to start a statement Ask.
const maxStatementBody = 16 << 10

// startStatementAsk is the public create route's answer to {action: 6, statement, title}: a page of the
// asset's own origin asks, and is given a pointer and the secret that releases the answer.
func (s *CoreServer) startStatementAsk(w http.ResponseWriter, r *http.Request, assetID, statement, title string) {
	askedFrom := r.Header.Get("Origin")
	if askedFrom == "" {
		http.Error(w, "a statement is asked for from a web page", http.StatusBadRequest)
		return
	}
	found, audience, code, msg := s.assetThatMaySign(assetID, "", askedFrom)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	if _, code, why := refuseFrontEnd(*found, "", "", true, false); code != 0 {
		http.Error(w, why, code)
		return
	}
	started, err := s.mintStatementAsk(found, audience, statement, title, s.getPublicURL(r))
	if err != nil {
		var refused *SignInRefused
		if errors.As(err, &refused) {
			http.Error(w, refused.Reason, refused.Code)
			return
		}
		http.Error(w, "could not start a statement", http.StatusInternalServerError)
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]string{
		"session_token":   started.Session,
		"relay_or_qr_url": started.Pointer,
		// Held by the page that started this and by nothing else; required to read the answer.
		"collector_secret": started.Collector,
	})
}

// StatementAsk is a statement asked of a person, as whoever started it is given it.
type StatementAsk struct {
	// Pointer is what the person's Identity Agent opens to fetch the Ask.
	Pointer string
	// Session names the Ask here. Collector is the secret that releases the answer: whoever started
	// the Ask keeps both and shows neither to a browser.
	Session, Collector string
	// SiteAID is the asset the Ask was signed as, which is what the signed bytes name.
	SiteAID string
}

// StartStatementAsk starts a statement Ask as an asset, for an add-on that fronts the asset (an app
// that serves pages): the same Ask the public route starts for a page, for a caller that is code in this
// process. audience is a plain name for what is asking (the app's name), shown to the person.
func (s *CoreServer) StartStatementAsk(assetID, audience, statement, title, publicURL string) (StatementAsk, error) {
	found, aud, code, msg := s.assetThatMaySign(assetID, audience, "")
	if code != 0 {
		return StatementAsk{}, &SignInRefused{code, msg}
	}
	if _, code, why := refuseFrontEnd(*found, asset.FrontEndBrowser, "", false, false); code != 0 {
		return StatementAsk{}, &SignInRefused{code, why}
	}
	return s.mintStatementAsk(found, aud, statement, title, publicURL)
}

// mintStatementAsk makes, signs and keeps the Ask. It refuses, before a pointer exists, whatever the
// person's own Identity Agent would refuse to show: the asker learns now rather than from a wait that
// never ends.
func (s *CoreServer) mintStatementAsk(found *asset.Asset, audience, statement, title, publicURL string) (StatementAsk, error) {
	if !assetMayAskToSign(found) {
		return StatementAsk{}, &SignInRefused{http.StatusForbidden, "this app has not been granted the right to ask a person to sign a statement"}
	}
	if _, err := statements.Show(statement, title); err != nil {
		return StatementAsk{}, &SignInRefused{http.StatusBadRequest, err.Error()}
	}
	if err := shownAudience(audience); err != nil {
		return StatementAsk{}, &SignInRefused{http.StatusBadRequest, "what is asking cannot be shown to a person: " + err.Error()}
	}
	seed, err := asset.AssetSigningSeed(s.DataDir, found.SigningIndex)
	if err != nil {
		return StatementAsk{}, fmt.Errorf("asset seed: %w", err)
	}
	nonceB, sessB, secB := make([]byte, 32), make([]byte, 16), make([]byte, 32)
	for _, b := range [][]byte{nonceB, sessB, secB} {
		if _, err := rand.Read(b); err != nil {
			return StatementAsk{}, err
		}
	}
	token := hex.EncodeToString(sessB)
	now := time.Now().UTC()
	siteOOBI := fmt.Sprintf("%s/public/oobi/%s", publicURL, found.PairwiseAID)
	ask := map[string]interface{}{
		"v": "ASK1", "t": ActionSignStatement,
		"site_aid": found.PairwiseAID, "site_oobi": siteOOBI, "signer_oobi": siteOOBI,
		"audience": audience, "nonce": base64.RawURLEncoding.EncodeToString(nonceB),
		"dt": now.Format(time.RFC3339), "expiry": now.Add(statementAskWindow).Format(time.RFC3339),
		"statement": statement, "session_token": token,
	}
	if title != "" {
		ask["title"] = title
	}
	unsigned, _ := json.Marshal(ask)
	sig, err := login.SignAsk(unsigned, seed)
	if err != nil {
		return StatementAsk{}, fmt.Errorf("sign failed: %w", err)
	}
	signed, err := injectSig(unsigned, sig)
	if err != nil {
		return StatementAsk{}, fmt.Errorf("sign failed: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(secB)
	rec := &statementAsk{
		assetID: found.ID, askBytes: signed, siteAID: found.PairwiseAID, nonce: ask["nonce"].(string),
		statement: statement, expires: now.Add(statementAskWindow), collector: sha256.Sum256([]byte(secret)),
	}
	s.statementMu.Lock()
	defer s.statementMu.Unlock()
	if s.statementAsks == nil {
		s.statementAsks = map[string]*statementAsk{}
	}
	for k, a := range s.statementAsks {
		if now.After(a.expires.Add(time.Minute)) {
			delete(s.statementAsks, k)
		}
	}
	if len(s.statementAsks) >= maxStatementAsks {
		return StatementAsk{}, &SignInRefused{http.StatusTooManyRequests, "too many statements are waiting to be signed"}
	}
	s.statementAsks[token] = rec
	return StatementAsk{Pointer: fmt.Sprintf("%s/i/%s", publicURL, token), Session: token, Collector: secret, SiteAID: found.PairwiseAID}, nil
}

// assetMayAskToSign is whether the asset's grant holds the right to start a statement Ask.
func assetMayAskToSign(a *asset.Asset) bool {
	for _, c := range a.Capabilities {
		if c == CapabilityAskToSign {
			return true
		}
	}
	return false
}

// statementAskBytes is the Ask served at /i/{token}, and notes that a device has fetched it.
func (s *CoreServer) statementAskBytes(token string) ([]byte, bool) {
	s.statementMu.Lock()
	defer s.statementMu.Unlock()
	a, ok := s.statementAsks[token]
	if !ok {
		return nil, false
	}
	a.fetched = true
	return a.askBytes, true
}

// StatementAskResult is how a statement Ask stands.
type StatementAskResult struct {
	// State is "pending", "scanned" (the person's device has the Ask), "declined", "expired" or
	// "verified".
	State string
	// Signature, SignerAID and KelSN are given when verified, and only once.
	Signature, SignerAID string
	KelSN                int
	// Withheld is true for a verified Ask whose answer was already released, or is asked for without
	// the secret.
	Withheld bool
	// LastRefusal is why the last answer was not accepted, for the holder of the secret.
	LastRefusal string
}

// readStatementAsk says how an Ask stands to someone who offers a secret. WHETHER it was signed is not
// the same secret as the signature: anybody who photographs the screen holds the token and may learn
// the state, and only the holder of the collector secret is given the signature, once. ok is false for
// an Ask that is not there or is not the asset's.
func (s *CoreServer) readStatementAsk(siteOrAssetOK func(*statementAsk) bool, token, offered string) (StatementAskResult, bool) {
	s.statementMu.Lock()
	defer s.statementMu.Unlock()
	a, ok := s.statementAsks[token]
	if !ok || !siteOrAssetOK(a) {
		return StatementAskResult{}, false
	}
	sum := sha256.Sum256([]byte(offered))
	held := offered != "" && subtle.ConstantTimeCompare(sum[:], a.collector[:]) == 1
	out := StatementAskResult{State: "pending"}
	switch {
	case a.done && (a.released || !held):
		out.State, out.Withheld = "verified", true
	case a.done:
		a.released = true
		out.State = "verified"
		out.Signature, out.SignerAID, out.KelSN = a.result.Signature, a.result.SignerAID, a.result.KelSN
	case time.Now().After(a.expires):
		out.State = "expired"
	case a.declined:
		out.State = "declined"
	case a.fetched:
		out.State = "scanned"
	}
	if !a.done && held {
		out.LastRefusal = a.lastRefusal
	}
	return out, true
}

// StatementAskResultFor is readStatementAsk for an add-on: only the asset the Ask was started as may
// read it, and a wrong secret reads as the same answer as no such Ask, so a guess learns nothing. The
// state of an Ask is told only with the secret.
func (s *CoreServer) StatementAskResultFor(siteAID, session, collector string) (StatementAskResult, error) {
	res, ok := s.readStatementAsk(func(a *statementAsk) bool { return a.siteAID == siteAID }, session, collector)
	if !ok || collector == "" {
		return StatementAskResult{}, errors.New("no such statement")
	}
	s.statementMu.Lock()
	a := s.statementAsks[session]
	sum := sha256.Sum256([]byte(collector))
	held := subtle.ConstantTimeCompare(sum[:], a.collector[:]) == 1
	s.statementMu.Unlock()
	if !held {
		return StatementAskResult{}, errors.New("no such statement")
	}
	return res, nil
}

// writeStatementStatus answers a page's poll for a statement Ask (the SDK's session read).
func (s *CoreServer) writeStatementStatus(w http.ResponseWriter, r *http.Request, assetID, token string) bool {
	res, ok := s.readStatementAsk(func(a *statementAsk) bool { return a.assetID == assetID }, token, r.Header.Get("X-Collector-Secret"))
	if !ok {
		return false
	}
	resp := map[string]interface{}{"state": res.State}
	if res.State == "pending" {
		resp["state"] = "connecting"
	}
	if res.Withheld {
		resp["identity_withheld"] = true
	}
	if res.Signature != "" {
		resp["signature"], resp["signer_aid"], resp["kel_sn"] = res.Signature, res.SignerAID, res.KelSN
	}
	if res.LastRefusal != "" {
		resp["last_refusal"] = res.LastRefusal
	}
	jsonreply.Write(w, http.StatusOK, resp)
	return true
}

type statementAnswer struct {
	Nonce      string `json:"nonce"`
	Declined   bool   `json:"declined"`
	Signature  string `json:"signature"`
	SignerAID  string `json:"signer_aid"`
	SignerOOBI string `json:"signer_oobi"`
	KelSN      *int   `json:"kel_sn"`
}

// handleStatementCallback takes the person's Identity Agent's answer. A signature that does not hold
// leaves the Ask open, as a refused sign-in does: someone who has seen the QR code can post garbage, and
// must not be able to end the person's wait by doing so.
func (s *CoreServer) handleStatementCallback(w http.ResponseWriter, r *http.Request) {
	body, err := boundedread.All(r.Body, boundedread.Document)
	if err != nil {
		http.Error(w, "bad json", boundedread.Status(err))
		return
	}
	var in statementAnswer
	if err := json.Unmarshal(body, &in); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	token := r.URL.Query().Get("session")
	s.statementMu.Lock()
	a, ok := s.statementAsks[token]
	if !ok {
		s.statementMu.Unlock()
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if a.done {
		s.statementMu.Unlock()
		http.Error(w, "this statement has already been answered", http.StatusConflict)
		return
	}
	if time.Now().After(a.expires) {
		s.statementMu.Unlock()
		http.Error(w, "this statement is no longer open", http.StatusGone)
		return
	}
	siteAID, nonce, statement := a.siteAID, a.nonce, a.statement
	s.statementMu.Unlock()

	if subtle.ConstantTimeCompare([]byte(in.Nonce), []byte(nonce)) != 1 {
		http.Error(w, "this answer is not to this statement", http.StatusUnauthorized)
		return
	}
	if in.Declined {
		s.statementMu.Lock()
		a.declined = true
		s.statementMu.Unlock()
		jsonreply.Write(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	refuse := func(why string, status int) {
		s.statementMu.Lock()
		a.lastRefusal = why
		s.statementMu.Unlock()
		log.Printf("[statement] an answer to a statement was not accepted: %s", why)
		http.Error(w, "not accepted", status)
	}
	if err := s.checkStatementAnswer(siteAID, statement, in); err != nil {
		refuse("the answer did not check against the signer's key", http.StatusUnauthorized)
		log.Printf("[statement] reason: %v", err)
		return
	}
	s.statementMu.Lock()
	if a.done {
		s.statementMu.Unlock()
		http.Error(w, "this statement has already been answered", http.StatusConflict)
		return
	}
	a.done = true
	a.declined = false
	a.result = statementResult{Signature: in.Signature, SignerAID: in.SignerAID, KelSN: *in.KelSN}
	s.statementMu.Unlock()
	jsonreply.Write(w, http.StatusOK, map[string]bool{"ok": true})
}

// checkStatementAnswer says why an answer is not a signature, by the signer's own current key from the
// key log its OOBI serves, over the envelope naming this asker and exactly the statement that was asked.
func (s *CoreServer) checkStatementAnswer(siteAID, statement string, in statementAnswer) error {
	if in.KelSN == nil || *in.KelSN < 0 {
		return fmt.Errorf("no key event sequence number")
	}
	oobiAID := strings.TrimRight(in.SignerOOBI, "/")
	if i := strings.LastIndex(oobiAID, "/"); i >= 0 {
		oobiAID = oobiAID[i+1:]
	}
	if in.SignerAID == "" || oobiAID != in.SignerAID {
		return fmt.Errorf("the signer's OOBI is not for the signer")
	}
	env, err := statements.Envelope(siteAID, statement)
	if err != nil {
		return err
	}
	raw, _, _, err := iacrypto.DecodeEd25519Signature(in.Signature, true)
	if err != nil {
		return fmt.Errorf("not an Ed25519 signature: %w", err)
	}
	pub, err := s.resolveSignerKey(in.SignerOOBI)
	if err != nil {
		return fmt.Errorf("the signer's key: %w", err)
	}
	if !ed25519.Verify(pub, env, raw) {
		return fmt.Errorf("the signature is not over what was asked by this asker")
	}
	return nil
}

// shownAudience is what is asking, as it may be shown to a person: a page's origin, or an app's name,
// as plain text on one line that a page could not use to write its own words on their screen.
func shownAudience(a string) error {
	if a == "" || len(a) > 200 || !utf8.ValidString(a) || !statements.Plain(a) || strings.ContainsRune(a, '\n') {
		return fmt.Errorf("it is empty, too long, or has characters that cannot be shown as they are")
	}
	return nil
}

func (s *CoreServer) mountStatementRoutes(r chi.Router) {
	r.Post("/api/statement/callback", s.handleStatementCallback)
}
