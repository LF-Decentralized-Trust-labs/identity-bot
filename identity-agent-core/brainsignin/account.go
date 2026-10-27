package brainsignin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Which account a sign-in is, so that every sign-in of one subscription
// account shares one cap on simultaneous runs, whichever AI agents hold it.
//
// A sign-in that names its account says so itself: Codex's and Grok's sign-in
// files carry the account they were made for. A Claude sign-in token and an
// API key name nothing the Identity Agent may read without using them, and it
// must not use a Claude subscription's token itself, so those are told apart
// by a fingerprint of the token: the same token is the same account. Two
// tokens made separately for one Claude account are two fingerprints, so a
// screen offers to reuse a sign-in an AI agent already has rather than making
// another.

// SignInFile is what a subscription's sign-in file says about itself.
type SignInFile struct {
	// Account is who it is for, as the person knows it: an email.
	Account string
	// AccountID is the provider's identifier of the account.
	AccountID string
	// Subject is who signed in, as the provider names them: the subject of
	// Codex's identity token, or Grok's user.
	Subject string
	// AccessExpires is when the access token in it lapses. The program
	// refreshes it, so this is not when the sign-in stops working.
	AccessExpires *time.Time
}

// ReadSignInFile reads a Codex or Grok sign-in file — the auth.json the
// program writes when a person signs in — and refuses anything else, so a
// pasted token or a half-copied file is caught when it is set rather than at
// the first run.
func ReadSignInFile(provider, content string) (SignInFile, error) {
	switch provider {
	case Codex:
		return readCodexSignIn(content)
	case Grok:
		return readGrokSignIn(content)
	}
	return SignInFile{}, fmt.Errorf("%s has no sign-in file", provider)
}

func readCodexSignIn(content string) (SignInFile, error) {
	var f struct {
		Tokens *struct {
			IDToken      string `json:"id_token"`
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			AccountID    string `json:"account_id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(content), &f); err != nil || f.Tokens == nil ||
		(f.Tokens.AccessToken == "" && f.Tokens.RefreshToken == "") {
		return SignInFile{}, errors.New("a Codex sign-in is the auth.json Codex writes when you sign in with ChatGPT, " +
			"and this is not one")
	}
	out := SignInFile{AccountID: f.Tokens.AccountID}
	var id struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
		Auth    struct {
			AccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if jwtClaims(f.Tokens.IDToken, &id) {
		out.Account, out.Subject = id.Email, id.Subject
		if out.AccountID == "" {
			out.AccountID = id.Auth.AccountID
		}
	}
	var access struct {
		Exp int64 `json:"exp"`
	}
	if jwtClaims(f.Tokens.AccessToken, &access) && access.Exp > 0 {
		t := time.Unix(access.Exp, 0).UTC()
		out.AccessExpires = &t
	}
	return out, nil
}

// readGrokSignIn reads Grok's auth.json, which holds a sign-in per issuer.
// The one that holds a token is the account in use. A file holding tokens for
// more than one account is refused rather than one picked from it, so which
// account runs never depends on the order a file was read in.
func readGrokSignIn(content string) (SignInFile, error) {
	var f map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &f); err != nil || len(f) == 0 {
		return SignInFile{}, errors.New("a Grok sign-in is the auth.json Grok writes when you sign in, and this is not one")
	}
	type entry struct {
		Key          string `json:"key"`
		RefreshToken string `json:"refresh_token"`
		UserID       string `json:"user_id"`
		Email        string `json:"email"`
		ExpiresAt    string `json:"expires_at"`
	}
	var found []entry
	for _, raw := range f {
		var e entry
		if json.Unmarshal(raw, &e) != nil || (e.Key == "" && e.RefreshToken == "") {
			continue
		}
		found = append(found, e)
	}
	switch {
	case len(found) == 0:
		return SignInFile{}, errors.New("this Grok sign-in holds no token; sign in again")
	case len(found) > 1:
		for _, e := range found[1:] {
			if e.UserID != found[0].UserID || e.Email != found[0].Email {
				return SignInFile{}, errors.New("this Grok sign-in holds more than one account; sign out of Grok, " +
					"sign in with the one account the agent should use, and try again")
			}
		}
		return SignInFile{}, errors.New("this Grok sign-in holds more than one token for its account; sign out of " +
			"Grok, sign in again, and try again")
	}
	e := found[0]
	out := SignInFile{Account: e.Email, AccountID: e.UserID, Subject: e.UserID}
	if t, err := time.Parse(time.RFC3339, e.ExpiresAt); err == nil {
		t = t.UTC()
		out.AccessExpires = &t
	}
	return out, nil
}

// SameSignInAs says why a sign-in file a program refreshed is not for the
// same person and account as the one it was lent, or nil when it is: the
// account and the subject it names must both match, and the lent one must
// name an account. The tokens' signatures are not verified — the Identity
// Agent does not fetch the providers' keys to check them — so this stops a
// mistaken or substituted file for another account, not one forged to name
// this one.
func SameSignInAs(provider, lent, refreshed string) error {
	was, err := ReadSignInFile(provider, lent)
	if err != nil {
		return err
	}
	now, err := ReadSignInFile(provider, refreshed)
	if err != nil {
		return err
	}
	switch {
	case was.AccountID == "":
		return errors.New("the sign-in lent names no account, so a refreshed one cannot be matched to it")
	case now.AccountID != was.AccountID:
		return errors.New("it is for another account")
	case now.Subject != was.Subject:
		return errors.New("it is for another person on the account")
	}
	return nil
}

// jwtClaims reads a JSON Web Token's claims without checking its signature:
// they are used only to name the account, never to trust anything.
func jwtClaims(token string, into any) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	return json.Unmarshal(b, into) == nil
}

// Fingerprint names a secret without revealing it: the same secret for the
// same provider is the same fingerprint, and nothing about the secret can be
// learned from it.
func Fingerprint(provider, secret string) string {
	h := sha256.Sum256([]byte("brain sign-in fingerprint\x00" + provider + "\x00" + secret))
	return hex.EncodeToString(h[:16])
}

// Pool is the account whose runs a cap counts: the account the sign-in names,
// or else the sign-in itself, by its fingerprint. Every sign-in in one pool
// shares one count of runs. Empty for a sign-in with neither, such as a model
// server with no key, which each AI agent counts on its own.
func (r Record) Pool() string {
	if r.AccountID != "" {
		return r.Provider + "/account/" + r.AccountID
	}
	if r.Secret != "" {
		return r.Provider + "/secret/" + Fingerprint(r.Provider, r.Secret)
	}
	return ""
}

// Identify fills in the account a subscription's sign-in file names, so the
// record can be pooled with every other sign-in of that account, and labels it
// with the account's email when the person gave no label.
func (r *Record) Identify() {
	if r.Kind != KindSubscription || (r.Provider != Codex && r.Provider != Grok) {
		r.AccountID = ""
		return
	}
	f, err := ReadSignInFile(r.Provider, r.Secret)
	if err != nil {
		return
	}
	r.AccountID = f.AccountID
	if r.Account == "" {
		r.Account = f.Account
	}
}
