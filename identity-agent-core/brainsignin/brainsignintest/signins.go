// Package brainsignintest builds the sign-in files Codex and Grok write, for
// tests of what is done with them.
package brainsignintest

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// jwt is an unsigned token carrying claims, as a sign-in file holds them.
func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

// CodexSignIn is a Codex auth.json for the ChatGPT account account, as Codex
// writes it.
func CodexSignIn(account, email, refresh string) string {
	b, _ := json.Marshal(map[string]any{
		"OPENAI_API_KEY": nil,
		"tokens": map[string]any{
			"id_token": jwt(map[string]any{"email": email, "sub": "user-" + email,
				"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": account}}),
			"access_token":  jwt(map[string]any{"exp": time.Now().Add(time.Hour).Unix()}),
			"refresh_token": refresh,
			"account_id":    account,
		},
		"last_refresh": time.Now().UTC().Format(time.RFC3339),
	})
	return string(b)
}

// GrokSignIn is a Grok auth.json for the xAI user user, as Grok writes it.
func GrokSignIn(user, email, key string) string {
	b, _ := json.Marshal(map[string]any{
		"https://auth.x.ai::client": map[string]any{
			"key": key, "auth_mode": "oidc", "user_id": user, "email": email,
			"refresh_token": "r-" + key, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	})
	return string(b)
}
