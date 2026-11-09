// Package fakedrive is a stand-in for the parts of Google's OAuth token
// endpoint and Drive v3 API that the backup uses, so tests never need a real
// account. It is test support: nothing in a running agent imports it.
package fakedrive

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"identity-agent-core/backup/remote"
)

const Scope = remote.GoogleAppDataScope

type file struct {
	ID, Name string
	Data     []byte
	Props    map[string]string
	Modified time.Time
}

// Drive is the stand-in. Fields are set by tests while it runs.
type Drive struct {
	Server *httptest.Server

	mu sync.Mutex
	// ClientID is the only OAuth client the token endpoint accepts.
	ClientID string
	// GrantedScope is what a code exchange reports as granted.
	GrantedScope string
	// OmitRefreshToken makes a code exchange return no refresh token.
	OmitRefreshToken bool
	// Full makes every upload fail as an account with no room does.
	Full bool

	refreshToken string
	accessTokens map[string]bool
	codes        map[string]string // code -> PKCE challenge
	files        []*file
	seq          int

	// Counters, for tests that check what was asked of Google.
	Refreshes, Uploads, Downloads int
	// Revoked are the tokens the app asked Google to cancel.
	Revoked []string
	// PageSize, when set, makes listings come in pages of this size.
	PageSize int
}

func New(clientID string) *Drive {
	d := &Drive{ClientID: clientID, GrantedScope: Scope, accessTokens: map[string]bool{}, codes: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", d.token)
	mux.HandleFunc("/revoke", d.revoke)
	mux.HandleFunc("/drive/v3/files", d.list)
	mux.HandleFunc("/drive/v3/files/", d.download)
	mux.HandleFunc("/upload/drive/v3/files", d.startUpload)
	mux.HandleFunc("/session/", d.finishUpload)
	d.Server = httptest.NewServer(mux)
	return d
}

func (d *Drive) Close() { d.Server.Close() }

func (d *Drive) Endpoints() remote.GoogleEndpoints {
	return remote.GoogleEndpoints{Token: d.Server.URL + "/token", API: d.Server.URL + "/drive/v3", Upload: d.Server.URL + "/upload/drive/v3", Revoke: d.Server.URL + "/revoke"}
}

// IssueCode is the person signing in and Google returning a code to the app.
// challenge is the code_challenge from the authorisation URL.
func (d *Drive) IssueCode(challenge string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seq++
	c := fmt.Sprintf("code-%d", d.seq)
	d.codes[c] = challenge
	return c
}

// GrantRefreshToken is a person having already signed in: it returns the
// refresh token the app would hold.
func (d *Drive) GrantRefreshToken() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seq++
	d.refreshToken = fmt.Sprintf("refresh-%d", d.seq)
	return d.refreshToken
}

// ExpireAccessTokens makes every access token handed out so far stop working,
// as an hour passing does.
func (d *Drive) ExpireAccessTokens() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.accessTokens = map[string]bool{}
}

// RevokeGrant is the person removing the app from their Google account.
func (d *Drive) RevokeGrant() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshToken = ""
	d.accessTokens = map[string]bool{}
}

// Tamper changes the stored bytes of a file without touching its recorded digest.
func (d *Drive) Tamper(name string, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.files {
		if f.Name == name {
			f.Data = data
		}
	}
}

// TamperAll rewrites bytes AND the recorded digest, as someone with full access
// to the app's folder could.
func (d *Drive) TamperAll(name string, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.files {
		if f.Name == name {
			f.Data = data
			sum := sha256.Sum256(data)
			f.Props["sha256"] = fmt.Sprintf("%x", sum)
		}
	}
}

// StripDigest removes the recorded digest, as a file written by something else has none.
func (d *Drive) StripDigest(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.files {
		if f.Name == name {
			delete(f.Props, "sha256")
		}
	}
}

func (d *Drive) Names() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for _, f := range d.files {
		out = append(out, f.Name)
	}
	return out
}

func (d *Drive) Bytes(name string) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.files {
		if f.Name == name {
			return append([]byte(nil), f.Data...)
		}
	}
	return nil
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func driveErr(w http.ResponseWriter, code int, reason, msg string) {
	jsonOut(w, code, map[string]any{"error": map[string]any{
		"code": code, "message": msg, "errors": []map[string]string{{"reason": reason}}}})
}

func (d *Drive) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d.mu.Lock()
	defer d.mu.Unlock()
	t := r.Form.Get("token")
	d.Revoked = append(d.Revoked, t)
	if t == d.refreshToken {
		d.refreshToken = ""
	}
	delete(d.accessTokens, t)
	w.WriteHeader(200)
}

func (d *Drive) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Form.Get("client_id") != d.ClientID {
		jsonOut(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		challenge, ok := d.codes[r.Form.Get("code")]
		delete(d.codes, r.Form.Get("code"))
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			jsonOut(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		d.seq++
		access := fmt.Sprintf("access-%d", d.seq)
		d.accessTokens[access] = true
		out := map[string]any{"access_token": access, "expires_in": 3600, "scope": d.GrantedScope, "token_type": "Bearer"}
		if !d.OmitRefreshToken {
			d.refreshToken = fmt.Sprintf("refresh-%d", d.seq)
			out["refresh_token"] = d.refreshToken
		}
		jsonOut(w, 200, out)
	case "refresh_token":
		if d.refreshToken == "" || r.Form.Get("refresh_token") != d.refreshToken {
			jsonOut(w, 400, map[string]string{"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
			return
		}
		d.Refreshes++
		d.seq++
		access := fmt.Sprintf("access-%d", d.seq)
		d.accessTokens[access] = true
		jsonOut(w, 200, map[string]any{"access_token": access, "expires_in": 3600, "scope": d.GrantedScope, "token_type": "Bearer"})
	default:
		jsonOut(w, 400, map[string]string{"error": "unsupported_grant_type"})
	}
}

// authorised reports whether the request carries a live access token, and
// answers 401 as Drive does when it does not.
func (d *Drive) authorised(w http.ResponseWriter, r *http.Request) bool {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	d.mu.Lock()
	ok := d.accessTokens[tok]
	d.mu.Unlock()
	if !ok {
		driveErr(w, 401, "authError", "Invalid Credentials")
	}
	return ok
}

func (d *Drive) startUpload(w http.ResponseWriter, r *http.Request) {
	if !d.authorised(w, r) {
		return
	}
	var meta struct {
		Name          string            `json:"name"`
		Parents       []string          `json:"parents"`
		AppProperties map[string]string `json:"appProperties"`
	}
	body, _ := io.ReadAll(r.Body)
	if json.Unmarshal(body, &meta) != nil || len(meta.Parents) != 1 || meta.Parents[0] != "appDataFolder" {
		driveErr(w, 400, "invalid", "uploads must go to the appDataFolder")
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Full {
		driveErr(w, 403, "storageQuotaExceeded", "The user's Drive storage quota has been exceeded.")
		return
	}
	d.seq++
	f := &file{ID: fmt.Sprintf("file-%d", d.seq), Name: meta.Name, Props: meta.AppProperties, Modified: time.Now().Add(time.Duration(d.seq) * time.Second)}
	d.files = append(d.files, f)
	// Unfinished until bytes arrive: keep it out of listings.
	f.Data = nil
	w.Header().Set("Location", d.Server.URL+"/session/"+f.ID)
	w.WriteHeader(200)
}

func (d *Drive) finishUpload(w http.ResponseWriter, r *http.Request) {
	if !d.authorised(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/session/")
	data, _ := io.ReadAll(r.Body)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Full {
		driveErr(w, 403, "storageQuotaExceeded", "The user's Drive storage quota has been exceeded.")
		return
	}
	for _, f := range d.files {
		if f.ID == id {
			f.Data = data
			d.Uploads++
			jsonOut(w, 200, map[string]string{"id": f.ID})
			return
		}
	}
	driveErr(w, 404, "notFound", "no such upload")
}

func (d *Drive) list(w http.ResponseWriter, r *http.Request) {
	if !d.authorised(w, r) {
		return
	}
	if r.URL.Query().Get("spaces") != "appDataFolder" {
		driveErr(w, 403, "insufficientPermissions", "this scope only reaches the appDataFolder")
		return
	}
	q := r.URL.Query().Get("q")
	want := ""
	if i := strings.Index(q, "name='"); i >= 0 {
		want = q[i+len("name='") : strings.LastIndex(q, "'")]
		want = strings.NewReplacer(`\'`, `'`, `\\`, `\`).Replace(want)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []map[string]any
	for _, f := range d.files {
		if f.Data == nil || (want != "" && f.Name != want) {
			continue
		}
		out = append(out, map[string]any{"id": f.ID, "name": f.Name,
			"modifiedTime": f.Modified.UTC().Format(time.RFC3339Nano), "appProperties": f.Props})
	}
	next := ""
	if d.PageSize > 0 {
		start := 0
		fmt.Sscanf(r.URL.Query().Get("pageToken"), "p%d", &start)
		if start > len(out) {
			start = len(out)
		}
		end := start + d.PageSize
		if end < len(out) {
			next = fmt.Sprintf("p%d", end)
		} else {
			end = len(out)
		}
		out = out[start:end]
	}
	resp := map[string]any{"files": out}
	if next != "" {
		resp["nextPageToken"] = next
	}
	jsonOut(w, 200, resp)
}

func (d *Drive) download(w http.ResponseWriter, r *http.Request) {
	if !d.authorised(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/drive/v3/files/")
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, f := range d.files {
		if f.ID == id && f.Data != nil {
			d.Downloads++
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(f.Data)
			return
		}
	}
	driveErr(w, 404, "notFound", "file not found")
}
