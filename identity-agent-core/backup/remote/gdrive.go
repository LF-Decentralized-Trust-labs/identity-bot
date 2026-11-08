package remote

import (
	"bytes"
	"context"
	"crypto/sha256"
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
)

// Google Drive as a backup destination.
//
// SCOPE. The only scope ever asked for is drive.appdata: a hidden folder that
// belongs to this app's OAuth client, which the app can read and write and which
// holds nothing of the person's own files — and which the app can see nothing
// outside of. drive.file would also work and shows the files in the person's
// Drive; the hidden folder is the narrower grant and is what is used. The
// consequence is that the archive is only reachable by the same "app" as
// Google counts it. Google's documentation says the folder is created per
// third-party app and does not say whether that means per OAuth client id or per
// Cloud project; a community report says per project. UNVERIFIED: until a file
// written with the desktop client has been listed with the iOS and Android
// clients on one account, assume nothing, and keep every client in ONE Cloud
// project (see GoogleAppDataScope).
//
// WHAT IS UPLOADED is the archive the core already made, encrypted before it
// reaches this file. Nothing here can read it and nothing here needs to.
//
// DETECTING A CHANGED ARCHIVE. Each upload records the SHA-256 of the bytes in
// the file's appProperties, and a download is compared with it. That catches an
// archive altered or truncated in the drive by something that did not also
// rewrite the property; an attacker who can rewrite both is stopped one layer
// further in, because the archive is authenticated and does not open.

// GoogleAppDataScope is the one scope this backend uses.
const maxArchiveBytes = 1 << 30

// A listing is bounded, as a download is. The folder is the person's account to
// write to, and a listing that follows pages without end is memory without end.
// A backup folder holds one file per backup, so these are far above any real one.
const (
	maxListedFiles = 20000
	maxListPages   = 50
)

const GoogleAppDataScope = "https://www.googleapis.com/auth/drive.appdata"

// Errors a caller can tell apart, because each needs a different thing said to
// the person.
var (
	// ErrSignInExpired: Google no longer honours the stored grant (revoked, the
	// password changed, unused for six months, or the consent screen is in
	// testing and the grant is a week old). Only the person signing in again fixes it.
	ErrSignInExpired = errors.New("google drive: sign in again — the stored sign-in is no longer accepted")
	// ErrDriveFull: the account has no room for the archive.
	ErrDriveFull = errors.New("google drive: the account is out of storage space")
	// ErrArchiveChanged: what came back is not what was uploaded.
	ErrArchiveChanged = errors.New("google drive: the archive in the drive is not the one that was uploaded")
)

// GoogleEndpoints are where the three Google services live. The zero value is
// Google. Only code that constructs a backend directly can change them — they
// are deliberately not reachable from a destination's saved configuration,
// because the refresh token goes to whatever the token URL is.
type GoogleEndpoints struct {
	Token  string // OAuth token endpoint
	API    string // Drive v3 base, e.g. https://www.googleapis.com/drive/v3
	Upload string // Drive upload base, e.g. https://www.googleapis.com/upload/drive/v3
	Revoke string // OAuth revoke endpoint
}

func (e GoogleEndpoints) withDefaults() GoogleEndpoints {
	if e.Token == "" {
		e.Token = "https://oauth2.googleapis.com/token"
	}
	if e.API == "" {
		e.API = "https://www.googleapis.com/drive/v3"
	}
	if e.Upload == "" {
		e.Upload = "https://www.googleapis.com/upload/drive/v3"
	}
	if e.Revoke == "" {
		e.Revoke = "https://oauth2.googleapis.com/revoke"
	}
	return e
}

// RevokeGoogleToken asks Google to cancel a token, best effort. Used when a
// grant is received and then refused, so a refused grant does not stay live in
// the person's account.
func RevokeGoogleToken(ctx context.Context, ep GoogleEndpoints, client *http.Client, token string) {
	if token == "" {
		return
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.withDefaults().Revoke,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

type googleDriveBackend struct {
	ep     GoogleEndpoints
	creds  CredentialSecrets
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	access  string
	expires time.Time
}

// NewGoogleDriveBackend returns a Backend over the person's Drive app-data
// folder. client may be nil.
func NewGoogleDriveBackend(dest DestinationConfig, creds CredentialSecrets, ep GoogleEndpoints, client *http.Client) (Backend, error) {
	_ = dest
	if creds.OAuthRefreshToken == "" || creds.OAuthClientID == "" {
		return nil, fmt.Errorf("google_drive destination requires a signed-in Google account")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	return &googleDriveBackend{ep: ep.withDefaults(), creds: creds, client: client, now: time.Now}, nil
}

// token returns a usable access token, renewing it when it has expired or is
// about to. force renews regardless — used after Drive answers 401.
func (b *googleDriveBackend) token(ctx context.Context, force bool) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !force && b.access != "" && b.now().Before(b.expires.Add(-30*time.Second)) {
		return b.access, nil
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {b.creds.OAuthRefreshToken},
		"client_id":     {b.creds.OAuthClientID},
	}
	if b.creds.OAuthClientSecret != "" {
		form.Set("client_secret", b.creds.OAuthClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.ep.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		// invalid_grant is Google saying the grant is dead. Anything else
		// (a 5xx, a network blip) is worth retrying and is not that.
		if out.Error == "invalid_grant" || out.Error == "invalid_client" || out.Error == "unauthorized_client" {
			return "", fmt.Errorf("%w (%s)", ErrSignInExpired, out.Error)
		}
		return "", fmt.Errorf("google token refresh %d: %s", resp.StatusCode, out.Error)
	}
	b.access = out.AccessToken
	b.expires = b.now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return b.access, nil
}

// do sends a request with a bearer token, renewing once on a 401. build is
// called per attempt so a body can be sent twice.
func (b *googleDriveBackend) do(ctx context.Context, build func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		tok, err := b.token(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		req, err := build()
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := b.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
}

// driveError turns a failed Drive response into an error, naming the cases a
// person has to act on.
func driveError(what string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var e struct {
		Error struct {
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	for _, x := range e.Error.Errors {
		switch x.Reason {
		case "storageQuotaExceeded":
			return fmt.Errorf("%w (%s)", ErrDriveFull, what)
		case "authError", "invalid_grant":
			return fmt.Errorf("%w (%s)", ErrSignInExpired, what)
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w (%s)", ErrSignInExpired, what)
	}
	return fmt.Errorf("google drive %s %d: %s", what, resp.StatusCode, e.Error.Message)
}

func (b *googleDriveBackend) Push(ctx context.Context, objectKey string, data []byte) error {
	meta, _ := json.Marshal(map[string]any{
		"name":          objectKey,
		"parents":       []string{"appDataFolder"},
		"mimeType":      "application/octet-stream",
		"appProperties": map[string]string{"sha256": sha256Hex(data), "size": fmt.Sprint(len(data))},
	})
	// Resumable, so a large archive is one request to start and one to send and
	// the size is not a case.
	start, err := b.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			b.ep.Upload+"/files?uploadType=resumable&fields=id", bytes.NewReader(meta))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
		req.Header.Set("X-Upload-Content-Type", "application/octet-stream")
		req.Header.Set("X-Upload-Content-Length", fmt.Sprint(len(data)))
		return req, nil
	})
	if err != nil {
		return err
	}
	defer start.Body.Close()
	if start.StatusCode != http.StatusOK {
		return driveError("start upload", start)
	}
	session := start.Header.Get("Location")
	if session == "" {
		return fmt.Errorf("google drive start upload: no upload location returned")
	}
	// The session URL carries its own authority, so it is sent with the token
	// too (Google accepts both) only because do() adds it; a stand-in need not
	// care.
	put, err := b.do(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, session, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		return req, nil
	})
	if err != nil {
		return err
	}
	defer put.Body.Close()
	if put.StatusCode < 200 || put.StatusCode >= 300 {
		return driveError("upload", put)
	}
	return nil
}

type driveFile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	ModifiedTime  string            `json:"modifiedTime"`
	AppProperties map[string]string `json:"appProperties"`
}

// files lists the app-data folder's files, following pages.
func (b *googleDriveBackend) files(ctx context.Context, q string) ([]driveFile, error) {
	var all []driveFile
	pageToken := ""
	for pages := 1; ; pages++ {
		v := url.Values{
			"spaces":   {"appDataFolder"},
			"fields":   {"nextPageToken,files(id,name,modifiedTime,appProperties)"},
			"pageSize": {"1000"},
			"q":        {q},
		}
		if pageToken != "" {
			v.Set("pageToken", pageToken)
		}
		resp, err := b.do(ctx, func() (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodGet, b.ep.API+"/files?"+v.Encode(), nil)
		})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			err := driveError("list", resp)
			resp.Body.Close()
			return nil, err
		}
		var page struct {
			NextPageToken string      `json:"nextPageToken"`
			Files         []driveFile `json:"files"`
		}
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, page.Files...)
		if page.NextPageToken == "" {
			return all, nil
		}
		if pages >= maxListPages || len(all) >= maxListedFiles {
			return nil, fmt.Errorf("google drive: the folder lists more than %d files over %d pages, "+
				"which is not a backup folder; refusing to read further", maxListedFiles, maxListPages)
		}
		pageToken = page.NextPageToken
	}
}

func (b *googleDriveBackend) List(ctx context.Context, prefix string) ([]string, error) {
	files, err := b.files(ctx, "trashed=false")
	if err != nil {
		return nil, err
	}
	prefix = strings.Trim(prefix, "/")
	seen := map[string]bool{}
	var keys []string
	for _, f := range files {
		if prefix != "" && !strings.HasPrefix(f.Name, prefix+"/") {
			continue
		}
		if !seen[f.Name] {
			seen[f.Name] = true
			keys = append(keys, f.Name)
		}
	}
	return keys, nil
}

// Pull returns the archive in memory. Large restores use PullTo.
func (b *googleDriveBackend) Pull(ctx context.Context, objectKey string) ([]byte, error) {
	var buf bytes.Buffer
	if err := b.PullTo(ctx, objectKey, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PullTo streams the archive to w, never holding it in memory, and checks it
// against the digest recorded when it was uploaded. On any error, including a
// digest that does not match, what was already written to w is not to be used.
func (b *googleDriveBackend) PullTo(ctx context.Context, objectKey string, w io.Writer) error {
	esc := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(objectKey)
	files, err := b.files(ctx, "trashed=false and name='"+esc+"'")
	if err != nil {
		return err
	}
	var newest *driveFile
	for i := range files {
		if files[i].Name == objectKey && (newest == nil || files[i].ModifiedTime > newest.ModifiedTime) {
			newest = &files[i]
		}
	}
	if newest == nil {
		return fmt.Errorf("google drive: %q not found", objectKey)
	}
	resp, err := b.do(ctx, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet,
			b.ep.API+"/files/"+url.PathEscape(newest.ID)+"?alt=media", nil)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return driveError("download", resp)
	}
	// An archive is megabytes; a gigabyte is not one.
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return err
	}
	if n > maxArchiveBytes {
		return fmt.Errorf("google drive: %q is larger than any archive this agent writes", objectKey)
	}
	// An archive with no recorded digest was not written by this backend, and
	// is not accepted as if it were.
	want := newest.AppProperties["sha256"]
	if want == "" || want != hex.EncodeToString(h.Sum(nil)) {
		return fmt.Errorf("%w: %q", ErrArchiveChanged, objectKey)
	}
	return nil
}
