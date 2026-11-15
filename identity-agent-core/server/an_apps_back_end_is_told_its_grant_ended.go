package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"identity-agent-core/asset"
)

// Revocation is pushed (ADR-072 section 6, Amendment 9). When an installed app's
// grant ends, by any road (the person, the owner, the owner switching the front end
// off, a member removed, the app itself), the core tells the app's back end, so it
// ends that person's sessions at once instead of at its next standing check.
//
// The notice is signed with the app's own asset key (the identifier the person's
// link names), which the back end already holds the key for; it is posted to the
// address the sign-in was approved for (the audience the back end itself named
// when it started the sign-in) at login's GrantEndedPath. The wire shape and the
// check are packages/login-go's (grant_ended.go) and both run
// packages/login-web/test-vectors/grant-ended.json.
//
// Telling the back end never holds up ending the grant, and never replaces the
// core's own refusal at each use: the grant is already gone here when the notice
// is sent. A back end that cannot be reached is tried again a few times, then left
// to its standing check, which asks whether the key still speaks (within a minute).
//
// Only an installed app's grant is pushed: a front end that lapses within a working
// day keeps no address, and is left to the back end's standing check (Amendment 9,
// "Not built").

const grantEndedPath = "/identity-agent/grant-ended"

// grantEndedBackoff is the wait before each attempt. A variable so a test need not wait.
var grantEndedBackoff = []time.Duration{0, 2 * time.Second, 10 * time.Second, 60 * time.Second}

// grantEndedNotice is the wire body, held to login-go's GrantEnded.
type grantEndedNotice struct {
	V         int    `json:"v"`
	Asset     string `json:"asset"`
	Key       string `json:"key"`
	Person    string `json:"person"`
	Issued    string `json:"issued"`
	Signature string `json:"signature"`
}

// grantEndedStatement is what the asset's key signs, held to login-go's GrantEndedStatement.
func grantEndedStatement(assetAID, key, person, issued string) []byte {
	return []byte("identity-agent grant-ended v1\n" + assetAID + "\n" + key + "\n" + person + "\n" + issued)
}

func signGrantEnded(seed []byte, assetAID, key, person string, at time.Time) grantEndedNotice {
	issued := at.UTC().Format("2006-01-02T15:04:05Z")
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), grantEndedStatement(assetAID, key, person, issued))
	return grantEndedNotice{V: 1, Asset: assetAID, Key: key, Person: person, Issued: issued,
		Signature: base64.RawURLEncoding.EncodeToString(sig)}
}

// pushOrigin is the address a notice goes to, or why not: an https origin and
// nothing more (no user, path, query or fragment), because the address came from
// the app and the core is the one that will call it.
func pushOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.Contains(origin, " ") {
		return "", errors.New("the address is not an https origin")
	}
	return "https://" + u.Host, nil
}

// refusePrivate stops a dial to an address that is not a public one: the core
// must not be made to call its own machine or a network behind it by an app that
// names such an address. It runs on the address actually dialled, after DNS.
func refusePrivate(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("%s is not a public address", host)
	}
	return nil
}

// grantPushHTTP is the client a notice is sent with: the one a test gives, or one
// that dials public addresses only, follows no redirect and gives up in ten seconds.
func (s *CoreServer) grantPushHTTP() *http.Client {
	if s.grantPushClient != nil {
		return s.grantPushClient
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, Control: refusePrivate}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// tellBackEndsGrantsEnded is browserKeys.ended: it starts one push for each grant
// that had an address, and returns at once.
func (s *CoreServer) tellBackEndsGrantsEnded(gone []browserKeyRecord) {
	for _, r := range gone {
		if r.Push == "" {
			continue
		}
		go s.tellBackEnd(r)
	}
}

func (s *CoreServer) tellBackEnd(r browserKeyRecord) {
	origin, err := pushOrigin(r.Push)
	if err != nil {
		log.Printf("[identity-agent-core] not telling the back end of %s its grant ended: %v", r.Asset, err)
		return
	}
	if s.assetHandler == nil || s.assetHandler.Store == nil {
		return
	}
	a, found, err := s.assetHandler.Store.GetAsset(r.Asset)
	if err != nil || !found || a.PairwiseAID == "" {
		return
	}
	seed, err := asset.AssetSigningSeed(s.DataDir, a.SigningIndex)
	if err != nil {
		log.Printf("[identity-agent-core] could not sign a grant-ended notice for %s: %v", r.Asset, err)
		return
	}
	ctx := s.AppCtx
	if ctx == nil {
		ctx = context.Background()
	}
	var last error
	for _, wait := range grantEndedBackoff {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		// Signed afresh each time, so a late attempt is not refused as stale.
		body, _ := json.Marshal(signGrantEnded(seed, a.PairwiseAID, r.Thumbprint, r.Person, time.Now()))
		last = s.postGrantEnded(ctx, origin+grantEndedPath, body)
		var refused *refusedNotice
		if last == nil || errors.As(last, &refused) {
			break
		}
	}
	if last != nil {
		log.Printf("[identity-agent-core] the back end of %s was not told a grant ended (it will find out at its standing check): %v", r.Asset, last)
	}
}

type refusedNotice struct{ code int }

func (e *refusedNotice) Error() string {
	return fmt.Sprintf("the back end refused the notice with %d", e.code)
}

func (s *CoreServer) postGrantEnded(ctx context.Context, to string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, to, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.grantPushHTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// A 4xx other than a timeout or a rate limit is the back end's answer, and the
	// same notice would be refused again.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout && resp.StatusCode != http.StatusTooManyRequests {
		return &refusedNotice{resp.StatusCode}
	}
	return fmt.Errorf("the back end answered %d", resp.StatusCode)
}
