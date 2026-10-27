package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// The statement GitHub takes as the App is signed RS256 with the App's key,
// names the App, and holds for less than GitHub's ten-minute limit.
func TestTheAppStatementIsSignedWithTheAppsKey(t *testing.T) {
	k, _ := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	jwt, err := AppJWT(k, 42, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	head, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if string(head) != `{"alg":"RS256","typ":"JWT"}` {
		t.Fatalf("header %s", head)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the statement is not signed by the App's key: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iat, Exp int64
		Iss      string
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if c.Iss != "42" || c.Exp-c.Iat > 600 || c.Exp <= now.Unix() || c.Iat > now.Unix() {
		t.Fatalf("claims %+v", c)
	}
}

// GitHub's own key files are PKCS#1; a key converted to PKCS#8 is read too.
// Anything else is refused, with why.
func TestAnAppKeyIsReadInEitherForm(t *testing.T) {
	k, pkcs1 := testKey(t)
	if _, err := ParsePrivateKey(pkcs1); err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	if _, err := ParsePrivateKey(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "not a key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"} {
		if _, err := ParsePrivateKey(bad); err == nil {
			t.Errorf("%q was taken as a key", bad)
		}
	}
}

func TestARepositoryIsNamedAsOwnerAndName(t *testing.T) {
	for in, want := range map[string]string{
		"Acme/Sandbox": "acme/sandbox", "https://github.com/acme/site.git": "acme/site", " acme/a.b-c_d ": "acme/a.b-c_d",
	} {
		if got, err := NormaliseRepository(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"acme", "acme/", "/x", "acme/x/y", "acme/..", "ac me/x", "acme/x?y"} {
		if _, err := NormaliseRepository(bad); err == nil {
			t.Errorf("%q was taken as a repository", bad)
		}
	}
}

// fakeGitHub answers as GitHub's token route does, with what it is told to.
func fakeGitHub(t *testing.T, answer func(body map[string]any) (int, any)) (*httptest.Server, *[]map[string]any, *[]string) {
	t.Helper()
	var asked []map[string]any
	var revoked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/access_tokens"):
			var body map[string]any
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			asked = append(asked, body)
			code, v := answer(body)
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		case r.Method == "DELETE" && r.URL.Path == "/installation/token":
			revoked = append(revoked, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &asked, &revoked
}

// A token is asked for exactly the repositories named, by name within the
// installation's account, with the access's permissions and no others.
func TestATokenIsAskedForExactlyTheRepositoriesAndAccessNamed(t *testing.T) {
	_, key := testKey(t)
	srv, asked, _ := fakeGitHub(t, func(map[string]any) (int, any) {
		return 201, map[string]any{"token": "ghs_write", "expires_at": time.Now().Add(time.Hour),
			"repositories": []map[string]string{{"full_name": "acme/sandbox"}, {"full_name": "acme/site"}},
			"permissions":  map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}}
	})
	c := Client{API: srv.URL}
	conn := Connection{AppID: 1, InstallationID: 2, PrivateKey: key, Account: "acme"}
	tok, err := c.Mint(context.Background(), conn, []string{"acme/site", "acme/sandbox"}, Write)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "ghs_write" || !reflect.DeepEqual(tok.Repositories, []string{"acme/sandbox", "acme/site"}) {
		t.Fatalf("token %+v", tok)
	}
	got := (*asked)[0]
	if !reflect.DeepEqual(got["repositories"], []any{"sandbox", "site"}) {
		t.Fatalf("repositories asked for: %v", got["repositories"])
	}
	if !reflect.DeepEqual(got["permissions"], map[string]any{"contents": "write", "pull_requests": "write", "metadata": "read"}) {
		t.Fatalf("permissions asked for: %v", got["permissions"])
	}
	if _, err := c.Mint(context.Background(), conn, []string{"other/repo"}, Read); err == nil {
		t.Fatal("a token was asked for a repository outside the installation's account")
	}
}

// A token GitHub made wider than asked — more repositories, or more
// permission — is withdrawn at once and not used.
func TestATokenWiderThanAskedIsWithdrawn(t *testing.T) {
	_, key := testKey(t)
	for name, answer := range map[string]map[string]any{
		"more repositories": {"token": "ghs_wide", "repositories": []map[string]string{{"full_name": "acme/sandbox"}, {"full_name": "acme/secret"}},
			"permissions": map[string]string{"contents": "read", "metadata": "read"}},
		"more permission": {"token": "ghs_wide", "repositories": []map[string]string{{"full_name": "acme/sandbox"}},
			"permissions": map[string]string{"contents": "write", "metadata": "read"}},
	} {
		srv, _, revoked := fakeGitHub(t, func(map[string]any) (int, any) { return 201, answer })
		c := Client{API: srv.URL}
		_, err := c.Mint(context.Background(), Connection{AppID: 1, InstallationID: 2, PrivateKey: key, Account: "acme"},
			[]string{"acme/sandbox"}, Read)
		if err == nil {
			t.Fatalf("%s: a wider token was taken", name)
		}
		if len(*revoked) != 1 || (*revoked)[0] != "ghs_wide" {
			t.Fatalf("%s: the wider token was not withdrawn: %v", name, *revoked)
		}
	}
}

// Withdrawing a token sends it to GitHub's revocation route; one already gone
// counts as withdrawn.
func TestATokenIsWithdrawnAtGitHub(t *testing.T) {
	srv, _, revoked := fakeGitHub(t, nil)
	if err := (Client{API: srv.URL}).Revoke(context.Background(), "ghs_lent"); err != nil {
		t.Fatal(err)
	}
	if len(*revoked) != 1 || (*revoked)[0] != "ghs_lent" {
		t.Fatalf("revoked: %v", *revoked)
	}
	gone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer gone.Close()
	if err := (Client{API: gone.URL}).Revoke(context.Background(), "ghs_gone"); err != nil {
		t.Fatalf("a token already gone: %v", err)
	}
}

// A request is never followed to another address: a redirect is answered as
// it came, so the key's statement or a token goes only where it was sent.
func TestARedirectIsNotFollowed(t *testing.T) {
	_, key := testKey(t)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the request was followed elsewhere, carrying %q", r.Header.Get("Authorization"))
	}))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/app", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if _, err := (Client{API: srv.URL}).Describe(context.Background(), Connection{AppID: 1, InstallationID: 2, PrivateKey: key}); err == nil {
		t.Fatal("a redirect was taken as GitHub's answer")
	}
}
