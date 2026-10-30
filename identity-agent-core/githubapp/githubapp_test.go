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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"identity-agent-core/githubrepo"
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

// A token is asked for exactly the repositories named, by GitHub's numbers
// for them, with the access's permissions and no others.
func TestATokenIsAskedForExactlyTheRepositoriesAndAccessNamed(t *testing.T) {
	_, key := testKey(t)
	srv, asked, _ := fakeGitHub(t, func(map[string]any) (int, any) {
		return 201, map[string]any{"token": "ghs_write", "expires_at": time.Now().Add(time.Hour), "repository_selection": "selected",
			"repositories": []map[string]any{{"id": 11, "full_name": "acme/sandbox"}, {"id": 12, "full_name": "Acme/Site"}},
			"permissions":  map[string]string{"contents": "write", "pull_requests": "write", "metadata": "read"}}
	})
	c := Client{API: srv.URL}
	conn := Connection{AppID: 1, InstallationID: 2, PrivateKey: key, Account: "acme"}
	tok, err := c.Mint(context.Background(), conn, []RepoRef{{12, "acme/site"}, {11, "acme/sandbox"}}, githubrepo.Write)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "ghs_write" || !reflect.DeepEqual(tok.Repositories, []string{"acme/sandbox", "acme/site"}) ||
		!reflect.DeepEqual(tok.RepositoryIDs, []int64{11, 12}) {
		t.Fatalf("token %+v", tok)
	}
	got := (*asked)[0]
	if !reflect.DeepEqual(got["repository_ids"], []any{float64(11), float64(12)}) || got["repositories"] != nil {
		t.Fatalf("repositories asked for: %v", got)
	}
	if !reflect.DeepEqual(got["permissions"], map[string]any{"contents": "write", "pull_requests": "write", "metadata": "read"}) {
		t.Fatalf("permissions asked for: %v", got["permissions"])
	}
	if _, err := c.Mint(context.Background(), conn, []RepoRef{{13, "other/repo"}}, githubrepo.Read); err == nil {
		t.Fatal("a token was asked for a repository outside the installation's account")
	}
	if _, err := c.Mint(context.Background(), conn, []RepoRef{{0, "acme/sandbox"}}, githubrepo.Read); err == nil {
		t.Fatal("a token was asked for a repository by name alone")
	}
	if _, err := c.Mint(context.Background(), conn, []RepoRef{{11, "acme/sandbox"}, {11, "acme/site"}}, githubrepo.Read); err == nil {
		t.Fatal("a token was asked for two repositories at one number")
	}
}

// A token GitHub made wider than asked — another repository, a repository by
// the same name that is not the one asked for, every repository, none named,
// or more permission or less than asked — is withdrawn at once and not used.
func TestATokenWiderThanAskedIsWithdrawn(t *testing.T) {
	_, key := testKey(t)
	read := map[string]string{"contents": "read", "metadata": "read"}
	sandbox := []map[string]any{{"id": 11, "full_name": "acme/sandbox"}}
	for name, answer := range map[string]map[string]any{
		"more repositories": {"token": "ghs_wide", "repository_selection": "selected", "permissions": read,
			"repositories": []map[string]any{{"id": 11, "full_name": "acme/sandbox"}, {"id": 99, "full_name": "acme/secret"}}},
		"a repository made again under the same name": {"token": "ghs_wide", "repository_selection": "selected", "permissions": read,
			"repositories": []map[string]any{{"id": 77, "full_name": "acme/sandbox"}}},
		// The grant named acme/sandbox with acme/secret's number.
		"another repository at the number granted": {"token": "ghs_wide", "repository_selection": "selected", "permissions": read,
			"repositories": []map[string]any{{"id": 11, "full_name": "acme/secret"}}},
		"every repository":    {"token": "ghs_wide", "repository_selection": "all", "permissions": read, "repositories": sandbox},
		"no repository named": {"token": "ghs_wide", "repository_selection": "selected", "permissions": read},
		"more permission": {"token": "ghs_wide", "repository_selection": "selected", "repositories": sandbox,
			"permissions": map[string]string{"contents": "write", "metadata": "read"}},
		"another permission": {"token": "ghs_wide", "repository_selection": "selected", "repositories": sandbox,
			"permissions": map[string]string{"contents": "read", "metadata": "read", "issues": "read"}},
		"an access it does not know": {"token": "ghs_wide", "repository_selection": "selected", "repositories": sandbox,
			"permissions": map[string]string{"contents": "admin", "metadata": "read"}},
	} {
		srv, _, revoked := fakeGitHub(t, func(map[string]any) (int, any) { return 201, answer })
		c := Client{API: srv.URL}
		_, err := c.Mint(context.Background(), Connection{AppID: 1, InstallationID: 2, PrivateKey: key, Account: "acme"},
			[]RepoRef{{11, "acme/sandbox"}}, githubrepo.Read)
		if err == nil {
			t.Fatalf("%s: a wider token was taken", name)
		}
		if len(*revoked) != 1 || (*revoked)[0] != "ghs_wide" {
			t.Fatalf("%s: the wider token was not withdrawn: %v", name, *revoked)
		}
	}
}

// Every page of repositories is read, however many there are.
func TestEveryRepositoryTheAppReachesIsListed(t *testing.T) {
	_, key := testKey(t)
	const total = 5234
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_list"})
		case r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			var page int
			_, _ = fmt.Sscanf(r.URL.Query().Get("page"), "%d", &page)
			var repos []map[string]any
			for i := (page - 1) * 100; i < page*100 && i < total; i++ {
				repos = append(repos, map[string]any{"id": i + 1, "full_name": fmt.Sprintf("acme/r%05d", i)})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"total_count": total, "repositories": repos})
		}
	}))
	defer srv.Close()
	got, err := (Client{API: srv.URL}).Repositories(context.Background(), Connection{AppID: 1, InstallationID: 2, PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != total || got[total-1].ID == 0 {
		t.Fatalf("%d of %d repositories listed", len(got), total)
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
