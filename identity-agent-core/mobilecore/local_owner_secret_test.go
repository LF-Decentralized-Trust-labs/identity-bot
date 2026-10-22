package mobilecore

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"identity-agent-core/server"
)

// The core a phone app starts answers its owner only with the secret the app
// declared, so another app on the phone reaching 127.0.0.1 is not the owner.
func TestThePhoneCoreAnswersItsOwnerOnlyWithTheDeclaredSecret(t *testing.T) {
	secret := strings.Repeat("s", 40)
	if err := DeclareLocalOwnerSecret(secret); err != nil {
		t.Fatal(err)
	}
	defer func() { declaredLocalOwnerSecret = "" }()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if err := StartServer(t.TempDir(), port); err != nil {
		t.Fatal(err)
	}
	defer StopServer()
	base := "http://127.0.0.1:" + strconv.Itoa(GetPort())

	ask := func(withSecret bool) int {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/settings/reachability/relay", nil)
		if withSecret {
			req.Header.Set(server.LocalOwnerSecretHeader, secret)
		}
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ {
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := ask(false); code != http.StatusForbidden {
		t.Fatalf("another app on the phone, without the secret: %d, want 403", code)
	}
	if code := ask(true); code == http.StatusForbidden {
		t.Fatal("the app that declared the secret was refused")
	}
}

func TestAShortSecretIsNotDeclared(t *testing.T) {
	if err := DeclareLocalOwnerSecret("short"); err == nil {
		t.Fatal("a short secret was declared")
	}
}
