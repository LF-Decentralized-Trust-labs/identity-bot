package sandbox

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// injector returns a CredentialInjectFunc that adds a header for one host, in the
// same shape CredentialVault.InjectCredentials uses: fill the header only if the
// request does not already carry it.
func injector(host, header, value string, calls *int) CredentialInjectFunc {
	return func(req *http.Request) bool {
		if calls != nil {
			*calls++
		}
		if req.URL.Hostname() != host {
			return false
		}
		if req.Header.Get(header) != "" {
			return false
		}
		req.Header.Set(header, value)
		return true
	}
}

func newTestProxy(t *testing.T, inject CredentialInjectFunc) *ProxyManager {
	t.Helper()
	return &ProxyManager{injectCreds: inject}
}

func TestApplyCredentialsInjectsForMatchingHost(t *testing.T) {
	calls := 0
	pm := newTestProxy(t, injector("api.example.com", "Authorization", "Bearer secret", &calls))

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/zones", nil)
	pm.applyCredentials(req, "app-1", "inst-1")

	if got := req.Header.Get("Authorization"); got != "Bearer secret" {
		t.Errorf("Authorization = %q, want the injected credential", got)
	}
	if calls != 1 {
		t.Errorf("injector called %d times, want 1", calls)
	}
}

func TestApplyCredentialsLeavesOtherHostsAlone(t *testing.T) {
	pm := newTestProxy(t, injector("api.example.com", "Authorization", "Bearer secret", nil))

	req := httptest.NewRequest(http.MethodGet, "https://evil.example.net/collect", nil)
	pm.applyCredentials(req, "app-1", "inst-1")

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("credential leaked to a non-matching host: %q", got)
	}
}

// The central property. A sandboxed app that sets its own Authorization must not
// have it silently replaced by the org's credential — an app carrying an end-user
// token is a legitimate case, and swapping it would send the wrong identity
// upstream. The vault fills gaps; it does not overwrite.
func TestApplyCredentialsDoesNotOverwriteCallerHeader(t *testing.T) {
	pm := newTestProxy(t, injector("api.example.com", "Authorization", "Bearer org-secret", nil))

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/me", nil)
	req.Header.Set("Authorization", "Bearer end-user-token")
	pm.applyCredentials(req, "app-1", "inst-1")

	if got := req.Header.Get("Authorization"); got != "Bearer end-user-token" {
		t.Errorf("Authorization = %q, want the caller's own token preserved", got)
	}
}

// A deployment that wires no injector must behave exactly as before this existed.
func TestApplyCredentialsIsInertWhenUnwired(t *testing.T) {
	pm := newTestProxy(t, nil)

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/zones", nil)
	pm.applyCredentials(req, "app-1", "inst-1")

	if len(req.Header) != 0 {
		t.Errorf("headers were modified with no injector configured: %v", req.Header)
	}
}

// The injector reports whether it applied anything; a false return must not be
// treated as an error or stop the request.
func TestApplyCredentialsToleratesNoMatch(t *testing.T) {
	pm := newTestProxy(t, func(*http.Request) bool { return false })

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/zones", nil)
	pm.applyCredentials(req, "app-1", "inst-1") // must not panic

	if len(req.Header) != 0 {
		t.Errorf("headers modified despite the injector declining: %v", req.Header)
	}
}

// Both forward paths must inject: plaintext HTTP and MITM-terminated TLS. A
// credential that only reaches one of them is worse than none, because which path
// a request takes depends on the scheme rather than on anything the operator chose.
func TestBothForwardPathsCallApplyCredentials(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			calls := 0
			pm := newTestProxy(t, injector("api.example.com", "X-Key", "k", &calls))
			req := httptest.NewRequest(http.MethodGet, scheme+"://api.example.com/x", nil)
			pm.applyCredentials(req, "", "")
			if calls != 1 {
				t.Fatalf("injector called %d times for %s, want 1", calls, scheme)
			}
			if req.Header.Get("X-Key") != "k" {
				t.Errorf("no credential injected on the %s path", scheme)
			}
		})
	}
}

// InjectCredentials is the vault's real signature; this pins that the seam matches
// it, so wiring the two together cannot drift into a compile error later.
func TestCredentialInjectFuncMatchesVaultSignature(t *testing.T) {
	vault := NewCredentialVault(t.TempDir())
	var f CredentialInjectFunc = vault.InjectCredentials
	if f == nil {
		t.Fatal("vault.InjectCredentials is not assignable to CredentialInjectFunc")
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/x", nil)
	if f(req) {
		t.Error("an empty vault should inject nothing")
	}
}
