package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"identity-agent-core/childenv"
	"identity-agent-core/permission"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Being at this computer is not enough to be its owner.
//
// A request that comes from this machine used to be the owner's by that fact
// alone: loopback, no forwarding headers, not issued by a web page. That is
// true of every program on the machine, and of every app on a phone, where
// any app may reach 127.0.0.1. So the core is started with a secret, and a
// request from this computer is the owner's only when it carries it.
//
// The app that starts the core chooses the secret and hands it over (the
// environment on a desktop, the start call on a phone) so it holds it before
// the core answers anything. A core started by hand mints its own. Either way
// it is written to the data directory, readable by this user alone, for the
// scripts and tools a person runs beside it.
//
// THE LIMIT. A program running as the same user can read that file, or the
// environment of the process that started the core. The boundary this draws
// is the operating-system user: a program that must not act as the owner has
// to run as a different one.

// LocalOwnerSecretHeader carries the secret on a request from this computer.
const LocalOwnerSecretHeader = "X-Local-Owner-Secret"

// LocalOwnerSecretEnv names the environment variable an app starting the
// core uses to hand it the secret.
const LocalOwnerSecretEnv = childenv.LocalOwnerSecretEnv

// LocalOwnerSecretFile is the file in the data directory holding the secret
// this core was started with.
const LocalOwnerSecretFile = "local-owner-secret"

// minLocalOwnerSecretLen is the shortest secret accepted: 32 characters of
// base64 carry 192 bits.
const minLocalOwnerSecretLen = 32

// establishLocalOwnerSecret settles the secret this start of the core uses,
// given, or minted when none was, and writes it where local tools find it.
func establishLocalOwnerSecret(dataDir, given string) (string, error) {
	secret := strings.TrimSpace(given)
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("mint a local owner secret: %w", err)
		}
		secret = base64.RawURLEncoding.EncodeToString(b)
	} else if len(secret) < minLocalOwnerSecretLen {
		return "", fmt.Errorf("the local owner secret is %d characters; at least %d are needed",
			len(secret), minLocalOwnerSecretLen)
	}
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return "", err
		}
		path := filepath.Join(dataDir, LocalOwnerSecretFile)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(secret+"\n"), 0o600); err != nil {
			return "", fmt.Errorf("write the local owner secret: %w", err)
		}
		// WriteFile keeps an existing file's mode, so set it explicitly.
		if err := os.Chmod(tmp, 0o600); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, path); err != nil {
			return "", fmt.Errorf("write the local owner secret: %w", err)
		}
		if msg := windowsSecretExposure(runtime.GOOS, dataDir, os.Getenv); msg != "" {
			log.Printf("[identity-agent-core] *** %s ***", msg)
		}
	}
	return secret, nil
}

// windowsSecretExposure says when the secret file may be readable by other
// users, or "" when it is not.
//
// On Windows a file's mode means little: who may read it is decided by the
// folder it inherits its access list from. A data directory inside the user's
// own profile inherits one only that user (and administrators) can read. One
// anywhere else, such as a shared folder or the root of a drive, may let every
// user on the machine read the secret, and so act as this identity's owner.
func windowsSecretExposure(goos, dataDir string, getenv func(string) string) string {
	if goos != "windows" {
		return ""
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		abs = dataDir
	}
	for _, v := range []string{"USERPROFILE", "LOCALAPPDATA", "APPDATA"} {
		root := getenv(v)
		if root == "" {
			continue
		}
		if rel, err := filepath.Rel(root, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return ""
		}
	}
	return fmt.Sprintf("the data directory %s is outside this user's profile, so other users of this computer may be able to read %s and act as this identity's owner; keep AGENT_DATA_DIR under the user profile",
		abs, LocalOwnerSecretFile)
}

// LocalOwnerSecret is the secret a request from this computer must carry to be
// the owner's, for an embedder that starts the core and talks to it.
func (s *CoreServer) LocalOwnerSecret() string { return s.localOwnerSecret }

// isLocalOwnerRequest reports whether r comes from this computer AND carries
// the secret this core was started with.
func (s *CoreServer) isLocalOwnerRequest(r *http.Request) bool {
	return isLocalConnection(r) && s.presentsLocalOwnerSecret(r)
}

func (s *CoreServer) presentsLocalOwnerSecret(r *http.Request) bool {
	got := r.Header.Get(LocalOwnerSecretHeader)
	return s.localOwnerSecret != "" && got != "" &&
		subtle.ConstantTimeCompare([]byte(got), []byte(s.localOwnerSecret)) == 1
}

// takeLocalOwnerSecretFromEnv reads the secret an app handed over in the
// environment and removes it there, so no process this one starts inherits it.
func takeLocalOwnerSecretFromEnv() string {
	v := os.Getenv(LocalOwnerSecretEnv)
	_ = os.Unsetenv(LocalOwnerSecretEnv)
	return v
}

// Before an app sends the secret anywhere it makes sure what it is talking to
// is the core it started. Another program can be listening on the port the app
// expects (on a phone, any app can take one before the core does), and a
// secret sent there is a secret given away. So the app asks for a proof first:
// a MAC, keyed by the secret, of a nonce it just chose and of the port this
// core is listening on. Only the holder of the secret can make it, and binding
// the port means a program on the expected port cannot pass a request through
// to the real core on another port and hand back that core's answer as its own.

// LocalOwnerProof is the MAC a core holding secret answers nonce with, when
// listening on port.
func LocalOwnerProof(secret, nonce string, port int) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "identity-agent local owner proof\n%d\n%s", port, nonce)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *CoreServer) handleLocalOwnerProof(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if len(nonce) < 16 || len(nonce) > 128 {
		writeError(w, http.StatusBadRequest, "A nonce is needed",
			"ask with a fresh nonce of 16 to 128 characters")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"port":  s.Port,
		"proof": LocalOwnerProof(s.localOwnerSecret, nonce, s.Port),
	})
}

// hasForwardingHeaders reports whether a request arrived through a tunnel/proxy —
// in which case a loopback RemoteAddr must NOT be trusted as the local owner.
//
// X-IA-Via-Ingress is the relay marker the Identity Agent sets itself on every
// request it serves from a relay stream (relayproto.AgentSession.Serve), so a
// relay-forwarded request is never mistaken for the genuinely-local owner. The others are added by the
// standard proxies/tunnels (Cloudflare, ngrok, an HTTP reverse proxy). Presence
// of any of these means the request came from outside, so the owner must prove
// it with a signature rather than being trusted for arriving on loopback.
func hasForwardingHeaders(r *http.Request) bool {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Cf-Connecting-Ip", "True-Client-Ip", "Forwarded", "X-IA-Via-Ingress"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// isBrowserOriginated reports whether this request was issued by a web page
// rather than by a program running on this machine.
//
// A page loaded from anywhere reaches 127.0.0.1 as a loopback connection with
// no forwarding headers, so by the old test every website in the world was the
// owner of this Identity Agent. Visiting a page was enough to read the roster, the
// invitation secrets and the identity.
//
// What separates the two is that a browser describes itself and cannot be
// talked out of it. Origin and the Sec-Fetch-* family are forbidden header
// names: they are set by the browser, and page script cannot change or remove
// them. A native client on this machine sends none of them.
//
// This does not defend against another program on the machine — that program
// already has the user's files and does not need the API. The browser is the
// caller this closes.
func isBrowserOriginated(r *http.Request) bool {
	if r.Header.Get("Origin") != "" {
		return true
	}
	// Sec-Fetch-Site is "none" for a request the user typed into the address
	// bar; anything else is a page acting on its own initiative.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "none" {
		return true
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode == "cors" || mode == "no-cors" {
		return true
	}
	return r.Header.Get("Sec-Fetch-Dest") != ""
}

// isLocalConnection reports whether r was made by a program on this computer:
// a loopback connection, no forwarding headers, and not issued by a web page.
// That says where the request came from and nothing about who sent it; being
// the owner also takes the secret the core was started with
// (CoreServer.isLocalOwnerRequest).
func isLocalConnection(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return permission.IsLoopbackHost(host) &&
		!hasForwardingHeaders(r) &&
		!isBrowserOriginated(r)
}
