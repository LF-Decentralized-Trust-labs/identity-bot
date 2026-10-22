package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
const LocalOwnerSecretEnv = "IDENTITY_AGENT_LOCAL_OWNER_SECRET"

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
	}
	return secret, nil
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
