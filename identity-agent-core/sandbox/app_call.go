package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"identity-agent-core/appcall"
)

// Telling an app who called it.
//
// An app that provides a capability is reached only through the Identity
// Agent, which has already decided the caller may make the call. What the app
// still needs is to know who that caller was — an owner or an AI agent, which
// one, from which machine — and to know it from the Identity Agent rather than
// from whoever reached its port. So every forwarded call is stamped under a key
// this Identity Agent keeps for that app alone (package appcall), and the app
// refuses a call that is not.

// appCallKeysDir holds one key per app, readable only by this user.
const appCallKeysDir = "app-call-keys"

var appCallKeyMu sync.Mutex

// AppCallKey is the key this Identity Agent stamps calls to appID with, made
// the first time it is asked for and kept after.
//
// Kept rather than made per launch, so an app that keeps running across a
// restart of the Identity Agent still recognises its calls.
func (m *Manager) AppCallKey(appID string) ([]byte, error) {
	if appID == "" || strings.ContainsAny(appID, `/\`) || strings.Contains(appID, "..") {
		return nil, fmt.Errorf("%q cannot name an app's key", appID)
	}
	appCallKeyMu.Lock()
	defer appCallKeyMu.Unlock()
	dir := filepath.Join(m.dataDir, appCallKeysDir)
	path := filepath.Join(dir, appID+".key")
	raw, err := os.ReadFile(path)
	if err == nil {
		return appcall.DecodeKey(string(raw))
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Unreadable is not absent. Replacing it would leave the running app
		// refusing every call with a key nobody can find out about.
		return nil, fmt.Errorf("the call key for %s could not be read: %w", appID, err)
	}
	k, err := appcall.NewKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(appcall.EncodeKey(k)); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return k, nil
}

// theCallerAnAppIsTold is the caller as the app hears it: what the Identity
// Agent established, and nothing a caller merely asserted except its session,
// which decides nothing here.
func theCallerAnAppIsTold(c CallerContext) appcall.Caller {
	out := appcall.Caller{
		Machine:   c.BodyHost,
		AuthLevel: c.AuthLevel,
		Grant:     c.GrantSAID,
		Session:   c.Session,
	}
	switch {
	case c.Owner || c.CallerAID == "local-owner":
		out.Kind = appcall.KindOwner
		if c.CallerAID != "local-owner" {
			out.Agent = c.CallerAID
		}
		if out.AuthLevel == "" {
			out.AuthLevel = "local"
		}
	case len(c.DelegationChain) > 0 || c.BodyHost != "":
		out.Kind = appcall.KindAIAgent
		out.Agent = c.CallerAID
		if c.AuthLevel == "signed_headers" {
			// A machine the identity owns, identified by its signature and
			// granted nothing for it.
			out.Kind = appcall.KindMachine
		}
	case strings.HasPrefix(c.CallerAID, "token:"):
		out.Kind = appcall.KindToken
		out.Agent = strings.TrimPrefix(c.CallerAID, "token:")
	default:
		out.Kind = appcall.KindToken
		out.Agent = c.CallerAID
	}
	return out
}
