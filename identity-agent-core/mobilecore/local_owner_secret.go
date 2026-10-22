package mobilecore

import (
	"fmt"
	"strings"
)

// The secret a request from this phone must carry to be the owner's.
//
// Any app on a phone can reach 127.0.0.1, so a request from this device is not
// the owner's by coming from here. The app that embeds the core chooses a
// secret, keeps it for its own requests, and hands it over here; the core then
// answers an owner-only request from this device only when it carries it.
//
// Must be called before StartServer, which reads it once. Left undeclared, the
// core mints one the app cannot know, so nothing on the device is the owner.

var declaredLocalOwnerSecret string

// DeclareLocalOwnerSecret names the secret the next StartServer uses.
func DeclareLocalOwnerSecret(secret string) error {
	secret = strings.TrimSpace(secret)
	if len(secret) < 32 {
		return fmt.Errorf("the local owner secret is %d characters; at least 32 are needed", len(secret))
	}
	mu.Lock()
	declaredLocalOwnerSecret = secret
	mu.Unlock()
	return nil
}
