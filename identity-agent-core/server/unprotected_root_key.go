package server

import (
	"log"
	"os"
	"strings"
	"sync"
)

// envAllowUnprotectedRootKey permits a root seed on hardware that has been
// measured and found to have no way of protecting it.
//
// Named for what it gives up rather than what it enables. A reader who finds
// this set in a config should be able to tell from the name alone that it is
// not a tuning parameter.
const envAllowUnprotectedRootKey = "IA_ALLOW_UNPROTECTED_ROOT_KEY"

var announceUnprotected sync.Once

// allowUnprotectedRootKey reports whether this agent has been told to accept a
// root key it cannot protect.
//
// Says so once at the point of use rather than only at startup, because a
// process that has been running for a month is exactly where a temporary
// arrangement goes to become permanent.
func allowUnprotectedRootKey() bool {
	on := strings.TrimSpace(os.Getenv(envAllowUnprotectedRootKey)) == "1"
	if on {
		announceUnprotected.Do(func() {
			log.Printf("[keystore] %s is set: this agent will hold a root key on hardware that "+
				"cannot protect it. Every identity founded here can be copied by anyone who can "+
				"read the disk, and no rotation undoes that.", envAllowUnprotectedRootKey)
		})
	}
	return on
}

// RootKeyIsUnprotected reports the same fact to anything that needs to record
// or display it, so the arrangement travels with the identity rather than
// living only in a log nobody reads.
func RootKeyIsUnprotected() bool { return allowUnprotectedRootKey() }
