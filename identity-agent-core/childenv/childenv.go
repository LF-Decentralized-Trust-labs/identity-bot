// Package childenv is the environment a process started by the core is given:
// the core's own, without what must never leave it.
//
// The core reads the secret that makes a local request its owner's from the
// environment at start and removes it there (server.DefaultConfig), so a child
// started afterwards inherits nothing. Every place that starts one also builds
// its environment here, so a child started some other way, or before that
// removal, still never receives it.
package childenv

import (
	"os"
	"strings"
)

// LocalOwnerSecretEnv names the variable an app starting the core hands it the
// local owner secret in.
const LocalOwnerSecretEnv = "IDENTITY_AGENT_LOCAL_OWNER_SECRET"

// withheld are the variables no child is ever given.
var withheld = []string{LocalOwnerSecretEnv}

// Environ is this process's environment for a child.
func Environ() []string { return Without(os.Environ()) }

// Without is env with every withheld variable removed.
func Without(env []string) []string {
	out := make([]string, 0, len(env))
next:
	for _, kv := range env {
		for _, name := range withheld {
			if strings.HasPrefix(kv, name+"=") {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}
