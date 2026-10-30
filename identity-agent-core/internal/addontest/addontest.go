// Package addontest is what one add-on's tests in this module set on
// another add-on, kept out of every add-on's public API. Each hook is set by
// the add-on it reaches when that add-on is imported, and nil otherwise.
package addontest

import (
	"identity-agent-core/sandbox"
	"identity-agent-core/server"
)

// UseSandboxManager makes m the sandbox manager on s, for a server a test
// makes by hand rather than with server.New. Set by sandboxedapps.
var UseSandboxManager func(s *server.CoreServer, m *sandbox.Manager)
