//go:build !linux

package agenthost

// notReadable does nothing here: macOS already keeps one process's
// environment and memory from another without the debugger's permission, and
// Windows runs the brain as the host's own user.
func notReadable() error { return nil }
