//go:build !(linux || freebsd || openbsd || netbsd)

package agenthost

// OpenScreen is not built for this operating system yet: reading and driving
// a Mac's or a Windows machine's screen each need their own system interfaces
// and permissions. Such a body says it has no screen, so nobody is offered a
// button that cannot work.
func OpenScreen(string) (Screen, error) { return nil, ErrNoScreen }
