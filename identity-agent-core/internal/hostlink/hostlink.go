// Package hostlink is how internal/addonhost reaches the server's side of the
// add-on handle without the server importing addonhost, which imports it.
package hostlink

// Of is set by the server package when it starts: it returns the server's
// handle on core, a *server.CoreServer, which may be nil for the helpers that
// need no server. Only internal/addonhost calls it.
var Of func(core any) any
