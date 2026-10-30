// Package hostlink holds the token server.AddonHost asks for, so that only
// this module, which can name it, reaches the server's side of the add-on
// handle (internal/addonhost).
package hostlink

// Token is what server.AddonHost asks for. Nothing outside this module can
// name it, so nothing outside this module can make one.
type Token struct{}
