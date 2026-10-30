// Package hostlink holds the token server.AddonHost and server.AddonFixtures
// ask for. Packages addon and addon/addontest make one, so they are the one
// way to the add-on handle and the core's test fixtures. It is a safeguard: it
// keeps the handle from being reached by accident, and keeps it out of
// programs that include no add-on. It is not a security boundary (see Token).
package hostlink

// Token is what server.AddonHost and server.AddonFixtures ask for.
//
// Only a token made by New is accepted. Code that cannot import this package
// cannot name the type, so writes no value that converts to it; and the zero
// Token it can still conjure without naming it (inferred from the function's
// own parameter by a generic call, or made by reflect) is refused, because
// only New sets the field that makes a token this module's. So code in any
// other module reaches the handle through package addon, the published
// plug-in point, and not by calling the server directly.
//
// What it is not: a boundary against code an app chooses to link. Any module
// may import package addon, which is the point of it: an add-on is code the
// app's maker chose to include. Go's internal packages are kept by import
// path, and this module's path is the bare identity-agent-core, so a module
// declaring itself identity-agent-core/<anything> imports this package
// directly; and code in the same process can always reach anything through
// unsafe or its memory. An app's builder decides what is trusted, by choosing
// the add-ons and other code it links.
type Token struct{ key *sentinel }

type sentinel struct{ _ byte }

// theKey is what a token made here carries.
var theKey = &sentinel{}

// New is a token of this module's.
func New() Token { return Token{key: theKey} }

// Valid reports whether t was made by New.
func (t Token) Valid() bool { return t.key == theKey }

// Refuse panics unless t was made by New. what names the function asked.
func Refuse(t Token, what string) {
	if !t.Valid() {
		panic(what + ": the token is not this module's: only identity-agent-core reaches the add-on handle")
	}
}
