// Package hostlink holds the token server.AddonHost and server.AddonFixtures
// ask for. It is a naming device, not a guard: packages addon and
// addon/addontest are the only code that makes one, so every use of the
// add-on handle is found through package addon, and every use of the test
// fixtures goes through addontest.New, which refuses a program that is not a
// test.
package hostlink

// Token is what server.AddonHost and server.AddonFixtures ask for. Code that
// cannot import this package cannot name the type, and a zero Token conjured
// without naming it (by a generic call, or by reflect) is refused, because
// only New sets the field that makes it this module's.
//
// It keeps nothing from code an app chooses to link. Any module may import
// package addon, which is its purpose; a module declaring itself
// identity-agent-core/<anything> may import this package; and code in the
// same process can reach anything through unsafe.
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
