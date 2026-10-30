// Package hostlink holds the token server.AddonHost and server.AddonFixtures
// ask for, so that only this module, which can make one, reaches the server's
// side of the add-on handle (internal/addonhost).
package hostlink

// Token is what server.AddonHost and server.AddonFixtures ask for.
//
// Only a token made by New is accepted. Code elsewhere cannot name the type,
// so writes no value that converts to it; and what it can still conjure
// without naming it, a zero Token (inferred from the function's own parameter
// by a generic call, or made by reflect), is refused, because only New sets
// the field that makes a token this module's. Nothing short of unsafe makes
// one elsewhere.
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
