package keriengine

import "testing"

// An identity made under a name is found by its identifier, and one the
// engine does not hold is reported as not held, without an error.
func TestAnIdentityIsFoundUnderTheNameItIsHeldBy(t *testing.T) {
	e := New()
	made, err := e.CreateInceptionNamed(newKey(t), newKey(t), "a-name-of-its-own")
	if err != nil {
		t.Fatal(err)
	}
	name, held, err := e.NameHolding(made.AID)
	if err != nil || !held || name != "a-name-of-its-own" {
		t.Fatalf("found %q (held=%v, %v)", name, held, err)
	}
	if _, held, err := e.NameHolding("ENobodyHere"); held || err != nil {
		t.Fatalf("an identity nobody made is held=%v, %v", held, err)
	}
}
