package server

import "testing"

// A production build stores a root key only on proven-usable hardware; a
// development build also stores one on a machine with no usable key store,
// because that is what the machines developer mode runs on. Tested directly
// because the build mode is fixed per test binary, so the handler path exercises
// only the production branch.
func TestRootKeyMayLiveHere(t *testing.T) {
	if !rootKeyMayLiveHere(true, false) {
		t.Fatal("a production build must store a root key on proven-usable hardware")
	}
	if rootKeyMayLiveHere(false, false) {
		t.Fatal("a production build must refuse a root key on a machine with no usable key store")
	}
	if !rootKeyMayLiveHere(false, true) {
		t.Fatal("a development build must store a root key even with no usable key store")
	}
	if !rootKeyMayLiveHere(true, true) {
		t.Fatal("a development build must still store a root key on usable hardware")
	}
}
