package server

import (
	"strings"
	"testing"
)

// The check used to return nil whenever the signature or the signer was absent,
// so an Ask carrying neither was accepted on the strength of the address it came
// from. Among the actions that skipped it was the invitation that decides who
// owns an organisation.
func TestAnUnsignedAskIsRefused(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}

	for _, c := range []struct{ name, ask string }{
		{"add contact, unsigned", `{"v":"ASK1","t":2}`},
		{"add employee, unsigned", `{"v":"ASK1","t":3}`},
		{"add signer, unsigned — decides who owns an organisation", `{"v":"ASK1","t":4}`},
		{"signed but naming no signer", `{"v":"ASK1","t":2,"sig":"AAAA"}`},
		{"naming a signer but unsigned", `{"v":"ASK1","t":2,"signer_oobi":"https://x/oobi"}`},
	} {
		err := s.verifyAskSignature([]byte(c.ask))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), "not signed") {
			t.Errorf("%s: refused for the wrong reason: %v", c.name, err)
		}
	}
}

// An action this agent does not know cannot state how it authenticates itself,
// so there is no way to decide whether it did.
func TestAnUnknownActionIsRefused(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	if err := s.verifyAskSignature([]byte(`{"v":"ASK1","t":9999,"sig":"AAAA","signer_oobi":"https://x"}`)); err == nil {
		t.Fatal("an unknown action was accepted")
	}
	if err := s.verifyAskSignature([]byte(`not json`)); err == nil {
		t.Fatal("something that is not an Ask was accepted")
	}
}

// Login legitimately carries no base-layer signature, because it checks the
// asker harder than this layer could — against the key the site's own address
// publishes, plus a delegation anchor where claimed. So does a computer asking
// to act for an identity, whose offer is checked against the key its
// identifier is. Each has to say so in code rather than by omission.
func TestLoginDeclaresThatItVerifiesItself(t *testing.T) {
	s := &CoreServer{localOwnerSecret: testOwnerSecret, DataDir: t.TempDir()}
	if err := s.verifyAskSignature([]byte(`{"v":"ASK1","t":1}`)); err != nil {
		t.Fatalf("login was refused: %v", err)
	}

	h, ok := lookupAsk(1)
	if !ok {
		t.Fatal("login is not registered")
	}
	a, ok := h.(AskAuthenticator)
	if !ok || a.AskAuth() != authSelfVerifying {
		t.Error("login passes without a signature but does not declare why")
	}

	// Exactly these actions establish the asker themselves: login, and a
	// computer asking to act for an identity, whose offer is signed by the key
	// its identifier is. Any other registered action must NOT be, or it
	// silently opts out of the check this test exists to enforce.
	selfVerifying := map[int]bool{1: true, ActionActForIdentity: true}
	for ty, h := range askRegistry {
		a, ok := h.(AskAuthenticator)
		declares := ok && a.AskAuth() == authSelfVerifying
		if declares != selfVerifying[ty] {
			t.Errorf("action %d (%s): self-verifying is %v, want %v", ty, h.Action(), declares, selfVerifying[ty])
		}
	}
}
