package relayproto

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

func TestCurrentKeyIsTheOneKeyTheLogNamesNow(t *testing.T) {
	id := newIdentity(t)
	first, err := CurrentKey(id.aid, id.kel())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := id.current.PublicKey()
	raw, _ := keri.MatterRaw(keri.CodeEd25519, want, ed25519.PublicKeySize)
	if !first.Equal(ed25519.PublicKey(raw)) {
		t.Fatal("CurrentKey is not the inception key")
	}
	id.rotate()
	after, err := CurrentKey(id.aid, id.kel())
	if err != nil {
		t.Fatal(err)
	}
	if after.Equal(first) {
		t.Fatal("after a rotation CurrentKey still names the key rotated away from")
	}
}

func TestCurrentKeyRefusesAnotherIdentitysLog(t *testing.T) {
	mine, theirs := newIdentity(t), newIdentity(t)
	if _, err := CurrentKey(mine.aid, theirs.kel()); err == nil {
		t.Fatal("another identity's log answered for this one")
	}
}

// A group identity with two signing keys is not enrolled as either of them:
// one member must not be able to act as the whole group.
func TestCurrentKeyRefusesALogWithSeveralKeys(t *testing.T) {
	a, _ := keri.GenerateSigner(true)
	b, _ := keri.GenerateSigner(true)
	na, _ := keri.GenerateSigner(true)
	nb, _ := keri.GenerateSigner(true)
	pa, _ := a.PublicKey()
	pb, _ := b.PublicKey()
	npa, _ := na.PublicKey()
	npb, _ := nb.PublicKey()
	da, _ := keri.NextDigest(npa)
	db, _ := keri.NextDigest(npb)
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pa, pb}, NextDigests: []string{da, db},
		Isith: json.RawMessage(`"2"`), Nsith: json.RawMessage(`"2"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, a, b)
	if err != nil {
		t.Fatal(err)
	}
	kel, err := keri.ExportKEL([][]byte{signed.Message})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CurrentKey(parsed.Identifier, kel); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("a two-key log was accepted as one signer: %v", err)
	}
}

func TestCurrentKeyRefusesAnOversizedLog(t *testing.T) {
	id := newIdentity(t)
	big := append(id.kel(), make([]byte, MaxKELBytes)...)
	if _, err := CurrentKey(id.aid, big); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("an oversized log was not refused for its size: %v", err)
	}
}
