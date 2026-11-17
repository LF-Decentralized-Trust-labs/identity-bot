package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func appVectors(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/seal-app-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The per-app key is the committed bytes other implementations derive it to.
func TestTheAppKeyIsTheCommittedVector(t *testing.T) {
	v := appVectors(t)
	for _, c := range []struct{ app, epoch, priv, pub string }{
		{v["app"], "1", v["private_epoch_1"], v["public_epoch_1"]},
		{v["app"], "2", v["private_epoch_2"], v["public_epoch_2"]},
	} {
		e := uint32(c.epoch[0] - '0')
		priv, pub, err := DeriveAppSealKeypair(hx(t, v["root_seed"]), c.app, e)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(priv) != c.priv || hex.EncodeToString(pub) != c.pub {
			t.Fatalf("epoch %d differs from the committed vector: %x %x", e, priv, pub)
		}
	}
}

// An app's key is nobody else's: not a person's key from the same seed, not another app's or epoch's, and an
// identifier is length-prefixed so one name followed by something is not another.
func TestAnAppKeyIsNotAPersonsOrAnotherAppsOrEpochs(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 64)
	_, one, _ := DeriveAppSealKeypair(seed, "EAppOne", 1)
	_, two, _ := DeriveAppSealKeypair(seed, "EAppTwo", 1)
	_, next, _ := DeriveAppSealKeypair(seed, "EAppOne", 2)
	_, person, _ := DeriveSealKeypair(seed)
	for name, k := range map[string][]byte{"another app": two, "another epoch": next, "a person's key": person} {
		if bytes.Equal(one, k) {
			t.Fatalf("the app's key is the same as %s", name)
		}
	}
	_, a, _ := DeriveAppSealKeypair(seed, "EAB", 1)
	_, b, _ := DeriveAppSealKeypair(seed, "EA", 1)
	if bytes.Equal(a, b) {
		t.Fatal("two identifiers gave one key")
	}
	if _, _, err := DeriveAppSealKeypair(seed[:16], "EAppOne", 1); err == nil {
		t.Fatal("a short seed was accepted")
	}
	if _, _, err := DeriveAppSealKeypair(seed, "", 1); err == nil {
		t.Fatal("no identifier was accepted")
	}
	if _, _, err := DeriveAppSealKeypair(seed, "EAppOne", 0); err == nil {
		t.Fatal("epoch 0 was accepted")
	}
}

// The open reply is the committed bytes the restoring machine checks, and opens there; it is not a slot of either kind.
func TestTheOpenReplyIsTheCommittedVector(t *testing.T) {
	v := appVectors(t)
	digest := hx(t, v["reply_request_digest"])
	got, err := sealOpenReplyWith(hx(t, v["reply_restore_public"]), hx(t, v["reply_content_key"]), digest,
		hx(t, v["reply_ephemeral_private"]), hx(t, v["reply_nonce"]))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != v["reply"] {
		t.Fatalf("the reply differs from the committed vector:\n got %x\nwant %s", got, v["reply"])
	}
	priv := hx(t, v["reply_restore_private"])
	// the restoring machine's way of opening it
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	shared, err := curve25519.X25519(priv, got[:32])
	if err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	hkdf.New(sha256.New, shared, append(append([]byte{}, got[:32]...), pub...), []byte(OpenReplyInfoV1)).Read(kek)
	block, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(block)
	if k, err := gcm.Open(nil, got[32:44], got[44:], digest); err != nil || hex.EncodeToString(k) != v["reply_content_key"] {
		t.Fatalf("the restoring machine cannot open it: %v", err)
	}
	if _, err := gcm.Open(nil, got[32:44], got[44:], bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("a reply opened for another request")
	}
	if _, err := UnsealBEK(priv, got[:32], got[44:], got[32:44]); err == nil {
		t.Fatal("a reply opened as a v1 slot")
	}
	if _, err := UnsealBEKForFile(priv, got[:32], got[44:], got[32:44], digest[:FileIDLen]); err == nil {
		t.Fatal("a reply opened as a v2 slot")
	}
}

// SealSlotForFile makes slots UnsealBEKForFile opens, SlotLen long, and the committed v2 slot is the same
// bytes as the one made with the committed random values.
func TestASlotMadeForAFileOpensAndIsTheCommittedVector(t *testing.T) {
	v := loadSlotVectors(t)
	eph, wrapped, nonce, err := sealBEKForFileWith(v.pub, v.bek, v.fid, v.eph, v.nonce)
	made := append(append(append([]byte{}, eph...), nonce...), wrapped...)
	if err != nil || !bytes.Equal(made, v.slotV2) || len(made) != SlotLen {
		t.Fatalf("the slot differs from the committed v2 vector: %x %v", made, err)
	}
	slot, err := SealSlotForFile(v.pub, v.bek, v.fid)
	if err != nil || len(slot) != SlotLen {
		t.Fatalf("SealSlotForFile: %v", err)
	}
	if k, err := UnsealBEKForFile(v.priv, slot[:32], slot[44:], slot[32:44], v.fid); err != nil || !bytes.Equal(k, v.bek) {
		t.Fatalf("a slot made for a file does not open: %v", err)
	}
	if _, err := SealSlotForFile(v.pub, v.bek, v.fid[:8]); err == nil {
		t.Fatal("a short file id was accepted")
	}
}
