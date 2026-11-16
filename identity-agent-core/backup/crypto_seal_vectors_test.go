package backup

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// The committed vectors for a backup slot, which other implementations check their slots against
// (reproducing slot_v1 and slot_v2 byte for byte). A change to the construction changes this file: it
// is the one place the construction is asserted.
type slotVectors struct {
	RecipientPrivate string `json:"recipient_private"`
	RecipientPublic  string `json:"recipient_public"`
	EphemeralPrivate string `json:"ephemeral_private"`
	Nonce            string `json:"nonce"`
	ContentKey       string `json:"content_key"`
	FileID           string `json:"file_id"`
	SlotV1           string `json:"slot_v1"`
	SlotV2           string `json:"slot_v2"`
}

func loadSlotVectors(t *testing.T) (v struct {
	priv, pub, eph, nonce, bek, fid, slotV1, slotV2 []byte
}) {
	t.Helper()
	raw, err := os.ReadFile("testdata/seal-slot-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var j slotVectors
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v.priv, v.pub, v.eph, v.nonce = dec(j.RecipientPrivate), dec(j.RecipientPublic), dec(j.EphemeralPrivate), dec(j.Nonce)
	v.bek, v.fid, v.slotV1, v.slotV2 = dec(j.ContentKey), dec(j.FileID), dec(j.SlotV1), dec(j.SlotV2)
	return v
}

func splitSlot(slot []byte) (eph, nonce, wrapped []byte) { return slot[:32], slot[32:44], slot[44:] }

func TestTheCommittedV1SlotOpensWithUnsealBEK(t *testing.T) {
	v := loadSlotVectors(t)
	eph, nonce, wrapped := splitSlot(v.slotV1)
	got, err := UnsealBEK(v.priv, eph, wrapped, nonce)
	if err != nil || !bytes.Equal(got, v.bek) {
		t.Fatalf("UnsealBEK on the committed v1 slot: %x %v", got, err)
	}
	if pub, _ := PublicFromPrivate(v.priv); !bytes.Equal(pub, v.pub) {
		t.Fatal("the committed recipient public key is not the private key's")
	}
}

// The v1 slot is rebuilt here from the same inputs with the same mechanics SealBEK uses (SealBEK itself draws its
// randomness, so it cannot be compared byte for byte): this proves the committed bytes are what the construction makes.
func TestTheCommittedV1SlotIsWhatTheConstructionMakes(t *testing.T) {
	v := loadSlotVectors(t)
	ephPub, _ := PublicFromPrivate(v.eph)
	shared, _ := x25519(v.eph, v.pub)
	kek, err := sealSharedKEK(shared, ephPub, v.pub)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := gcmFor(kek)
	rebuilt := append(append(append([]byte{}, ephPub...), v.nonce...), g.Seal(nil, v.nonce, v.bek, nil)...)
	if !bytes.Equal(rebuilt, v.slotV1) {
		t.Fatalf("the v1 slot is not what the construction makes:\n got %x\nwant %x", rebuilt, v.slotV1)
	}
}

func TestTheCommittedV2SlotIsReproducedByteForByteAndOpens(t *testing.T) {
	v := loadSlotVectors(t)
	eph, wrapped, nonce, err := sealBEKForFileWith(v.pub, v.bek, v.fid, v.eph, v.nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got := append(append(append([]byte{}, eph...), nonce...), wrapped...); !bytes.Equal(got, v.slotV2) {
		t.Fatalf("the v2 slot differs from the committed one:\n got %x\nwant %x", got, v.slotV2)
	}
	e, n, w := splitSlot(v.slotV2)
	got, err := UnsealBEKForFile(v.priv, e, w, n, v.fid)
	if err != nil || !bytes.Equal(got, v.bek) {
		t.Fatalf("UnsealBEKForFile on the committed v2 slot: %x %v", got, err)
	}
}

func TestAV2SlotIsBoundToItsFileAndIsNotAV1Slot(t *testing.T) {
	v := loadSlotVectors(t)
	e, n, w := splitSlot(v.slotV2)
	if _, err := UnsealBEKForFile(v.priv, e, w, n, bytes.Repeat([]byte{0}, FileIDLen)); err == nil {
		t.Fatal("a v2 slot opened for another file")
	}
	if _, err := UnsealBEK(v.priv, e, w, n); err == nil {
		t.Fatal("a v2 slot opened as a v1 slot")
	}
	e1, n1, w1 := splitSlot(v.slotV1)
	if _, err := UnsealBEKForFile(v.priv, e1, w1, n1, v.fid); err == nil {
		t.Fatal("a v1 slot opened as a v2 slot")
	}
}

func TestSealBEKForFileRoundTripsAndDrawsFreshRandomness(t *testing.T) {
	v := loadSlotVectors(t)
	e1, w1, n1, err := sealBEKForFile(v.pub, v.bek, v.fid)
	if err != nil {
		t.Fatal(err)
	}
	e2, w2, n2, _ := sealBEKForFile(v.pub, v.bek, v.fid)
	if bytes.Equal(e1, e2) || bytes.Equal(n1, n2) || bytes.Equal(w1, w2) {
		t.Fatal("two seals of one key were identical: the randomness is not drawn each time")
	}
	if got, err := UnsealBEKForFile(v.priv, e1, w1, n1, v.fid); err != nil || !bytes.Equal(got, v.bek) {
		t.Fatalf("round trip: %v", err)
	}
	if _, _, _, err := sealBEKForFile(v.pub, v.bek, v.fid[:8]); err == nil {
		t.Fatal("a short file id was accepted")
	}
	e, n, w := splitSlot(v.slotV2)
	if _, err := UnsealBEKForFile(v.priv, e, w, n[:8], v.fid); err == nil {
		t.Fatal("a short nonce was accepted (and must not panic)")
	}
}

func x25519(priv, pub []byte) ([]byte, error) { return curve25519.X25519(priv, pub) }
