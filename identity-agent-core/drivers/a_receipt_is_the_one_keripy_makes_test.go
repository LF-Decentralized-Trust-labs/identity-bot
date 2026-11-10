package drivers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// vector is what keripy 1.3.6 produced: see interop/make_witness_receipt_vectors.py.
type vector struct {
	Controller string   `json:"controller"`
	EventSAID  string   `json:"event_said"`
	EventB64   string   `json:"event_b64"`
	Witnesses  []string `json:"witnesses"`
	Receipts   []struct {
		Witness    string `json:"witness"`
		SeedB64    string `json:"seed_b64"`
		Index      int    `json:"index"`
		ReceiptB64 string `json:"receipt_b64"`
		Attachment string `json:"attachment"`
	} `json:"receipts"`
	// Later events of the same log: a rotation that changed the witness list,
	// and an event whose sequence number is written in hex.
	Later []struct {
		SN        int      `json:"sn"`
		EventSAID string   `json:"event_said"`
		EventB64  string   `json:"event_b64"`
		Witnesses []string `json:"witnesses"`
		Receipts  []struct {
			Witness    string `json:"witness"`
			SeedB64    string `json:"seed_b64"`
			Index      int    `json:"index"`
			ReceiptB64 string `json:"receipt_b64"`
			Attachment string `json:"attachment"`
		} `json:"receipts"`
	} `json:"later"`
}

func loadVector(t *testing.T) (vector, []byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/keripy_witness_receipts.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(v.EventB64)
	return v, raw
}

// indexedSigOf is the signature in keripy's attachment: -VAX (group), -BAB (one
// witness-indexed signature), then the 88-character indexed signature.
func indexedSigOf(t *testing.T, attachment string) string {
	t.Helper()
	if !strings.HasPrefix(attachment, "-VAX-BAB") || len(attachment) != 8+88 {
		t.Fatalf("not the attachment shape keripy writes: %q", attachment)
	}
	return attachment[8:]
}

// Our receipt is keripy's receipt, byte for byte, and our signature is keripy's.
func TestOurReceiptIsTheOneKeripyMakes(t *testing.T) {
	v, raw := loadVector(t)
	for _, r := range v.Receipts {
		want, _ := base64.StdEncoding.DecodeString(r.ReceiptB64)
		got, err := ReceiptMessage(v.Controller, 0, v.EventSAID)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("receipt differs from keripy's:\n ours   %s\n keripy %s", got, want)
		}
		seed, _ := base64.StdEncoding.DecodeString(r.SeedB64)
		sig, err := SignEventReceipt(raw, seed, r.Index)
		if err != nil {
			t.Fatal(err)
		}
		if sig != indexedSigOf(t, r.Attachment) {
			t.Fatalf("signature of witness %d differs from keripy's:\n ours   %s\n keripy %s",
				r.Index, sig, indexedSigOf(t, r.Attachment))
		}
	}
}

// What keripy's own Hab.witness signed is accepted, at its place in the list and
// by no other, and not for another event.
func TestAKeripyReceiptVerifies(t *testing.T) {
	v, raw := loadVector(t)
	for _, r := range v.Receipts {
		sig := indexedSigOf(t, r.Attachment)
		if err := VerifyEventReceipt(r.Witness, raw, v.EventSAID, sig, v.Witnesses); err != nil {
			t.Fatalf("keripy's receipt from witness %d is refused: %v", r.Index, err)
		}
		other := v.Witnesses[1-r.Index]
		if VerifyEventReceipt(other, raw, v.EventSAID, sig, v.Witnesses) == nil {
			t.Fatal("a receipt was accepted as another witness's")
		}
		changed := append([]byte(nil), raw...)
		changed[len(changed)-5] ^= 1
		if VerifyEventReceipt(r.Witness, changed, v.EventSAID, sig, v.Witnesses) == nil {
			t.Fatal("a receipt was accepted for an event it did not sign")
		}
		// Right signature, wrong place in the list.
		swapped := []string{v.Witnesses[1], v.Witnesses[0]}
		if VerifyEventReceipt(r.Witness, raw, v.EventSAID, sig, swapped) == nil {
			t.Fatal("a receipt was accepted at an index that is not the witness's place")
		}
	}
}

func TestTheReceiptHasKeripysFiveFields(t *testing.T) {
	b, err := ReceiptMessage("EController", 255, "EEvent")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":"KERI10JSON000063_","t":"rct","d":"EEvent","i":"EController","s":"ff"}`
	want = strings.Replace(want, "000063", "0000"+hex2(len(want)), 1)
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}

func hex2(n int) string {
	const h = "0123456789abcdef"
	return string([]byte{h[n>>4&15], h[n&15]})
}

// A witness that still sends the earlier form, an unindexed signature over the
// SAID string, is still read, until it is upgraded.
func TestTheEarlierReceiptFormIsStillRead(t *testing.T) {
	v, raw := loadVector(t)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	// 0B + the 64 signature bytes behind two bytes of padding, as qb64 writes it.
	raw64 := ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(v.EventSAID))
	sig := "0B" + base64.RawURLEncoding.EncodeToString(append([]byte{0, 0}, raw64...))[2:]
	if !strings.HasPrefix(sig, "0B") {
		t.Fatalf("the earlier form is a 0B signature, got %s", sig[:4])
	}
	if err := VerifyEventReceipt(v.Receipts[0].Witness, raw, v.EventSAID, sig, v.Witnesses); err != nil {
		t.Fatalf("the earlier receipt form is no longer read: %v", err)
	}
	if VerifyEventReceipt(v.Receipts[1].Witness, raw, v.EventSAID, sig, v.Witnesses) == nil {
		t.Fatal("an earlier-form receipt was accepted as another witness's")
	}
}

// Writes our receipts of keripy's own inception, for interop/verify_witness_receipts_with_keripy.py
// to give to keripy. Skipped unless OUR_RECEIPTS_OUT names the file.
func TestWriteOurReceiptsForKeripyToJudge(t *testing.T) {
	out := os.Getenv("OUR_RECEIPTS_OUT")
	if out == "" {
		t.Skip("set OUR_RECEIPTS_OUT to write the cases keripy judges")
	}
	v, raw := loadVector(t)
	var raw0 struct {
		EventMessageB64 string `json:"event_message_b64"`
	}
	b, _ := os.ReadFile("testdata/keripy_witness_receipts.json")
	_ = json.Unmarshal(b, &raw0)
	var msgs []string
	for _, r := range v.Receipts {
		seed, _ := base64.StdEncoding.DecodeString(r.SeedB64)
		rct, err := ReceiptMessage(v.Controller, 0, v.EventSAID)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := SignEventReceipt(raw, seed, r.Index)
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, base64.StdEncoding.EncodeToString(append(rct, []byte("-VAX-BAB"+sig)...)))
	}
	cases, _ := json.Marshal(map[string]interface{}{
		"event_message_b64": raw0.EventMessageB64, "controller": v.Controller,
		"event_said": v.EventSAID, "receipts": msgs,
	})
	if err := os.WriteFile(out, cases, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A later event's receipt is keripy's too: the sequence number is written in
// lowercase hex (26 is "1a"), and after a rotation cut a witness the one that
// is left stands at index 0, where it stood at 1 before.
func TestKeripysReceiptsOfLaterEventsAreOurs(t *testing.T) {
	v, _ := loadVector(t)
	if len(v.Later) < 2 {
		t.Fatal("the vectors carry no later events")
	}
	for _, e := range v.Later {
		raw, _ := base64.StdEncoding.DecodeString(e.EventB64)
		for _, r := range e.Receipts {
			want, _ := base64.StdEncoding.DecodeString(r.ReceiptB64)
			got, err := ReceiptMessage(v.Controller, uint64(e.SN), e.EventSAID)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("receipt of sn %d differs from keripy's:\n ours   %s\n keripy %s", e.SN, got, want)
			}
			seed, _ := base64.StdEncoding.DecodeString(r.SeedB64)
			sig, err := SignEventReceipt(raw, seed, r.Index)
			if err != nil {
				t.Fatal(err)
			}
			if sig != indexedSigOf(t, r.Attachment) {
				t.Fatalf("signature at sn %d differs from keripy's", e.SN)
			}
			if err := VerifyEventReceipt(r.Witness, raw, e.EventSAID, sig, e.Witnesses); err != nil {
				t.Fatalf("keripy's receipt of sn %d is refused: %v", e.SN, err)
			}
			// The list before the rotation puts this witness elsewhere.
			if VerifyEventReceipt(r.Witness, raw, e.EventSAID, sig, v.Witnesses) == nil {
				t.Fatalf("a receipt indexed for the rotated list was accepted against the list before it")
			}
		}
	}
	if string(mustReceipt(t, v, 26)) == "" || !strings.Contains(string(mustReceipt(t, v, 26)), `"s":"1a"`) {
		t.Fatal("sequence number 26 is not written as 1a")
	}
}

func mustReceipt(t *testing.T, v vector, sn uint64) []byte {
	t.Helper()
	b, err := ReceiptMessage(v.Controller, sn, v.EventSAID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The list in force at an event is the inception's, amended by each rotation.
func TestTheListInForceAtAnEventIsCarriedThroughRotations(t *testing.T) {
	v, icp := loadVector(t)
	rot, _ := base64.StdEncoding.DecodeString(v.Later[0].EventB64)
	log := [][]byte{icp, rot}
	at0, ok := DesignatedAfter(log, v.EventSAID)
	if !ok || len(at0) != 2 || at0[0] != v.Witnesses[0] || at0[1] != v.Witnesses[1] {
		t.Fatalf("at the inception: %v %v", at0, ok)
	}
	at1, ok := DesignatedAfter(log, v.Later[0].EventSAID)
	if !ok || len(at1) != 1 || at1[0] != v.Later[0].Witnesses[0] {
		t.Fatalf("after the rotation: %v %v", at1, ok)
	}
	if _, ok := DesignatedAfter(log, "ENotInTheLog"); ok {
		t.Fatal("an event that is not in the log has a list")
	}
	if got := DesignatedByInception(icp); len(got) != 2 {
		t.Fatalf("an inception names its own list: %v", got)
	}
	if DesignatedByInception(rot) != nil {
		t.Fatal("a rotation's list depends on the log, not on itself")
	}
}
