package witness

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// BringUpToDate checks a returned receipt's index against the list in force at
// its event: another witness's place is not counted, the right one is.
func TestBringUpToDateCountsAReceiptOnlyAtTheWitnessesPlace(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 5
	wkey := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	other := iacrypto.NonTransferableAIDQB64(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))

	w := witnessFor(t)
	w.OurWitnessAID = func() (string, error) { return wkey, nil }
	w.SignReceipt = func(said string) (string, string, error) {
		raw := ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(said))
		sig, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
		return wkey, sig, err
	}

	o := newOwner(t)
	toad := 1
	icp, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{pub(t, o.now)}, NextDigests: []string{digest(t, o.next)},
		Witnesses: []string{other, wkey}, Toad: &toad, Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := parsed(t, icp)
	rawSig, _ := o.now.Sign(icp)
	cesr, _ := keri.MatterQB64(keri.CodeEd25519Sig, rawSig)
	log := []SignedEvent{{RawBytesB64: base64.StdEncoding.EncodeToString(icp), CesrSignature: cesr}}

	run := func(index int) int {
		sender, mc := testService(t)
		mc.contacts["EWitness"] = store.ContactRecord{AID: "EWitness", OobiURL: "http://w.test", IsWitness: true}
		_ = sender.Store.SaveContactMeta(ContactMeta{ContactAID: "EWitness", WitnessKey: wkey})
		sender.PostEvent = func(_ context.Context, _ string, body []byte) (map[string]interface{}, error) {
			var req struct {
				Event string `json:"event_b64"`
			}
			_ = json.Unmarshal(body, &req)
			raw, _ := base64.StdEncoding.DecodeString(req.Event)
			sig, err := drivers.SignEventReceipt(raw, seed, index)
			if err != nil {
				t.Fatal(err)
			}
			return map[string]interface{}{"event_said": ev.SAID, "witness_aid": wkey, "cesr_signature": sig}, nil
		}
		sender.FetchTip = func(_ context.Context, url string) (TipAnswer, error) {
			_, nonce, _ := strings.Cut(url, "?nonce=")
			return w.KelTip(ev.Identifier, nonce, true)
		}
		sender.BringUpToDate(context.Background(), ev.Identifier, log, []string{wkey}, 1)
		f, _ := sender.Store.GetFinalization(ev.SAID)
		if f == nil {
			t.Fatal("no finalisation was started for the event")
		}
		return f.ReceiptCount
	}
	if n := run(0); n != 0 {
		t.Fatalf("a receipt at place 0, where the list has the witness at 1, was counted (%d)", n)
	}
	if n := run(1); n != 1 {
		t.Fatalf("the receipt at the witness's own place was not counted (%d)", n)
	}
}
