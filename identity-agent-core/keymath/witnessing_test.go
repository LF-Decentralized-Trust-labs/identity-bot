package keymath

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	keri "github.com/grapeid/keri-go"
)

func sig(t *testing.T, s keri.Signer, msg []byte) string {
	t.Helper()
	raw, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	q, err := keri.MatterQB64(keri.CodeEd25519Sig, raw)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// A receipt verifies under the witness it names and for the event it was
// issued for, and under nothing else.
func TestAReceiptIsTheNamedWitnesssSignatureOverTheDigest(t *testing.T) {
	w, _ := keri.GenerateSigner(false)
	other, _ := keri.GenerateSigner(false)
	wid, _ := w.PublicKey()
	oid, _ := other.PublicKey()
	digest := "EAAAsomeeventidentifier0123456789ABCDEFGHIJK"
	good := sig(t, w, []byte(digest))
	ask := func(witness, d, s string) error {
		body, _ := json.Marshal(map[string]string{"witness": witness, "digest": d, "sig": s})
		_, err := Do("verify_receipt", body)
		return err
	}
	if err := ask(wid, digest, good); err != nil {
		t.Fatalf("a genuine receipt was refused: %v", err)
	}
	if ask(oid, digest, good) == nil {
		t.Fatal("a receipt was counted for a witness that did not sign it")
	}
	if ask(wid, "EBBBsomeothereventidentifier0123456789ABCDEFG", good) == nil {
		t.Fatal("a receipt for one event was counted for another")
	}
	if ask(wid, digest, sig(t, other, []byte(digest))) == nil {
		t.Fatal("another key's signature was counted as the witness's receipt")
	}
}

// A log is judged from its founding, and the state it ends in is reported:
// where it ends, the keys in force and the witnesses.
func TestALogIsJudgedFromItsFounding(t *testing.T) {
	s, _ := keri.GenerateSigner(true)
	n, _ := keri.GenerateSigner(true)
	w, _ := keri.GenerateSigner(false)
	p, _ := s.PublicKey()
	np, _ := n.PublicKey()
	wid, _ := w.PublicKey()
	d, _ := keri.NextDigest(np)
	one := 1
	raw, err := keri.BuildInception(keri.InceptionInput{Keys: []string{p}, NextDigests: []string{d},
		Witnesses: []string{wid}, Toad: &one, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := keri.ParseEvent(raw)
	signed := SignedEvent{RawB64: base64.StdEncoding.EncodeToString(raw), Sigs: []string{sig(t, s, raw)}}
	ask := func(aid string, events ...SignedEvent) (*LogState, error) {
		body, _ := json.Marshal(map[string]any{"aid": aid, "events": events})
		out, err := Do("verify_log", body)
		if err != nil {
			return nil, err
		}
		var st LogState
		return &st, json.Unmarshal(out, &st)
	}
	st, err := ask(ev.Identifier, signed)
	if err != nil {
		t.Fatalf("a signed founding was refused: %v", err)
	}
	if st.SN != 0 || st.Digest != ev.SAID || st.Ilk != "icp" || len(st.Witnesses) != 1 ||
		st.Witnesses[0] != wid || st.TOAD != 1 || st.Keys[0] != p || st.Next[0] != d {
		t.Fatalf("the state was reported wrongly: %+v", st)
	}
	if _, err := ask("E"+strings.Repeat("A", 43), signed); err == nil {
		t.Fatal("a log was reported as another identity's")
	}
	forged := SignedEvent{RawB64: signed.RawB64, Sigs: []string{sig(t, n, raw)}}
	if _, err := ask(ev.Identifier, forged); err == nil {
		t.Fatal("a founding signed by a key it does not name was accepted")
	}
	if _, err := ask(ev.Identifier, SignedEvent{RawB64: signed.RawB64}); err == nil {
		t.Fatal("an unsigned founding was accepted")
	}
}
