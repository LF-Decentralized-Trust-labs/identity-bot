package server

import (
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"

	keri "github.com/grapeid/keri-go"
)

// receiptSignerFor signs event receipts as the witness the signer's key makes,
// in the form the agent does: an indexed signature over the event's bytes. The
// index is 0 whatever the event's witness list, which these tests do not set.
func receiptSignerFor(signer keri.Signer, key string) func([]byte, []string) (string, string, error) {
	return func(raw []byte, designated []string) (string, string, error) {
		sig, err := signer.Sign(raw)
		if err != nil {
			return "", "", err
		}
		// Indexed by the witness's place in the list, as the real signer does;
		// a witness the test did not designate is 0, which the real one refuses.
		at := drivers.WitnessPosition(designated, key)
		if at < 0 {
			at = 0
		}
		q, err := iacrypto.MatterIndexedSigQB64("A", at, sig, 88)
		return key, q, err
	}
}

// The agent receipts an event as a witness that the event designates, with the
// index of its place in the list, and refuses an event that does not designate it.
func TestTheAgentReceiptsOnlyAnEventThatDesignatesIt(t *testing.T) {
	s := witnessWithSeed(t, 3)
	_, aid, err := s.witnessSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	event := []byte(`{"v":"KERI10JSON000000_","t":"icp"}`)
	other := "BSomeOtherWitnessAIDthatIsNotThisOne01234567"
	_, sig, err := s.signWitnessEventReceipt(event, []string{other, aid})
	if err != nil {
		t.Fatal(err)
	}
	if sig[:2] != "AB" {
		t.Fatalf("the second witness in the list is indexed 1 (AB), got %.2s", sig)
	}
	if err := drivers.VerifyEventReceipt(aid, event, "", sig, []string{other, aid}); err != nil {
		t.Fatalf("our own receipt does not verify: %v", err)
	}
	if _, _, err := s.signWitnessEventReceipt(event, []string{other}); err == nil {
		t.Fatal("receipted an event that does not designate this witness")
	}
}
