package recovery

import (
	"encoding/base64"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

func TestPairwiseMismatchHardError(t *testing.T) {
	seed, err := backup.MnemonicToBIP39Seed(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	contacts := []ContactPairwiseExpectation{{
		ContactRecord: store.ContactRecord{
			AID:       "Econtact00000000000000000000000000001",
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Status:    "accepted",
		},
	}}

	_, err = VerifyPairwiseContacts(seed, contacts)
	if err == nil {
		t.Fatal("expected pairwise mismatch hard error")
	}
	if _, ok := err.(*ErrPairwiseMismatch); !ok {
		t.Fatalf("expected ErrPairwiseMismatch, got %T: %v", err, err)
	}
}

func TestPairwiseMatchSucceeds(t *testing.T) {
	seed, err := backup.MnemonicToBIP39Seed(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	pub, aid, err := DerivePairwiseAtIndex(seed, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	contacts := []ContactPairwiseExpectation{{
		ContactRecord: store.ContactRecord{
			AID:       "Econtact00000000000000000000000000001",
			PublicKey: NormalizePublicKeyB64(pub),
			Status:    "accepted",
		},
	}}

	results, err := VerifyPairwiseContacts(seed, contacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Matched {
		t.Fatalf("unexpected results: %+v", results)
	}
	if results[0].PairwiseAID != aid {
		t.Fatalf("aid mismatch: %s vs %s", results[0].PairwiseAID, aid)
	}
}

func TestVerifyEndpointRejectsPairwiseMismatch(t *testing.T) {
	seed, _ := backup.MnemonicToBIP39Seed(testMnemonic, "")
	pub, _, _ := DerivePairwiseAtIndex(seed, 0, 0)
	contacts := []ContactPairwiseExpectation{{
		ContactRecord: store.ContactRecord{
			AID:       "Econtact00000000000000000000000000001",
			PublicKey: NormalizePublicKeyB64(pub),
		},
		// Explicit wrong expectation must fail even if public_key matches.
		PairwisePublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
	}}
	archive := buildTestArchive(t, testMnemonic, contacts)

	svc := NewService(t.TempDir(), nil, nil)
	_, err := svc.Verify(VerifyRequest{
		ArchiveB64: encodeB64(archive),
		Mnemonic:   testMnemonic,
	})
	if err == nil {
		t.Fatal("verify must fail on pairwise mismatch")
	}
}

// A key compares equal to itself in every spelling, including one whose
// standard base64 begins with "B", which was stripped as if it were a code.
func TestAKeyStartingWithBComparesEqualToItself(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString("B/awzunMRvtYlgq21ZegG9MD5kNmLbPNspHGcryAbK4=")
	if err != nil {
		t.Fatal(err)
	}
	std := NormalizePublicKeyB64(raw)
	for _, other := range []string{std, base64.RawURLEncoding.EncodeToString(raw), iacrypto.VerkeyQB64(raw), iacrypto.NonTransferableAIDQB64(raw)} {
		if ok, _, _, err := PublicKeysEqual(std, other); err != nil || !ok {
			t.Fatalf("%s and %s did not compare equal (%v)", std, other, err)
		}
	}
}
