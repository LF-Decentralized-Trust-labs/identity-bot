//go:build kerigo_pqtest

package iacrypto

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// Two KERI implementations live in this codebase: this package, which builds
// hybrid inception events itself, and keri-go, which builds every other kind.
//
// That is the arrangement keri-go exists to end. Two implementations of one
// protocol do not announce that they have drifted — a KERI identifier is a
// digest of its own event, so a single byte of disagreement produces an identity
// nobody else recognises, and nothing fails until something real is attempted.
//
// So before this package's builder is replaced by keri-go, the two are compared
// on the event this package actually produces. If they agree, the swap is safe.
// If they do not, one of them is already wrong.
//
// NOTE: since the builder was swapped to keri-go this compares keri-go with
// keri-go, so it can no longer fail for disagreement between two engines. It
// guards the swap not drifting back; the independent check, against keripy,
// is recorded at TestTheRecordedInceptionBytesHaveNotChanged.
func TestHybridInceptionAgreesWithKeriGo(t *testing.T) {
	ours, err := BuildHybridInception(SyntheticHybridKeyMaterial(0))
	if err != nil {
		t.Fatal(err)
	}
	ourRaw, err := base64.StdEncoding.DecodeString(ours.RawBytesB64)
	if err != nil {
		t.Fatal(err)
	}

	// The same event, described to keri-go: two signing keys and a threshold of
	// two, so neither signs alone, two pre-rotation commitments, and the
	// cipher-suite anchor that marks the identity as hybrid.
	anchor, err := json.Marshal(map[string]any{
		"ia": CipherSuiteIAHybrid1,
		"ka": []string{ours.CESR.X25519Agreement, ours.CESR.MLKEM768Encap},
	})
	if err != nil {
		t.Fatal(err)
	}

	theirs, err := keri.BuildInception(keri.InceptionInput{
		Keys:        []string{ours.CESR.Ed25519Signing, ours.CESR.MLDSA65Signing},
		Isith:       json.RawMessage(`"2"`),
		NextDigests: []string{ours.CESR.NextEd25519Digest, ours.CESR.NextMLDSA65Digest},
		Nsith:       json.RawMessage(`"2"`),
		Data:        []json.RawMessage{anchor},
	})
	if err != nil {
		t.Fatalf("keri-go could not build the hybrid inception: %v", err)
	}

	if string(ourRaw) != string(theirs) {
		t.Errorf("the two implementations in this codebase disagree about the same "+
			"event, so they would create different identities from the same keys\n"+
			" iacrypto: %s\n keri-go : %s", firstDiff(ourRaw, theirs), firstDiff(theirs, ourRaw))
	}

	ev, err := keri.ParseEvent(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Identifier != ours.AID {
		t.Errorf("the identities differ: iacrypto %s, keri-go %s", ours.AID, ev.Identifier)
	}
}

// firstDiff shows where two events start to differ, rather than printing two
// multi-kilobyte events and leaving the reader to find it.
func firstDiff(a, b []byte) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			start := i - 40
			if start < 0 {
				start = 0
			}
			end := i + 40
			if end > len(a) {
				end = len(a)
			}
			return string(a[start:end])
		}
	}
	if len(a) != len(b) {
		return "identical up to the shorter one, then lengths differ"
	}
	return "identical"
}
