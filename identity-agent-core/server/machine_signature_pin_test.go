package server

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
)

// The other end of this signature is not written in this repository.
//
// A machine that enrols with its own key has to sign requests, and it cannot
// import this module to do so — pulling a tunnelling client and an SMB library
// into a sealed image would defeat the point of measuring what runs in it. So
// it reimplements the encoding, and two implementations of one format drift.
//
// The symptom of drift is not an error. It is that nothing the machine says is
// believed any more, silently, and the messages that stop arriving are the ones
// somebody was relying on.
//
// So the vector below is checked in both places. It was produced here, and the
// machine's own tests check the same bytes. Either side changing the
// construction breaks a test rather than a customer.

const (
	pinnedMachineVerkey = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	pinnedMachineDigest = "EECyjWt6_CZmUe8VvRe5in80_uEt0ruMVnWNiauIP4tA"
	pinnedMachineSig    = "0BDF0T59HFRU7yGgzQvgDVY6ezsXhYyxYpxdbp2hXSrc7IGZddHPe1y-CFJmHJeQIKDJtcGqsOV3gwvdE4qr43cJ"

	pinnedMachineStamp = "2026-07-31T12:00:00Z"
	pinnedMachinePath  = "/api/notify"
)

var pinnedMachineBody = []byte(`{"to_aid":"ECUSTOMER","title":"Your instance stops on 14 August"}`)

// Seed 0,1,2…31, so the vector is reproducible from nothing but this file.
func pinnedMachineSeed() []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func TestAMachinesKeyEncodingIsPinned(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(pinnedMachineSeed()).Public().(ed25519.PublicKey)
	if got := iacrypto.VerkeyQB64(pub); got != pinnedMachineVerkey {
		t.Errorf("a machine enrolling would present a key this agent cannot decode\n got %q\nwant %q",
			got, pinnedMachineVerkey)
	}
}

func TestTheBodyDigestIsPinned(t *testing.T) {
	if got := iacrypto.Blake3QB64Must(pinnedMachineBody); got != pinnedMachineDigest {
		t.Errorf("the digest changed, so every machine signature would fail\n got %q\nwant %q",
			got, pinnedMachineDigest)
	}
}

// The bytes actually signed. Two sides that agree on the hash but assemble the
// string differently produce signatures that verify against nothing.
func TestTheSignedStringIsPinned(t *testing.T) {
	want := "IA-REQ-V1\nPOST\n" + pinnedMachinePath + "\n" + pinnedMachineStamp + "\n" + pinnedMachineDigest
	got := canonicalRequestString(http.MethodPost, pinnedMachinePath, pinnedMachineStamp, pinnedMachineBody)
	if got != want {
		t.Errorf("the signed string changed\n got %q\nwant %q", got, want)
	}
}

// The whole construction, end to end.
func TestAPinnedSignatureStillVerifies(t *testing.T) {
	seed := pinnedMachineSeed()
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	produced, err := SignOwnerRequest(http.MethodPost, pinnedMachinePath, pinnedMachineStamp,
		pinnedMachineBody, seed)
	if err != nil {
		t.Fatal(err)
	}
	if produced != pinnedMachineSig {
		t.Errorf("this agent now produces a different signature than the machine expects\n got %q\nwant %q",
			produced, pinnedMachineSig)
	}

	// And the pinned one — not the freshly produced one — verifies, which is
	// what a machine will actually present.
	ok, err := login.VerifyString(
		canonicalRequestString(http.MethodPost, pinnedMachinePath, pinnedMachineStamp, pinnedMachineBody),
		pinnedMachineSig, pub)
	if err != nil || !ok {
		t.Fatalf("a signature a machine produced no longer verifies: ok=%v err=%v", ok, err)
	}
}
