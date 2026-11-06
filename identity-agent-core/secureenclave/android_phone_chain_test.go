package secureenclave

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

// The bytes the app sends for a two-certificate chain. Pinned on the Kotlin side by
// AttestationChainFormatTest in the shared-ui repo (packages/grape_android_keystore).
func TestAChainIsSentAsLengthPrefixedCertificates(t *testing.T) {
	got := JoinAttestationChain([]byte{1, 2}, []byte{0xff})
	want := []byte{0, 0, 0, 2, 1, 2, 0, 0, 0, 1, 0xff}
	if string(got) != string(want) {
		t.Fatalf("% x", got)
	}
}

// Proof on a real phone: the chain the app logged is checked by the core's own
// verifier against Google's real root, and must name the hardware the phone has.
//
//	ANDROID_ATTESTATION_CHAIN_B64=$(cat chain.b64) EXPECT_LEVEL=strongbox go test -v -run TestAPhonesOwnChain ./secureenclave
//
// Skipped when the variable is not set. EXPECT_LEVEL is "strongbox" or "tee" and
// is required, so a pass says which hardware was proven, not just that something was.
func TestAPhonesOwnChain(t *testing.T) {
	b64 := strings.TrimSpace(os.Getenv("ANDROID_ATTESTATION_CHAIN_B64"))
	if b64 == "" {
		t.Skip("ANDROID_ATTESTATION_CHAIN_B64 not set (see the comment above for how to run this on a phone)")
	}
	want := os.Getenv("EXPECT_LEVEL")
	if want != "strongbox" && want != "tee" {
		t.Fatal(`set EXPECT_LEVEL to "strongbox" or "tee"`)
	}
	chain, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	f, err := VerifyAndroidKeyAttestation(chain, []byte(SeedWrapAttestationChallenge), time.Now())
	if err != nil {
		t.Fatalf("this phone's chain was refused: %v", err)
	}
	if err := seedWrapKeyPolicy(f); err != nil {
		t.Fatalf("the key does not suit the seed: %v", err)
	}
	t.Logf("verified: held in %s, generated=%v, noAuthRequired=%v, boot state %q, bootloader locked=%v, made %s",
		f.LevelName(), f.Generated, f.NoAuthRequired, f.BootState, f.DeviceLocked, f.Created.Format(time.RFC3339))
	if f.LevelName() != want {
		t.Fatalf("the hardware says %s, expected %s", f.LevelName(), want)
	}
}
