package witness

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// A pin says who is expected; the check says who is answering. Neither alone is
// enough, and these hold both halves.

const pinnedKey = "BMtfjviEMpF2xWVW0CRPKoVPX1mOMzNurvUjD-0RN_Jl"

func answering(aid string) IdentityChecker {
	return func(ctx context.Context, baseURL string) (string, error) { return aid, nil }
}

func unreachable() IdentityChecker {
	return func(ctx context.Context, baseURL string) (string, error) {
		return "", fmt.Errorf("connection refused")
	}
}

// The ordinary case: the service is who the registry says, so it is designated
// — and what is designated is the PIN, never the live answer.
func TestAServiceThatIsWhoItClaimsIsDesignated(t *testing.T) {
	got, err := ConfirmWitnessIdentity(context.Background(), answering(pinnedKey),
		"https://witness1.example", pinnedKey)
	if err != nil {
		t.Fatalf("a matching service was refused: %v", err)
	}
	if got != pinnedKey {
		t.Fatalf("designated %s rather than the pinned identifier", got)
	}
}

// The case the pin exists for. Whoever controls the address at this moment must
// not be able to write themselves into an inception event, which cannot be
// amended afterwards.
func TestAnAddressAnsweringAsSomebodyElseIsRefused(t *testing.T) {
	_, err := ConfirmWitnessIdentity(context.Background(),
		answering("BAnAttackerWhoControlsThisHostnameRightNow01"),
		"https://witness1.example", pinnedKey)
	if err == nil {
		t.Fatal("whoever answered that address was accepted as the witness, so a hijacked " +
			"hostname could put itself permanently into somebody's key log")
	}
	if !strings.Contains(err.Error(), "pinned as") {
		t.Errorf("the refusal does not explain the mismatch: %v", err)
	}
}

// The case the check exists for. A service redeployed onto a new volume answers
// as a different identity, and the stale pin would otherwise be designated
// permanently as a witness that cannot receipt.
func TestAStalePinIsRefusedRatherThanDesignated(t *testing.T) {
	_, err := ConfirmWitnessIdentity(context.Background(),
		answering("BTheKeyItActuallyHasAfterBeingRedeployed001"),
		"https://witness1.example", pinnedKey)
	if err == nil {
		t.Fatal("a stale pin was designated; every identity founded afterwards would name a " +
			"witness that no longer exists")
	}
}

// Unreachable is not a reason to designate hopefully.
func TestAServiceThatCannotBeReachedIsNotDesignated(t *testing.T) {
	if _, err := ConfirmWitnessIdentity(context.Background(), unreachable(),
		"https://witness1.example", pinnedKey); err == nil {
		t.Fatal("a service that could not be reached was designated anyway")
	}
}

// No pin means no basis for designating at all — that is what makes changing a
// default a deliberate edit to a committed file rather than something a DNS
// answer can do on its own.
func TestAnUnpinnedServiceIsNotDesignated(t *testing.T) {
	if _, err := ConfirmWitnessIdentity(context.Background(), answering("BAnything"),
		"https://witness1.example", ""); err == nil {
		t.Fatal("an unpinned service was designated on its own say-so")
	}
}

// End to end through the selection: a confirmed service is designated, an
// impostor is dropped, and the threshold follows what actually survived.
func TestDesignationDropsWhatItCannotConfirm(t *testing.T) {
	candidates := []witnessTarget{
		{AID: "E1", WitnessKey: "BOne", URL: "https://one.example", Commercial: true},
		{AID: "E2", WitnessKey: "BTwo", URL: "https://two.example", Commercial: true},
		{AID: "E3", WitnessKey: "BThree", URL: "https://three.example", Commercial: true},
	}
	check := func(ctx context.Context, baseURL string) (string, error) {
		switch baseURL {
		case "https://one.example":
			return "BOne", nil
		case "https://two.example":
			return "BSomebodyElseEntirely", nil // impostor or redeployed
		default:
			return "BThree", nil
		}
	}
	keys, toad := DesignatableWitnessesChecked(context.Background(), candidates, check)
	if len(keys) != 2 {
		t.Fatalf("expected the unconfirmed service dropped, designated %v", keys)
	}
	for _, k := range keys {
		if k == "BTwo" {
			t.Fatal("a service answering as somebody else was designated")
		}
	}
	if toad != 2 {
		t.Fatalf("threshold is %d; a majority of the two that survived is 2", toad)
	}
}

// A contact's key was learned from its own OOBI rather than pinned in a shipped
// file, so there is no second opinion to check it against and it is not treated
// as though there were.
func TestAContactWitnessIsNotSubjectToThePinCheck(t *testing.T) {
	candidates := []witnessTarget{
		{AID: "EFriend", WitnessKey: "BFriendKey", URL: "https://friend.example"},
	}
	keys, _ := DesignatableWitnessesChecked(context.Background(), candidates, unreachable())
	if len(keys) != 1 {
		t.Fatalf("a contact witness was dropped by a check that does not apply to it: %v", keys)
	}
}
