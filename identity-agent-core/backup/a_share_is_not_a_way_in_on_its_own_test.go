package backup

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// A holder, with a keypair it alone holds the private half of.
func aHolder(t *testing.T, id, kind string) (ShareHolder, []byte) {
	t.Helper()
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	priv, pub, err := DeriveSealKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	return ShareHolder{ID: id, Kind: kind, PublicKeyB64: EncodeB64(pub)}, priv
}

// openShare is what a holder does when it decides to release: unseal its own
// share with a private key nothing else has.
func openShare(t *testing.T, priv []byte, s SealedShare) []byte {
	t.Helper()
	eph, err := DecodeB64(s.EphemeralPubB64)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := DecodeB64(s.WrappedB64)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := DecodeB64(s.NonceB64)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnsealBEK(priv, eph, wrapped, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func aSplitOf(t *testing.T, n, k int) (HowTheWayInIsSplit, map[string][]byte) {
	t.Helper()
	split := HowTheWayInIsSplit{Needed: k}
	privs := map[string][]byte{}
	for i := 0; i < n; i++ {
		h, priv := aHolder(t, fmt.Sprintf("EHolder%d", i), "witness")
		split.Holders = append(split.Holders, h)
		privs[h.ID] = priv
	}
	return split, privs
}

// Any k shares open it, and every combination of k does.
//
// Not one combination sampled — all of them. A wrap that was built wrong for
// one particular set is a recovery that fails for exactly the people who
// happen to answer, which is not something to find out during one.
func TestAnyThreeOfFiveOpenTheArchive(t *testing.T) {
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split, privs := aSplitOf(t, 5, 3)
	sealed, wraps, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}
	if len(wraps) != 10 {
		t.Fatalf("three of five should be ten combinations, got %d", len(wraps))
	}

	byHolder := map[string]SealedShare{}
	for _, s := range sealed {
		byHolder[s.HolderID] = s
	}

	ids := holderIDs(split.Holders)
	for _, subset := range combinations(ids, 3) {
		gathered := map[string][]byte{}
		for _, id := range subset {
			gathered[id] = openShare(t, privs[id], byHolder[id])
		}
		got, err := ReassembleTheWayIn(seedKEK, gathered, wraps)
		if err != nil {
			t.Fatalf("%v could not open it: %v", subset, err)
		}
		if !bytes.Equal(got, bek) {
			t.Fatalf("%v opened it to the wrong key", subset)
		}
	}
}

// Fewer than k never opens it — every combination of k-1, not a sample.
//
// This is the property the whole design rests on. If any k-1 set opened the
// archive, the threshold would be a decoration and the words plus one stolen
// share would be the whole of the security again.
func TestNoTwoOfFiveOpenTheArchive(t *testing.T) {
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split, privs := aSplitOf(t, 5, 3)
	sealed, wraps, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}
	byHolder := map[string]SealedShare{}
	for _, s := range sealed {
		byHolder[s.HolderID] = s
	}

	ids := holderIDs(split.Holders)
	for _, size := range []int{1, 2} {
		for _, subset := range combinations(ids, size) {
			gathered := map[string][]byte{}
			for _, id := range subset {
				gathered[id] = openShare(t, privs[id], byHolder[id])
			}
			if _, err := ReassembleTheWayIn(seedKEK, gathered, wraps); err == nil {
				t.Fatalf("%d shares (%v) opened an archive needing 3", size, subset)
			}
		}
	}
}

// The recovery words alone are not enough, which is the entire point.
func TestTheWordsAloneDoNotOpenIt(t *testing.T) {
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split, _ := aSplitOf(t, 5, 3)
	_, wraps, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReassembleTheWayIn(seedKEK, map[string][]byte{}, wraps); err == nil {
		t.Fatal("the words alone opened the archive")
	}
}

// Shares alone, without the words, are not enough either.
//
// The threshold is a second factor, not a replacement for the first. If k
// holders could open an archive between them, the people asked to protect an
// identity would become people able to take it.
func TestTheHoldersCannotOpenItBetweenThemselves(t *testing.T) {
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split, privs := aSplitOf(t, 5, 3)
	sealed, wraps, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}
	byHolder := map[string]SealedShare{}
	for _, s := range sealed {
		byHolder[s.HolderID] = s
	}

	gathered := map[string][]byte{}
	for _, id := range holderIDs(split.Holders)[:3] {
		gathered[id] = openShare(t, privs[id], byHolder[id])
	}
	// Everything the holders have, and the wrong words.
	wrongWords := make([]byte, 32)
	rand.Read(wrongWords)
	if _, err := ReassembleTheWayIn(wrongWords, gathered, wraps); err == nil {
		t.Fatal("three holders opened the archive without the recovery words")
	}
}

// A share is sealed to one holder, and nobody else can read it.
//
// The agent that WROTE the backup must not be able to open it either, which is
// what makes a machine able to write a backup it cannot read.
func TestOnlyTheHolderCanOpenItsOwnShare(t *testing.T) {
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split, privs := aSplitOf(t, 3, 2)
	sealed, _, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}

	first, second := sealed[0], sealed[1]
	eph, _ := DecodeB64(first.EphemeralPubB64)
	wrapped, _ := DecodeB64(first.WrappedB64)
	nonce, _ := DecodeB64(first.NonceB64)
	if _, err := UnsealBEK(privs[second.HolderID], eph, wrapped, nonce); err == nil {
		t.Fatal("one holder opened another holder's share")
	}
}

// Two holders swapping shares must not produce the key the pair holding them
// correctly would.
//
// WHAT THIS DOES NOT PROVE. Removing the holder-name binding from the key
// derivation leaves this passing: the ids are sorted and the secrets random, so
// a swap already reverses the concatenation and fails on that alone. So this
// pins the behaviour, and the name binding beside it is defence in depth rather
// than the thing being tested.
func TestSharesAreBoundToTheHolderTheyWereGivenTo(t *testing.T) {
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split, privs := aSplitOf(t, 3, 2)
	sealed, wraps, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}
	byHolder := map[string]SealedShare{}
	for _, s := range sealed {
		byHolder[s.HolderID] = s
	}
	ids := holderIDs(split.Holders)
	a, b := ids[0], ids[1]

	swapped := map[string][]byte{
		a: openShare(t, privs[b], byHolder[b]),
		b: openShare(t, privs[a], byHolder[a]),
	}
	if _, err := ReassembleTheWayIn(seedKEK, swapped, wraps); err == nil {
		t.Fatal("two shares presented under each other's names opened the archive")
	}
}

// A split that could never be satisfied is refused when it is chosen.
//
// Asking for three approvals from two holders does not protect the owner from
// an attacker; it protects the identity from its owner, and the worst possible
// moment to discover that is during a recovery.
func TestASplitThatCouldNeverBeOpenedIsRefused(t *testing.T) {
	split, _ := aSplitOf(t, 2, 3)
	err := split.Validate()
	if err == nil {
		t.Fatal("a threshold larger than the number of holders was accepted")
	}
	if !strings.Contains(err.Error(), "could never be opened") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

func TestOneHolderNamedTwiceCannotCountTwice(t *testing.T) {
	h, _ := aHolder(t, "ESame", "witness")
	split := HowTheWayInIsSplit{Needed: 2, Holders: []ShareHolder{h, h}}
	if err := split.Validate(); err == nil {
		t.Fatal("the same holder was allowed to satisfy a threshold of two on its own")
	}
}

func TestAHolderIsNamedByItsIdentifierNotAnEmailAddress(t *testing.T) {
	h, _ := aHolder(t, "friend@example.com", "witness")
	split := HowTheWayInIsSplit{Needed: 1, Holders: []ShareHolder{h}}
	err := split.Validate()
	if err == nil {
		t.Fatal("a holder was accepted at an email address")
	}
	if !strings.Contains(err.Error(), "own identifier") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A threshold of zero would open with nothing at all.
func TestAThresholdOfZeroIsRefused(t *testing.T) {
	split, _ := aSplitOf(t, 3, 0)
	if err := split.Validate(); err == nil {
		t.Fatal("a threshold of zero was accepted")
	}
}

// The combinatorial cost is bounded when it is chosen, not discovered.
func TestATooLargeSplitIsRefusedWithTheNumbers(t *testing.T) {
	split, _ := aSplitOf(t, 20, 10)
	err := split.Validate()
	if err == nil {
		t.Fatal("a split needing 184756 wrappings was accepted")
	}
	if !strings.Contains(err.Error(), "past the limit") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A PIN as the only share is a way in, not a share.
func TestAPassphraseAloneIsRecognisedAsTheOnlyShare(t *testing.T) {
	h, _ := aHolder(t, "Epassphrase", "passphrase")
	split := HowTheWayInIsSplit{Needed: 1, Holders: []ShareHolder{h}}
	if !split.OnlyShareIsAPassphrase() {
		t.Fatal("a lone passphrase share was not recognised as such")
	}
	// And a passphrase beside real holders is not the same thing.
	w, _ := aHolder(t, "EWitness", "witness")
	split.Holders = append(split.Holders, w)
	split.Needed = 2
	if split.OnlyShareIsAPassphrase() {
		t.Fatal("a passphrase alongside a witness was treated as standing alone")
	}
}
