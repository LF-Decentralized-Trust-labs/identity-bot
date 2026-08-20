package backup

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"identity-agent-core/store"
)

// aCollectorForAnIdentity is a collector that knows whose backup it is
// writing, which is what puts an AID in the manifest and therefore in the
// bootstrap envelope. A recovering machine reads that to know what it is about
// to become.
func aCollectorForAnIdentity(t *testing.T, aid string) *Collector {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewSQLiteStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SaveIdentity(store.IdentityState{
		AID: aid, PublicKey: "dGVzdA==", NextKeyDigest: "d",
		Created: "2026-01-01T00:00:00Z", EventCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return &Collector{DataDir: dir, Store: st}
}

const wordsForTest = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

// aSplitArchive builds a real archive whose way in is split across holders.
func aSplitArchive(t *testing.T, n, k int) ([]byte, HowTheWayInIsSplit, map[string][]byte) {
	t.Helper()
	split, privs := aSplitOf(t, n, k)

	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	bundle.addSection("identity_state", []byte(`{"aid":"EMyIdentity"}`))
	bundle.addSection("credentials", []byte(`[{"said":"Ecred","secret":"the thing worth stealing"}]`))

	c := aCollectorForAnIdentity(t, "EMyIdentity")
	res, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, ExportRequest{
		Mnemonic:     wordsForTest,
		Tiers:        []string{TierCritical},
		Bundle:       bundle,
		Split:        split,
		DuressPolicy: []byte(`{"hold_for_hours":48}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Bytes, split, privs
}

func sharesFrom(t *testing.T, data []byte, privs map[string][]byte, ids []string) map[string][]byte {
	t.Helper()
	env, _, err := OpenBootstrap(data, OpenRequest{Mnemonic: wordsForTest})
	if err != nil {
		t.Fatal(err)
	}
	byHolder := map[string]SealedShare{}
	for _, s := range env.SealedShares {
		byHolder[s.HolderID] = s
	}
	out := map[string][]byte{}
	for _, id := range ids {
		out[id] = openShare(t, privs[id], byHolder[id])
	}
	return out
}

// The recovery words no longer open a backup.
//
// This is the property the whole change exists for, tested against a real
// archive rather than the pieces: correct words, correct file, and the data is
// not there.
func TestTheRightWordsAloneDoNotOpenASplitArchive(t *testing.T) {
	data, split, _ := aSplitArchive(t, 5, 3)

	_, _, err := OpenArchive(data, OpenRequest{Mnemonic: wordsForTest})
	if err == nil {
		t.Fatal("the recovery words alone opened the archive")
	}
	var needs *ErrNeedsShares
	if !errors.As(err, &needs) {
		t.Fatalf("refused, but not in a way a screen can act on: %v", err)
	}
	if needs.Bootstrap.Split.Needed != split.Needed {
		t.Fatalf("the refusal does not say how many shares are needed: %+v", needs.Bootstrap.Split)
	}
	// And it says so in words somebody can act on.
	if !strings.Contains(err.Error(), "words are right") {
		t.Fatalf("the message does not distinguish this from a wrong phrase: %v", err)
	}
	// The secret is not in the archive's readable parts.
	if strings.Contains(string(data), "the thing worth stealing") {
		t.Fatal("the payload is in the clear")
	}
}

// The words plus enough shares do open it.
func TestTheWordsAndThreeSharesOpenIt(t *testing.T) {
	data, split, privs := aSplitArchive(t, 5, 3)
	ids := holderIDs(split.Holders)[:3]

	bundle, _, err := OpenArchive(data, OpenRequest{
		Mnemonic: wordsForTest,
		Shares:   sharesFrom(t, data, privs, ids),
	})
	if err != nil {
		t.Fatalf("the words and three shares did not open it: %v", err)
	}
	if got := string(bundle.Sections["credentials"]); !strings.Contains(got, "worth stealing") {
		t.Fatalf("the payload did not come back: %q", got)
	}
}

// Two shares do not, and the refusal is the same shape as none.
func TestTheWordsAndTwoSharesDoNotOpenIt(t *testing.T) {
	data, split, privs := aSplitArchive(t, 5, 3)
	ids := holderIDs(split.Holders)[:2]

	_, _, err := OpenArchive(data, OpenRequest{
		Mnemonic: wordsForTest,
		Shares:   sharesFrom(t, data, privs, ids),
	})
	if err == nil {
		t.Fatal("two of three shares opened the archive")
	}
	var needs *ErrNeedsShares
	if !errors.As(err, &needs) || needs.Gathered != 2 {
		t.Fatalf("the refusal does not say what was gathered: %v", err)
	}
}

// No key slot may hold the body key.
//
// This is the mistake that would make the whole design decorative: leave the
// seed slot wrapping the payload key and the recovery words open the body
// directly, whatever the shares say. The check is on the archive itself rather
// than on the code that writes it.
func TestASplitArchiveCarriesNoSlotThatWouldOpenItAlone(t *testing.T) {
	data, _, _ := aSplitArchive(t, 5, 3)

	arch, err := DecodeArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(arch.Manifest.KeySlots) != 0 {
		t.Fatalf("a split archive carries %d key slot(s); any one of them is a way past the shares",
			len(arch.Manifest.KeySlots))
	}
	if arch.Manifest.BootstrapB64 == "" {
		t.Fatal("a split archive has no bootstrap envelope, so nothing says who to ask")
	}
}

// What the words open is readable, and is only the envelope.
func TestTheWordsOpenTheEnvelopeAndTheEnvelopeOnly(t *testing.T) {
	data, split, _ := aSplitArchive(t, 5, 3)

	env, _, err := OpenBootstrap(data, OpenRequest{Mnemonic: wordsForTest})
	if err != nil {
		t.Fatalf("the words did not open the envelope: %v", err)
	}
	if env.IdentityAID == "" {
		t.Fatal("the envelope does not say which identity this is")
	}
	if len(env.Split.Holders) != len(split.Holders) {
		t.Fatal("the envelope does not say who to ask")
	}
	if len(env.DuressPolicy) == 0 {
		t.Fatal("the duress policy is not readable before shares are gathered")
	}
	// And nothing from the body is in it.
	raw, _ := json.Marshal(env)
	if strings.Contains(string(raw), "worth stealing") {
		t.Fatal("payload data is in the envelope the words open")
	}
}

// The wrong words are refused the same way they always were.
func TestWrongWordsStillSayTheSameThing(t *testing.T) {
	data, _, _ := aSplitArchive(t, 5, 3)
	other := "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

	_, _, err := OpenBootstrap(data, OpenRequest{Mnemonic: other})
	if err == nil {
		t.Fatal("the wrong words opened the envelope")
	}
	// A wrong phrase and a phrase needing shares must not read alike.
	var needs *ErrNeedsShares
	if errors.As(err, &needs) {
		t.Fatal("a wrong phrase was reported as needing shares")
	}
}

// An archive written without a split is unchanged.
//
// Every archive that exists today is of that shape, and this change must not
// make one of them unopenable.
func TestAnArchiveWrittenWithoutASplitStillOpensFromTheWords(t *testing.T) {
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	bundle.addSection("identity_state", []byte(`{"aid":"EOld"}`))

	c := aCollectorForAnIdentity(t, "EOld")
	res, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, ExportRequest{
		Mnemonic: wordsForTest,
		Tiers:    []string{TierCritical},
		Bundle:   bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := OpenArchive(res.Bytes, OpenRequest{Mnemonic: wordsForTest})
	if err != nil {
		t.Fatalf("an archive of the older shape no longer opens: %v", err)
	}
	if string(got.Sections["identity_state"]) != `{"aid":"EOld"}` {
		t.Fatal("it opened to the wrong thing")
	}
	// And OpenBootstrap says "there isn't one" rather than failing.
	env, _, err := OpenBootstrap(res.Bytes, OpenRequest{Mnemonic: wordsForTest})
	if err != nil {
		t.Fatalf("asking an old archive for an envelope failed: %v", err)
	}
	if env != nil {
		t.Fatal("an old archive reported having a bootstrap envelope")
	}
}

// A passphrase cannot be the only thing beside the words.
func TestAPassphraseAloneIsRefusedAtTheMomentOfWriting(t *testing.T) {
	h, _ := aHolder(t, "Epassphrase", "passphrase")
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	bundle.addSection("identity_state", []byte(`{"aid":"E"}`))

	c := aCollectorForAnIdentity(t, "EPass")
	_, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, ExportRequest{
		Mnemonic: wordsForTest,
		Tiers:    []string{TierCritical},
		Bundle:   bundle,
		Split:    HowTheWayInIsSplit{Needed: 1, Holders: []ShareHolder{h}},
	})
	if err == nil {
		t.Fatal("an archive protected only by a passphrase was written")
	}
	if !strings.Contains(err.Error(), "add a device or a person") {
		t.Fatalf("refused without saying what to do instead: %v", err)
	}
}
