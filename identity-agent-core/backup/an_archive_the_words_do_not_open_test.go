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

// A split archive passes the check that runs before a backup is kept.
//
// The machine that just wrote the backup holds none of its shares — that is
// the entire point — so asking for the body back fails, and the caller treats
// a failed verification as "not kept". Wiring shares into the export path
// would therefore have discarded every backup it produced.
func TestASplitArchiveSurvivesTheCheckBeforeItIsKept(t *testing.T) {
	data, split, _ := aSplitArchive(t, 5, 3)
	arch, err := DecodeArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	result := &ExportResult{Bytes: data, Manifest: arch.Manifest}

	if err := verifyArchiveOpens(result, ExportRequest{
		Mnemonic: wordsForTest, Split: split,
	}, nil); err != nil {
		t.Fatalf("a split archive failed the check that decides whether to keep it: %v", err)
	}
}

// And a damaged one still fails it.
func TestADamagedSplitArchiveIsStillCaught(t *testing.T) {
	data, split, _ := aSplitArchive(t, 5, 3)
	arch, err := DecodeArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	// The envelope no longer opens.
	arch.Manifest.BootstrapB64 = EncodeB64([]byte("not an envelope"))
	damaged, err := EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}
	result := &ExportResult{Bytes: damaged, Manifest: arch.Manifest}

	if err := verifyArchiveOpens(result, ExportRequest{
		Mnemonic: wordsForTest, Split: split,
	}, nil); err == nil {
		t.Fatal("an archive whose envelope will not open was accepted and kept")
	}
}

// Shares cannot yet be combined with the other ways into an archive, and that
// is said rather than silently dropped.
//
// The split path returns before any slot is written, so a caller asking for a
// sealed recipient got an archive where none exists and no error — and the
// export path always passes sealed recipients, so wiring a split in would have
// produced archives every destination meant to open them could not.
func TestSharesCannotBeSilentlyCombinedWithTheOtherWaysIn(t *testing.T) {
	_, split, _ := aSplitArchive(t, 3, 2)
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	bundle.addSection("identity_state", []byte(`{"aid":"E"}`))
	c := aCollectorForAnIdentity(t, "EMyIdentity")

	for _, extra := range []struct {
		what string
		req  ExportRequest
	}{
		{"a sealed recipient", ExportRequest{SealToPublicKeys: [][]byte{make([]byte, 32)}}},
		{"a passphrase", ExportRequest{Passphrase: "something"}},
		{"a guardian slot", ExportRequest{GuardianSlots: []KeySlot{{Type: SlotGuardianMS}}}},
	} {
		req := extra.req
		req.Mnemonic = wordsForTest
		req.Tiers = []string{TierCritical}
		req.Bundle = bundle
		req.Split = split

		_, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, req)
		if err == nil {
			t.Fatalf("%s was silently discarded from a split archive", extra.what)
		}
		if !strings.Contains(err.Error(), "cannot yet be combined") {
			t.Fatalf("%s was refused for the wrong reason: %v", extra.what, err)
		}
	}
}

// Enough shares that do not work is a different thing from too few.
//
// Saying "you need 2 of 3 shares and 3 have been gathered" is both false and
// hides the condition the owner most needs told: a holder handed back
// something that is not its share. That is either a broken holder or a lying
// one, and neither is fixed by finding more holders.
func TestAWrongShareIsNotReportedAsAMissingOne(t *testing.T) {
	data, split, privs := aSplitArchive(t, 3, 2)
	ids := holderIDs(split.Holders)[:2]
	good := sharesFrom(t, data, privs, ids)

	// One holder returns something that is not its share.
	poisoned := map[string][]byte{}
	for id, s := range good {
		poisoned[id] = s
	}
	poisoned[ids[0]] = make([]byte, 32)

	_, _, err := OpenArchive(data, OpenRequest{Mnemonic: wordsForTest, Shares: poisoned})
	if err == nil {
		t.Fatal("a wrong share opened the archive")
	}
	var needs *ErrNeedsShares
	if errors.As(err, &needs) {
		t.Fatalf("a holder returning the wrong share was reported as needing more: %v", err)
	}
	if !strings.Contains(err.Error(), "not its share") {
		t.Fatalf("the message does not say a holder returned something wrong: %v", err)
	}
}

// An archive from a future version says so, rather than sending somebody
// looking for holders.
func TestAFutureArchiveSaysToUpdateRatherThanToFindHolders(t *testing.T) {
	data, _, _ := aSplitArchive(t, 3, 2)
	arch, err := DecodeArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	arch.Manifest.FormatVersion = FormatVersion + 5
	future, err := EncodeArchive(arch)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = OpenArchive(future, OpenRequest{Mnemonic: wordsForTest})
	if err == nil {
		t.Fatal("an archive from a newer format was opened")
	}
	if !strings.Contains(err.Error(), "update the software") {
		t.Fatalf("it did not say what to do: %v", err)
	}
	var needs *ErrNeedsShares
	if errors.As(err, &needs) {
		t.Fatal("a future-format archive sent somebody looking for holders")
	}
}
