package backup

import (
	"testing"
)

// A passphrase must strengthen an archive, never weaken it.
//
// Under the OR policy the passphrase slot wraps the payload key itself, so the
// passphrase ALONE opens the archive. That is a second key to somebody's whole
// identity, and a far weaker one than twenty-four words: an attacker holding
// the file can grind it offline for as long as they like. No caller outside
// this package's tests ever set a policy and the default was OR, so every
// archive any route could produce was in that mode.

func TestAPassphraseAloneCannotOpenAnArchive(t *testing.T) {
	m := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	const pass = "hunter2"

	c := &Collector{DataDir: t.TempDir()}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	c.addRawSection(bundle, "identity_state", []byte(`{"aid":"EMyIdentity"}`))

	res, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, ExportRequest{
		Mnemonic:   m,
		Passphrase: pass,
		Tiers:      []string{TierCritical},
		Bundle:     bundle,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The passphrase on its own must not be a way in.
	if _, _, err := OpenArchive(res.Bytes, OpenRequest{Passphrase: pass}); err == nil {
		t.Fatal("the passphrase alone opened the archive, so it is a second and weaker key")
	}

	// Neither is the phrase on its own, once a passphrase was set: somebody who
	// adds one is asking for both to be required.
	if _, _, err := OpenArchive(res.Bytes, OpenRequest{Mnemonic: m}); err == nil {
		t.Fatal("the phrase alone opened an archive that was given a passphrase")
	}

	// Both together do.
	if _, _, err := OpenArchive(res.Bytes, OpenRequest{Mnemonic: m, Passphrase: pass}); err != nil {
		t.Fatalf("both factors together did not open the archive: %v", err)
	}

	if res.Manifest.SlotPolicy != PolicyAND {
		t.Fatalf("an archive with a passphrase is in %q mode", res.Manifest.SlotPolicy)
	}
}

func TestAnArchiveWithNoPassphraseStillOpensFromTheWordsAlone(t *testing.T) {
	// The ordinary case must be untouched: no passphrase means the recovery
	// phrase is the only thing needed, which is what recovery depends on.
	m := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
	c := &Collector{DataDir: t.TempDir()}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	c.addRawSection(bundle, "identity_state", []byte(`{"aid":"EMyIdentity"}`))

	res, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, ExportRequest{
		Mnemonic: m,
		Tiers:    []string{TierCritical},
		Bundle:   bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenArchive(res.Bytes, OpenRequest{Mnemonic: m}); err != nil {
		t.Fatalf("an archive with no passphrase no longer opens from the words: %v", err)
	}
	if res.Manifest.SlotPolicy == PolicyAND {
		t.Fatal("an archive with no passphrase was made to require two factors")
	}
	// The manifest, not the first 64 bytes — the slot list sits past the magic
	// and the length prefix, so a window that small could never contain it and
	// the check read as though it proved something.
	for _, slot := range res.Manifest.KeySlots {
		if slot.Type == SlotPassphrase {
			t.Fatal("a passphrase slot was written for an archive that has no passphrase")
		}
	}
}
