package backup

import (
	"errors"
	"strings"
	"testing"
)

// A verifier that never rejects anything is indistinguishable from no verifier,
// and the second one is what was there before. These give it archives that are
// wrong in the specific ways a real one goes wrong, and require it to say so.

func anArchiveAndWhatWentIntoIt(t *testing.T) (*ExportResult, ExportRequest, *PayloadBundle) {
	t.Helper()

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	// Built through addRawSection, the way the collector builds one. A bundle
	// assembled by hand into Sections alone archives NOTHING and reports no
	// error, because CreateArchive writes from Ordered.
	c := &Collector{DataDir: t.TempDir()}
	bundle := &PayloadBundle{Sections: map[string][]byte{}}
	c.addRawSection(bundle, "identity_state", []byte(`{"aid":"EMyIdentity"}`))
	c.addRawSection(bundle, "contacts", []byte(`[{"aid":"EAFriend"}]`))

	req := ExportRequest{
		BIP39Seed: seed,
		Tiers:     []string{TierCritical},
		Bundle:    bundle,
	}
	result, err := c.CreateArchive(CollectOptions{Tiers: []string{TierCritical}}, req)
	if err != nil {
		t.Fatalf("create the archive: %v", err)
	}
	return result, req, bundle
}

func TestAGoodArchivePassesVerification(t *testing.T) {
	result, req, bundle := anArchiveAndWhatWentIntoIt(t)

	if err := verifyArchiveOpens(result, req, bundle); err != nil {
		t.Fatalf("a good archive was rejected: %v", err)
	}
}

// The failure that matters: the file is present, the right size, and does not
// open. Every check that existed before this passed on exactly this archive.
func TestACorruptArchiveIsRejected(t *testing.T) {
	result, req, bundle := anArchiveAndWhatWentIntoIt(t)

	// Damage the ciphertext, not the header — a truncated file is caught by
	// parsing, which was never the gap. This one parses.
	corrupt := make([]byte, len(result.Bytes))
	copy(corrupt, result.Bytes)
	corrupt[len(corrupt)-1] ^= 0xFF
	damaged := &ExportResult{Bytes: corrupt, Manifest: result.Manifest}

	err := verifyArchiveOpens(damaged, req, bundle)
	if err == nil {
		t.Fatal("a corrupt archive passed verification, so verification proves nothing")
	}
	if !strings.Contains(err.Error(), "could not be reopened") {
		t.Errorf("the failure should say the archive would not reopen, said: %v", err)
	}
}

func TestAnEmptyArchiveIsRejected(t *testing.T) {
	_, req, bundle := anArchiveAndWhatWentIntoIt(t)

	if err := verifyArchiveOpens(&ExportResult{}, req, bundle); err == nil {
		t.Fatal("an empty archive passed verification")
	}
}

// An archive that opens perfectly and is missing something that went into it.
// This is the shape of problem 183 one layer earlier: valid, complete against
// its own manifest, and short.
func TestAnArchiveMissingWhatWentIntoItIsRejected(t *testing.T) {
	result, req, bundle := anArchiveAndWhatWentIntoIt(t)

	// Something the collector gathered that never reached the archive.
	claimed := &PayloadBundle{Sections: map[string][]byte{}}
	for k, v := range bundle.Sections {
		claimed.Sections[k] = v
	}
	claimed.Sections["credentials"] = []byte(`[{"said":"ENeverArrived"}]`)

	err := verifyArchiveOpens(result, req, claimed)
	if err == nil {
		t.Fatal("an archive missing a collected section passed verification")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("the failure should name the missing section, said: %v", err)
	}
}

// A device holding no key that opens its own archive says so, and does not
// report the backup as failed. Refusing to keep it would mean refusing to back
// up in the configuration that keeps the key furthest from the machine.
func TestADeviceWithNoKeyToVerifyWithSaysSo(t *testing.T) {
	result, _, bundle := anArchiveAndWhatWentIntoIt(t)

	err := verifyArchiveOpens(result, ExportRequest{}, bundle)
	if !errors.Is(err, ErrNoKeyToVerifyWith) {
		t.Fatalf("expected the archive to be reported as unverifiable here, got: %v", err)
	}
}
