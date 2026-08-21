package backup

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrNoKeyToVerifyWith means this device holds nothing that opens the archive
// it just made, so it cannot check its own work.
//
// That happens for an archive sealed only to the owner's recovery keys, and it
// is the design working: the private key deliberately is not here. Such a
// backup is kept and recorded as UNVERIFIED rather than failed, because the
// alternative is refusing to back up at all in exactly the configuration that
// keeps the key furthest from the machine.
var ErrNoKeyToVerifyWith = errors.New("this device holds no key that opens the archive it made")

// An archive counts as a backup only once it has been opened.
//
// Until now the first read of any archive was the day somebody needed it,
// which is the one day a bad answer is useless. Everything before that point
// checks the process rather than the product: the collector ran, the file
// wrote, the destination accepted it. An archive can pass all of that and be
// unopenable, and nothing would say so for months.
//
// So the archive is opened here, at the moment it is made, while the data it
// came from is still on the disk beside it and the person could still act.
//
// This is deliberately not a restore. It does not write anything anywhere. It
// re-derives the key, decrypts the payload, and checks that what comes out is
// what the manifest promised — which is the part that fails when a backup is
// going to fail.
func verifyArchiveOpens(result *ExportResult, req ExportRequest, collected *PayloadBundle) error {
	if result == nil || len(result.Bytes) == 0 {
		return fmt.Errorf("the archive is empty")
	}

	if req.Mnemonic == "" && len(req.BIP39Seed) == 0 && req.Passphrase == "" {
		return ErrNoKeyToVerifyWith
	}

	// An archive protected by shares is verified as far as it CAN be verified
	// here, which is the envelope and everything needed to reassemble the key.
	//
	// The body deliberately does not open without k shares, and the machine
	// that just wrote the backup has none — that is the entire point of it. So
	// asking for the body back would fail every split archive, and the caller
	// treats a failed verification as "not kept", meaning the moment shares
	// were wired into the export path every backup would be discarded.
	//
	// What can be checked is checked: that the words open the envelope, that
	// it names holders and carries a share for each, and that there is
	// something for k of them to reassemble. What cannot be is stated rather
	// than skipped — see the returned error when the envelope is unusable.
	if verr := verifySplitArchiveOpens(result, req); verr != errNotASplitArchive {
		return verr
	}

	// Opened the way a person in trouble would open it — from the key material
	// alone. Verifying with anything the maker happens to be holding would
	// prove the archive opens for somebody who does not need it to.
	opened, manifest, err := OpenArchive(result.Bytes, OpenRequest{
		Mnemonic:   req.Mnemonic,
		BIP39Seed:  req.BIP39Seed,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		return fmt.Errorf("the archive could not be reopened: %w", err)
	}
	if manifest == nil || opened == nil {
		return fmt.Errorf("the archive opened to nothing")
	}

	// Every section the manifest promises is present, and holds something.
	// A section that opens to nothing is the failure this exists to catch:
	// the file is valid, the digest matches, and the data is gone.
	for _, want := range manifest.Sections {
		got, ok := opened.Sections[want.Name]
		if !ok {
			return fmt.Errorf("the manifest promises section %q and the archive does not contain it", want.Name)
		}
		if want.SizePlaintext > 0 && len(got) == 0 {
			return fmt.Errorf("section %q opened to nothing, and the manifest says it holds %d bytes",
				want.Name, want.SizePlaintext)
		}
	}

	// What was collected is what came back. The manifest is written from the
	// bundle, so checking the archive against the manifest alone would compare
	// it to its own account of itself.
	if collected != nil {
		for name, data := range collected.Sections {
			got, ok := opened.Sections[name]
			if !ok {
				return fmt.Errorf("section %q was collected and is not in the archive", name)
			}
			if !bytes.Equal(got, data) {
				return fmt.Errorf("section %q came back different from what was collected: %d bytes, was %d",
					name, len(got), len(data))
			}
		}
	}

	return nil
}

// errNotASplitArchive says this archive is of the older shape and should be
// verified the ordinary way.
var errNotASplitArchive = fmt.Errorf("not a split archive")

// verifySplitArchiveOpens checks everything about a share-protected archive
// that can be checked without the shares.
func verifySplitArchiveOpens(result *ExportResult, req ExportRequest) error {
	if result.Manifest.BootstrapB64 == "" {
		return errNotASplitArchive
	}

	env, _, err := OpenBootstrap(result.Bytes, OpenRequest{
		Mnemonic:  req.Mnemonic,
		BIP39Seed: req.BIP39Seed,
	})
	if err != nil {
		return fmt.Errorf("the archive could not be reopened: %w", err)
	}
	if env == nil {
		return fmt.Errorf("the archive says it is protected by shares and carries no envelope")
	}
	// The same checks the envelope refuses to be built without, run again on
	// what actually reached the file — because the thing being verified is the
	// bytes, not the intention.
	if err := env.Validate(); err != nil {
		return fmt.Errorf("the archive's envelope would not let it be opened: %w", err)
	}
	if want := countCombinations(len(env.Split.Holders), env.Split.Needed); len(env.SubsetWraps) != want {
		return fmt.Errorf(
			"this archive carries %d ways to reassemble its key and needs %d, so some "+
				"combinations of holders could never open it", len(env.SubsetWraps), want)
	}
	return nil
}
