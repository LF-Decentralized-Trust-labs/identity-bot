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
