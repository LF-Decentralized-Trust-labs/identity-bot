package server

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Remembering the identity this agent offered for pairing.
//
// An agent with no owner mints a pairwise AID, publishes it, and waits for
// somebody to pair against it. The AID travels outwards as an OOBI and is
// handed to whoever is going to claim the agent — so from the moment it is
// published, it is an address a person is holding.
//
// It was minted once per PROCESS and kept in memory. So an agent that restarted
// minted a second one and offered that instead, and the address the person was
// holding stopped resolving. Nothing failed, nothing was logged, and the agent
// looked healthy the whole time — it had simply become a different agent than
// the one somebody had been told to come and claim.
//
// The AID itself was never the fragile part: its keys derive from the root seed
// and its key event log lives in the KERI store, both of which are on disk. What
// was missing was any record of WHICH pairwise AID had been published, plus the
// two in-memory registries that make it resolvable — so this stores exactly
// those three facts and puts them back at startup.
//
// It is a file next to the root seed rather than a row in the data store,
// because it is the same kind of fact: something this agent must know about
// itself before it has an identity, and therefore before most of the store is
// meaningful.

const pairingOfferFileName = "provisioning-pairing.json"

// storedPairingOffer is what has to survive a restart for a published pairing
// address to keep working.
//
// The OOBI is deliberately NOT stored. It is composed from the agent's current
// public URL, and that URL legitimately changes — a tunnel reconnects, a proxy
// tells the agent a new address. Storing it would pin the agent to wherever it
// was when it first started and reintroduce the same defect one layer along.
// The AID is the durable fact; the address is looked up fresh.
type storedPairingOffer struct {
	AID string `json:"aid"`
	// PublicKey is the base64url Ed25519 verification key, which is what
	// /public/{aid}/did.json serves.
	PublicKey string `json:"public_key"`
	// KEL is the key event log, which is what /public/oobi/{aid} serves. Without
	// it the AID is remembered but cannot be resolved, which to anybody holding
	// the address is indistinguishable from it being gone.
	KEL []map[string]interface{} `json:"kel"`
}

func pairingOfferPath(dataDir string) string {
	return filepath.Join(dataDir, pairingOfferFileName)
}

// savePairingOffer records the identity this agent has just published.
//
// Called after the offer is minted and before it is served, so an agent cannot
// hand out an address it has not written down. The other order would leave the
// exact hole this closes: a person holding an address the agent will not
// remember.
func savePairingOffer(dataDir string, offer storedPairingOffer) error {
	if dataDir == "" {
		return fmt.Errorf("no data directory, so the published pairing identity cannot be remembered")
	}
	if offer.AID == "" {
		return fmt.Errorf("refusing to record a pairing offer with no AID")
	}
	raw, err := json.MarshalIndent(offer, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}
	// Written beside, flushed to the disk, and only then renamed into place.
	//
	// The flush is the part that is easy to leave out and is the whole point
	// here. Write-and-rename is atomic against a half-written file, and atomic
	// against nothing at all if the machine stops before the data leaves its
	// cache: the rename lands in the page cache too, so an agent that is killed
	// rather than shut down comes back to a file that was never there.
	//
	// That is not a rare case for this particular record. It is written by an
	// agent nobody has claimed yet, during the handover window, and the ordinary
	// way that window ends is somebody stopping the agent — which on most
	// deployments is a signal, not a shutdown. Measured directly: the record was
	// written, the process was killed, and the agent came back with no record and
	// minted a second identity, silently replacing the address a person was
	// holding.
	//
	// The directory is flushed as well as the file. A rename is a directory
	// change, so without it the file's contents can be durable while the name
	// pointing at them is not.
	tmp := pairingOfferPath(dataDir) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("the pairing identity could not be flushed to disk, so it would not survive this agent stopping: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, pairingOfferPath(dataDir)); err != nil {
		os.Remove(tmp)
		return err
	}
	if dir, derr := os.Open(dataDir); derr == nil {
		// Reported but not fatal: the contents are already durable, so the worst
		// case is losing the record rather than corrupting it, and refusing to
		// pair over it would be a worse trade.
		if serr := dir.Sync(); serr != nil {
			log.Printf("[provisioning] WARNING: could not flush the directory holding the pairing identity, "+
				"so it may not survive this agent stopping: %v", serr)
		}
		dir.Close()
	}
	return nil
}

// loadPairingOffer reads back what this agent published, if anything.
//
// A missing file is not an error: an agent that has never offered itself for
// pairing is the ordinary case, and by far the most common one.
func loadPairingOffer(dataDir string) (*storedPairingOffer, bool, error) {
	if dataDir == "" {
		return nil, false, nil
	}
	raw, err := os.ReadFile(pairingOfferPath(dataDir))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var offer storedPairingOffer
	if err := json.Unmarshal(raw, &offer); err != nil {
		return nil, false, fmt.Errorf(
			"the recorded pairing identity is unreadable, so this agent cannot tell which address it published: %w", err)
	}
	if offer.AID == "" {
		return nil, false, fmt.Errorf("the recorded pairing identity has no AID")
	}
	return &offer, true, nil
}
