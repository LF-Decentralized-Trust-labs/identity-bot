package server

import (
	"encoding/json"
	"fmt"
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
	// Written beside and renamed, so an agent interrupted mid-write comes back
	// with the previous file rather than a truncated one. A half-written file
	// here reads as "never published anything", which is the state this exists
	// to prevent.
	tmp := pairingOfferPath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, pairingOfferPath(dataDir)); err != nil {
		os.Remove(tmp)
		return err
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
