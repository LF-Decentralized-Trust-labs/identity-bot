package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// Finding the key to a machine again, from the recovery words alone.
//
// WHAT WENT MISSING. A machine answers to a pairwise identity derived from the
// owner's root seed at an index. The words re-derive the seed; nothing in them
// says which index. That index is written down on the device that minted it and
// carried in its backup archive — so words plus archive recovers a machine, and
// words alone do not.
//
// Before machines were paired this way the words were enough on their own,
// because the machine was delegated from the root and the root is exactly what
// the words produce. Losing that was the accepted cost of not publishing the
// owner's root identifier. What was not intended was that losing an archive
// should be unrecoverable.
//
// SO THE INDEX IS SEARCHED FOR RATHER THAN REMEMBERED. Identities in a pool are
// derived from a known base, in order, so a device holding only the words can
// derive forward until it finds the one this machine answers to. That turns
// "the archive is gone" from unrecoverable into slow.
//
// WHAT IT COMPARES, AND WHY NOT THE IDENTIFIER. The obvious test is to rebuild
// each candidate identity and compare identifiers. That does not work, and the
// reason is worth writing down: an identifier is a digest of the event that
// created it, and that event names the witnesses in force at the time. Rebuild
// it when the witness pool has changed and the identifier comes out different
// for the same key — so a search on identifiers would quietly find nothing and
// report the machine unrecoverable.
//
// The PUBLIC KEY does not move. It is a function of the seed and the index and
// nothing else. So the machine is asked which key it sealed, and the search
// compares keys. It is also far cheaper: deriving a key is arithmetic, while
// rebuilding an identity is a round trip through the KERI engine.
//
// It proves nothing by itself. Finding the index does not make anybody the
// owner; it recovers the ability to sign as an identity this device could
// always have derived. Somebody without the words derives different keys and
// matches nothing.

// ownerSearchLimit bounds how far the search goes.
//
// A person does not own thousands of machines, and an unbounded search on a
// route anybody can call is a way to make an agent do arbitrary work. Two
// thousand covers any real number of machines and takes well under a second.
const ownerSearchLimit = 2000

type recoverOwnerRequest struct {
	// MachineURL is where the machine is. Its own address, because what is
	// being recovered is the ability to speak to that specific machine.
	MachineURL string `json:"machine_url"`
}

type recoverOwnerResponse struct {
	OwnerAID string `json:"owner_aid"`
	// Index is where the key came from, recorded again so the search does not
	// have to be repeated.
	Index int `json:"owner_index"`
	// Searched says how far it went, so a failure can be told apart from a
	// machine that was never this device's to begin with.
	Searched int `json:"searched"`
}

// handleRecoverMachineOwner finds which derivation index owns a machine.
//
// Called on a device that has the root seed — restored from the recovery words
// — and has lost the record of which index it minted for that machine.
func (s *CoreServer) handleRecoverMachineOwner(w http.ResponseWriter, r *http.Request) {
	var req recoverOwnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	base := strings.TrimRight(strings.TrimSpace(req.MachineURL), "/")
	if base == "" {
		writeError(w, http.StatusBadRequest, "No machine given",
			"say where the machine is; what is being recovered is the ability to speak to it")
		return
	}

	ownerAID, ownerKey, err := fetchOwnerAuthority(base)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Could not ask that machine who it answers to", err.Error())
		return
	}
	if ownerKey == "" {
		writeError(w, http.StatusConflict, "That machine names no owner key",
			"it answers to "+ownerAID+" but does not say which key, so there is nothing to "+
				"search for. A machine that has not been claimed is in this state, and so is "+
				"one that answers to nobody")
		return
	}

	rootSeed, err := ensureRootSeed(s.DataDir)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "No root seed on this device", err.Error())
		return
	}

	base0, err := store.PoolBase("machines")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not find where machine identities start", err.Error())
		return
	}

	for i := 0; i < ownerSearchLimit; i++ {
		idx := base0 + i
		seed, derr := backup.DerivePairwiseSeed(rootSeed, idx, 0)
		if derr != nil {
			continue
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if iacrypto.VerkeyQB64(pub) != ownerKey {
			continue
		}

		// Found. Written down again so this is a one-off rather than something
		// the owner repeats every time they speak to the machine.
		if werr := s.DataStore.RememberMachineOwnerIdentity(ownerAID, idx); werr != nil {
			writeError(w, http.StatusInternalServerError, "Found it, but could not record it",
				"the key is at index "+fmt.Sprint(idx)+" and this device could not write that "+
					"down: "+werr.Error())
			return
		}
		writeJSON(w, recoverOwnerResponse{OwnerAID: ownerAID, Index: idx, Searched: i + 1})
		return
	}

	writeError(w, http.StatusNotFound, "This device did not mint that identity",
		fmt.Sprintf("searched %d indices from the machine pool and none produced the key %s "+
			"answers to. Either these are not the recovery words that machine was set up with, "+
			"or it belongs to somebody else", ownerSearchLimit, ownerAID))
}

// fetchOwnerAuthority asks a machine which identity it answers to.
func fetchOwnerAuthority(base string) (aid, publicKey string, err error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(base + "/api/owners/authority")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Owner *struct {
			AID       string `json:"aid"`
			PublicKey string `json:"public_key"`
		} `json:"owner"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", err
	}
	if out.Owner == nil {
		return "", "", fmt.Errorf("that machine answers to nobody yet")
	}
	return out.Owner.AID, out.Owner.PublicKey, nil
}
