package server

import (
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Offering a computer you are sitting at.
//
// A computer somebody else set up is TOLD who may claim it, by whoever started
// it, while it is still reachable by nobody else. Nothing does that for a
// laptop: nothing provisions it, and it is on a network from the moment it
// starts. Requiring it anyway is why an ordinary computer could not be paired
// at all — every claim was refused for arriving at a machine that had been told
// nothing.
//
// So the machine issues its own claim code and shows it on its own screen.
//
// WHAT MAKES THIS SAFE IS NOT THIS FILE. It is that a claim has to prove
// control of the identity making it — see claim_proves_control.go. Without that
// the code would be a bearer secret and whoever picked it up could take the
// machine; with it, the code is one factor and the key is the other. This is
// the reason the two were built together rather than this arriving first.
//
// What this file adds on top is narrow and worth being precise about:
//
//   - The code is minted here and returned once, for this machine's own screen.
//     No route serves it afterwards.
//   - The request must be genuinely local. Not because being local is what
//     authorises the pairing — the signature does that — but because the code
//     is a secret displayed on a screen, and a route that handed it to anyone
//     who asked would put it on the network, which is exactly where it must not
//     be.
//   - It expires, and it is spent when used. An offer left standing is a
//     machine still claimable by whoever reaches it later.
//
// A machine that was already told who may claim it cannot be re-offered this
// way. It belongs to that claim, and console access must not redirect it.

var localOffer struct {
	sync.Mutex
	token   string
	expires time.Time
}

// localOfferWindow is how long an offer stands: long enough to walk to another
// room and back with a phone, short enough that a forgotten one closes itself.
const localOfferWindow = 10 * time.Minute

// localPairingOffer returns the live offer, if there is one.
//
// An expired offer reports as absent rather than as a mismatch. The two are
// different failures, and somebody who waited too long should be told to offer
// the machine again rather than that their code was wrong.
func localPairingOffer() (token string, live bool) {
	localOffer.Lock()
	defer localOffer.Unlock()
	if localOffer.token == "" || time.Now().After(localOffer.expires) {
		return "", false
	}
	return localOffer.token, true
}

// clearLocalPairingOffer spends the offer. A code that still works after the
// machine has been claimed is a second owner waiting to happen.
func clearLocalPairingOffer() {
	localOffer.Lock()
	defer localOffer.Unlock()
	localOffer.token, localOffer.expires = "", time.Time{}
}

func resetLocalPairingOfferForTest() { clearLocalPairingOffer() }

// newPairingCode mints the code shown on screen.
//
// Base32 uppercased and grouped: it is read off one screen and typed into
// another. 80 bits, because it is read by a person and still has to be far
// beyond guessing within the window it stands for.
func newPairingCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	c := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	return c[0:4] + "-" + c[4:8] + "-" + c[8:12] + "-" + c[12:16], nil
}

// handleOfferThisComputer offers the machine this request came from.
func (s *CoreServer) handleOfferThisComputer(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		writeError(w, http.StatusForbidden, "Not from this computer",
			"the code is shown on this machine's own screen, so it is only handed to "+
				"something running on it — being able to reach it over the network is not "+
				"the same as being at it")
		return
	}
	if s.DataStore != nil {
		if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
			writeError(w, http.StatusConflict, "Already set up",
				"this computer already has an identity, so there is nothing to pair it into")
			return
		}
	}
	if _, _, told := expectedAdoption(); told {
		writeError(w, http.StatusConflict, "Already promised to somebody",
			"this computer was set up for a specific identity before it started, and "+
				"being at its keyboard does not override that")
		return
	}

	code, err := newPairingCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not create a code", err.Error())
		return
	}
	localOffer.Lock()
	localOffer.token, localOffer.expires = code, time.Now().Add(localOfferWindow)
	localOffer.Unlock()

	writeJSON(w, map[string]any{
		"code": code,
		// So the screen counts down with the machine rather than to its own
		// idea of how long is left.
		"expires_in_seconds": int(localOfferWindow.Seconds()),
	})
}

// handleThisComputersPairingState tells the screen what has happened to the
// code it is showing.
//
// The screen has to say WHO took the machine, not just that somebody did. A
// code displayed on a screen can be read by anyone who can see the screen, and
// first-write-wins means whoever presents it first decides who owns the
// machine. That is bounded — they have to be looking at it — but it is not
// nothing, and the only remedy is that the person standing there finds out
// immediately rather than after they have set the machine up.
//
// Local-only for the same reason as the offer itself: this reports on a secret
// shown on that machine's screen.
func (s *CoreServer) handleThisComputersPairingState(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		writeError(w, http.StatusForbidden, "Not from this computer",
			"what this computer is showing on its own screen is not reported over the network")
		return
	}
	out := map[string]any{}
	if s.DataStore != nil {
		if identity, err := s.DataStore.GetIdentity(); err == nil && identity != nil {
			out["paired"] = true
			out["identity"] = identity.AID
		}
	}
	if code, live := localPairingOffer(); live {
		out["code"] = code
		out["expires_in_seconds"] = int(time.Until(localOfferExpiry()).Seconds())
	}
	// Whoever has said they will claim it. Until somebody scans, this is empty
	// and the screen simply waits.
	if _, ownerAID, told := expectedAdoption(); told && ownerAID != "" {
		out["claimed_by"] = ownerAID
	}
	writeJSON(w, out)
}

// localOfferExpiry is when the standing offer runs out.
func localOfferExpiry() time.Time {
	localOffer.Lock()
	defer localOffer.Unlock()
	return localOffer.expires
}
