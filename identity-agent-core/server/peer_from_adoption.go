package server

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"identity-agent-core/didcomm"
)

// Establishing a private channel at the moment both parties are already proven.
//
// Two agents can only encrypt to each other once each holds the other's keys.
// The way that happened was a fetch: ask the other side's address for its keys
// and believe the answer. Over a connection somebody else terminates, that is
// the one step they can answer themselves — and then read everything encrypted
// to the keys they supplied. The protection was undone at the step that set it
// up.
//
// Adoption is the natural place to avoid it entirely. By the time an instance
// is adopted, both sides have already proved who they are: the owner presented
// an adoption code issued to them and a key the instance was told in advance to
// expect. Keys carried inside that exchange are as trustworthy as the adoption,
// and nothing has to be fetched from anybody afterwards.
//
// This is one direction. The other is the instance's own keys, returned in the
// same response, so the owner completes their half without a fetch either.

// deviceName is the name given for the owner's device, or "" for none.
func (s *CoreServer) rememberPeerFromAdoption(did *didcomm.DID, endpoint, deviceName string) error {
	if did == nil || did.AID == "" {
		return fmt.Errorf("no owner keys were supplied")
	}
	// Everything the envelope needs, checked before it is stored rather than
	// when it is first used — which would be during whatever the owner was
	// trying to do, and would look like that failing.
	if _, err := didcomm.ParseDIDForCheck(did); err != nil {
		return fmt.Errorf("the owner's keys could not be read: %w", err)
	}

	didcommMu.Lock()
	defer didcommMu.Unlock()
	peers, err := s.loadPeers()
	if err != nil {
		return err
	}
	if existing, ok := peers[did.AID]; ok && existing.DID.X25519 != did.X25519 {
		// Adoption happens once. A second one arriving with different keys for
		// the same identity is either a mistake or somebody replacing the
		// owner's keys with their own, and quietly overwriting would make the
		// second case invisible.
		return fmt.Errorf("this instance already holds different keys for %s, so these were not stored", did.AID)
	}
	name := cleanDeviceName(deviceName)
	if existing, ok := peers[did.AID]; ok && name == "" {
		name = existing.DeviceName // a repeat adoption without a name keeps the one given
	}
	peers[did.AID] = peerRecord{
		AID:        did.AID,
		DID:        *did,
		Endpoint:   canonicalPeerEndpoint(endpoint),
		AddedAt:    time.Now().UTC(),
		DeviceName: name,
	}
	return s.savePeers(peers)
}

// maxDeviceNameRunes bounds a device's name; it is shown on a screen, not stored as data.
const maxDeviceNameRunes = 80

// cleanDeviceName makes a name fit to show: control characters made spaces, format characters
// (direction overrides, zero-width) dropped, runs of
// space collapsed, cut at maxDeviceNameRunes. "" where nothing readable is left.
func cleanDeviceName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) {
			r = ' '
		}
		if unicode.Is(unicode.Cf, r) {
			continue // invisible: direction overrides and zero-width characters disguise a name
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if rs := []rune(out); len(rs) > maxDeviceNameRunes {
		out = strings.TrimSpace(string(rs[:maxDeviceNameRunes]))
	}
	return out
}

// keyDeviceName is the name of the device that holds the identity's key, as
// given when it was adopted; "" when it was not given or is not known.
func (s *CoreServer) keyDeviceName() string {
	oa, err := s.ownerAuthority()
	if err != nil || oa == nil || oa.AID == "" {
		return ""
	}
	peer, ok, err := s.peerFor(oa.AID)
	if err != nil || !ok {
		return ""
	}
	return peer.DeviceName
}
