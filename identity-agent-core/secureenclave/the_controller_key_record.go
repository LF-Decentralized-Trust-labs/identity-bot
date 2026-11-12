package secureenclave

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"identity-agent-core/atomicfile"
)

// WHICH CONTROLLER KEY A GATED PROFILE OWNS (ADR-074 section 3).
//
// Two things were missing from the controller key of a Mac or Windows computer:
//
//  1. A profile with no seed (a desktop never holds a root) had nothing but
//     gate/gate.json to say it was gated, so deleting that one file made the next
//     start found the profile again: a new gate key, an open core, and a controller
//     key that no longer opened. The key itself says the profile is gated, so
//     Gated asks for it (TheControllerKeyIsUnderAGate).
//  2. On Windows the core opened any key of the profile's computable name, so
//     same-user code could pre-create one with no authorization value and have the
//     core sign with it while locked. The core now records the public key of the
//     key it made, sealed under the gate key, and refuses any other.

// controllerKeyRecordFile is where a Windows controller key's record is kept,
// under the profile's own data directory.
const controllerKeyRecordFile = "controller_key.json"

// theMachineKeyFileOnDisk is the macOS controller key (signer_darwin_sep.go), here
// by name so this file, which builds everywhere, can tell whether it is gated
// without the cgo that reads it.
const theMachineKeyFileOnDisk = "machine_key.sep"

func controllerKeyPath(dataDir, file string) string {
	return filepath.Join(dataDir, "secureenclave", file)
}

// theControllerKeyRecord is controller_key.json.
type theControllerKeyRecord struct {
	V        int    `json:"v"`
	Platform string `json:"platform"`
	// Name is the key's name inside the platform's provider.
	Name string `json:"name"`
	// Gate names the scheme Public is sealed under. Always the gate scheme: a
	// record of an ungated profile's key is never written.
	Gate string `json:"gate"`
	// Public is the controller key's public key, sealed under GK: the planted
	// record of a different key does not open, and a locked profile reads nothing.
	Public string `json:"public"`
}

// ErrControllerKeyNotOurs is the refusal to use a hardware key the core did not
// make for this profile, or one it cannot show it made.
var ErrControllerKeyNotOurs = errors.New("this computer holds a controller key for this identity that the Identity Agent did not make, or cannot show it made, so it will not sign with it")

// TheControllerKeyIsUnderAGate says the profile at dataDir owns a controller key
// that was made under a gate: a Mac's machine key sealed under the gate key, or a
// Windows record of the key the core made, or (Windows) a TPM key of the
// profile's own name. A profile like that is gated whether or not gate/gate.json
// is still there, which is what stops a deleted record from founding it again.
//
// profileID may be "": the key held by the hardware is then not asked about.
func TheControllerKeyIsUnderAGate(dataDir, profileID string) bool {
	if env, ok := readTheMachineKeyEnvelope(dataDir); ok && env.Gate != "" {
		return true
	}
	if rec, err := readControllerKeyRecord(dataDir); err == nil && rec.Gate != "" {
		return true
	} else if err != nil && !os.IsNotExist(err) {
		// Present and unreadable is not evidence of no gate.
		return true
	}
	return profileID != "" && aHardwareKeyOfThisProfileExists(dataDir, profileID)
}

// aHardwareKeyOfThisProfileExists asks the platform's provider whether a key of
// the profile's own name exists. False wherever the platform has no named
// controller key; signer_windows.go sets it.
var aHardwareKeyOfThisProfileExists = func(dataDir, profileID string) bool { return false }

// aHardwareControllerKeyExistsAt says there is a stored controller key for this
// profile that a signer was meant to open: so when none opens, the answer is a
// refusal, and never the software signer.
func aHardwareControllerKeyExistsAt(dataDir string) bool {
	if _, err := os.Stat(controllerKeyPath(dataDir, theMachineKeyFileOnDisk)); err == nil {
		return true
	}
	_, err := os.Stat(controllerKeyPath(dataDir, controllerKeyRecordFile))
	return err == nil
}

// theMachineKeyEnvelopeHead is the part of the macOS key file the gate cares
// about; the rest (the sealed blob) is the signer's.
type theMachineKeyEnvelopeHead struct {
	Gate string `json:"gate"`
}

func readTheMachineKeyEnvelope(dataDir string) (theMachineKeyEnvelopeHead, bool) {
	b, err := os.ReadFile(controllerKeyPath(dataDir, theMachineKeyFileOnDisk))
	if err != nil {
		return theMachineKeyEnvelopeHead{}, false
	}
	var h theMachineKeyEnvelopeHead
	if err := json.Unmarshal(b, &h); err != nil {
		// A key file somebody damaged still marks a hardware key that was made.
		// Reported as gated: a profile must not fall open on a file it cannot read.
		return theMachineKeyEnvelopeHead{Gate: "unreadable"}, true
	}
	return h, true
}

func readControllerKeyRecord(dataDir string) (theControllerKeyRecord, error) {
	var rec theControllerKeyRecord
	b, err := os.ReadFile(controllerKeyPath(dataDir, controllerKeyRecordFile))
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("the controller key record is unreadable: %w", err)
	}
	return rec, nil
}

// recordTheControllerKey writes the record of the key the core just made, its
// public key sealed under the gate key. Refuses for a locked profile.
func recordTheControllerKey(dataDir, platform, name string, pub []byte) error {
	sealer, gated, err := theGateForThisSeed(dataDir)
	if err != nil {
		return err
	}
	if !gated {
		return nil
	}
	sealed, err := sealer.Seal(pub)
	if err != nil {
		return fmt.Errorf("seal the controller key's public key under the gate key: %w", err)
	}
	b, err := json.Marshal(theControllerKeyRecord{V: 1, Platform: platform, Name: name, Gate: gateScheme,
		Public: base64.StdEncoding.EncodeToString(sealed)})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(controllerKeyPath(dataDir, controllerKeyRecordFile)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(controllerKeyPath(dataDir, controllerKeyRecordFile), b, 0o600)
}

// theControllerKeyIsTheOneWeMade checks pub against the recorded key of the
// profile at dataDir. Locked is ErrIdentityLocked. A gated profile with no record
// is ErrControllerKeyNotOurs, never a key to adopt: the key may be one planted
// under the profile's computable name. An ungated profile has no record and any
// key of its name is the one it always used.
func theControllerKeyIsTheOneWeMade(dataDir, name string, pub []byte) error {
	sealer, gated, err := theGateForThisSeed(dataDir)
	if err != nil {
		return err
	}
	if !gated {
		return nil
	}
	rec, err := readControllerKeyRecord(dataDir)
	if err != nil {
		return fmt.Errorf("%w: there is no record of it (%v)", ErrControllerKeyNotOurs, err)
	}
	if rec.Name != name || rec.Gate != gateScheme {
		return fmt.Errorf("%w: the record is for a different key", ErrControllerKeyNotOurs)
	}
	sealed, err := base64.StdEncoding.DecodeString(rec.Public)
	if err != nil {
		return fmt.Errorf("%w: the record is damaged", ErrControllerKeyNotOurs)
	}
	want, err := sealer.Open(sealed)
	if err != nil {
		return fmt.Errorf("%w: the record does not open under the gate key", ErrControllerKeyNotOurs)
	}
	if !bytes.Equal(want, pub) {
		return ErrControllerKeyNotOurs
	}
	return nil
}

// refusingControllerKey is the signer for a hardware controller key that exists
// and cannot be opened (the chip is not this one, the file is damaged, the key is
// not the one the core made): it says what holds the key and signs nothing, with
// the reason. It is returned instead of falling through to the software signer,
// which is a different key in a plain file (ADR-074 section 3).
type refusingControllerKey struct {
	platform, label string
	why             error
}

func (s refusingControllerKey) Available() bool            { return true }
func (s refusingControllerKey) Platform() string           { return s.platform }
func (s refusingControllerKey) Label() string              { return s.label }
func (s refusingControllerKey) PublicKey() ([]byte, error) { return nil, s.err() }
func (s refusingControllerKey) Sign([]byte) ([]byte, error) {
	return nil, s.err()
}
func (s refusingControllerKey) err() error {
	if s.why == nil {
		return ErrSignerUnavailable
	}
	return fmt.Errorf("the controller key cannot be used: %w", s.why)
}
