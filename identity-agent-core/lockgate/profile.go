package lockgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/atomicfile"
	"identity-agent-core/buildmode"
	"identity-agent-core/secureenclave"
)

// Files, all in <data dir>/gate/. Only the two .key files are secret, and both
// are held under the platform's hardware key; the rest says nothing a copied
// directory should not be able to read.
const (
	gateDirName      = "gate"
	recordFile       = "gate.json"
	gateCopyFile     = "gate-copy.key"
	deviceHeldFile   = "device-held.key"
	attemptsFile     = "attempts.json"
	useGateCopy      = "gate-copy"
	useDeviceHeld    = "device-held"
	currentRecordVer = 1
)

// record is gate.json: what a reader may know without any key.
type record struct {
	V       int       `json:"v"`
	Profile string    `json:"profile"`
	Created time.Time `json:"created"`
	// Secret is present when the owner set the optional identity secret
	// (ADR-074 section 4). It holds the salt and a check value, never the secret.
	Secret *secretRecord `json:"secret,omitempty"`
}

// ErrNoGate is the answer when a profile has no gate: it was made before this
// existed, or has not been made yet.
var ErrNoGate = errors.New("this profile has no gate")

// ErrAlreadyGated is Create's answer for a profile that has one. A gate is made
// once, when the profile is: a second GK would orphan everything sealed under
// the first.
var ErrAlreadyGated = errors.New("this profile already has a gate")

// ErrHardwareLayerMissing is the refusal to rest a GK where the platform has
// nothing to wrap it with. A production build stores neither copy unwrapped, for
// the reason it stores no root seed unwrapped (ADR-028).
var ErrHardwareLayerMissing = errors.New("this machine has no working hardware key to rest the gate key under, so the gate key would sit in a plain file")

// Profile is one identity's gate on this device.
type Profile struct {
	dir string
	id  string
	mu  sync.Mutex
}

// OpenProfile names the gate of the profile whose data directory is dataDir.
// Nothing is read or written until it is used.
func OpenProfile(dataDir, profileID string) *Profile {
	return &Profile{dir: dataDir, id: profileID}
}

// ID is the profile's identifier.
func (p *Profile) ID() string { return p.id }

// DataDir is the profile's data directory.
func (p *Profile) DataDir() string { return p.dir }

func (p *Profile) path(name string) string { return filepath.Join(p.dir, gateDirName, name) }

// Gated reports whether this profile has a gate.
func (p *Profile) Gated() bool {
	_, err := os.Stat(p.path(recordFile))
	return err == nil
}

// HardwareHeld reports whether the gate copy was written under the platform's
// hardware key, from what its own envelope says. It asks the platform nothing,
// so a screen can poll it.
func (p *Profile) HardwareHeld() bool {
	b, err := os.ReadFile(p.path(gateCopyFile))
	return err == nil && secureenclave.HeldKeyIsWrapped(b)
}

// LoggedIn reports whether the device-held copy exists: the one state of a gated
// profile from which a restart reopens with nobody present.
func (p *Profile) LoggedIn() bool {
	_, err := os.Stat(p.path(deviceHeldFile))
	return err == nil
}

func (p *Profile) readRecord() (*record, error) {
	b, err := os.ReadFile(p.path(recordFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoGate
		}
		return nil, err
	}
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("the gate record is unreadable: %w", err)
	}
	if r.Profile != p.id {
		return nil, fmt.Errorf("the gate record is for profile %q, not %q", r.Profile, p.id)
	}
	return &r, nil
}

func (p *Profile) writeRecord(r *record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return atomicfile.Write(p.path(recordFile), b, 0o600)
}

func (p *Profile) mustHaveHardwareLayer() error {
	if buildmode.IsDev() || secureenclave.TheWrapperWorksHere(p.dir) {
		return nil
	}
	return ErrHardwareLayerMissing
}

// Create makes the gate: mints GK, writes the gate copy and the device-held copy
// (a new profile is logged in), and the record. It returns GK for the caller to
// seal the profile's secret under, and the caller owns zeroing it.
//
// A profile with a record always has both copies; a partial run leaves files
// and no record, and is redone.
func (p *Profile) Create() (GK, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Gated() {
		return nil, ErrAlreadyGated
	}
	if err := p.mustHaveHardwareLayer(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(p.dir, gateDirName), 0o700); err != nil {
		return nil, err
	}
	gk, err := NewGK()
	if err != nil {
		return nil, err
	}
	// The record is written last and Gated() keys on it, so a crash part way
	// leaves files and no gate, and the next Create overwrites them.
	if err := p.writeHeld(gateCopyFile, useGateCopy, gk); err != nil {
		gk.Zero()
		return nil, err
	}
	if err := p.writeHeld(deviceHeldFile, useDeviceHeld, gk); err != nil {
		gk.Zero()
		return nil, err
	}
	if err := p.writeRecord(&record{V: currentRecordVer, Profile: p.id, Created: time.Now().UTC()}); err != nil {
		gk.Zero()
		return nil, err
	}
	return gk, nil
}

func (p *Profile) writeHeld(file, use string, gk GK) error {
	held, err := secureenclave.KeyToHoldUnderTheWrapper(p.dir, use+":"+p.id, gk)
	if err != nil {
		return err
	}
	return atomicfile.Write(p.path(file), held, 0o600)
}

func (p *Profile) readHeld(file, use string) (GK, error) {
	b, err := os.ReadFile(p.path(file))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	k, _, err := secureenclave.OpenKeyHeldUnderTheWrapper(use+":"+p.id, b)
	if err != nil {
		return nil, err
	}
	if !GK(k).Valid() {
		return nil, fmt.Errorf("the stored gate key is %d bytes", len(k))
	}
	return k, nil
}

// ReadDeviceHeld returns the key a logged-in profile reopens with after a
// restart. os.ErrNotExist when the profile is logged out.
func (p *Profile) ReadDeviceHeld() (GK, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.readHeld(deviceHeldFile, useDeviceHeld)
}

// WriteDeviceHeld makes the device-held copy: called at log-in, after the gate
// has released the key.
func (p *Profile) WriteDeviceHeld(gk GK) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.Gated() {
		return ErrNoGate
	}
	return p.writeHeld(deviceHeldFile, useDeviceHeld, gk)
}

// DeleteDeviceHeld removes the device-held copy and PROVES it is gone. A log-out
// whose deletion failed is not a log-out: the caller must report it as not
// logged out, never as locked, so a remove error and a file still present are
// both errors here.
func (p *Profile) DeleteDeviceHeld() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := p.path(deviceHeldFile)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete the device-held gate key: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return errors.New("the device-held gate key is still there after it was deleted")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("could not confirm the device-held gate key is gone: %w", err)
	}
	return nil
}

// readGateCopy is read by Gate.Release only.
func (p *Profile) readGateCopy() (GK, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.Gated() {
		return nil, ErrNoGate
	}
	return p.readHeld(gateCopyFile, useGateCopy)
}
