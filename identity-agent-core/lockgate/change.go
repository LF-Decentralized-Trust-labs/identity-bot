package lockgate

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"identity-agent-core/atomicfile"
	"identity-agent-core/secureenclave"
)

// A CHANGE OF THE IDENTITY SECRET IS TWO FILES AND A SEED.
//
// The seed is sealed under the effective key, the record says which secret that
// key comes from, and the device-held copy is what a restart reopens with. They
// cannot be written at once. Done in sequence with nothing written down, a crash
// between the first and the last leaves the seed under a key the record does not
// describe, and only the recovery phrase gets it back.
//
// So the change is written down first, as a journal holding the new record and
// both keys (each under the hardware wrapper, as the device-held copy is), and
// then done in an order that can be repeated: re-seal the seed (which opens
// under either key, so doing it twice is the same as once), write the record,
// write the device-held copy, delete the journal. Whatever is left when the
// journal is found is finished, never abandoned and never undone.

const (
	changeJournalFile = "change.journal"
	useChangeOld      = "change-old"
	useChangeNew      = "change-new"
)

type changeJournal struct {
	V      int           `json:"v"`
	Secret *secretRecord `json:"secret,omitempty"` // the record after the change; nil = no secret
	Old    string        `json:"old"`              // base64, under the hardware wrapper
	New    string        `json:"new"`
}

// afterSeedResealed lets a test stop the change where a crash would. It is nil
// outside tests.
var afterStep func(step string) error

func step(name string) error {
	if afterStep != nil {
		return afterStep(name)
	}
	return nil
}

// changeLocked journals and performs the change. The caller holds p.mu.
func (p *Profile) changeLocked(old, new GK, secret *secretRecord) error {
	if err := p.mustHaveHardwareLayer(); err != nil {
		return err
	}
	wo, err := secureenclave.KeyToHoldUnderTheWrapper(p.dir, useChangeOld+":"+p.id, old)
	if err != nil {
		return err
	}
	wn, err := secureenclave.KeyToHoldUnderTheWrapper(p.dir, useChangeNew+":"+p.id, new)
	if err != nil {
		return err
	}
	b, err := json.Marshal(changeJournal{V: 1, Secret: secret,
		Old: base64.StdEncoding.EncodeToString(wo), New: base64.StdEncoding.EncodeToString(wn)})
	if err != nil {
		return err
	}
	if err := atomicfile.Write(p.path(changeJournalFile), b, 0o600); err != nil {
		return fmt.Errorf("could not write down the change, so nothing was changed: %w", err)
	}
	if err := step("journalled"); err != nil {
		return err
	}
	return p.completeLocked(old, new, secret)
}

func (p *Profile) completeLocked(old, new GK, secret *secretRecord) error {
	// The seed opens under either key, so a repeat after a crash is harmless.
	err := secureenclave.ReSealRootSeed(p.dir,
		func(b []byte) ([]byte, error) {
			if plain, err := Open(old, p.id, b); err == nil {
				return plain, nil
			}
			return Open(new, p.id, b)
		},
		func(b []byte) ([]byte, error) { return Seal(new, p.id, b) })
	if err != nil && !errors.Is(err, os.ErrNotExist) { // no seed yet: nothing is sealed under the key
		return err
	}
	// The recovery phrases and the backup key are sealed under the same key.
	if err := secureenclave.ReSealGateHeldSecrets(p.dir,
		func(b []byte) ([]byte, error) {
			if plain, err := Open(old, p.id, b); err == nil {
				return plain, nil
			}
			return Open(new, p.id, b)
		},
		func(b []byte) ([]byte, error) { return Seal(new, p.id, b) }); err != nil {
		return err
	}
	if err := step("seed"); err != nil {
		return err
	}
	r, err := p.readRecord()
	if err != nil {
		return err
	}
	r.Secret = secret
	if err := p.writeRecord(r); err != nil {
		return err
	}
	if secret == nil {
		_ = os.Remove(p.path(attemptsFile))
	} else {
		_ = p.writeAttempts(attempts{})
	}
	if err := step("record"); err != nil {
		return err
	}
	if p.LoggedIn() {
		if err := p.writeHeld(deviceHeldFile, useDeviceHeld, new); err != nil {
			return err
		}
	}
	if err := step("device-held"); err != nil {
		return err
	}
	if err := os.Remove(p.path(changeJournalFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// FinishPendingChange completes a secret change a crash cut short. It does
// nothing when there is none. Call before reading the record or the keys.
func (p *Profile) FinishPendingChange() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.finishPendingChangeLocked()
}

func (p *Profile) finishPendingChangeLocked() error {
	b, err := os.ReadFile(p.path(changeJournalFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var j changeJournal
	if err := json.Unmarshal(b, &j); err != nil {
		return fmt.Errorf("the journal of a secret change is unreadable: %w", err)
	}
	open := func(use, enc string) (GK, error) {
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, err
		}
		k, _, err := secureenclave.OpenKeyHeldUnderTheWrapper(use+":"+p.id, raw)
		if err != nil {
			return nil, err
		}
		if !GK(k).Valid() {
			return nil, errors.New("the journalled key has the wrong length")
		}
		return k, nil
	}
	old, err := open(useChangeOld, j.Old)
	if err != nil {
		return fmt.Errorf("the journal of a secret change cannot be opened: %w", err)
	}
	defer old.Zero()
	new, err := open(useChangeNew, j.New)
	if err != nil {
		return fmt.Errorf("the journal of a secret change cannot be opened: %w", err)
	}
	defer new.Zero()
	return p.completeLocked(old, new, j.Secret)
}
