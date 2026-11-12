package lockgate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

	"identity-agent-core/atomicfile"
)

// The optional identity secret (ADR-074 section 4). Off by default. If set,
//
//	GK' = HKDF(GK, Argon2id(secret, salt))
//
// and GK' is what seals the profile, so the secret is a key input and not a
// check a copied file can skip.
//
// HONESTY. Where the hardware layer is absent, an attacker holding the files can
// try secrets offline at Argon2id's speed; the attempt counter below is kept in
// the profile directory and slows a person down, and does not stop that
// attacker. The Security screen says so.

type secretRecord struct {
	Salt  string `json:"salt"`
	Check string `json:"check"` // HMAC under GK' of a fixed label: tells a wrong secret from a right one
	Time  uint32 `json:"time"`
	MemKB uint32 `json:"mem_kb"`
	Par   uint8  `json:"par"`
}

// Argon2id cost. A variable so a test can run cheaply; never lowered in code.
var (
	argonTime uint32 = 3
	argonMem  uint32 = 64 * 1024
	argonPar  uint8  = 4
)

// Errors a caller tells a person about.
var (
	ErrSecretNeeded = errors.New("this identity has a secret, and none was given")
	ErrWrongSecret  = errors.New("that is not this identity's secret")
)

// DelayedError says a person must wait before the next try.
type DelayedError struct{ RetryAfter time.Duration }

func (e *DelayedError) Error() string {
	return fmt.Sprintf("too many wrong secrets; try again in %s", e.RetryAfter.Round(time.Second))
}

const (
	freeAttempts = 5
	firstDelay   = time.Minute
	longestDelay = time.Hour
)

// delayAfter is how long to wait after the nth consecutive wrong secret: five
// tries are free, so the sixth waits. None after fewer than five wrong, then a
// minute, doubling, to an hour.
func delayAfter(n int) time.Duration {
	if n < freeAttempts {
		return 0
	}
	d := firstDelay
	for i := freeAttempts; i < n; i++ {
		d *= 2
		if d >= longestDelay {
			return longestDelay
		}
	}
	return d
}

type attempts struct {
	Wrong int       `json:"wrong"`
	Last  time.Time `json:"last"`
}

func (p *Profile) readAttempts() attempts {
	var a attempts
	if b, err := os.ReadFile(p.path(attemptsFile)); err == nil {
		_ = json.Unmarshal(b, &a)
	}
	return a
}

func (p *Profile) writeAttempts(a attempts) error {
	b, _ := json.Marshal(a)
	return atomicfile.Write(p.path(attemptsFile), b, 0o600)
}

func stretch(gk GK, secret string, salt []byte, t, m uint32, par uint8) (GK, error) {
	if !gk.Valid() {
		return nil, errors.New("bad gate key")
	}
	st := argon2.IDKey([]byte(secret), salt, t, m, par, 32)
	defer zero(st)
	out := make([]byte, KeyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, gk, st, []byte("identity-agent gate secret v1")), out); err != nil {
		return nil, err
	}
	return out, nil
}

func checkOf(effective GK) string {
	m := hmac.New(sha256.New, effective)
	m.Write([]byte("identity-agent gate secret check v1"))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// HasSecret reports whether the owner set an identity secret.
func (p *Profile) HasSecret() bool {
	r, err := p.readRecord()
	return err == nil && r.Secret != nil
}

// effective returns the key that seals the profile: base itself when no secret
// is set, else GK' (after the delay and counter rules, before any stretching).
func (p *Profile) effective(base GK, secret string, now time.Time) (GK, error) {
	r, err := p.readRecord()
	if err != nil {
		return nil, err
	}
	if r.Secret == nil {
		return base, nil
	}
	if secret == "" {
		return nil, ErrSecretNeeded
	}
	a := p.readAttempts()
	if d := delayAfter(a.Wrong); d > 0 {
		if wait := a.Last.Add(d).Sub(now); wait > 0 {
			return nil, &DelayedError{RetryAfter: wait}
		}
	}
	// COUNT BEFORE STRETCHING. The failure is written down before any work is
	// done, so killing the process at the right moment does not buy a free try.
	a.Wrong++
	a.Last = now
	if err := p.writeAttempts(a); err != nil {
		return nil, fmt.Errorf("could not record the attempt, so none was made: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(r.Secret.Salt)
	if err != nil {
		return nil, fmt.Errorf("the secret's salt is unreadable: %w", err)
	}
	eff, err := stretch(base, secret, salt, r.Secret.Time, r.Secret.MemKB, r.Secret.Par)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(checkOf(eff)), []byte(r.Secret.Check)) {
		zero(eff)
		return nil, ErrWrongSecret
	}
	_ = p.writeAttempts(attempts{})
	return eff, nil
}

// SetSecret turns the optional secret on, or changes it. current is the key now
// sealing the profile (what Release returned) and reseal is called with it and
// the new key, to re-seal everything under the new one BEFORE anything here
// changes; if reseal fails nothing changed. Changing or removing an existing
// secret needs the current key, and the caller gets that only by passing the
// gate with the current secret.
func (p *Profile) SetSecret(current GK, secret string, reseal func(old, new GK) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if secret == "" {
		return errors.New("an identity secret cannot be empty; remove it instead")
	}
	r, err := p.readRecord()
	if err != nil {
		return err
	}
	base, err := p.readHeld(gateCopyFile, useGateCopy)
	if err != nil {
		return err
	}
	defer base.Zero()
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	eff, err := stretch(base, secret, salt, argonTime, argonMem, argonPar)
	if err != nil {
		return err
	}
	defer eff.Zero()
	if err := reseal(current, eff); err != nil {
		return fmt.Errorf("re-seal under the new secret: %w", err)
	}
	r.Secret = &secretRecord{Salt: base64.StdEncoding.EncodeToString(salt), Check: checkOf(eff),
		Time: argonTime, MemKB: argonMem, Par: argonPar}
	if err := p.writeRecord(r); err != nil {
		return err
	}
	_ = p.writeAttempts(attempts{})
	if p.LoggedIn() {
		return p.writeHeld(deviceHeldFile, useDeviceHeld, eff)
	}
	return nil
}

// RemoveSecret turns the secret off; current is the key sealing the profile now
// (which proves the current secret, since Release produced it) and reseal moves
// everything back under the base key.
func (p *Profile) RemoveSecret(current GK, reseal func(old, new GK) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, err := p.readRecord()
	if err != nil {
		return err
	}
	if r.Secret == nil {
		return nil
	}
	base, err := p.readHeld(gateCopyFile, useGateCopy)
	if err != nil {
		return err
	}
	defer base.Zero()
	if err := reseal(current, base); err != nil {
		return fmt.Errorf("re-seal without the secret: %w", err)
	}
	r.Secret = nil
	if err := p.writeRecord(r); err != nil {
		return err
	}
	_ = os.Remove(p.path(attemptsFile))
	if p.LoggedIn() {
		return p.writeHeld(deviceHeldFile, useDeviceHeld, base)
	}
	return nil
}
