// Package enrolsecret keeps one-time enrolment secrets: the string an owner
// hands to a machine so that machine, once, can ask to be enrolled.
//
// It exists once so every kind of enrolment treats its secret the same way:
//
//   - Only a digest is stored. A copy of the file is not a pile of usable
//     secrets, and the store cannot give a secret back — the caller sees it
//     once, when it is issued.
//   - A secret is compared in constant time against every stored digest.
//   - Issuing a new secret for a subject voids the unused older ones for that
//     subject, so a string left in a scrollback stops working the moment a
//     fresh one exists.
//   - A secret is good once. Claiming removes it, and expired or voided ones
//     are pruned, so the file does not grow with every string ever issued.
//   - Every reason a secret cannot be used is the same answer, ErrUnusable, so
//     somebody probing secrets learns nothing from which reason it was.
//
// What an enrolment then does — the record of what was expected, who approves
// it, which keys it accepts — belongs to the caller. This only guards the
// secret.
package enrolsecret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// ErrUnusable is every reason a secret cannot be used, as one answer: unknown,
// expired, already used, replaced by a newer one, or issued for another
// subject.
var ErrUnusable = errors.New("this enrolment secret cannot be used: it is unknown, expired, already used, or replaced by a newer one")

// Entry is an issued secret as the store knows it. It holds no secret.
type Entry struct {
	// Digest identifies the secret: the hex SHA-256 of it.
	Digest string `json:"secret_digest"`
	// Subject is what the secret enrols; at most one unused secret exists per
	// subject. Empty means it is not exclusive to anything.
	Subject string    `json:"subject,omitempty"`
	Expires time.Time `json:"expires"`
}

type file struct {
	Secrets []Entry `json:"secrets"`
}

// Store keeps the digests of unused secrets in one file under one lock.
type Store struct {
	mu   sync.Mutex
	path string
}

// Open returns the store kept in the file at path. The file need not exist.
func Open(path string) *Store { return &Store{path: path} }

// Digest is how a secret is kept: never the secret itself.
func Digest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Mint makes a new random secret. It is not stored anywhere: the caller shows
// it once and keeps only Digest(secret).
func Mint() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Equal reports whether secret is the one a digest was made from, in constant
// time. Anything that looks a presented secret up among stored digests uses
// this against every one of them, never a map keyed by the secret.
func Equal(secret, digest string) bool {
	return subtle.ConstantTimeCompare([]byte(Digest(secret)), []byte(digest)) == 1
}

func (s *Store) load(now time.Time) (file, error) {
	f, _, err := s.loadPruned(now)
	return f, err
}

// loadPruned also reports whether anything was pruned, so a caller that is
// otherwise not writing can still drop what has expired.
func (s *Store) loadPruned(now time.Time) (f file, pruned bool, err error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, false, nil
	}
	if err != nil {
		return f, false, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, false, fmt.Errorf("the enrolment secret store is unreadable: %w", err)
	}
	n := len(f.Secrets)
	prune(&f, now)
	return f, len(f.Secrets) != n, nil
}

func (s *Store) save(f file) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// prune drops what can never be used again.
func prune(f *file, now time.Time) {
	kept := f.Secrets[:0]
	for _, e := range f.Secrets {
		if now.Before(e.Expires) {
			kept = append(kept, e)
		}
	}
	f.Secrets = kept
}

// Issue creates a secret good for window from now, and voids every unused
// secret already issued for subject (when subject is not empty). The secret is
// returned here and nowhere else.
func (s *Store) Issue(subject string, window time.Duration, now time.Time) (string, Entry, error) {
	secret, err := Mint()
	if err != nil {
		return "", Entry{}, err
	}
	e := Entry{Digest: Digest(secret), Subject: subject, Expires: now.Add(window).UTC()}

	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load(now)
	if err != nil {
		return "", Entry{}, err
	}
	f.Secrets = withoutSubject(f.Secrets, subject)
	f.Secrets = append(f.Secrets, e)
	if err := s.save(f); err != nil {
		return "", Entry{}, err
	}
	return secret, e, nil
}

func withoutDigest(in []Entry, digest string) []Entry {
	out := in[:0]
	for _, e := range in {
		if e.Digest != digest {
			out = append(out, e)
		}
	}
	return out
}

func withoutSubject(in []Entry, subject string) []Entry {
	if subject == "" {
		return in
	}
	out := in[:0]
	for _, e := range in {
		if e.Subject != subject {
			out = append(out, e)
		}
	}
	return out
}

// Claim spends a secret, returning what it was issued for. If subject is not
// empty the secret must have been issued for it; one issued for something else
// is refused and left unspent. Whatever the reason a secret cannot be used, the
// error is ErrUnusable.
func (s *Store) Claim(secret, subject string, now time.Time) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, pruned, err := s.loadPruned(now)
	if err != nil {
		return Entry{}, err
	}
	d := []byte(Digest(secret))
	// Compare against every entry and never stop early, so the time taken does
	// not say how much of a guess was right or where it sits in the file.
	idx := -1
	for i, e := range f.Secrets {
		if subtle.ConstantTimeCompare(d, []byte(e.Digest)) == 1 {
			idx = i
		}
	}
	if idx < 0 || (subject != "" && f.Secrets[idx].Subject != subject) {
		if pruned {
			if err := s.save(f); err != nil {
				return Entry{}, err
			}
		}
		return Entry{}, ErrUnusable
	}
	e := f.Secrets[idx]
	f.Secrets = append(f.Secrets[:idx], f.Secrets[idx+1:]...)
	return e, s.save(f)
}

// Release hands back a claimed secret whose enrolment produced nothing, so the
// machine it was issued for can try again. It does nothing if a newer secret
// has since been issued for the same subject (the older one stays void) or the
// secret has expired; ErrUnusable says so.
func (s *Store) Release(e Entry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load(now)
	if err != nil {
		return err
	}
	if !now.Before(e.Expires) {
		return ErrUnusable
	}
	for _, other := range f.Secrets {
		if other.Digest == e.Digest || (e.Subject != "" && other.Subject == e.Subject) {
			return ErrUnusable
		}
	}
	f.Secrets = append(f.Secrets, e)
	return s.save(f)
}

// Void ends the unused secret with this digest, and no other. Voiding one that
// is not there is not an error.
func (s *Store) Void(digest string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load(now)
	if err != nil {
		return err
	}
	kept := f.Secrets[:0]
	for _, e := range f.Secrets {
		if e.Digest != digest {
			kept = append(kept, e)
		}
	}
	f.Secrets = kept
	return s.save(f)
}

// Adopt records a secret that already exists and is known only by its digest —
// one issued before this store did, being carried across. It voids older ones
// for the subject like Issue does.
func (s *Store) Adopt(e Entry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load(now)
	if err != nil {
		return err
	}
	if !now.Before(e.Expires) {
		return nil
	}
	f.Secrets = withoutSubject(f.Secrets, e.Subject)
	// Adopting is repeatable: a crash between this and the caller rewriting the
	// file it migrates from means the same secret is adopted again on the next
	// start. One digest is one secret, never two.
	f.Secrets = withoutDigest(f.Secrets, e.Digest)
	f.Secrets = append(f.Secrets, e)
	return s.save(f)
}
