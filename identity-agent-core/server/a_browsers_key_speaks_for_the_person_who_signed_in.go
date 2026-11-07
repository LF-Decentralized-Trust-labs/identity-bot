package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/internal/atomicfile"
	"identity-agent-core/login"
	"identity-agent-core/trail"
)

// Which browser key speaks for which person (ADR-066, ADR-067).
//
// When a person signs in to an app's asset for a key their browser holds, the
// core verifies the person's own signed assertion, which names that key
// (login.VerifyAssertionForBrowserKey). That is the one moment the core knows,
// from the person and not from the app, that this key is theirs. It keeps it:
// "key K speaks for person P at asset A until T". Later the person's browser
// signs a statement over a fingerprint of its words (ADR-067) and the app's
// back end carries it to the core; trail.CheckAuthor asks this record whether
// the key that signed it speaks for the person (trail.KeyRoster). Nothing the
// app says can add to it.

// browserKeyLife is how long a sign-in lets its key speak: the person's
// approval is for a working day, then they sign in again. Shortening it is a
// reversible, local change.
const browserKeyLife = 12 * time.Hour

type browserKeyRecord struct {
	Asset      string    `json:"asset"`
	Person     string    `json:"person"`
	Thumbprint string    `json:"thumbprint"`
	Until      time.Time `json:"until"`
}

// browserKeys is the record, kept in a file of its own beside the others so a
// restart does not make everyone sign in again.
type browserKeys struct {
	dataDir string
}

// One lock for the process, for the reason grantsLock is.
var browserKeysLock sync.Mutex

func (s *CoreServer) browserKeys() *browserKeys { return &browserKeys{dataDir: s.DataDir} }

func (b *browserKeys) path() string { return filepath.Join(b.dataDir, "browser_key_sign_ins.json") }

func (b *browserKeys) load() (map[string]browserKeyRecord, error) {
	out := map[string]browserKeyRecord{}
	raw, err := os.ReadFile(b.path())
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the record of which browser keys speak for whom could not be read: %w", err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the record of which browser keys speak for whom is not readable: %w", err)
	}
	return out, nil
}

func browserKeyEntry(asset, thumbprint string) string { return asset + "\n" + thumbprint }

// Record keeps that the key with this thumbprint speaks for person at asset
// until the time given. A key speaks for one person at one asset: recording it
// again replaces the earlier, so a key cannot speak for two people.
func (b *browserKeys) Record(asset, person, thumbprint string, until, now time.Time) error {
	if asset == "" || person == "" {
		return errors.New("a browser key speaks for a person at an asset")
	}
	if err := login.CheckBrowserKeyThumbprint(thumbprint); err != nil {
		return err
	}
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return err
	}
	for k, r := range all {
		if !now.Before(r.Until) {
			delete(all, k)
		}
	}
	all[browserKeyEntry(asset, thumbprint)] = browserKeyRecord{Asset: asset, Person: person, Thumbprint: thumbprint, Until: until}
	raw, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.dataDir, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(b.path(), raw, 0o600)
}

// Whose is the person the key speaks for at the asset, if it still does.
func (b *browserKeys) Whose(asset, thumbprint string, now time.Time) (string, bool) {
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return "", false
	}
	r, ok := all[browserKeyEntry(asset, thumbprint)]
	if !ok || !now.Before(r.Until) {
		return "", false
	}
	return r.Person, true
}

// keysSpeakingAt is the trail.KeyRoster for one app asset: a key speaks for a
// person when a sign-in at this asset named it, it has not lapsed, and the
// asset still admits that person (assetStillAdmits, so someone removed since
// is no longer spoken for).
type keysSpeakingAt struct {
	s     *CoreServer
	asset string
}

var _ trail.KeyRoster = keysSpeakingAt{}

func (k keysSpeakingAt) KeySpeaksFor(person, signer, verkey string) bool {
	tp, err := login.BrowserKeyThumbprintOfMachineKey(verkey)
	if err != nil {
		return false
	}
	who, ok := k.s.browserKeys().Whose(k.asset, tp, time.Now())
	if !ok || who != person {
		return false
	}
	admitted, err := k.s.assetStillAdmits(k.asset, person)
	return err == nil && admitted
}

// assetIDOfSite is the id of the asset whose pairwise identifier is siteAID.
func (s *CoreServer) assetIDOfSite(siteAID string) (string, bool) {
	if s.assetHandler == nil || siteAID == "" {
		return "", false
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return "", false
	}
	for _, a := range assets {
		if a.PairwiseAID == siteAID {
			return a.ID, true
		}
	}
	return "", false
}
