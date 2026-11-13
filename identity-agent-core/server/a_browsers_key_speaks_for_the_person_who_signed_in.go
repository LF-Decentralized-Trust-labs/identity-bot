package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/atomicfile"
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
	Asset      string `json:"asset"`
	Person     string `json:"person"`
	Thumbprint string `json:"thumbprint"`
	// Until is when the key stops speaking. Zero means it speaks until it is
	// ended: an installed app's key is held in the device's secure hardware, so
	// its sign-in is an app-key grant that lasts until revoked, not a working
	// day's session (ADR-072 section 4).
	Until time.Time `json:"until"`
	// FrontEnd is the kind of front end the key belongs to: "browser" (or empty,
	// as before) or "installed_app".
	FrontEnd string `json:"front_end,omitempty"`
	// Proof is how the core established that an installed app's key is held in
	// hardware (nil for a browser's key).
	Proof *installedAppFact `json:"proof,omitempty"`
	// Presented is what the person presented at sign-in that the asset's
	// required credential was judged on (nil when the asset requires none), kept
	// so the same gate can be asked again whenever the key is used: a credential
	// that has lapsed or been revoked since stops the key speaking.
	Presented []interface{} `json:"presented,omitempty"`
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
func (b *browserKeys) Record(asset, person, thumbprint string, until, now time.Time, presented []interface{}) error {
	return b.record(asset, person, thumbprint, login.FrontEndBrowser, until, now, presented)
}

// RecordAppKey keeps that an installed app's hardware key speaks for person at
// asset until it is ended (an app-key grant, ADR-072 section 4).
func (b *browserKeys) RecordAppKey(asset, person, thumbprint string, now time.Time, presented []interface{}, proof installedAppFact) error {
	return b.recordWith(asset, person, thumbprint, login.FrontEndInstalledApp, time.Time{}, now, presented, &proof)
}

// liveAt: a record with a lapse time lives until it; only an installed app's
// grant, which the core recorded after proving the key in hardware, lives
// without one. A browser record with no lapse time is not forever: it speaks
// for no one.
func (b *browserKeyRecord) liveAt(now time.Time) bool {
	if b.Until.IsZero() {
		return b.FrontEnd == login.FrontEndInstalledApp
	}
	return now.Before(b.Until)
}

func (b *browserKeys) record(asset, person, thumbprint, frontEnd string, until, now time.Time, presented []interface{}) error {
	return b.recordWith(asset, person, thumbprint, frontEnd, until, now, presented, nil)
}

func (b *browserKeys) recordWith(asset, person, thumbprint, frontEnd string, until, now time.Time, presented []interface{}, proof *installedAppFact) error {
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
		if !r.liveAt(now) {
			delete(all, k)
		}
	}
	all[browserKeyEntry(asset, thumbprint)] = browserKeyRecord{Asset: asset, Person: person, Thumbprint: thumbprint, Until: until, FrontEnd: frontEnd, Proof: proof, Presented: presented}
	return b.save(all)
}

func (b *browserKeys) save(all map[string]browserKeyRecord) error {
	raw, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.dataDir, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(b.path(), raw, 0o600)
}

// Get is the live record for the key at the asset, if there is one.
func (b *browserKeys) Get(asset, thumbprint string, now time.Time) (browserKeyRecord, bool) {
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return browserKeyRecord{}, false
	}
	r, ok := all[browserKeyEntry(asset, thumbprint)]
	if !ok || !r.liveAt(now) {
		return browserKeyRecord{}, false
	}
	return r, true
}

// Whose is the person the key speaks for at the asset, if it still does.
func (b *browserKeys) Whose(asset, thumbprint string, now time.Time) (string, bool) {
	r, ok := b.Get(asset, thumbprint, now)
	return r.Person, ok
}

// Of are the live records of the person at the asset.
func (b *browserKeys) Of(asset, person string, now time.Time) []browserKeyRecord {
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return nil
	}
	var out []browserKeyRecord
	for _, r := range all {
		if r.Asset == asset && r.Person == person && r.liveAt(now) {
			out = append(out, r)
		}
	}
	return out
}

// End ends the records at the asset of the key with this thumbprint, or, when
// thumbprint is empty, of every key the person holds there. It reports how many
// it ended. A record is ended before its time when the person signs out or the
// app signs them out; a key whose record is gone speaks for no one, and speaking
// again takes a new sign-in.
func (b *browserKeys) End(asset, thumbprint, person string) (int, error) {
	if asset == "" || (thumbprint == "" && person == "") {
		return 0, errors.New("ending a browser key names the asset and the key or the person")
	}
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return 0, err
	}
	n := 0
	for k, r := range all {
		if r.Asset != asset {
			continue
		}
		if (thumbprint != "" && r.Thumbprint == thumbprint) || (thumbprint == "" && r.Person == person) {
			delete(all, k)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, b.save(all)
}

// keysSpeakingAt is the trail.KeyRoster for one app asset: a key speaks for a
// person when a sign-in at this asset named it, it has not lapsed, and the
// asset still stands behind that person (assetStillStands: membership and, where
// the policy requires one, the credential, asked again on each use).
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
	rec, ok := k.s.browserKeys().Get(k.asset, tp, time.Now())
	if !ok || rec.Person != person {
		return false
	}
	return k.s.assetStillStands(rec)
}

// assetStillStands asks the asset the question it asked at sign-in, now: the
// enrolment policy's membership gate and, where the policy requires a
// credential, that credential as the person presented it, verified again. Who
// is on the employee list is not the asset's answer. An asset that cannot be
// read admits nobody.
func (s *CoreServer) assetStillStands(rec browserKeyRecord) bool {
	if s.assetHandler == nil {
		return false
	}
	a, found, err := s.assetHandler.Store.GetAsset(rec.Asset)
	if err != nil || !found {
		return false
	}
	// The owner's setting, asked on every use and not only at sign-in: a front
	// end the owner has switched off stops speaking now, however long ago it was
	// approved (ADR-072 section 3). Only a key's record is asked: the bare
	// person-at-asset question has no front end.
	if rec.Thumbprint != "" {
		kind := rec.FrontEnd
		if kind == "" {
			kind = login.FrontEndBrowser
		}
		if a.FrontEndRefusal(kind) != "" {
			return false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ok, _ := s.authorizeAssetAccess(ctx, a.PairwiseAID, rec.Person, rec.Presented)
	return ok
}

// personStandsAtAsset is whether the asset still stands behind the person: by
// a live key's sign-in, asked again with what they presented, or, with no live
// key (it lapsed or they signed out), by the asset's gate on its own, which an
// asset that requires a credential cannot pass because nothing presented is
// kept past the key. Used for a conversation the person opened and an AI agent
// still asks in their name; speaking needs the live key (KeySpeaksFor).
func (s *CoreServer) personStandsAtAsset(assetID, person string) bool {
	recs := s.browserKeys().Of(assetID, person, time.Now())
	for _, rec := range recs {
		if s.assetStillStands(rec) {
			return true
		}
	}
	if len(recs) > 0 {
		return false
	}
	return s.assetStillStands(browserKeyRecord{Asset: assetID, Person: person})
}

// endBrowserKeys ends the browser-key records of the app's own asset: the app
// whose back end signed this request, and no other. The key is named by its
// thumbprint, or the person by their identifier at the asset when every key of
// theirs is to end. Ending only takes power away, so the app, which signed the
// person in, may do it when it signs them out.
func (s *CoreServer) endBrowserKeys(r *http.Request, thumbprint, person string) (int, error) {
	app, ok := TheAppThatAsked(r)
	if !ok {
		return 0, errors.New("only an app's back end, signing as the app, has sign-ins to end")
	}
	if thumbprint != "" {
		if err := login.CheckBrowserKeyThumbprint(thumbprint); err != nil {
			return 0, err
		}
	}
	return s.browserKeys().End(app.Asset, thumbprint, person)
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
