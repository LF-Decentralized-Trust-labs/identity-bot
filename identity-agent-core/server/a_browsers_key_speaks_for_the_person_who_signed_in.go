package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/atomicfile"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
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

// How long a sign-in lets its key speak is the asset's: its owner sets it for a
// utility app, and every other asset has the default (asset.Asset.SignInLifetime,
// within asset.MaxSignInLifetime). The time is fixed when the person approves
// and kept in the record; changing the setting later does not move it.

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
	// Push is the address the app's back end took this sign-in at (the origin the
	// person approved it for), where the core tells it the grant has ended
	// (ADR-072 section 6). Only an installed app's grant keeps one.
	Push string `json:"push,omitempty"`
}

// browserKeys is the record, kept in a file of its own beside the others so a
// restart does not make everyone sign in again.
type browserKeys struct {
	dataDir string
	// ended is told which installed-app grants an End just removed, after the
	// record is saved. It must not wait on anything: the owner's or the person's
	// own action is not held up by an app's back end.
	ended func([]browserKeyRecord)
}

// One lock for the process, for the reason grantsLock is.
var browserKeysLock sync.Mutex

func (s *CoreServer) browserKeys() *browserKeys {
	return &browserKeys{dataDir: s.DataDir, ended: s.tellBackEndsGrantsEnded}
}

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
	return b.RecordAppKeyAt("", asset, person, thumbprint, now, presented, proof)
}

// RecordAppKeyAt is RecordAppKey for a grant whose back end is told when it ends,
// at push.
func (b *browserKeys) RecordAppKeyAt(push, asset, person, thumbprint string, now time.Time, presented []interface{}, proof installedAppFact) error {
	return b.recordWith(asset, person, thumbprint, login.FrontEndInstalledApp, time.Time{}, now, presented, &proof, push)
}

// RecordSoftwareAppKeyAt keeps that an installed app's key held in software
// speaks for person at asset until the time given: nothing proves where the key
// is kept, so it lapses as a browser's does (ADR-072 Amendment 17). Its back end
// is told at push when it ends early.
func (b *browserKeys) RecordSoftwareAppKeyAt(push, asset, person, thumbprint string, until, now time.Time, presented []interface{}, proof installedAppFact) error {
	if until.IsZero() || proof.Grade() != KeyGradeSoftware {
		return errors.New("a key held in software is kept with a lapse time, at the software grade")
	}
	return b.recordWith(asset, person, thumbprint, login.FrontEndInstalledApp, until, now, presented, &proof, push)
}

// liveAt: a record with a lapse time lives until it; only an installed app's
// grant, which the core recorded after proving the key in hardware, lives
// without one. A browser record, or an installed app's record of a key held in
// software, with no lapse time is not forever: it speaks for no one.
func (b *browserKeyRecord) liveAt(now time.Time) bool {
	if b.Until.IsZero() {
		return b.FrontEnd == login.FrontEndInstalledApp && b.Proof != nil && b.Proof.Grade() == KeyGradeHardware
	}
	return now.Before(b.Until)
}

// Grade is the grade an installed app's key was kept at, or "" for a browser's.
func (b browserKeyRecord) Grade() string {
	if b.FrontEnd != login.FrontEndInstalledApp || b.Proof == nil {
		return ""
	}
	return b.Proof.Grade()
}

func (b *browserKeys) record(asset, person, thumbprint, frontEnd string, until, now time.Time, presented []interface{}) error {
	return b.recordWith(asset, person, thumbprint, frontEnd, until, now, presented, nil, "")
}

// errGrantHeld is a live app-key grant for another person at the key.
var errGrantHeld = errors.New("this key already speaks for another person: that grant must end first")

func (b *browserKeys) recordWith(asset, person, thumbprint, frontEnd string, until, now time.Time, presented []interface{}, proof *installedAppFact, push string) error {
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
	// A live app-key grant is never replaced by a different person's: it does
	// not lapse, so whoever it was made for would lose it to a sign-in anyone
	// could start naming their key. The grant ends first (the person, the owner,
	// the app), then the key can speak for someone else.
	if held, live := all[browserKeyEntry(asset, thumbprint)]; live && held.FrontEnd == login.FrontEndInstalledApp &&
		held.liveAt(now) && held.Person != person {
		return errGrantHeld
	}
	for k, r := range all {
		if !r.liveAt(now) {
			delete(all, k)
		}
	}
	all[browserKeyEntry(asset, thumbprint)] = browserKeyRecord{Asset: asset, Person: person, Thumbprint: thumbprint, Until: until, FrontEnd: frontEnd, Proof: proof, Presented: presented, Push: push}
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
	var gone []browserKeyRecord
	for k, r := range all {
		if r.Asset != asset {
			continue
		}
		if (thumbprint != "" && r.Thumbprint == thumbprint) || (thumbprint == "" && r.Person == person) {
			delete(all, k)
			n++
			gone = append(gone, r)
		}
	}
	if n == 0 {
		return 0, nil
	}
	if err := b.save(all); err != nil {
		return n, err
	}
	b.tell(gone)
	return n, nil
}

// tell passes on the installed-app grants a call just removed.
func (b *browserKeys) tell(gone []browserKeyRecord) {
	if b.ended == nil {
		return
	}
	var apps []browserKeyRecord
	for _, r := range gone {
		if r.FrontEnd == login.FrontEndInstalledApp {
			apps = append(apps, r)
		}
	}
	if len(apps) > 0 {
		b.ended(apps)
	}
}

// keysSpeakingAt is the trail.KeyRoster for one app asset: a key speaks for a
// person when a sign-in at this asset named it, it has not lapsed, and the
// asset still stands behind that person (assetStillStands: membership and, where
// the policy requires one, the credential, asked again on each use).
type keysSpeakingAt struct {
	s     *CoreServer
	asset string
}

var _ trail.AssertionRoster = keysSpeakingAt{}

// VerifyAssertion: an installed app's key on Apple signs only App Attest
// assertions, so a statement it signed is checked as one, for the program the
// owner names now (the owner's setting, asked on every use). Every other key
// signs a plain statement (handled is false).
func (k keysSpeakingAt) VerifyAssertion(person, signer, verkey string, clientDataHash [32]byte, signature string) (bool, error) {
	tp, err := login.BrowserKeyThumbprintOfMachineKey(verkey)
	if err != nil {
		return false, nil
	}
	rec, ok := k.s.browserKeys().Get(k.asset, tp, time.Now())
	if !ok || rec.FrontEnd != login.FrontEndInstalledApp || rec.Proof == nil || rec.Proof.Platform != "apple" {
		return false, nil
	}
	if k.s.assetHandler == nil {
		return true, errors.New("the assets are not open")
	}
	a, found, err := k.s.assetHandler.Store.GetAsset(k.asset)
	if err != nil || !found || a.InstalledApp.AppleAppID == "" {
		return true, errors.New("the owner names no Apple program for this app")
	}
	raw, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return true, errors.New("an App Attest assertion is base64url")
	}
	pub, err := p256FromMachineVerkey(verkey)
	if err != nil {
		return true, err
	}
	if _, err := verifyAppleInstalledAssertion(raw, clientDataHash[:], pub, a.InstalledApp.AppleAppID); err != nil {
		return true, err
	}
	return true, nil
}

// p256FromMachineVerkey is the P-256 public key a machine verkey stands for.
func p256FromMachineVerkey(verkey string) (*ecdsa.PublicKey, error) {
	raw, err := iacrypto.KeyFromMachineVerkey(verkey)
	if err != nil {
		return nil, err
	}
	var x, y *big.Int
	switch len(raw) {
	case 33:
		x, y = elliptic.UnmarshalCompressed(elliptic.P256(), raw)
	case 65:
		x, y = elliptic.Unmarshal(elliptic.P256(), raw)
	}
	if x == nil {
		return nil, errors.New("the key is not a P-256 point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func (k keysSpeakingAt) KeySpeaksFor(person, signer, verkey string) bool {
	tp, err := login.BrowserKeyThumbprintOfMachineKey(verkey)
	if err != nil {
		return false
	}
	_, ok := k.s.keySpeaksUntil(k.asset, person, tp, time.Now())
	return ok
}

// keySpeaksUntil is whether the key with this thumbprint speaks for person at
// the asset now, and until when: a live record of a sign-in at the asset for
// that person, and the asset still standing behind them. A zero time is an
// installed app's grant, which speaks until it is ended. It is the one reading
// of whether a key speaks: a statement is judged by it (KeySpeaksFor), and a
// utility app's back end asks it (BrowserKeySpeaksUntil) so the session it holds for
// the key ends when the key stops speaking, not later.
func (s *CoreServer) keySpeaksUntil(assetID, person, thumbprint string, now time.Time) (time.Time, bool) {
	rec, ok := s.browserKeys().Get(assetID, thumbprint, now)
	if !ok || rec.Person != person || !s.assetStillStands(rec) {
		return time.Time{}, false
	}
	return rec.Until, true
}

// browserKeySpeaksUntil is keySpeaksUntil for an add-on, which names the key
// by its RFC 7638 thumbprint; a malformed one is an error, not a "no".
func (s *CoreServer) browserKeySpeaksUntil(assetID, person, thumbprint string) (time.Time, bool, error) {
	if assetID == "" || person == "" {
		return time.Time{}, false, errors.New("ask whether a key speaks by the asset and the person")
	}
	if err := login.CheckBrowserKeyThumbprint(thumbprint); err != nil {
		return time.Time{}, false, err
	}
	until, ok := s.keySpeaksUntil(assetID, person, thumbprint, time.Now())
	return until, ok, nil
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
		if !tpmProofStillAllowed(rec.Proof, a.InstalledApp) {
			return false
		}
		// The owner's requirement of a hardware key, asked on every use: a key in
		// software stops speaking the moment the owner requires one (ADR-072
		// Amendment 17), however it was approved.
		if a.RequireHardwareKey && rec.FrontEnd == login.FrontEndInstalledApp && rec.Grade() != KeyGradeHardware {
			return false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ok, _ := s.authorizeAssetAccess(ctx, a.PairwiseAID, rec.Person, rec.Presented)
	return ok
}

// tpmProofStillAllowed is whether the owner still accepts the kind of chip a TPM key was
// proved in, asked on every use as the front-end switch is: an owner who withdraws
// tpm_keys stops every grant held by a TPM key, and one who withdraws virtual_tpm_keys
// stops every grant held by a virtual or cloud TPM's key, however long ago it was approved.
// A key proved on another platform is not this rule's.
func tpmProofStillAllowed(p *installedAppFact, id asset.InstalledAppIdentity) bool {
	if p == nil || p.Platform != "tpm" {
		return true
	}
	if !id.TPMKeys {
		return false
	}
	switch p.EKClass {
	case secureenclave.TPMClassPhysical:
		return true
	case secureenclave.TPMClassVirtual:
		return id.AcceptsVirtualTPM()
	default:
		// A TPM proof that names no class was not kept by this core; it is not trusted for one.
		return false
	}
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

// endAppKey ends one key's records at the app's own asset, for a call an add-on
// has authenticated itself (the app's machine, sealed to this Identity Agent): callerAsset
// is the app the add-on found asking, as for startFrontEndKeySignIn, and the rules are
// those of theAppAsking. Ending only takes power away, so the app that signed the person in may.
func (s *CoreServer) endAppKey(r *http.Request, callerAsset, thumbprint string) (int, error) {
	if thumbprint == "" {
		return 0, errors.New("ending an app key names the key")
	}
	if err := s.theAppAsking(r, callerAsset, callerAsset); err != nil {
		return 0, err
	}
	if aPageAsked(r) {
		return 0, errors.New("a request that came from a web page cannot end an app's key")
	}
	if err := login.CheckBrowserKeyThumbprint(thumbprint); err != nil {
		return 0, err
	}
	return s.browserKeys().End(callerAsset, thumbprint, "")
}

// appKeyStillSpeaks is whether the key still speaks for the person at the app's own
// asset, by the same rule every use of it is held to: a live record, not ended by the
// person, the owner or the app, whose front-end kind the owner has not switched off, and
// whose person the asset still admits. For an app's back end, which holds its own session
// for the key and asks this now and then (an add-on that has authenticated the machine:
// callerAsset is the app it found asking).
func (s *CoreServer) appKeyStillSpeaks(callerAsset, thumbprint, person string) bool {
	rec, ok := s.browserKeys().Get(callerAsset, thumbprint, time.Now())
	if !ok || rec.Person != person {
		return false
	}
	return s.assetStillStands(rec)
}

// assetIDOfSite is the id of the asset whose pairwise identifier is siteAID.
func (s *CoreServer) assetIDOfSite(siteAID string) (string, bool) {
	a, ok := s.assetOfSite(siteAID)
	return a.ID, ok
}

// assetOfSite is the asset whose pairwise identifier is siteAID.
func (s *CoreServer) assetOfSite(siteAID string) (asset.Asset, bool) {
	if s.assetHandler == nil || siteAID == "" {
		return asset.Asset{}, false
	}
	assets, err := s.assetHandler.Store.ListAssets()
	if err != nil {
		return asset.Asset{}, false
	}
	for _, a := range assets {
		if a.PairwiseAID == siteAID {
			return a, true
		}
	}
	return asset.Asset{}, false
}
