package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
)

// An app-key grant has no end of its own, so it must be easy to end and
// impossible to forget (ADR-072 section 4, Amendment 3). It ends when:
//
//   - the app's back end signs the person out (EndBrowserKeys, as before);
//   - the PERSON ends it: their Identity Agent proves who they are with a signed
//     assertion for the grant's key (POST /api/login/app-key/end, after a nonce
//     from /begin), and only the person the grant is for can;
//   - the asset's OWNER ends it (DELETE /api/assets/{id}/app-key-grants/{key}),
//     and reads which are held (GET /api/assets/{id}/app-key-grants);
//   - the owner switches the installed_app front end off (asset.Handler.
//     OnFrontEndsSwitchedOff), which also stops it speaking at once on every
//     use (assetStillStands);
//   - the person is removed from the asset (OnMemberRemoved), so the grant
//     cannot wake if they are added again.
//   - for a key held in software, the owner requires a hardware key
//     (OnHardwareKeyRequired, ADR-072 Amendment 17), or its lapse time passes.
// An asset that is gone speaks for no one (assetStillStands).

// EndKind ends every record at the asset of the front-end kind, and says how many.
func (b *browserKeys) EndKind(asset, kind string) (int, error) {
	return b.endWhere(asset, func(r browserKeyRecord) bool {
		rk := r.FrontEnd
		if rk == "" {
			rk = login.FrontEndBrowser
		}
		return rk == kind
	})
}

// EndSoftwareAppKeys ends every installed app's grant at the asset that a key
// held in software holds: what the owner's requiring a hardware key ends (ADR-072
// Amendment 17). Its back ends are told, as for any other ending.
func (b *browserKeys) EndSoftwareAppKeys(asset string) (int, error) {
	return b.endWhere(asset, func(r browserKeyRecord) bool {
		return r.FrontEnd == login.FrontEndInstalledApp && r.Grade() != KeyGradeHardware
	})
}

// endWhere ends every record at the asset that ends says to, and says how many.
func (b *browserKeys) endWhere(asset string, ends func(browserKeyRecord) bool) (int, error) {
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return 0, err
	}
	n := 0
	var gone []browserKeyRecord
	for k, r := range all {
		if r.Asset == asset && ends(r) {
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

// AppKeyGrants are the live installed-app records at the asset, oldest first.
func (b *browserKeys) AppKeyGrants(asset string, now time.Time) []browserKeyRecord {
	browserKeysLock.Lock()
	defer browserKeysLock.Unlock()
	all, err := b.load()
	if err != nil {
		return nil
	}
	var out []browserKeyRecord
	for _, r := range all {
		if r.Asset == asset && r.FrontEnd == login.FrontEndInstalledApp && r.liveAt(now) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := time.Time{}, time.Time{}
		if out[i].Proof != nil {
			ti = out[i].Proof.Proved
		}
		if out[j].Proof != nil {
			tj = out[j].Proof.Proved
		}
		return ti.Before(tj)
	})
	return out
}

type appKeyGrantView struct {
	Key      string    `json:"key"`
	Person   string    `json:"person"`
	Platform string    `json:"platform,omitempty"`
	Level    string    `json:"level,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	// Grade is "hardware" when the device's secure hardware proved the key and
	// "software" when nothing did (ADR-072 Amendment 17). Until is when a key in
	// software stops speaking; a hardware key's grant has none.
	Grade string     `json:"grade,omitempty"`
	Until *time.Time `json:"until,omitempty"`
	// For a TPM key, who certified the chip's endorsement key and its class: "physical", or
	// "virtual" where the owner opted in to virtual TPMs. Notice says, for a virtual one, what
	// that means for the owner, in the words every screen uses.
	EKIssuer string `json:"ek_issuer,omitempty"`
	EKClass  string `json:"ek_class,omitempty"`
	Notice   string `json:"notice,omitempty"`
}

// handleListAppKeyGrants: GET /api/assets/{id}/app-key-grants, the owner's.
func (s *CoreServer) handleListAppKeyGrants(w http.ResponseWriter, r *http.Request) {
	out := []appKeyGrantView{}
	for _, g := range s.browserKeys().AppKeyGrants(chi.URLParam(r, "id"), time.Now()) {
		v := appKeyGrantView{Key: g.Thumbprint, Person: g.Person}
		v.Grade = g.Grade()
		if !g.Until.IsZero() {
			until := g.Until
			v.Until = &until
		}
		if g.Proof != nil {
			v.Platform, v.Level, v.Since = g.Proof.Platform, g.Proof.Level, g.Proof.Proved
			v.EKIssuer, v.EKClass = g.Proof.EKIssuer, g.Proof.EKClass
			if v.EKClass == secureenclave.TPMClassVirtual {
				v.Notice = asset.VirtualTPMKeysWarning
			}
		}
		out = append(out, v)
	}
	jsonreply.Write(w, http.StatusOK, out)
}

// handleEndAppKeyGrant: DELETE /api/assets/{id}/app-key-grants/{key}, the owner's.
func (s *CoreServer) handleEndAppKeyGrant(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if err := login.CheckBrowserKeyThumbprint(key); err != nil {
		writeError(w, http.StatusBadRequest, "which key", err.Error())
		return
	}
	n, err := s.browserKeys().End(chi.URLParam(r, "id"), key, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not end it", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]int{"ended": n})
}

// The person ends their own grant in two steps, so what they sign is fresh: a
// nonce from the core, then an assertion naming it, for the grant's key and the
// installed_app kind, from the person the grant is for.
const (
	endAppKeyAudience = login.EndAppKeyAudience
	endAppKeyLife     = 5 * time.Minute
)

// errNoLongerLive is the host's answer (410 Gone) when the grant is not live.
// The person's Identity Agent matches it by status, not by this text.
const errNoLongerLive = "no longer live"

type endAppKeyAsk struct {
	assetID, key string
	caller       string // who asked for the nonce: its address, as the core sees it
	until        time.Time
}

// /begin is public (the person's Identity Agent has no credential yet), so its
// nonces are capped by who asked and by app, never by one count for everyone: a
// single caller filling a shared cap would stop every other person ending a
// grant. A caller is refused at endAppKeyPerCaller, an app's nonces stop at
// endAppKeyPerAsset (so one app cannot be used to fill the whole table), the
// table at endAppKeyTotal, and every nonce expires in endAppKeyLife.
const (
	endAppKeyPerCaller = 20
	endAppKeyPerAsset  = 200
	endAppKeyTotal     = 5000
)

var (
	endAppKeyMu    sync.Mutex
	endAppKeyAsked = map[string]endAppKeyAsk{} // nonce -> ask
)

// handleBeginEndAppKey: POST /api/login/app-key/end/begin {asset_aid, key}.
// It answers the fields the person's Identity Agent signs an assertion over.
func (s *CoreServer) handleBeginEndAppKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SiteAID string `json:"site_aid"`
		Key     string `json:"key"`
	}
	raw, err := boundedread.All(r.Body, boundedread.Document)
	if err != nil || json.Unmarshal(raw, &body) != nil || login.CheckBrowserKeyThumbprint(body.Key) != nil {
		writeError(w, http.StatusBadRequest, "bad request", "")
		return
	}
	assetID, found := s.assetIDOfSite(body.SiteAID)
	if !found {
		writeError(w, http.StatusNotFound, "no such app", "")
		return
	}
	// A grant that is not live (the owner ended it, or it was already ended) is
	// said so, so the person's list can drop it instead of showing it as live.
	if _, live := s.browserKeys().Get(assetID, body.Key, time.Now()); !live {
		writeError(w, http.StatusGone, errNoLongerLive, "")
		return
	}
	nb := make([]byte, 24)
	if _, err := rand.Read(nb); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start", "")
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	now := time.Now()
	endAppKeyMu.Lock()
	for n, a := range endAppKeyAsked {
		if now.After(a.until) {
			delete(endAppKeyAsked, n)
		}
	}
	caller, perCaller, perAsset := callerKey(r), 0, 0
	for _, a := range endAppKeyAsked {
		if a.caller == caller {
			perCaller++
		}
		if a.assetID == assetID {
			perAsset++
		}
	}
	if perCaller >= endAppKeyPerCaller || perAsset >= endAppKeyPerAsset || len(endAppKeyAsked) >= endAppKeyTotal {
		endAppKeyMu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many open", "")
		return
	}
	endAppKeyAsked[nonce] = endAppKeyAsk{assetID: assetID, key: body.Key, caller: caller, until: now.Add(endAppKeyLife)}
	endAppKeyMu.Unlock()
	jsonreply.Write(w, http.StatusOK, map[string]string{
		"nonce": nonce, "audience": endAppKeyAudience, "site_aid": body.SiteAID,
		"browser_key": body.Key, "front_end": login.FrontEndInstalledApp,
	})
}

// handleEndAppKey: POST /api/login/app-key/end, the assertion as the body. It
// ends the grant only when the assertion verifies and is from the person the
// grant is for.
func (s *CoreServer) handleEndAppKey(w http.ResponseWriter, r *http.Request) {
	body, err := boundedread.All(r.Body, boundedread.Document)
	if err != nil {
		writeError(w, boundedread.Status(err), "bad request", "")
		return
	}
	_, a, _, err := login.ReadSignInPost(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad request", "")
		return
	}
	// One use: the nonce is spent whether or not the assertion verifies.
	endAppKeyMu.Lock()
	ask, ok := endAppKeyAsked[a.Nonce]
	delete(endAppKeyAsked, a.Nonce)
	endAppKeyMu.Unlock()
	if !ok || time.Now().After(ask.until) {
		writeError(w, http.StatusForbidden, "not authorized", "")
		return
	}
	siteAID := ""
	if ass, found, err := s.assetHandler.Store.GetAsset(ask.assetID); err == nil && found {
		siteAID = ass.PairwiseAID
	}
	res := login.VerifyAssertionForFrontEnd(a, a.Nonce, endAppKeyAudience, siteAID, ask.key, login.FrontEndInstalledApp, 300)
	if !res.Valid {
		writeError(w, http.StatusForbidden, "not authorized", "")
		return
	}
	rec, held := s.browserKeys().Get(ask.assetID, ask.key, time.Now())
	if !held {
		// Ended between the nonce and the answer: the same "not live" as at /begin.
		writeError(w, http.StatusGone, errNoLongerLive, "")
		return
	}
	if rec.Person != res.PairwiseAID {
		writeError(w, http.StatusForbidden, "not authorized", "")
		return
	}
	n, err := s.browserKeys().End(ask.assetID, ask.key, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not end it", "")
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]int{"ended": n})
}
