package login

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"identity-agent-core/atomicfile"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/internal/jsonreply"
)

// The person's own record of the installed-app sign-ins they approved.
//
// Approving an installed app's sign-in lets its key speak for the person until
// they or the app's owner end it (ADR-072 section 4), so the person needs a list
// of what they approved and a way to end each one. The grant itself is held where
// the app lives; this is the person's own copy of what they said yes to, kept in
// their own Identity Agent, and it is what ending reads from.

// InstalledAppSignIn is one approved sign-in for an installed app's key.
type InstalledAppSignIn struct {
	Key         string    `json:"key"`      // the installed app's key thumbprint, as signed in the challenge
	SiteAID     string    `json:"site_aid"` // the utility app's identifier
	SiteOOBI    string    `json:"site_oobi,omitempty"`
	Audience    string    `json:"audience,omitempty"` // the address the app named for itself
	PairwiseAID string    `json:"pairwise_aid"`       // who the person is to that app
	ApprovedAt  time.Time `json:"approved_at"`
	// RelationshipKey names the relationship the sign-in was made under, which
	// is the site's identifier or, for a membership site, the controller's.
	RelationshipKey string `json:"relationship_key"`
	// EndBase is where the app's host takes the signed end: the sign-in's own
	// callback address without its last part.
	EndBase string `json:"end_base"`
}

// InstalledAppSignInStore keeps them on disk, one per (app, key).
type InstalledAppSignInStore struct {
	mu    sync.Mutex
	path  string
	items map[string]InstalledAppSignIn
}

func NewInstalledAppSignInStore(dataDir string) (*InstalledAppSignInStore, error) {
	s := &InstalledAppSignInStore{
		path:  filepath.Join(dataDir, "installed_app_sign_ins.json"),
		items: map[string]InstalledAppSignIn{},
	}
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.items); err != nil {
		return nil, err
	}
	return s, nil
}

func installedAppSignInID(siteAID, key string) string { return siteAID + "|" + key }

func (s *InstalledAppSignInStore) save() error {
	b, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return atomicfile.Write(s.path, b, 0o600)
}

func (s *InstalledAppSignInStore) Put(r InstalledAppSignIn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[installedAppSignInID(r.SiteAID, r.Key)] = r
	return s.save()
}

func (s *InstalledAppSignInStore) Get(siteAID, key string) (InstalledAppSignIn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.items[installedAppSignInID(siteAID, key)]
	return r, ok
}

func (s *InstalledAppSignInStore) Delete(siteAID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[installedAppSignInID(siteAID, key)]; !ok {
		return nil
	}
	delete(s.items, installedAppSignInID(siteAID, key))
	return s.save()
}

// List is newest first.
func (s *InstalledAppSignInStore) List() []InstalledAppSignIn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]InstalledAppSignIn, 0, len(s.items))
	for _, r := range s.items {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ApprovedAt.After(out[j].ApprovedAt) })
	return out
}

// EndAppKeyAudience is the only audience a signed end is made for. The host's
// /app-key/end/begin names it and the person's Identity Agent insists on it.
const EndAppKeyAudience = "end-app-key"

const callbackSuffix = "/callback"

// installedAppEndBase is where the app's host takes the signed end, taken from
// the sign-in's callback address (".../api/login/callback" -> ".../api/login").
func installedAppEndBase(callbackURL string) string {
	u := callbackURL
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if !strings.HasSuffix(u, callbackSuffix) {
		return ""
	}
	return strings.TrimSuffix(u, callbackSuffix)
}

// recordInstalledAppSignIn is called before the assertion is posted, so a
// grant the host accepts always has a record here to end it by.
func (h *Handler) recordInstalledAppSignIn(rel *SiteRelationship, b *ChallengeBundle) (undo func(), err error) {
	if b.FrontEnd != FrontEndInstalledApp || b.BrowserKey == "" || h.InstalledApps == nil {
		return func() {}, nil
	}
	prev, had := h.InstalledApps.Get(b.SiteAID, b.BrowserKey)
	relKey := b.SiteAID
	if b.RelationshipAnchorAID != "" {
		relKey = b.RelationshipAnchorAID
	}
	err = h.InstalledApps.Put(InstalledAppSignIn{
		Key: b.BrowserKey, SiteAID: b.SiteAID, SiteOOBI: b.SiteOOBI, Audience: b.Audience,
		PairwiseAID: rel.PairwiseAID, ApprovedAt: time.Now().UTC(),
		RelationshipKey: relKey, EndBase: installedAppEndBase(b.CallbackURL),
	})
	undo = func() {
		if had {
			_ = h.InstalledApps.Put(prev)
		} else {
			_ = h.InstalledApps.Delete(b.SiteAID, b.BrowserKey)
		}
	}
	return undo, err
}

// ListInstalledAppSignIns: GET, the person's own list.
func (h *Handler) HandleInstalledAppSignIns(w http.ResponseWriter, _ *http.Request) {
	out := []InstalledAppSignIn{}
	if h.InstalledApps != nil {
		out = h.InstalledApps.List()
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"installed_app_sign_ins": out})
}

// HandleEndInstalledAppSignIn: POST {site_aid, key}, the person ends one.
func (h *Handler) HandleEndInstalledAppSignIn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SiteAID string `json:"site_aid"`
		Key     string `json:"key"`
	}
	raw, err := boundedread.All(r.Body, boundedread.Document)
	if err != nil || json.Unmarshal(raw, &body) != nil || body.SiteAID == "" || CheckBrowserKeyThumbprint(body.Key) != nil {
		jsonreply.Write(w, http.StatusBadRequest, map[string]string{"error": "say which app and which key"})
		return
	}
	already, status, err := h.EndInstalledAppSignIn(body.SiteAID, body.Key)
	if err != nil {
		jsonreply.Write(w, status, map[string]string{"error": err.Error()})
		return
	}
	reply := map[string]interface{}{"ok": true, "ended": true, "already_ended": already}
	if already {
		reply["message"] = AlreadyEndedMessage
	}
	jsonreply.Write(w, http.StatusOK, reply)
}

// EndInstalledAppSignIn ends the person's own grant with the existing signed
// end: a nonce from the app's host, then an assertion for the grant's key from
// the person. It forgets the record only when the host says it is ended or says
// it is no longer live (the owner already ended it: alreadyEnded is true then,
// and it is not an error), and answers the status a caller should relay.
func (h *Handler) EndInstalledAppSignIn(siteAID, key string) (alreadyEnded bool, status int, err error) {
	if h.InstalledApps == nil {
		return false, http.StatusNotFound, fmt.Errorf("no installed-app sign-ins are kept here")
	}
	rec, ok := h.InstalledApps.Get(siteAID, key)
	if !ok {
		return false, http.StatusNotFound, fmt.Errorf("you have no approved sign-in for that key")
	}
	if rec.EndBase == "" {
		return false, http.StatusConflict, fmt.Errorf("this sign-in did not say where it is ended; ask the app's owner to end it")
	}
	post := func(path string, payload []byte) (int, []byte, error) {
		url := rec.EndBase + path
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := h.peerClient(url).Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		b, _ := boundedread.All(resp.Body, boundedread.Document)
		return resp.StatusCode, b, nil
	}
	begin, _ := json.Marshal(map[string]string{"site_aid": rec.SiteAID, "key": rec.Key})
	code, resp, err := post("/app-key/end/begin", begin)
	if err != nil {
		return false, http.StatusBadGateway, fmt.Errorf("the app's host could not be reached, so nothing was ended: %w", err)
	}
	if code == http.StatusGone {
		return h.forgetAlreadyEnded(rec), http.StatusOK, nil
	}
	if code != http.StatusOK {
		return false, http.StatusBadGateway, fmt.Errorf("the app's host would not start ending it (%d)", code)
	}
	var ask map[string]string
	if json.Unmarshal(resp, &ask) != nil || ask["nonce"] == "" {
		return false, http.StatusBadGateway, fmt.Errorf("the app's host answered something unreadable")
	}
	// The host names what is signed, so the host is not trusted with it: the
	// audience is the fixed end-app-key one (a sign-in made here is valid nowhere
	// else) and the site is the record's own. The relationship is the person's
	// existing one, never made here.
	if ask["audience"] != EndAppKeyAudience || ask["site_aid"] != rec.SiteAID ||
		ask["browser_key"] != rec.Key || ask["front_end"] != FrontEndInstalledApp {
		return false, http.StatusBadGateway, fmt.Errorf("the app's host asked for something other than ending this sign-in, so nothing was signed")
	}
	bundle := &ChallengeBundle{
		SiteAID: rec.SiteAID, Audience: EndAppKeyAudience, Nonce: ask["nonce"],
		BrowserKey: rec.Key, FrontEnd: FrontEndInstalledApp,
	}
	relv, found := h.Store.Get(rec.RelationshipKey)
	if !found {
		return false, http.StatusConflict, fmt.Errorf("this Identity Agent has no relationship with that app any more, so nothing was signed")
	}
	rel := &relv
	as, err := h.BuildAssertion(rel, bundle, nil)
	if err != nil {
		return false, http.StatusInternalServerError, err
	}
	signed, err := json.Marshal(as)
	if err != nil {
		return false, http.StatusInternalServerError, err
	}
	code, _, err = post("/app-key/end", signed)
	if err != nil {
		return false, http.StatusBadGateway, fmt.Errorf("the app's host could not be reached, so nothing was ended: %w", err)
	}
	if code == http.StatusGone {
		return h.forgetAlreadyEnded(rec), http.StatusOK, nil
	}
	if code != http.StatusOK {
		return false, http.StatusConflict, fmt.Errorf("the app's host did not end it (%d)", code)
	}
	_ = h.InstalledApps.Delete(rec.SiteAID, rec.Key)
	return false, http.StatusOK, nil
}

// AlreadyEndedMessage is what the person is told when the host says the sign-in
// is no longer live.
const AlreadyEndedMessage = "It had already been ended"

// forgetAlreadyEnded drops the person's record of a sign-in the host says is no
// longer live, so the list never shows it as live. It answers true.
func (h *Handler) forgetAlreadyEnded(rec InstalledAppSignIn) bool {
	_ = h.InstalledApps.Delete(rec.SiteAID, rec.Key)
	return true
}
