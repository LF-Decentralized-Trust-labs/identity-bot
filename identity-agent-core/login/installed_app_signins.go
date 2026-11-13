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
	status, err := h.EndInstalledAppSignIn(body.SiteAID, body.Key)
	if err != nil {
		jsonreply.Write(w, status, map[string]string{"error": err.Error()})
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"ok": true, "ended": true})
}

// EndInstalledAppSignIn ends the person's own grant with the existing signed
// end: a nonce from the app's host, then an assertion for the grant's key from
// the person. It forgets the record only when the host says it is ended, and
// answers the status a caller should relay.
func (h *Handler) EndInstalledAppSignIn(siteAID, key string) (int, error) {
	if h.InstalledApps == nil {
		return http.StatusNotFound, fmt.Errorf("no installed-app sign-ins are kept here")
	}
	rec, ok := h.InstalledApps.Get(siteAID, key)
	if !ok {
		return http.StatusNotFound, fmt.Errorf("you have no approved sign-in for that key")
	}
	if rec.EndBase == "" {
		return http.StatusConflict, fmt.Errorf("this sign-in did not say where it is ended; ask the app's owner to end it")
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
		return http.StatusBadGateway, fmt.Errorf("the app's host could not be reached, so nothing was ended: %w", err)
	}
	if code != http.StatusOK {
		return http.StatusBadGateway, fmt.Errorf("the app's host would not start ending it (%d)", code)
	}
	var ask map[string]string
	if json.Unmarshal(resp, &ask) != nil || ask["nonce"] == "" {
		return http.StatusBadGateway, fmt.Errorf("the app's host answered something unreadable")
	}
	bundle := &ChallengeBundle{
		SiteAID: ask["site_aid"], Audience: ask["audience"], Nonce: ask["nonce"],
		BrowserKey: ask["browser_key"], FrontEnd: ask["front_end"],
	}
	if bundle.BrowserKey != rec.Key || bundle.FrontEnd != FrontEndInstalledApp {
		return http.StatusBadGateway, fmt.Errorf("the app's host named a different key, so nothing was signed")
	}
	rel, err := h.GetOrCreateRelationship(rec.RelationshipKey, bundle)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	as, err := h.BuildAssertion(rel, bundle, nil)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	signed, err := json.Marshal(as)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	code, _, err = post("/app-key/end", signed)
	if err != nil {
		return http.StatusBadGateway, fmt.Errorf("the app's host could not be reached, so nothing was ended: %w", err)
	}
	if code != http.StatusOK {
		return http.StatusConflict, fmt.Errorf("the app's host did not end it (%d); it may already have been ended there", code)
	}
	_ = h.InstalledApps.Delete(rec.SiteAID, rec.Key)
	return http.StatusOK, nil
}
