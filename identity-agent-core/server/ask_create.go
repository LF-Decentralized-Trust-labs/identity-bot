package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
)

// mintedAsks holds IA-originated Asks (e.g. an add-contact "add me" QR), served at /i/{token}
// alongside login challenge bundles. Login Asks are minted by the website; peer-to-peer Asks
// are minted here by the IA itself.
var mintedAsks = struct {
	sync.Mutex
	m map[string][]byte
}{m: map[string][]byte{}}

func getMintedAsk(token string) ([]byte, bool) {
	mintedAsks.Lock()
	defer mintedAsks.Unlock()
	b, ok := mintedAsks.m[token]
	return b, ok
}

// AskMinter is implemented by actions an IA can originate itself (host its own /i/{token}).
// Login is minted by the relying-party website, so loginAsk does NOT implement this;
// add-contact does (you mint your own "add me" QR for others to scan).
type AskMinter interface {
	Mint(s *CoreServer) ([]byte, error)
}

// Mint builds this agent's add-contact Ask (t=2): "add me as a contact".
func (addContactAsk) Mint(s *CoreServer) ([]byte, error) {
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		return nil, fmt.Errorf("no local identity")
	}
	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		return nil, fmt.Errorf("no public URL (tunnel) available")
	}
	alias := id.AID
	if len(alias) >= 12 {
		alias = alias[:12] + "..."
	}
	if p, _ := s.DataStore.GetProfile(); p != nil && p.FullName != "" {
		alias = p.FullName
	}
	return json.Marshal(map[string]interface{}{
		"v":           "ASK1",
		"t":           2,
		"asker_aid":   id.AID,
		"asker_oobi":  fmt.Sprintf("%s/public/oobi/%s", publicURL, id.AID),
		"asker_alias": alias,
	})
}

func (s *CoreServer) mountAskCreateRoute(r chi.Router) {
	r.Post("/api/ask/create", s.handleAskCreate)
}

// POST /api/ask/create {t} -> {token, url}. Mints an IA-originated Ask of action t and hosts it
// at /i/{token} so it can be shown as a QR.
func (s *CoreServer) handleAskCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		T int `json:"t"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	h, ok := lookupAsk(body.T)
	if !ok {
		http.Error(w, fmt.Sprintf("unknown action t=%d", body.T), http.StatusNotImplemented)
		return
	}
	minter, ok := h.(AskMinter)
	if !ok {
		http.Error(w, fmt.Sprintf("action t=%d is not IA-mintable (originated elsewhere)", body.T), http.StatusBadRequest)
		return
	}
	ask, err := minter.Mint(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tb := make([]byte, 16)
	_, _ = rand.Read(tb)
	token := hex.EncodeToString(tb)
	mintedAsks.Lock()
	mintedAsks.m[token] = ask
	mintedAsks.Unlock()

	publicURL := s.EndpointService.CurrentURL()
	if publicURL == "" {
		publicURL = s.getPublicURL(r)
	}
	scanWriteJSON(w, map[string]string{"token": token, "url": fmt.Sprintf("%s/i/%s", publicURL, token)})
}
