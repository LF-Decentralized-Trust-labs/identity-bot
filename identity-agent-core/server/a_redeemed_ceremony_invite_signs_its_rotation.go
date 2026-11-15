package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// An owner's own device signs an ownership ceremony's rotations with the key it
// derived for that organisation. That key never leaves this agent, so the app
// that shows the person the rotation asks this agent to make the signature.
//
// What this will sign is narrow on purpose: only for an invite this agent
// redeemed into a ceremony, only a rotation of that organisation's identity, and
// only with a key (the one in force, or the one it committed to) that the
// rotation itself reveals. It is not a way to sign anything else with that key.
func (s *CoreServer) mountCeremonySigningRoutes(r chi.Router) {
	r.Post("/api/redeemed-invites/ceremony-signature", s.handleSignACeremonyRotation)
}

// ceremonyKeyGenerations are the keys of a relationship a ceremony uses: 0 is
// the key the owner accepted with, signing the first rotation; 1 is the key it
// committed to there, which a hand-over reveals and signs the second with.
const ceremonyKeyGenerations = 2

func (s *CoreServer) handleSignACeremonyRotation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InviteToken string `json:"invite_token"`
		Generation  int    `json:"generation"`
		RawB64      string `json:"raw_b64"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, maxKeyEventBody)).Decode(&body) != nil || body.InviteToken == "" || body.RawB64 == "" {
		http.Error(w, "invite_token, generation and raw_b64 required", http.StatusBadRequest)
		return
	}
	if body.Generation < 0 || body.Generation >= ceremonyKeyGenerations {
		http.Error(w, "only the key in force and the one it committed to sign a ceremony's rotations", http.StatusBadRequest)
		return
	}
	in, ok := s.recallRedeemedInvite(body.InviteToken)
	if !ok || !in.ceremony || s.loginHandler == nil {
		http.Error(w, "this agent has not accepted that invitation into an ownership ceremony, or it was too long ago", http.StatusNotFound)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.RawB64)
	if err != nil {
		http.Error(w, "raw_b64 is not base64", http.StatusBadRequest)
		return
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil || ev.Ilk != "rot" || ev.Identifier != in.siteAID {
		http.Error(w, "that is not a rotation of the organisation that invited this agent", http.StatusBadRequest)
		return
	}
	rel, err := s.loginHandler.GetOrCreateRelationship(in.siteAID, &login.ChallengeBundle{SiteAID: in.siteAID, SiteOOBI: in.siteOOBI})
	if err != nil || rel == nil || rel.RelationshipIndex <= 0 {
		http.Error(w, "the key this invitation was accepted with could not be loaded", http.StatusInternalServerError)
		return
	}
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		http.Error(w, "this device has no root seed to sign with", http.StatusInternalServerError)
		return
	}
	seed, err := backup.DerivePairwiseSeed(root, rel.RelationshipIndex, body.Generation)
	if err != nil {
		http.Error(w, "the key could not be derived", http.StatusInternalServerError)
		return
	}
	key := ed25519.NewKeyFromSeed(seed)
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
		for i := range key {
			key[i] = 0
		}
	}()
	mine := iacrypto.VerkeyQB64(key.Public().(ed25519.PublicKey))
	revealed := false
	for _, k := range ev.Keys {
		if k == mine {
			revealed = true
		}
	}
	if !revealed {
		http.Error(w, fmt.Sprintf("that rotation does not reveal this device's key (generation %d)", body.Generation), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]string{"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
}

// ceremonyInvitesFile is where invitations into an ownership ceremony are kept,
// beside the other things this agent keeps for itself.
const ceremonyInvitesFile = "redeemed_ceremony_invites.json"

type keptCeremonyInvite struct {
	Base     string    `json:"base"`
	SiteAID  string    `json:"site_aid"`
	SiteOOBI string    `json:"site_oobi"`
	At       time.Time `json:"at"`
}

var ceremonyInvitesMu sync.Mutex

// keepCeremonyInvite writes [in] to disk under its code. The file is private to
// this agent, and what is held is the code that lets this phone's agent sign for
// that one ceremony, which is why entries are dropped when their time is up.
func (s *CoreServer) keepCeremonyInvite(token string, in redeemedInvite) error {
	ceremonyInvitesMu.Lock()
	defer ceremonyInvitesMu.Unlock()
	kept := s.readCeremonyInvites()
	kept[token] = keptCeremonyInvite{Base: in.base, SiteAID: in.siteAID, SiteOOBI: in.siteOOBI, At: time.Now().UTC()}
	b, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	path := filepath.Join(s.DataDir, ceremonyInvitesFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readCeremonyInvites is what is on disk and not yet out of time. Callers hold
// ceremonyInvitesMu.
func (s *CoreServer) readCeremonyInvites() map[string]keptCeremonyInvite {
	kept := map[string]keptCeremonyInvite{}
	b, err := os.ReadFile(filepath.Join(s.DataDir, ceremonyInvitesFile))
	if err != nil || json.Unmarshal(b, &kept) != nil {
		return map[string]keptCeremonyInvite{}
	}
	for t, k := range kept {
		if time.Since(k.At) > redeemedCeremonyMemory {
			delete(kept, t)
		}
	}
	return kept
}

// recallRedeemedInvite is the invite this agent redeemed under [token]: from
// memory, or, for an ownership ceremony, from disk after a restart.
func (s *CoreServer) recallRedeemedInvite(token string) (redeemedInvite, bool) {
	if in, ok := s.redeemedInvites.recall(token); ok {
		return in, true
	}
	ceremonyInvitesMu.Lock()
	k, ok := s.readCeremonyInvites()[token]
	ceremonyInvitesMu.Unlock()
	if !ok {
		return redeemedInvite{}, false
	}
	in := redeemedInvite{base: k.Base, siteAID: k.SiteAID, siteOOBI: k.SiteOOBI, ceremony: true, at: k.At}
	s.redeemedInvites.remember(token, in)
	return in, true
}
