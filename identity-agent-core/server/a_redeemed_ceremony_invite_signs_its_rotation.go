package server

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// An owner's own device signs an ownership ceremony's rotations with the key it
// derived for that organisation. That key never leaves this Identity Agent, so
// the front end that shows the person the rotation asks this Identity Agent to
// make the signature.
//
// What this will sign is narrow on purpose: only for an invite this Identity Agent
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
		http.Error(w, "this Identity Agent has not accepted that invitation into an ownership ceremony, or it was too long ago", http.StatusNotFound)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.RawB64)
	if err != nil {
		http.Error(w, "raw_b64 is not base64", http.StatusBadRequest)
		return
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil || ev.Ilk != "rot" || ev.Identifier != in.siteAID {
		http.Error(w, "that is not a rotation of the organisation that invited this Identity Agent", http.StatusBadRequest)
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

	// WHERE THE ROTATION GOES IN THE ORGANISATION'S LOG IS NOT TAKEN ON ITS
	// WORD (ADR-061 section 9). A signer outside the core takes the place it
	// signs at from the key state it has verified itself: an organisation's
	// Identity Agent that hid an establishment event, or showed a different
	// history to each owner, would otherwise get its owners' signatures on a
	// rotation that forks its log.
	//
	// The place is decided once per place, under ceremonyInvitesMu, and the
	// decision is kept with the invitation before the signature is returned:
	//   - the event this device already signed at that place is signed again
	//     (an answer lost on the way back);
	//   - a different event at a place this device already signed at is refused,
	//     whatever the organisation says: that is a second history;
	//   - an event that follows the one this device signed (a hand-over's second
	//     rotation, after its first) is placed by that signature;
	//   - anything else must follow the end of the organisation's log as this
	//     device reads it from the organisation and checks it with the
	//     witnesses the log names.
	//
	// The organisation's log is read without the lock held, so a slow or
	// unanswering organisation holds up nothing else on this device; the place
	// is decided again under the lock, against what is on disk then, before
	// the decision is kept.
	ceremonyInvitesMu.Lock()
	k, onDisk := s.readCeremonyInvites()[body.InviteToken]
	ceremonyInvitesMu.Unlock()
	if !onDisk {
		http.Error(w, "this device could not keep a record of what it signs for this ownership change, so it will not sign: "+
			"a signature it cannot remember is one it could be asked to contradict", http.StatusInternalServerError)
		return
	}
	logChecked := false
	if ceremonyPlaceOf(k, ev) == placeNeedsTheLog {
		if why, code := s.followsTheOrganisationsLog(in, ev); why != "" {
			http.Error(w, why, code)
			return
		}
		logChecked = true
	}

	ceremonyInvitesMu.Lock()
	defer ceremonyInvitesMu.Unlock()
	kept := s.readCeremonyInvites()
	k, onDisk = kept[body.InviteToken]
	switch p := ceremonyPlaceOf(k, ev); {
	case !onDisk:
		http.Error(w, "this ownership change is no longer kept on this device, so it will not sign", http.StatusNotFound)
		return
	case p == placeTaken:
		http.Error(w, fmt.Sprintf("this device already signed a different event at place %d of the organisation's key history; "+
			"signing this one too would give the organisation two histories", ev.SN), http.StatusConflict)
		return
	case p == placeNeedsTheLog && !logChecked:
		http.Error(w, "what this device has signed for this change moved while it was checking; ask again", http.StatusConflict)
		return
	}
	if k.Signed == nil {
		k.Signed = map[string]string{}
	}
	k.Signed[strconv.FormatUint(ev.SN, 10)] = ev.SAID
	kept[body.InviteToken] = k
	if err := s.writeCeremonyInvites(kept); err != nil {
		http.Error(w, "this device could not record what it is about to sign, so it did not sign it", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
}

// Where a rotation goes, as what this device already signed decides it.
const (
	placeSignedAlready = iota // this very event: sign it again
	placeTaken                // another event was signed there: refuse
	placeFollowsSigned        // follows the event signed at the place before
	placeNeedsTheLog          // only the organisation's log can say
)

func ceremonyPlaceOf(k keptCeremonyInvite, ev *keri.Event) int {
	if signed, ok := k.Signed[strconv.FormatUint(ev.SN, 10)]; ok {
		if signed == ev.SAID {
			return placeSignedAlready
		}
		return placeTaken
	}
	if ev.SN > 0 {
		if prev, ok := k.Signed[strconv.FormatUint(ev.SN-1, 10)]; ok && prev == ev.PriorSAID {
			return placeFollowsSigned
		}
	}
	return placeNeedsTheLog
}

// followsTheOrganisationsLog reports why [ev] does not follow the end of the
// inviting organisation's key history, with the status to answer, or "" when
// it does. The history is read from the organisation's own address, its
// signatures checked here, and its end checked with the witnesses it names:
// the organisation could show a shortened log, and only a party that saw its
// events as they happened can say it is the whole one (witness.Corroborate).
func (s *CoreServer) followsTheOrganisationsLog(in redeemedInvite, ev *keri.Event) (string, int) {
	if in.siteOOBI == "" {
		return "this invitation did not say where the organisation's key history is, so where this change goes cannot be checked", http.StatusConflict
	}
	// The address came with the invitation, so it is read as any address a
	// scanned code chose is (siteClient).
	records, err := fetchKELWith(siteClient(15*time.Second, in.siteOOBI), in.siteOOBI)
	if err != nil || len(records) == 0 {
		return "the organisation's key history could not be read, so where this change goes could not be checked; try again shortly", http.StatusServiceUnavailable
	}
	msgs, err := drivers.SignedMessagesFromRecords(records)
	if err != nil {
		return fmt.Sprintf("the organisation's key history does not prove itself (%v), so this device will not sign a change to it", err), http.StatusConflict
	}
	verified, err := drivers.VerifiedLogOf(in.siteAID, msgs)
	if err != nil {
		return fmt.Sprintf("the organisation's key history does not check out (%v), so this device will not sign a change to it", err), http.StatusConflict
	}
	tip := verified.State()
	if keys := tip.Witnesses(); len(keys) > 0 {
		// Each witness is found by its key in this Identity Agent's own registry,
		// never by an address the organisation gave, as askTheWitnesses does.
		c := witness.CorroborateThrough(nil, witness.BootstrapPool(), in.siteAID, records, keys)
		if c.Contradicted {
			return "the organisation's witnesses do not hold the history it showed this device: " + c.Why, http.StatusConflict
		}
		// One witness holding the whole history is enough to place the event,
		// and one honest witness that holds more, or a different event, or a
		// signed rival, refuses it (Contradicted). Asking for the log's full
		// threshold would leave a phone unable to sign whenever one witness was
		// down, and what it adds (several witnesses lying together while every
		// honest one is out of reach) is what duplicity detection is for.
		if !c.Corroborated() {
			return fmt.Sprintf("none of the organisation's witnesses could confirm its key history yet (%d named, %d answered, %d behind, %d could not be asked), "+
				"so where this change goes could not be checked; try again shortly", c.Designated, c.Asked, c.Behind, c.Failed), http.StatusServiceUnavailable
		}
	} else {
		// An identity that never named witnesses has nobody else to ask: its own
		// verified history is all there is, as ADR-061 section 9 allows. One
		// whose history named witnesses and now names none is refused: an
		// organisation holds its own keys, so it can write a branch that cuts
		// every witness and show its owners that instead of the history its
		// witnesses hold.
		for sn := uint64(0); sn < tip.SN(); sn++ {
			if st := verified.StateAt(sn); st != nil && len(st.Witnesses()) > 0 {
				return "the organisation's key history names no witnesses now but did before, so nobody can confirm it is the history " +
					"its witnesses hold, and this device will not sign a change to it", http.StatusConflict
			}
		}
		log.Printf("[ceremony] %s names no witnesses; its own key history, checked here, places this change", in.siteAID)
	}
	if ev.SN != tip.SN()+1 || ev.PriorSAID != tip.Digest() {
		return fmt.Sprintf("this change does not follow the end of the organisation's key history (it goes at place %d after %s; the history ends at place %d with %s), "+
			"so signing it could give the organisation a second history", ev.SN, ev.PriorSAID, tip.SN(), tip.Digest()), http.StatusConflict
	}
	return "", 0
}

// ceremonyInvitesFile is where invitations into an ownership ceremony are kept,
// beside the other things this Identity Agent keeps for itself.
const ceremonyInvitesFile = "redeemed_ceremony_invites.json"

type keptCeremonyInvite struct {
	Base     string    `json:"base"`
	SiteAID  string    `json:"site_aid"`
	SiteOOBI string    `json:"site_oobi"`
	At       time.Time `json:"at"`
	// Signed is the event this device signed at each place of the
	// organisation's key history, by place: what it will sign again, and the
	// only thing it will sign there.
	Signed map[string]string `json:"signed,omitempty"`
}

// keptCeremonyInvites is the file as written: the entries, and a tag over them
// made with a key derived from this device's root seed. A file is only as
// private as the folder it is in, and what it holds decides which identity this
// device reveals a key for, so a write to that folder by anything else must not
// be believed: it cannot make the tag.
type keptCeremonyInvites struct {
	Invites json.RawMessage `json:"invites"`
	TagB64  string          `json:"tag_b64"`
}

var ceremonyInvitesMu sync.Mutex

// ceremonyInvitesTag is the tag over the entries' exact bytes.
func (s *CoreServer) ceremonyInvitesTag(invites []byte) ([]byte, error) {
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return nil, err
	}
	key, err := backup.DeriveCeremonyInvitesTagKey(root)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, key)
	m.Write(invites)
	return m.Sum(nil), nil
}

// keepCeremonyInvite writes [in] to disk under its code. What is held is the
// code that lets this phone's Identity Agent sign for that one ceremony, which
// is why entries are dropped when their time is up, and why the file carries a
// tag. A file whose tag does not hold reads as empty, so it is replaced by one
// holding only this entry: its entries were never to be believed, and are not
// carried over.
func (s *CoreServer) keepCeremonyInvite(token string, in redeemedInvite) error {
	ceremonyInvitesMu.Lock()
	defer ceremonyInvitesMu.Unlock()
	kept := s.readCeremonyInvites()
	k := kept[token]
	k.Base, k.SiteAID, k.SiteOOBI, k.At = in.base, in.siteAID, in.siteOOBI, time.Now().UTC()
	kept[token] = k
	return s.writeCeremonyInvites(kept)
}

// writeCeremonyInvites replaces what is on disk with [kept], tagged. Callers
// hold ceremonyInvitesMu.
func (s *CoreServer) writeCeremonyInvites(kept map[string]keptCeremonyInvite) error {
	inner, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	tag, err := s.ceremonyInvitesTag(inner)
	if err != nil {
		return err
	}
	b, err := json.Marshal(keptCeremonyInvites{Invites: inner, TagB64: base64.StdEncoding.EncodeToString(tag)})
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

// readCeremonyInvites is what is on disk, tagged as this device wrote it, and
// not yet out of time. A file whose tag does not hold, or that has none, or
// that cannot be checked because the root seed cannot be read, holds nothing:
// the ceremonies in it are not signed for, and the person is asked again.
//
// The tag says this device wrote the file; it does not say this is the newest
// file it wrote. An older copy put back holds a valid tag and may lack a pin
// written since. What stops a second, different event at a pinned place then
// is the front end's own record of what it agreed to and signed, kept in the
// platform's secure storage rather than in this folder, and the organisation's
// log as its witnesses hold it, read again before signing.
// Callers hold ceremonyInvitesMu.
func (s *CoreServer) readCeremonyInvites() map[string]keptCeremonyInvite {
	none := map[string]keptCeremonyInvite{}
	b, err := os.ReadFile(filepath.Join(s.DataDir, ceremonyInvitesFile))
	if err != nil {
		return none
	}
	var file keptCeremonyInvites
	if json.Unmarshal(b, &file) != nil || len(file.Invites) == 0 {
		return none
	}
	got, err := base64.StdEncoding.DecodeString(file.TagB64)
	if err != nil {
		return none
	}
	want, err := s.ceremonyInvitesTag(file.Invites)
	if err != nil || !hmac.Equal(got, want) {
		return none
	}
	kept := map[string]keptCeremonyInvite{}
	if json.Unmarshal(file.Invites, &kept) != nil {
		return none
	}
	for t, k := range kept {
		if time.Since(k.At) > redeemedCeremonyMemory {
			delete(kept, t)
		}
	}
	return kept
}

// recallRedeemedInvite is the invite this Identity Agent redeemed under [token]: from
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
